# SPDX-License-Identifier: Apache-2.0
function Set-T0M365RoleAssignment {
    <#
    .SYNOPSIS
        Applies the reviewed role plan (1_m365_role-plan.csv): removes admin rights, makes them
        eligible or time-bound. Dry run unless -Apply is given.
    .DESCRIPTION
        Fill in the action column of the plan written by Invoke-T0M365AdminInventory:

          remove                  remove the assignment (role or app permission)
          make-eligible           PIM: replace the active assignment with an eligible one (Entra ID P2)
          time-bound              PIM: give the active assignment an end date, new_end_date (P2)
          make-permanent          PIM: remove the end date again (used by rollback)
          restore-active          add the active assignment again (used by rollback)
          restore-eligible        add the eligible assignment again (used by rollback)
          restore-app-permission  grant the app permission again (used by rollback)

        Safety:
        - Without -Apply nothing changes; the output says what would happen.
        - Break-glass accounts (targetzero.yaml) are never changed.
        - It refuses any change that would leave the tenant without an active Global Administrator.
        - Every applied change is logged, and a rollback plan is written next to it:
          Set-T0M365RoleAssignment -PlanPath <rollback csv> -Apply undoes the run.

        Needs Connect-T0M365 -ReadWrite and the Privileged Role Administrator role.
    .EXAMPLE
        Set-T0M365RoleAssignment -Config $config -PlanPath output/2026-11-19/1_m365_role-plan.csv
        Set-T0M365RoleAssignment -Config $config -PlanPath output/2026-11-19/1_m365_role-plan.csv -Apply
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][PSTypeName('TargetZero.Config')]$Config,
        [Parameter(Mandatory)][string]$PlanPath,
        [switch]$Apply,
        [datetime]$RunDate = (Get-Date)
    )
    $actions = 'remove', 'make-eligible', 'time-bound', 'make-permanent', 'restore-active', 'restore-eligible', 'restore-app-permission'
    $rows = @(Import-Csv -LiteralPath $PlanPath | Where-Object { $_.action })
    if (-not $rows) {
        Write-Warning "No rows with an action in $PlanPath. Fill in the action column first."
        return
    }
    $breakGlass = @($Config.BreakGlass['m365'])
    $plans = @(Invoke-T0Graph -Uri 'subscribedSkus' -All | Where-Object { $_['capabilityStatus'] -eq 'Enabled' } |
            ForEach-Object { $_['servicePlans'] } | ForEach-Object { $_['servicePlanName'] })
    $hasPim = $plans -contains 'AAD_PREMIUM_P2'

    # Live count of active Global Administrators, to refuse removing the last one.
    $activeGa = @(Invoke-T0Graph -Uri "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$script:T0GlobalAdminTemplate'" -All).Count
    # Break-glass rows are refused below, so they do not reduce the count.
    $gaLoss = @($rows | Where-Object {
            $_.kind -eq 'role' -and $_.state -eq 'active' -and $_.role_definition_id -eq $script:T0GlobalAdminTemplate -and
            $_.action -in 'remove', 'make-eligible' -and
            $_.break_glass -ne 'Y' -and $breakGlass -notcontains $_.account.ToLowerInvariant()
        }).Count

    $changes = [System.Collections.Generic.List[object]]::new()
    $rollback = [System.Collections.Generic.List[object]]::new()
    $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)

    foreach ($row in $rows) {
        $result = [ordered]@{ plan_id = $row.plan_id; account = $row.account; role = $row.role; action = $row.action; status = ''; detail = '' }
        $refuse = $null
        if ($row.action -notin $actions) { $refuse = "unknown action '$($row.action)'" }
        elseif ($row.break_glass -eq 'Y' -or $breakGlass -contains $row.account.ToLowerInvariant()) { $refuse = 'break-glass account: never changed' }
        elseif ($row.action -in 'make-eligible', 'time-bound', 'make-permanent', 'restore-eligible' -and -not $hasPim) { $refuse = 'needs PIM (Entra ID P2)' }
        elseif ($row.action -eq 'time-bound') {
            $end = [datetime]::MinValue
            if (-not [datetime]::TryParse($row.new_end_date, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$end) -or $end -le (Get-Date)) {
                $refuse = 'time-bound needs a future new_end_date (YYYY-MM-DD)'
            }
        }
        elseif ($row.kind -eq 'app-permission' -and $row.action -notin 'remove', 'restore-app-permission') { $refuse = "action '$($row.action)' does not apply to app permissions" }
        if (-not $refuse -and $gaLoss -and $row.role_definition_id -eq $script:T0GlobalAdminTemplate -and $row.action -in 'remove', 'make-eligible' -and $activeGa - $gaLoss -lt 1) {
            $refuse = "would leave no active Global Administrator ($activeGa active, $gaLoss planned to go)"
        }
        if ($refuse) {
            $result.status = 'refused'; $result.detail = $refuse
            $changes.Add($result); [pscustomobject]$result
            continue
        }

        $justification = if ($row.justification) { $row.justification } else { 'Target 0: admin rights reduction' }
        $request = @{
            principalId = $row.principal_id; roleDefinitionId = $row.role_definition_id
            directoryScopeId = if ($row.directory_scope_id) { $row.directory_scope_id } else { '/' }; justification = $justification
        }
        $permanentSchedule = @{ startDateTime = $now; expiration = @{ type = 'noExpiration' } }
        # Each entry is one Graph call: @(method, uri, body). @() keeps a single call as a list.
        $calls = @(switch ($row.action) {
            'remove' {
                if ($row.kind -eq 'app-permission') { , @('DELETE', "servicePrincipals/$($row.principal_id)/appRoleAssignments/$($row.assignment_id)", $null) }
                elseif ($row.state -eq 'eligible') { , @('POST', 'roleManagement/directory/roleEligibilityScheduleRequests', ($request + @{ action = 'adminRemove' })) }
                elseif ($hasPim) { , @('POST', 'roleManagement/directory/roleAssignmentScheduleRequests', ($request + @{ action = 'adminRemove' })) }
                else { , @('DELETE', "roleManagement/directory/roleAssignments/$($row.assignment_id)", $null) }
            }
            'make-eligible' {
                $expiration = if ($row.new_end_date) { @{ type = 'afterDateTime'; endDateTime = "$($row.new_end_date)T23:59:59Z" } } else { @{ type = 'noExpiration' } }
                , @('POST', 'roleManagement/directory/roleEligibilityScheduleRequests', ($request + @{ action = 'adminAssign'; scheduleInfo = @{ startDateTime = $now; expiration = $expiration } }))
                , @('POST', 'roleManagement/directory/roleAssignmentScheduleRequests', ($request + @{ action = 'adminRemove' }))
            }
            'time-bound' {
                , @('POST', 'roleManagement/directory/roleAssignmentScheduleRequests', ($request + @{ action = 'adminUpdate'; scheduleInfo = @{ startDateTime = $now; expiration = @{ type = 'afterDateTime'; endDateTime = "$($row.new_end_date)T23:59:59Z" } } }))
            }
            'make-permanent' {
                , @('POST', 'roleManagement/directory/roleAssignmentScheduleRequests', ($request + @{ action = 'adminUpdate'; scheduleInfo = $permanentSchedule }))
            }
            'restore-active' {
                if ($hasPim) { , @('POST', 'roleManagement/directory/roleAssignmentScheduleRequests', ($request + @{ action = 'adminAssign'; scheduleInfo = $permanentSchedule })) }
                else { , @('POST', 'roleManagement/directory/roleAssignments', @{ principalId = $row.principal_id; roleDefinitionId = $row.role_definition_id; directoryScopeId = $request.directoryScopeId }) }
            }
            'restore-eligible' {
                , @('POST', 'roleManagement/directory/roleEligibilityScheduleRequests', ($request + @{ action = 'adminAssign'; scheduleInfo = $permanentSchedule }))
            }
            'restore-app-permission' {
                , @('POST', "servicePrincipals/$($row.principal_id)/appRoleAssignments", @{ principalId = $row.principal_id; resourceId = $row.resource_id; appRoleId = $row.app_role_id })
            }
        })

        # Rollback rows: the same plan row with the action that undoes this one.
        $undo = @(switch ($row.action) {
            'remove' { if ($row.kind -eq 'app-permission') { , @('restore-app-permission', 'active') } elseif ($row.state -eq 'eligible') { , @('restore-eligible', 'eligible') } else { , @('restore-active', 'active') } }
            'make-eligible' { , @('restore-active', 'active'); , @('remove', 'eligible') }
            'time-bound' { , @('make-permanent', 'active') }
            'make-permanent' { , @('time-bound', 'active') }
            'restore-active' { , @('remove', 'active') }
            'restore-eligible' { , @('remove', 'eligible') }
            'restore-app-permission' { , @('remove', 'active') }
        })

        $description = ($calls | ForEach-Object { "$($_[0]) $($_[1])" }) -join ' + '
        if (-not $Apply) {
            $result.status = 'dry-run'; $result.detail = "would call $description"
        }
        elseif ($PSCmdlet.ShouldProcess("$($row.account) / $($row.role)", $row.action)) {
            try {
                foreach ($call in $calls) {
                    $response = Invoke-T0GraphWrite -Method $call[0] -Uri $call[1] -Body $call[2]
                    if ($call[0] -eq 'POST' -and $call[1] -like '*/appRoleAssignments') { $row.assignment_id = $response['id'] }
                }
                $result.status = 'applied'; $result.detail = $description
                foreach ($u in $undo) {
                    $back = [ordered]@{}
                    foreach ($f in $script:T0RolePlanFields) { $back[$f] = $row.$f }
                    $back['action'] = $u[0]; $back['state'] = $u[1]; $back['new_end_date'] = $row.current_end_date
                    $back['justification'] = "Rollback of $($row.action) $(Get-Date -Format 'yyyy-MM-dd')"
                    $rollback.Add($back)
                }
                if ($row.role_definition_id -eq $script:T0GlobalAdminTemplate -and $row.action -in 'remove', 'make-eligible') { $activeGa-- }
            }
            catch {
                $result.status = 'failed'; $result.detail = $_.Exception.Message
            }
        }
        else {
            $result.status = 'skipped'; $result.detail = 'not confirmed'
        }
        $changes.Add($result)
        [pscustomobject]$result
    }

    $dir = Get-T0RunDirectory -Config $Config -RunDate $RunDate
    $paths = Save-T0ChangeLog -RunDirectory $dir -Name 'm365_roles' -Change $changes.ToArray() -Rollback $rollback.ToArray() `
        -Property $script:T0RolePlanFields -DryRun:(-not $Apply)
    Write-Information "Log: $($paths -join ', ')" -InformationAction Continue
}
