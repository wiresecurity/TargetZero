# SPDX-License-Identifier: Apache-2.0
# Columns of the role plan written by Invoke-T0M365AdminInventory (1_m365_role-plan.csv) and read
# by Set-T0M365RoleAssignment. People fill in action, new_end_date and justification.
$script:T0RolePlanFields = @(
    'plan_id', 'kind', 'account', 'principal_id', 'principal_type', 'role', 'role_definition_id',
    'directory_scope_id', 'state', 'permanent', 'current_end_date', 'assignment_id', 'resource_id',
    'app_role_id', 'privileged', 'break_glass', 'mfa_class', 'action', 'new_end_date', 'justification'
)

# Role template id of Global Administrator (the same in every tenant).
$script:T0GlobalAdminTemplate = '62e90394-69f5-4237-9190-012177145e10'
