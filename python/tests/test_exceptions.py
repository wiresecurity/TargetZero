# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import date

from targetzero.registers.exceptions import check_row

RUN = date(2026, 11, 19)


def row(**overrides: str) -> dict[str, str]:
    base = {
        "id": "EXC-001", "zero": "4", "items": "external:203.0.113.5/tcp-3389",
        "description": "Legacy app needs RDP until migration",
        "compensating_control": "Source IP allow-list",
        "accepted_by": "J. Smith, CEO", "signed_date": "2026-11-18", "expiry_date": "2027-02-15",
        "notes": "",
    }
    return base | overrides


def test_valid_exception() -> None:
    record = check_row(row(), RUN, 90)
    assert record.valid, record.problems
    assert record.zero == 4
    assert record.items == {"external:203.0.113.5/tcp-3389"}


def test_unsigned_is_a_gap() -> None:
    assert "accepted_by is empty" in check_row(row(accepted_by=""), RUN, 90).problems


def test_no_expiry_is_a_gap() -> None:
    assert not check_row(row(expiry_date=""), RUN, 90).valid


def test_longer_than_90_days_is_a_gap() -> None:
    record = check_row(row(expiry_date="2027-03-01"), RUN, 90)
    assert any("maximum is 90" in p for p in record.problems)


def test_expired_is_a_gap() -> None:
    record = check_row(row(signed_date="2026-08-01", expiry_date="2026-10-30"), RUN, 90)
    assert any("expired" in p for p in record.problems)


def test_bad_date_is_a_gap() -> None:
    assert not check_row(row(signed_date="18/11/2026"), RUN, 90).valid
