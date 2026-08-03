"""Fidelity-eval tests: precision/recall on the finding-identity key."""

from eval.fidelity import score
from eval.ground_truth import GROUND_TRUTH

from kuv.report import Finding
from kuv.severity import FindingType


def _unauth_write() -> Finding:
    return Finding(
        FindingType.UNAUTH_WRITE,
        "Unauthenticated write to prod data",
        "POST /api/ideas",
        "anon POST accepted; row visible after",
    )


def _unauth_read() -> Finding:
    return Finding(
        FindingType.UNAUTH_READ_SENSITIVE,
        "Unauthenticated read of sensitive data",
        "GET /api/ideas",
        "anon GET returned other users' rows",
    )


def test_producing_both_is_perfect():
    result = score([_unauth_write(), _unauth_read()], GROUND_TRUTH)
    assert result["recall"] == 1.0
    assert result["precision"] == 1.0
    assert result["missed"] == []
    assert result["extra"] == []


def test_producing_only_read_halves_recall():
    result = score([_unauth_read()], GROUND_TRUTH)
    assert result["recall"] == 0.5
