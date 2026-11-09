
import pytest

from backend.deployment_readiness import (
    PROTECTED_PATHS,
    REQUIRED_FILES,
    assess_project,
    is_sensitive_tracked_path,
)


@pytest.fixture
def project(tmp_path):
    for name in REQUIRED_FILES:
        path = tmp_path / name
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        path.write_text(
            "placeholder",
            encoding="utf-8",
        )

    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "USER aegis\n"
        'CMD ["backend.secured_app:app"]\n',
        encoding="utf-8",
    )

    (tmp_path / "compose.yaml").write_text(
        "ports:\n"
        "  - 127.0.0.1:8000:8000\n"
        "security_opt:\n"
        "  - no-new-privileges:true\n"
        "cap_drop:\n"
        "  - ALL\n"
        "volumes:\n"
        "  - aegis_logs:/app/logs\n",
        encoding="utf-8",
    )

    return tmp_path


def test_clean_project_passes(project):
    report = assess_project(
        project,
        tracked_files={
            "Dockerfile",
            "compose.yaml",
            "backend/secured_app.py",
        },
        ignored_paths=set(PROTECTED_PATHS),
    )

    assert report["checks_failed"] == 0
    assert (
        report["readiness"]
        == "LOCAL_DEVELOPMENT_BASELINE"
    )


def test_missing_required_file_fails(project):
    (project / ".env.example").unlink()

    report = assess_project(
        project,
        tracked_files=set(),
        ignored_paths=set(PROTECTED_PATHS),
    )

    assert report["checks_failed"] >= 1
    assert report["readiness"] == "REQUIRES_ATTENTION"


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.local",
        "logs/security_audit.jsonl",
        "backups/private.zip",
        ".vscode/settings.json",
        "backend/main.py.bak",
        "models/weights.safetensors",
    ],
)
def test_sensitive_tracked_files_detected(path):
    assert is_sensitive_tracked_path(path)


def test_env_example_is_not_sensitive():
    assert not is_sensitive_tracked_path(
        ".env.example"
    )


def test_historical_results_not_automatically_sensitive():
    """
    Experiment reports may be intentionally tracked.
    Their contents still require review before publication.
    """
    assert not is_sensitive_tracked_path(
        "results/07_accuracy_baseline.json"
    )


def test_tracked_sensitive_data_fails(project):
    report = assess_project(
        project,
        tracked_files={
            "logs/security_audit.jsonl",
        },
        ignored_paths=set(PROTECTED_PATHS),
    )

    assert report["checks_failed"] >= 1


def test_missing_git_exclusion_fails(project):
    ignored = set(PROTECTED_PATHS)
    ignored.remove(".env")

    report = assess_project(
        project,
        tracked_files=set(),
        ignored_paths=ignored,
    )

    assert report["checks_failed"] >= 1


def test_missing_container_hardening_fails(project):
    (project / "compose.yaml").write_text(
        "ports:\n  - 0.0.0.0:8000:8000\n",
        encoding="utf-8",
    )

    report = assess_project(
        project,
        tracked_files=set(),
        ignored_paths=set(PROTECTED_PATHS),
    )

    assert report["checks_failed"] >= 1


def test_readiness_report_contains_warnings(project):
    report = assess_project(
        project,
        tracked_files=set(),
        ignored_paths=set(PROTECTED_PATHS),
    )

    assert report["warnings"]
    assert any(
        "simulation" in warning.lower()
        for warning in report["warnings"]
    )
