
"""
Experiment 65 — Deployment Readiness Audit.

Checks repository hygiene, Git exclusions,
Docker hardening, and operational documentation.

Does not read secret values, start models,
modify files, or perform network requests.

Usage:
    python -m backend.deployment_readiness
"""

import json
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

PROTECTED_PATHS = (
    ".env",
    ".env.local",
    ".vscode/settings.json",
    "backend/main.py.bak",
    "logs/security_audit.jsonl",
    "backups/backup.zip",
    "results/private_report.json",
)

REQUIRED_FILES = (
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    ".gitignore",
    ".env.example",
    "requirements-docker.txt",
    "backend/secured_app.py",
    "docs/DEPLOYMENT.md",
)

SENSITIVE_TRACKED_PREFIXES = (
    "logs/",
    "backups/",
    ".venv/",
)

SENSITIVE_TRACKED_SUFFIXES = (
    ".bak",
    ".safetensors",
    ".pt",
    ".pth",
    ".ckpt",
)

SENSITIVE_TRACKED_EXACT = {
    ".env",
    ".env.local",
}


def run_git(root: Path, *arguments: str):
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        check=False,
    )


def get_tracked_files(root: Path) -> set[str]:
    result = run_git(
        root,
        "ls-files",
        "-z",
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Git repository inspection failed"
        )

    return {
        name.decode(
            "utf-8",
            errors="replace",
        ).replace("\\", "/")
        for name in result.stdout.split(b"\0")
        if name
    }


def check_ignored(
    root: Path,
    relative_path: str,
) -> bool:
    result = run_git(
        root,
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative_path,
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Git ignore inspection failed"
        )

    return result.returncode == 0


def is_sensitive_tracked_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lowered = normalized.lower()

    if (
        normalized in SENSITIVE_TRACKED_EXACT
        or normalized.startswith(
            SENSITIVE_TRACKED_PREFIXES
        )
        or normalized.startswith(".vscode/")
        or normalized.startswith(".idea/")
        or lowered.endswith(
            SENSITIVE_TRACKED_SUFFIXES
        )
    ):
        return True

    if normalized.startswith(".env."):
        return normalized != ".env.example"

    return False


def add_check(
    checks: list,
    name: str,
    passed: bool,
    detail: str,
):
    checks.append({
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    })


def assess_project(
    root: Path,
    tracked_files: set[str],
    ignored_paths: set[str],
) -> dict:
    """
    Pure assessment, separated from Git command execution
    so that it can be unit tested safely.
    """

    checks = []
    warnings = []

    for filename in REQUIRED_FILES:
        add_check(
            checks,
            f"Required file: {filename}",
            (root / filename).is_file(),
            "Present" if (root / filename).is_file()
            else "Missing",
        )

    for path in PROTECTED_PATHS:
        add_check(
            checks,
            f"Git exclusion: {path}",
            path in ignored_paths,
            "Ignored by Git" if path in ignored_paths
            else "Not ignored",
        )

    sensitive_tracked = sorted(
        path
        for path in tracked_files
        if is_sensitive_tracked_path(path)
    )

    add_check(
        checks,
        "No sensitive runtime paths tracked",
        not sensitive_tracked,
        (
            "No protected paths found"
            if not sensitive_tracked
            else "Tracked paths: "
            + ", ".join(sensitive_tracked)
        ),
    )

    dockerfile = root / "Dockerfile"

    if dockerfile.is_file():
        docker_text = dockerfile.read_text(
            encoding="utf-8"
        )

        add_check(
            checks,
            "Docker uses an unprivileged user",
            "USER aegis" in docker_text,
            "Non-root user directive",
        )

        add_check(
            checks,
            "Docker uses integrated API entrypoint",
            "backend.secured_app:app" in docker_text,
            "Integrated API entrypoint",
        )

        if (
            "--index-url"
            in docker_text
            and "torch\n" in docker_text
        ):
            warnings.append(
                "CPU PyTorch is not pinned to an exact "
                "version. Rebuilds may resolve a different "
                "dependency release."
            )

    compose_file = root / "compose.yaml"

    if compose_file.is_file():
        compose_text = compose_file.read_text(
            encoding="utf-8"
        )

        add_check(
            checks,
            "Compose uses localhost binding",
            "127.0.0.1:8000:8000"
            in compose_text,
            "Host port restricted to localhost",
        )

        add_check(
            checks,
            "Compose disables privilege escalation",
            "no-new-privileges:true"
            in compose_text,
            "No-new-privileges configured",
        )

        add_check(
            checks,
            "Compose drops Linux capabilities",
            "cap_drop:" in compose_text
            and "- ALL" in compose_text,
            "All capabilities dropped",
        )

        add_check(
            checks,
            "Compose uses a persistent logs volume",
            "aegis_logs:/app/logs"
            in compose_text,
            "SOC logs volume configured",
        )

    warnings.append(
        "HTTP Basic authentication is suitable only "
        "for this restricted local development deployment. "
        "Production requires TLS and stronger identity controls."
    )

    warnings.append(
        "Incident-response actions are simulations. "
        "This platform is not approved for autonomous "
        "production security enforcement."
    )

    passed = sum(
        item["status"] == "PASS"
        for item in checks
    )

    return {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "checks": checks,
        "warnings": warnings,
        "readiness": (
            "LOCAL_DEVELOPMENT_BASELINE"
            if passed == len(checks)
            else "REQUIRES_ATTENTION"
        ),
    }


def main() -> int:
    try:
        tracked_files = get_tracked_files(ROOT)

        ignored_paths = {
            path
            for path in PROTECTED_PATHS
            if check_ignored(ROOT, path)
        }

        report = assess_project(
            ROOT,
            tracked_files,
            ignored_paths,
        )

    except (OSError, RuntimeError) as exc:
        print(
            "Readiness audit could not complete: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    print("Experiment 65 — Deployment Readiness")
    print()

    for check in report["checks"]:
        print(
            f"{check['status']:4} | "
            f"{check['name']}"
        )

    print()
    print(
        f"Checks passed: "
        f"{report['checks_passed']}/"
        f"{report['checks_total']}"
    )

    print(f"Readiness: {report['readiness']}")

    print()
    print("Known limitations:")

    for warning in report["warnings"]:
        print(f"- {warning}")

    # Save reports only under the Git-ignored results folder.
    output = ROOT / "results" / "65_readiness.json"
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print()
    print(f"Report saved: {output}")

    return 0 if report["checks_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
