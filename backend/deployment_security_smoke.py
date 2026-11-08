
"""
Experiment 62 — Deployed API Security Smoke Test.

Run inside the Docker container:

    python -m backend.deployment_security_smoke

Uses credentials from the container environment.
Does not print credentials or submit valid agent jobs.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request


BASE_URL = "http://127.0.0.1:8000"


def request(
    path: str,
    *,
    method: str = "GET",
    authenticated: bool = False,
    password_override: str | None = None,
    payload: dict | None = None,
    extra_headers: dict | None = None,
) -> tuple[int, str]:
    headers = {}

    if authenticated:
        username = os.environ["DASHBOARD_USERNAME"]
        password = (
            password_override
            if password_override is not None
            else os.environ["DASHBOARD_PASSWORD"]
        )

        encoded = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")

        headers["Authorization"] = f"Basic {encoded}"

    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if extra_headers:
        headers.update(extra_headers)

    http_request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers=headers,
    )

    try:
        with urllib.request.urlopen(
            http_request,
            timeout=15,
        ) as response:
            return (
                response.status,
                response.read(65536).decode(
                    "utf-8",
                    errors="replace",
                ),
            )

    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(65536).decode(
                "utf-8",
                errors="replace",
            ),
        )


def main() -> int:
    if not all(
        os.environ.get(name)
        for name in (
            "DASHBOARD_USERNAME",
            "DASHBOARD_PASSWORD",
            "AGENT_CASE_ACCESS_JSON",
        )
    ):
        print(
            "FAIL: Required authentication or agent "
            "permission configuration is missing"
        )
        return 1

    checks = [
        (
            "Health endpoint responds",
            "/health",
            {},
            200,
        ),
        (
            "Anonymous agent access rejected",
            "/agent/monitor",
            {},
            401,
        ),
        (
            "Invalid credentials rejected",
            "/agent/monitor",
            {
                "authenticated": True,
                "password_override": (
                    "intentionally-invalid-password"
                ),
            },
            401,
        ),
        (
            "Authenticated agent monitor available",
            "/agent/monitor",
            {"authenticated": True},
            200,
        ),
        (
            "Invalid monitoring window rejected",
            "/agent/monitor?window_minutes=999",
            {"authenticated": True},
            422,
        ),
        (
            "Role escalation field rejected",
            "/agent/chat",
            {
                "method": "POST",
                "authenticated": True,
                "payload": {
                    "question": "Find VPN policy",
                    "role": "admin",
                },
                "extra_headers": {
                    "X-Requested-With": "XMLHttpRequest",
                },
            },
            422,
        ),
        (
            "Missing write verification rejected",
            "/agent/chat",
            {
                "method": "POST",
                "authenticated": True,
                "payload": {
                    "question": "Find VPN policy",
                },
            },
            403,
        ),
        (
            "Agent Security Dashboard available",
            "/dashboard/agent-security",
            {"authenticated": True},
            200,
        ),
        (
            "SOC Dashboard available",
            "/dashboard/",
            {"authenticated": True},
            200,
        ),
    ]

    failures = 0

    for label, path, options, expected in checks:
        try:
            code, body = request(path, **options)

            password = os.environ["DASHBOARD_PASSWORD"]

            passed = (
                code == expected
                and password not in body
            )

        except Exception as exc:
            print(
                f"FAIL | {label}: "
                f"{type(exc).__name__}"
            )
            failures += 1
            continue

        status = "PASS" if passed else "FAIL"

        print(
            f"{status} | {label} "
            f"| HTTP {code} "
            f"| expected {expected}"
        )

        if not passed:
            failures += 1

    print()
    print(
        f"Deployment security checks: "
        f"{len(checks) - failures}/{len(checks)} passed"
    )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
