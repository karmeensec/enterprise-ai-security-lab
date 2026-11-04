
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = (
    ROOT
    / "data"
    / "knowledge_base"
    / "security_policies.json"
)

MANIFEST_FILE = (
    ROOT
    / "config"
    / "trusted_policy_manifest.json"
)

EXPECTED_IDS = {
    "POL-001",
    "POL-002",
    "POL-003",
    "POL-004",
    "POL-005",
}


def main():
    print("=" * 65)
    print("EXPERIMENT 46 - TRUSTED DOCUMENT BASELINE")
    print("=" * 65)

    if not POLICY_FILE.is_file():
        raise FileNotFoundError(
            f"Knowledge base missing: {POLICY_FILE}"
        )

    if MANIFEST_FILE.exists():
        raise FileExistsError(
            "Trusted manifest already exists. "
            "Refusing to overwrite the baseline."
        )

    # Hash the exact file bytes, not a modified
    # or reformatted JSON representation.
    raw_bytes = POLICY_FILE.read_bytes()

    policies = json.loads(raw_bytes.decode("utf-8"))

    if not isinstance(policies, list):
        raise ValueError(
            "Expected a list of policy documents."
        )

    ids = []
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("Invalid policy record.")

        for field in ("id", "title", "content"):
            if (
                not isinstance(policy.get(field), str)
                or not policy[field].strip()
            ):
                raise ValueError(
                    f"Invalid or missing field: {field}"
                )

        ids.append(policy["id"])

    if (
        len(ids) != len(EXPECTED_IDS)
        or set(ids) != EXPECTED_IDS
    ):
        raise ValueError(
            "Policy IDs do not match the expected "
            "baseline inventory."
        )

    if len(ids) != len(set(ids)):
        raise ValueError(
            "Duplicate policy identifiers detected."
        )

    digest = hashlib.sha256(raw_bytes).hexdigest()

    manifest = {
        "manifest_version": 1,
        "algorithm": "sha256",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "source": "data/knowledge_base/security_policies.json",
        "sha256": digest,
        "file_size_bytes": len(raw_bytes),
        "document_count": len(policies),
        "document_ids": sorted(ids),
        "approval_status": "pending_manual_review",
    }

    MANIFEST_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    MANIFEST_FILE.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print("Source:", POLICY_FILE)
    print("Documents:", len(policies))
    print("Document IDs:", sorted(ids))
    print("File size:", len(raw_bytes), "bytes")
    print("SHA-256:", digest)
    print("Approval: pending_manual_review")
    print("Manifest:", MANIFEST_FILE)
    print()
    print("Baseline generated successfully.")
    print("Review it before approving or committing.")


if __name__ == "__main__":
    main()
