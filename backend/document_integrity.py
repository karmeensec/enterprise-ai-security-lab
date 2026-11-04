
import hashlib
import hmac
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_POLICY_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)

DEFAULT_MANIFEST_FILE = (
    ROOT / "config" / "trusted_policy_manifest.json"
)


class DocumentIntegrityError(Exception):
    """Knowledge-base integrity validation failed."""


def verify_policy_integrity(
    policy_file: Path = DEFAULT_POLICY_FILE,
    manifest_file: Path = DEFAULT_MANIFEST_FILE,
) -> dict:
    """
    Verify policy bytes against a separately approved manifest.

    This checks integrity relative to the manifest.
    It does not authenticate who approved that manifest.
    """
    policy_file = Path(policy_file)
    manifest_file = Path(manifest_file)

    if not policy_file.is_file():
        raise DocumentIntegrityError(
            "Policy file missing."
        )

    if not manifest_file.is_file():
        raise DocumentIntegrityError(
            "Trusted manifest missing."
        )

    try:
        manifest = json.loads(
            manifest_file.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise DocumentIntegrityError(
            "Manifest cannot be read or parsed."
        ) from exc

    if not isinstance(manifest, dict):
        raise DocumentIntegrityError(
            "Manifest must be a JSON object."
        )

    if (
        type(manifest.get("manifest_version")) is not int
        or manifest["manifest_version"] != 1
        or manifest.get("algorithm") != "sha256"
        or manifest.get("source")
        != "data/knowledge_base/security_policies.json"
    ):
        raise DocumentIntegrityError(
            "Unsupported manifest configuration."
        )

    expected_hash = manifest.get("sha256")

    if (
        not isinstance(expected_hash, str)
        or re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ) is None
    ):
        raise DocumentIntegrityError(
            "Invalid manifest SHA-256 digest."
        )

    expected_ids = manifest.get("document_ids")

    if (
        not isinstance(expected_ids, list)
        or not expected_ids
        or any(
            not isinstance(item, str)
            or not re.fullmatch(r"POL-\d{3}", item)
            for item in expected_ids
        )
        or len(expected_ids) != len(set(expected_ids))
    ):
        raise DocumentIntegrityError(
            "Invalid manifest document inventory."
        )

    expected_size = manifest.get("file_size_bytes")
    expected_count = manifest.get("document_count")

    if (
        type(expected_size) is not int
        or expected_size < 1
        or type(expected_count) is not int
        or expected_count < 1
        or expected_count != len(expected_ids)
    ):
        raise DocumentIntegrityError(
            "Invalid manifest size or document count."
        )

    if manifest.get("approval_status") != "approved":
        raise DocumentIntegrityError(
            "Manifest has not been approved."
        )

    try:
        raw = policy_file.read_bytes()
    except OSError as exc:
        raise DocumentIntegrityError(
            "Policy file cannot be read."
        ) from exc

    actual_hash = hashlib.sha256(raw).hexdigest()

    if not hmac.compare_digest(
        actual_hash, expected_hash
    ):
        raise DocumentIntegrityError(
            "SHA-256 mismatch: policy file modified."
        )

    if len(raw) != expected_size:
        raise DocumentIntegrityError(
            "Policy file size mismatch."
        )

    try:
        documents = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise DocumentIntegrityError(
            "Policy JSON is invalid."
        ) from exc

    if not isinstance(documents, list):
        raise DocumentIntegrityError(
            "Policy JSON must contain a list."
        )

    ids = []

    for document in documents:
        if not isinstance(document, dict):
            raise DocumentIntegrityError(
                "Invalid policy document."
            )

        for key in ("id", "title", "content"):
            value = document.get(key)

            if (
                not isinstance(value, str)
                or not value.strip()
            ):
                raise DocumentIntegrityError(
                    f"Invalid policy field: {key}"
                )

        ids.append(document["id"])

    if (
        len(documents) != expected_count
        or len(ids) != len(set(ids))
        or sorted(ids) != sorted(expected_ids)
    ):
        raise DocumentIntegrityError(
            "Policy inventory does not match manifest."
        )

    return {
        "status": "verified",
        "document_count": len(documents),
        "document_ids": sorted(ids),
        "sha256": actual_hash,
        "file_size_bytes": len(raw),
        "manifest_approval": "approved",
    }
