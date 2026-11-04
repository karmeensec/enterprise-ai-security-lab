
import json
from pathlib import Path

import pytest

from backend.document_integrity import (
    DEFAULT_MANIFEST_FILE,
    DEFAULT_POLICY_FILE,
    DocumentIntegrityError,
    verify_policy_integrity,
)


@pytest.fixture
def integrity_files(tmp_path):
    policy = tmp_path / "security_policies.json"
    manifest = tmp_path / "trusted_policy_manifest.json"

    policy.write_bytes(DEFAULT_POLICY_FILE.read_bytes())

    data = json.loads(
        DEFAULT_MANIFEST_FILE.read_text(encoding="utf-8")
    )

    # Approve only this isolated test fixture.
    # The actual project manifest stays pending.
    data["approval_status"] = "approved"

    manifest.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    return policy, manifest



def test_approved_real_manifest_verifies():
    result = verify_policy_integrity()

    assert result["status"] == "verified"
    assert result["document_count"] == 5
    assert result["manifest_approval"] == "approved"



def test_unchanged_policy_passes(integrity_files):
    policy, manifest = integrity_files

    result = verify_policy_integrity(policy, manifest)

    assert result["status"] == "verified"
    assert result["document_count"] == 5


def test_modified_policy_blocked(integrity_files):
    policy, manifest = integrity_files

    contents = policy.read_text(encoding="utf-8")
    contents = contents.replace(
        "approved company VPN",
        "unapproved personal VPN",
    )

    policy.write_text(contents, encoding="utf-8")

    with pytest.raises(
        DocumentIntegrityError,
        match="SHA-256 mismatch",
    ):
        verify_policy_integrity(policy, manifest)


def test_missing_policy_blocked(integrity_files):
    policy, manifest = integrity_files
    policy.unlink()

    with pytest.raises(
        DocumentIntegrityError,
        match="Policy file missing",
    ):
        verify_policy_integrity(policy, manifest)


def test_missing_manifest_blocked(integrity_files):
    policy, manifest = integrity_files
    manifest.unlink()

    with pytest.raises(
        DocumentIntegrityError,
        match="Trusted manifest missing",
    ):
        verify_policy_integrity(policy, manifest)


def test_unapproved_manifest_blocked(integrity_files):
    policy, manifest = integrity_files

    data = json.loads(manifest.read_text())
    data["approval_status"] = "pending_manual_review"

    manifest.write_text(json.dumps(data))

    with pytest.raises(
        DocumentIntegrityError,
        match="not been approved",
    ):
        verify_policy_integrity(policy, manifest)


def test_invalid_manifest_hash_rejected(integrity_files):
    policy, manifest = integrity_files

    data = json.loads(manifest.read_text())
    data["sha256"] = "not-a-sha256"

    manifest.write_text(json.dumps(data))

    with pytest.raises(
        DocumentIntegrityError,
        match="Invalid manifest SHA-256",
    ):
        verify_policy_integrity(policy, manifest)


def test_wrong_document_inventory_rejected(
    integrity_files,
):
    policy, manifest = integrity_files

    data = json.loads(manifest.read_text())
    data["document_ids"] = [
        "POL-001",
        "POL-002",
        "POL-003",
        "POL-004",
        "POL-999",
    ]

    manifest.write_text(json.dumps(data))

    with pytest.raises(
        DocumentIntegrityError,
        match="Policy inventory",
    ):
        verify_policy_integrity(policy, manifest)


def test_missing_content_rejected_with_matching_hash(
    integrity_files,
):
    """
    Even a matching new hash cannot make a
    malformed policy record structurally valid.
    """
    import hashlib

    policy, manifest = integrity_files

    documents = json.loads(policy.read_text())
    del documents[0]["content"]

    raw = json.dumps(documents).encode("utf-8")
    policy.write_bytes(raw)

    data = json.loads(manifest.read_text())
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    data["file_size_bytes"] = len(raw)

    manifest.write_text(json.dumps(data))

    with pytest.raises(
        DocumentIntegrityError,
        match="Invalid policy field: content",
    ):
        verify_policy_integrity(policy, manifest)
