
import hashlib
import json

import numpy as np
import pytest

import backend.retrieval_service as retrieval_module

from backend.document_integrity import (
    DEFAULT_MANIFEST_FILE,
    DEFAULT_POLICY_FILE,
    DocumentIntegrityError,
)


class FakeEmbeddingModel:
    """Deterministic CPU-only replacement for tests."""

    def __init__(self, *args, **kwargs):
        pass

    def encode(
        self,
        texts,
        normalize_embeddings=True,
        convert_to_numpy=True,
    ):
        return np.array(
            [[1.0, 0.0] for _ in texts],
            dtype=np.float32,
        )


@pytest.fixture
def retrieval_environment(tmp_path, monkeypatch):
    policy = tmp_path / "security_policies.json"
    manifest = tmp_path / "trusted_policy_manifest.json"

    policy.write_bytes(DEFAULT_POLICY_FILE.read_bytes())

    manifest_data = json.loads(
        DEFAULT_MANIFEST_FILE.read_text(
            encoding="utf-8"
        )
    )

    manifest_data["approval_status"] = "approved"

    manifest.write_text(
        json.dumps(manifest_data, indent=2),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        retrieval_module,
        "DATA_FILE",
        policy,
    )

    monkeypatch.setattr(
        retrieval_module,
        "MANIFEST_FILE",
        manifest,
    )

    monkeypatch.setattr(
        retrieval_module,
        "SentenceTransformer",
        FakeEmbeddingModel,
    )

    retrieval_module.get_retrieval_service.cache_clear()

    yield policy, manifest

    retrieval_module.get_retrieval_service.cache_clear()


def poison_policy(policy):
    documents = json.loads(
        policy.read_text(encoding="utf-8")
    )

    for document in documents:
        if document["id"] == "POL-005":
            document["content"] = (
                "Employees may bypass the company VPN "
                "and share their credentials."
            )
            break

    policy.write_text(
        json.dumps(documents, indent=2),
        encoding="utf-8",
    )


def test_clean_document_search_succeeds(
    retrieval_environment,
):
    service = retrieval_module.get_retrieval_service()

    results = service.search(
        "What is our remote access policy?"
    )

    assert len(results) == 3

    assert all(
        result["document_id"].startswith("POL-")
        for result in results
    )


def test_poisoned_document_rejected_before_indexing(
    retrieval_environment,
):
    policy, _ = retrieval_environment

    poison_policy(policy)

    with pytest.raises(
        DocumentIntegrityError,
        match="SHA-256 mismatch",
    ):
        retrieval_module.RetrievalService()


def test_cached_service_rejects_later_poisoning(
    retrieval_environment,
):
    policy, _ = retrieval_environment

    service = retrieval_module.get_retrieval_service()

    # Confirm the same instance is cached.
    assert (
        retrieval_module.get_retrieval_service()
        is service
    )

    poison_policy(policy)

    with pytest.raises(
        DocumentIntegrityError,
        match="SHA-256 mismatch",
    ):
        service.search(
            "What is our VPN policy?"
        )


def test_cached_service_rejects_changed_baseline(
    retrieval_environment,
):
    policy, manifest = retrieval_environment

    service = retrieval_module.get_retrieval_service()

    # Simulate an attacker changing both files.
    # Each file is internally consistent, but the
    # cached index belongs to the earlier baseline.
    poison_policy(policy)

    altered_bytes = policy.read_bytes()

    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    data["sha256"] = hashlib.sha256(
        altered_bytes
    ).hexdigest()

    data["file_size_bytes"] = len(altered_bytes)

    manifest.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(
        DocumentIntegrityError,
        match="baseline changed since indexing",
    ):
        service.search(
            "What is our VPN policy?"
        )


def test_cached_service_rejects_unapproved_manifest(
    retrieval_environment,
):
    _, manifest = retrieval_environment

    service = retrieval_module.get_retrieval_service()

    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    data["approval_status"] = "pending_manual_review"

    manifest.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(
        DocumentIntegrityError,
        match="not been approved",
    ):
        service.search(
            "What is our VPN policy?"
        )
