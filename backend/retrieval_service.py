
import hashlib
import hmac
import json
from functools import lru_cache
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from backend.document_integrity import (
    DEFAULT_MANIFEST_FILE,
    DocumentIntegrityError,
    verify_policy_integrity,
)


ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)

MANIFEST_FILE = DEFAULT_MANIFEST_FILE

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class RetrievalService:
    def __init__(self):
        # Verify the policy file before loading or indexing.
        integrity = verify_policy_integrity(
            policy_file=DATA_FILE,
            manifest_file=MANIFEST_FILE,
        )

        # Read the exact bytes we intend to index.
        raw_bytes = DATA_FILE.read_bytes()

        actual_digest = hashlib.sha256(
            raw_bytes
        ).hexdigest()

        # Protect against a file change between
        # verification and loading.
        if not hmac.compare_digest(
            actual_digest,
            integrity["sha256"],
        ):
            raise DocumentIntegrityError(
                "Policy changed during retrieval initialization."
            )

        self.documents = json.loads(
            raw_bytes.decode("utf-8")
        )

        # Keep the trusted baseline associated
        # with this particular retrieval instance.
        self.trusted_digest = integrity["sha256"]

        print("Knowledge-base integrity verified.")
        print("Loading embedding model on CPU...")

        self.model = SentenceTransformer(
            EMBEDDING_MODEL,
            device="cpu",
        )

        texts = [
            f"{doc['title']}. {doc['content']}"
            for doc in self.documents
        ]

        self.embeddings = self.model.encode(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

        print(
            f"Indexed {len(self.documents)} verified documents."
        )

    def _verify_current_integrity(self):
        """
        Fail closed if the policy file or approved
        manifest no longer matches this index.
        """
        integrity = verify_policy_integrity(
            policy_file=DATA_FILE,
            manifest_file=MANIFEST_FILE,
        )

        if not hmac.compare_digest(
            integrity["sha256"],
            self.trusted_digest,
        ):
            raise DocumentIntegrityError(
                "Knowledge-base baseline changed since indexing."
            )

    def search(self, question: str, top_k: int = 3):
        # This executes on every search, including
        # searches through a cached RetrievalService.
        self._verify_current_integrity()

        query_embedding = self.model.encode(
            [question],
            normalize_embeddings=True,
            convert_to_numpy=True,
        )[0]

        similarities = self.embeddings @ query_embedding

        ranked_indices = np.argsort(
            similarities
        )[::-1]

        results = []

        for index in ranked_indices[:top_k]:
            doc = self.documents[int(index)]

            results.append({
                "document_id": doc["id"],
                "title": doc["title"],
                "content": doc["content"],
                "similarity_score": round(
                    float(similarities[index]), 4,
                ),
            })

        # Check again before returning trusted context.
        # This catches changes during the search.
        self._verify_current_integrity()

        return results


@lru_cache(maxsize=1)
def get_retrieval_service():
    return RetrievalService()
