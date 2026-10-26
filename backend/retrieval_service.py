
import json
from functools import lru_cache
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class RetrievalService:
    def __init__(self):
        with DATA_FILE.open("r", encoding="utf-8") as f:
            self.documents = json.load(f)

        print("Loading embedding model on CPU...")

        self.model = SentenceTransformer(
            EMBEDDING_MODEL,
            device="cpu"
        )

        texts = [
            f"{doc['title']}. {doc['content']}"
            for doc in self.documents
        ]

        self.embeddings = self.model.encode(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        print(
            f"Indexed {len(self.documents)} documents."
        )

    def search(self, question: str, top_k: int = 3):
        query_embedding = self.model.encode(
            [question],
            normalize_embeddings=True,
            convert_to_numpy=True
        )[0]

        similarities = self.embeddings @ query_embedding

        ranked_indices = np.argsort(similarities)[::-1]

        results = []

        for index in ranked_indices[:top_k]:
            doc = self.documents[int(index)]

            results.append({
                "document_id": doc["id"],
                "title": doc["title"],
                "content": doc["content"],
                "similarity_score": round(
                    float(similarities[index]), 4
                )
            })

        return results


@lru_cache(maxsize=1)
def get_retrieval_service():
    return RetrievalService()
