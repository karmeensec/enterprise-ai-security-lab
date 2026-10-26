
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)

RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "13_retrieval_results.json"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

print("=== Experiment 13: Semantic Document Search ===")
print(f"Embedding model: {MODEL_NAME}")

# Load synthetic enterprise documents
with DATA_FILE.open("r", encoding="utf-8") as f:
    documents = json.load(f)

print(f"Documents loaded: {len(documents)}")

# Load embedding model on CPU
model = SentenceTransformer(MODEL_NAME, device="cpu")

# Convert documents to embeddings
document_texts = [
    f"{doc['title']}. {doc['content']}"
    for doc in documents
]

document_embeddings = model.encode(
    document_texts,
    normalize_embeddings=True,
    convert_to_numpy=True
)

print(f"Embedding dimensions: {document_embeddings.shape[1]}")

# Test question
question = (
    "What should I do if I receive an unexpected "
    "login approval notification?"
)

print(f"\nQuestion: {question}")

# Generate question embedding
question_embedding = model.encode(
    [question],
    normalize_embeddings=True,
    convert_to_numpy=True
)[0]

# Calculate cosine similarities
similarities = document_embeddings @ question_embedding

# Rank documents by similarity
ranked_indices = np.argsort(similarities)[::-1]

results = []

print("\n=== Retrieved Documents ===")

# FIRST: Populate the results list
for rank, index in enumerate(ranked_indices[:3], start=1):
    doc = documents[int(index)]
    score = float(similarities[index])

    results.append({
        "rank": rank,
        "document_id": doc["id"],
        "title": doc["title"],
        "similarity_score": round(score, 4),
        "content": doc["content"]
    })

    print(f"\nRank {rank}: {doc['title']}")
    print(f"Document ID: {doc['id']}")
    print(f"Cosine similarity: {score:.4f}")
    print(f"Content: {doc['content']}")

# SECOND: Evaluate retrieval performance
expected_id = "POL-001"

top_1_correct = (
    results[0]["document_id"] == expected_id
)

top_3_correct = any(
    item["document_id"] == expected_id
    for item in results[:3]
)

print("\n=== Retrieval Evaluation ===")
print(f"Expected document: {expected_id}")
print(f"Actual top document: {results[0]['document_id']}")
print(f"Top-1 correct: {top_1_correct}")
print(f"Top-3 correct: {top_3_correct}")

# THIRD: Save complete results
report = {
    "experiment": "13_semantic_document_search",
    "embedding_model": MODEL_NAME,
    "question": question,
    "expected_top_document": expected_id,
    "top_1_correct": top_1_correct,
    "top_3_correct": top_3_correct,
    "retrieved_documents": results
}

with OUTPUT_FILE.open("w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"\nResults saved: {OUTPUT_FILE}")
print("\nExperiment 13 completed!")
