from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")

APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

from db.init_db import init_db  # noqa: E402
from services.semantic_search_service import (  # noqa: E402
    build_missing_embeddings,
    get_embedding_provider,
    get_openai_embedding_model_identifier,
    get_sentence_transformer_model_name,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and persist pgvector embeddings.")
    parser.add_argument(
        "--artifact-type",
        default="All",
        choices=["All", "Jobs", "Routines", "Joblets"],
        help="Limit embeddings to a specific artifact type.",
    )
    args = parser.parse_args()

    init_db()
    print(f"Python executable: {sys.executable}")
    provider = get_embedding_provider()
    print(f"Embedding provider: {provider}")
    print("Building missing embeddings...")
    try:
        considered, updated = build_missing_embeddings(
            args.artifact_type,
            allow_model_download=True,
        )
    except RuntimeError as exc:
        print(exc)
        print("Sentence transformer model could not be loaded.")
        return 1

    model_name = get_sentence_transformer_model_name()
    print(f"Artifacts considered: {considered}")
    print(f"Embeddings created/updated: {updated}")
    if provider == "openai":
        print(f"Embedding model: {get_openai_embedding_model_identifier()}")
    elif provider == "local":
        print(f"Embedding model: {model_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
