from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from db.session import SessionLocal
from models.artifact import Artifact
from repositories.artifact_repository import (
    search_artifacts,
    search_artifacts_by_pgvector,
    update_artifact_embedding,
)


@dataclass
class SemanticSearchResult:
    artifact: Artifact
    score: float


_SENTENCE_MODEL = None
_SENTENCE_MODEL_NAME = None
_SENTENCE_MODEL_LOAD_ERROR = ""
_HOSTED_EMBEDDING_ERROR = ""


def build_missing_embeddings(
    artifact_type: str = "All",
    allow_model_download: bool = False,
) -> tuple[int, int]:
    if get_embedding_provider() == "openai":
        return build_missing_openai_embeddings(artifact_type=artifact_type)

    model = get_sentence_transformer_model(allow_download=allow_model_download)
    if model is None:
        detail = f" Detail: {_SENTENCE_MODEL_LOAD_ERROR}" if _SENTENCE_MODEL_LOAD_ERROR else ""
        raise RuntimeError(
            "Sentence transformer model could not be loaded. "
            "Run the embedding backfill from the same virtualenv after installing requirements."
            f"{detail}"
        )

    model_name = get_sentence_transformer_model_name()
    with SessionLocal() as db:
        artifacts = [
            artifact
            for artifact in search_artifacts(db, query="", artifact_type=artifact_type)
            if artifact.embedding_vector is None and has_summary(artifact)
        ]
        updated = ensure_pgvector_embeddings(db, artifacts, model, model_name)

    return len(artifacts), updated


def semantic_search_artifacts(
    artifacts: list[Artifact],
    query: str,
    limit: int = 25,
    min_score: float = 0.03,
) -> list[SemanticSearchResult]:
    clean_query = query.strip()
    if not clean_query:
        return [SemanticSearchResult(artifact=artifact, score=0.0) for artifact in artifacts[:limit]]

    indexed_artifacts = [
        artifact for artifact in artifacts if build_semantic_document(artifact).strip()
    ]
    if not indexed_artifacts:
        return []

    corpus = [build_semantic_document(artifact) for artifact in indexed_artifacts]
    transformer_results = search_with_sentence_transformers(
        indexed_artifacts=indexed_artifacts,
        corpus=corpus,
        query=clean_query,
        limit=limit,
        min_score=min_score,
    )
    if transformer_results is not None:
        return transformer_results

    return search_with_tfidf(
        indexed_artifacts=indexed_artifacts,
        corpus=corpus,
        query=clean_query,
        limit=limit,
        min_score=min_score,
    )


def semantic_search_artifacts_pgvector(
    query: str,
    artifact_type: str = "All",
    limit: int = 25,
    min_score: float = 0.03,
) -> list[SemanticSearchResult] | None:
    clean_query = query.strip()
    if not clean_query:
        return None

    if get_embedding_provider() == "openai":
        return semantic_search_artifacts_openai_pgvector(
            query=clean_query,
            artifact_type=artifact_type,
            limit=limit,
            min_score=min_score,
        )

    model = get_sentence_transformer_model(allow_download=False)
    if model is None:
        return None

    model_name = get_sentence_transformer_model_name()

    try:
        with SessionLocal() as db:
            query_vector = model.encode([clean_query], normalize_embeddings=True)[0]
            ranked = search_artifacts_by_pgvector(
                db=db,
                query_vector=format_pgvector(query_vector),
                embedding_model=model_name,
                artifact_type=artifact_type,
                limit=limit,
                min_score=min_score,
            )
    except Exception:
        return None

    return [
        SemanticSearchResult(artifact=artifact, score=score)
        for artifact, score in ranked
    ]


def build_missing_openai_embeddings(artifact_type: str = "All") -> tuple[int, int]:
    model_name = get_openai_embedding_model_identifier()
    with SessionLocal() as db:
        artifacts = [
            artifact
            for artifact in search_artifacts(db, query="", artifact_type=artifact_type)
            if artifact.embedding_vector is None and has_summary(artifact)
        ]
        updated = ensure_openai_embeddings(db, artifacts, model_name)

    return len(artifacts), updated


def semantic_search_artifacts_openai_pgvector(
    query: str,
    artifact_type: str,
    limit: int,
    min_score: float,
) -> list[SemanticSearchResult] | None:
    try:
        query_vector = create_openai_embeddings([query])[0]
        with SessionLocal() as db:
            ranked = search_artifacts_by_pgvector(
                db=db,
                query_vector=format_pgvector(query_vector),
                embedding_model=get_openai_embedding_model_identifier(),
                artifact_type=artifact_type,
                limit=limit,
                min_score=min_score,
            )
    except Exception:
        return None

    return [
        SemanticSearchResult(artifact=artifact, score=score)
        for artifact, score in ranked
    ]


def ensure_openai_embeddings(
    db,
    artifacts: list[Artifact],
    model_name: str,
) -> int:
    stale_artifacts = []
    stale_texts = []

    for artifact in artifacts:
        text = build_semantic_document(artifact)
        source_hash = build_embedding_source_hash(text)
        if (
            artifact.embedding_hash == source_hash
            and artifact.embedding_model == model_name
            and artifact.embedding_vector is not None
        ):
            continue

        stale_artifacts.append(artifact)
        stale_texts.append(text)

    updated = 0
    batch_size = get_embedding_batch_size()
    for start in range(0, len(stale_texts), batch_size):
        batch_artifacts = stale_artifacts[start:start + batch_size]
        batch_texts = stale_texts[start:start + batch_size]
        generated_vectors = create_openai_embeddings(batch_texts)
        for artifact, text, generated_vector in zip(
            batch_artifacts,
            batch_texts,
            generated_vectors,
            strict=False,
        ):
            update_artifact_embedding(
                db=db,
                artifact_id=artifact.id,
                embedding_vector=format_pgvector(generated_vector),
                embedding_hash=build_embedding_source_hash(text),
                embedding_model=model_name,
            )
            updated += 1

    return updated


def create_openai_embeddings(texts: list[str]) -> list[list[float]]:
    global _HOSTED_EMBEDDING_ERROR

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        _HOSTED_EMBEDDING_ERROR = "OPENAI_API_KEY is not set."
        raise RuntimeError(_HOSTED_EMBEDDING_ERROR)

    try:
        from openai import OpenAI
    except Exception as exc:
        _HOSTED_EMBEDDING_ERROR = f"Could not import openai package: {exc}"
        raise RuntimeError(_HOSTED_EMBEDDING_ERROR) from exc

    client = OpenAI(api_key=api_key)
    model = get_openai_embedding_model_name()
    dimensions = get_embedding_dimensions()
    response = client.embeddings.create(
        model=model,
        input=texts,
        dimensions=dimensions,
    )
    _HOSTED_EMBEDDING_ERROR = ""
    return [item.embedding for item in response.data]


def get_embedding_provider() -> str:
    provider = os.getenv("EMBEDDING_PROVIDER", "").strip().lower()
    if provider:
        return provider
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "local"


def get_openai_embedding_model_name() -> str:
    return os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")


def get_embedding_dimensions() -> int:
    try:
        return int(os.getenv("EMBEDDING_DIMENSIONS", "384"))
    except ValueError:
        return 384


def get_openai_embedding_model_identifier() -> str:
    return f"openai:{get_openai_embedding_model_name()}:{get_embedding_dimensions()}"


def search_with_sentence_transformers(
    indexed_artifacts: list[Artifact],
    corpus: list[str],
    query: str,
    limit: int,
    min_score: float,
) -> list[SemanticSearchResult] | None:
    model = get_sentence_transformer_model(allow_download=False)
    if model is None:
        return None

    model_name = get_sentence_transformer_model_name()
    document_vectors = get_or_create_document_vectors(indexed_artifacts, corpus, model, model_name)
    query_vector = model.encode([query], normalize_embeddings=True)
    scores = cosine_similarity(query_vector, document_vectors).ravel()
    return build_ranked_results(indexed_artifacts, scores, limit=limit, min_score=min_score)


def ensure_pgvector_embeddings(
    db,
    artifacts: list[Artifact],
    model,
    model_name: str,
) -> int:
    stale_artifacts = []
    stale_texts = []

    for artifact in artifacts:
        text = build_semantic_document(artifact)
        source_hash = build_embedding_source_hash(text)
        if (
            artifact.embedding_hash == source_hash
            and artifact.embedding_model == model_name
            and artifact.embedding_vector is not None
        ):
            continue

        stale_artifacts.append(artifact)
        stale_texts.append(text)

    if not stale_texts:
        return 0

    updated = 0
    batch_size = get_embedding_batch_size()
    for start in range(0, len(stale_texts), batch_size):
        batch_artifacts = stale_artifacts[start:start + batch_size]
        batch_texts = stale_texts[start:start + batch_size]
        generated_vectors = model.encode(batch_texts, normalize_embeddings=True)
        for artifact, text, generated_vector in zip(
            batch_artifacts,
            batch_texts,
            generated_vectors,
            strict=False,
        ):
            update_artifact_embedding(
                db=db,
                artifact_id=artifact.id,
                embedding_vector=format_pgvector(generated_vector),
                embedding_hash=build_embedding_source_hash(text),
                embedding_model=model_name,
            )
            updated += 1

    return updated


def get_embedding_batch_size() -> int:
    try:
        return max(1, int(os.getenv("EMBEDDING_BATCH_SIZE", "16")))
    except ValueError:
        return 16


def encode_in_batches(model, texts: list[str]):
    vectors = []
    batch_size = get_embedding_batch_size()
    for start in range(0, len(texts), batch_size):
        generated_vectors = model.encode(
            texts[start:start + batch_size],
            normalize_embeddings=True,
        )
        vectors.extend(generated_vectors)
    return vectors


def get_sentence_transformer_model(allow_download: bool = False):
    global _SENTENCE_MODEL, _SENTENCE_MODEL_NAME, _SENTENCE_MODEL_LOAD_ERROR

    if os.getenv("DISABLE_SENTENCE_TRANSFORMERS", "").lower() in {"1", "true", "yes"}:
        _SENTENCE_MODEL_LOAD_ERROR = "DISABLE_SENTENCE_TRANSFORMERS is enabled."
        return None

    if _SENTENCE_MODEL is not None:
        return _SENTENCE_MODEL

    try:
        quiet_transformers_warnings()
        from sentence_transformers import SentenceTransformer
    except Exception as exc:
        _SENTENCE_MODEL_LOAD_ERROR = f"Could not import sentence_transformers: {exc}"
        return None

    model_name = get_sentence_transformer_model_name()
    try:
        _SENTENCE_MODEL = SentenceTransformer(
            model_name,
            local_files_only=not allow_download,
        )
        _SENTENCE_MODEL_NAME = model_name
        _SENTENCE_MODEL_LOAD_ERROR = ""
    except Exception as exc:
        mode = "local cache" if not allow_download else "download/cache"
        _SENTENCE_MODEL_LOAD_ERROR = f"Could not load {model_name} from {mode}: {exc}"
        return None

    return _SENTENCE_MODEL


def quiet_transformers_warnings() -> None:
    os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    warnings.filterwarnings(
        "ignore",
        message=r".*Accessing `__path__` from.*",
    )
    try:
        from transformers.utils import logging as transformers_logging

        transformers_logging.set_verbosity_error()
    except Exception:
        pass


def get_sentence_transformer_model_name() -> str:
    return os.getenv("SENTENCE_TRANSFORMER_MODEL", "sentence-transformers/all-MiniLM-L6-v2")


def get_or_create_document_vectors(
    artifacts: list[Artifact],
    corpus: list[str],
    model,
    model_name: str,
):
    vectors = []
    missing_indexes = []
    missing_texts = []

    for index, (artifact, text) in enumerate(zip(artifacts, corpus, strict=False)):
        source_hash = build_embedding_source_hash(text)
        vector = load_persisted_vector(artifact, source_hash, model_name)
        if vector is None:
            vectors.append(None)
            missing_indexes.append(index)
            missing_texts.append(text)
            continue
        vectors.append(vector)

    if missing_texts:
        generated_vectors = encode_in_batches(model, missing_texts)
        with SessionLocal() as db:
            for missing_index, generated_vector in zip(missing_indexes, generated_vectors, strict=False):
                vector_list = [float(value) for value in generated_vector]
                vectors[missing_index] = vector_list
                source_hash = build_embedding_source_hash(corpus[missing_index])
                update_artifact_embedding(
                    db=db,
                    artifact_id=artifacts[missing_index].id,
                    embedding_vector=format_pgvector(vector_list),
                    embedding_hash=source_hash,
                    embedding_model=model_name,
                )

    return np.array(vectors, dtype="float32")


def load_persisted_vector(
    artifact: Artifact,
    source_hash: str,
    model_name: str,
) -> list[float] | None:
    if artifact.embedding_hash != source_hash:
        return None
    if artifact.embedding_model != model_name:
        return None
    if not artifact.embedding_vector:
        return None

    vector = artifact.embedding_vector

    if not isinstance(vector, list) or not vector:
        return None
    return [float(value) for value in vector]


def format_pgvector(vector) -> str:
    return "[" + ",".join(f"{float(value):.8g}" for value in vector) + "]"


def build_embedding_source_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def search_with_tfidf(
    indexed_artifacts: list[Artifact],
    corpus: list[str],
    query: str,
    limit: int,
    min_score: float,
) -> list[SemanticSearchResult]:
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=1,
    )
    matrix = vectorizer.fit_transform(corpus)
    query_vector = vectorizer.transform([query])
    scores = cosine_similarity(query_vector, matrix).ravel()
    return build_ranked_results(indexed_artifacts, scores, limit=limit, min_score=min_score)


def build_ranked_results(
    indexed_artifacts: list[Artifact],
    scores,
    limit: int,
    min_score: float,
) -> list[SemanticSearchResult]:
    ranked = sorted(
        zip(indexed_artifacts, scores, strict=False),
        key=lambda item: (item[1], item[0].artifact_type == "job", -item[0].id),
        reverse=True,
    )

    results = [
        SemanticSearchResult(artifact=artifact, score=float(score))
        for artifact, score in ranked
        if score >= min_score
    ]
    return results[:limit]


def build_semantic_document(artifact: Artifact) -> str:
    parts = [
        artifact.name,
        artifact.artifact_type,
        artifact.summary,
        artifact.embedding_text,
        artifact.component_types,
    ]
    return "\n".join(str(part or "") for part in parts)


def has_summary(artifact: Artifact) -> bool:
    return bool(str(artifact.summary or "").strip())
