# Talend Repo Agent

Talend Repo Agent is a RAG-style knowledge base for Talend repositories. It ingests Talend jobs, routines, joblets, schemas, SQL, dependency metadata, screenshots, and vulnerability evidence, then turns that evidence into searchable context for retrieval, impact analysis, catalog exploration, and implementation-neutral ETL blueprints.

The project is meant to showcase how a retrieval-augmented architecture can be built over legacy ETL assets:

```text
Talend files -> evidence extraction -> structured KB -> embeddings/search -> grounded answers and blueprints
```

Teams can ask questions like:

- Which jobs use a table, column, component, endpoint, or credential pattern?
- What fields look like customer, email, order, DOB, SSN, or other sensitive data?
- Which Talend jobs call other jobs?
- Which Maven dependencies or exported jars may have known vulnerabilities?
- Why did a search result match: column name, table name, semantic meaning, evidence text, or component metadata?
- What implementation-neutral blueprint can be derived from this Talend job?

The application is designed as a local analysis tool. Source code is versioned, while scanned repositories, SQLite/Postgres data exports, vulnerability inputs, and secrets stay local.

## Features

- **Knowledge Base Search**
  - Scans Talend artifacts from `data/repos`.
  - Extracts job metadata, component types, SQL evidence, contexts, URLs, authentication/configuration signals, and job dependencies.
  - Supports text search and semantic search.
  - Can build pgvector embeddings for faster semantic retrieval.
  - Tracks `.item` source hashes so unchanged artifacts can be skipped and changed artifacts can be marked stale for regeneration.

- **Data Catalog**
  - Scans Talend metadata, SQL, context, and parameter evidence.
  - Groups findings by job, table, column, match type, or evidence type.
  - Distinguishes exact column/table matches from partial matches and related evidence matches.
  - Separates detected fields from SQL keywords.
  - Supports `Text + Meaning`, `Meaning only`, and `Text only` search modes.
  - Exports catalog results to CSV.

- **Vulnerability Scan**
  - Scans Maven `pom.xml` files and standalone vulnerability input folders.
  - Can parse Talend exported job jars and local jar folders.
  - Queries OSV when enabled.
  - Stores vulnerability findings separately from knowledge-base artifacts.
  - Exports vulnerability findings to CSV.

- **Optional LLM Summaries**
  - Deterministic local summaries are built from parsed evidence.
  - Optional OpenAI-based summaries can be enabled with environment variables.

- **ETL Blueprint Generation**
  - Builds implementation-neutral job blueprints from parsed evidence.
  - Summarizes purpose, pattern, source/target tables, fields, components, SQL operations, context variables, auth/config signals, dependencies, and implementation notes.
  - Exports blueprint YAML from the artifact detail page.

## RAG Architecture

This project uses a RAG-oriented architecture rather than a model-training-first architecture.

```text
                 +-------------------------+
                 | Talend Repositories     |
                 | .item, routines, poms   |
                 +------------+------------+
                              |
                              v
                 +-------------------------+
                 | Ingestion / Freshness   |
                 | source_hash, mtime      |
                 +------------+------------+
                              |
                              v
                 +-------------------------+
                 | Parsers / Scanners      |
                 | components, SQL, schema |
                 | context, deps, evidence |
                 +------------+------------+
                              |
                              v
                 +-------------------------+
                 | Structured Knowledge DB |
                 | Postgres + pgvector     |
                 +------------+------------+
                              |
                  +-----------+------------+
                  |                        |
                  v                        v
      +-----------------------+  +-----------------------+
      | Keyword / Filter      |  | Semantic Retrieval    |
      | SQLAlchemy search     |  | embeddings + pgvector |
      +-----------+-----------+  +-----------+-----------+
                  |                        |
                  +-----------+------------+
                              |
                              v
                 +-------------------------+
                 | Grounded UI / Outputs   |
                 | results, catalog,       |
                 | lineage, blueprints     |
                 +-------------------------+
```

### RAG Layers

- **Document source layer**: Talend `.item` files, routine code, poms, screenshots, exported jobs, and jar folders.
- **Freshness layer**: stores a semantic `source_hash` and `source_modified_at` for each artifact so unchanged `.item` behavior does not trigger unnecessary downstream work.
- **Evidence layer**: extracts structured facts such as components, SQL operations, tables, columns, contexts, URLs, auth signals, dependencies, and routine references.
- **Knowledge layer**: stores artifacts, catalog findings, vulnerability findings, summaries, and embedding metadata in Postgres.
- **Retrieval layer**: combines keyword filters, semantic search, pgvector embeddings, catalog grouping, and match-reason labeling.
- **Grounding layer**: every displayed summary, catalog hit, vulnerability row, and blueprint is derived from stored evidence.
- **Agent/output layer**: generates ETL blueprints and YAML from retrieved evidence. This is intentionally implementation-neutral before attempting any code or Talend XML generation.

### Retrieval

Retrieval finds the most relevant Talend evidence for a user question or workflow.

The project currently supports several retrieval paths:

- **Keyword retrieval**: SQLAlchemy search over artifact names, summaries, component types, file paths, dependency evidence, and parsed evidence JSON.
- **Semantic retrieval**: optional embedding generation with local sentence-transformers or OpenAI embeddings, persisted in Postgres/pgvector.
- **Catalog retrieval**: table, column, meaning, evidence type, and match-type search over `catalog_findings`.
- **Filter retrieval**: project, artifact type, component, database, auth signal, config signal, SQL presence, REST/API presence, secret/key-material signal, and dependency filters.
- **Graph-style retrieval**: parent/child job dependency lookup for jobs connected through `tRunJob`.
- **Vulnerability retrieval**: dependency and advisory findings linked back to KB artifacts.

Retrieval results include match explanations where possible:

```text
Exact column name match - customer
Column name contains - customer_id
Exact table name match - customer
Evidence text match
Component match
```

This makes retrieved context auditable instead of opaque.

### Augmentation

Augmentation enriches retrieved artifacts with structured context before display or generation.

The system augments retrieved Talend jobs with:

- job metadata: project, repo, file path, artifact type
- component evidence: component names and component families
- SQL evidence: operations, signatures, tables, and columns
- catalog evidence: detected fields, SQL keywords, semantic meaning, source type, direction, confidence, and best evidence
- connectivity evidence: URLs, context variables, database technology, auth/config signals
- dependency evidence: parent jobs, child jobs, and unresolved job references
- vulnerability evidence: package, version, advisory, severity, and recommended fix
- visual evidence: job screenshot preview when a `.screenshot` file is available

This augmented context is what makes downstream outputs grounded. The app does not simply answer from a model's memory; it answers from parsed Talend evidence stored in the KB.

### Generation

Generation is intentionally limited and evidence-grounded.

Current generated outputs include:

- deterministic artifact summaries
- optional LLM summaries when explicitly enabled
- catalog match explanations
- vulnerability summaries
- ETL Blueprint YAML

The ETL Blueprint is the clearest RAG-style generated artifact. It is created from retrieved and parsed evidence and includes purpose, inferred pattern, source/target tables, fields, components, SQL operations, context variables, auth/config signals, child job dependencies, and implementation notes.

### Grounding And Traceability

Every major output should be traceable back to source evidence:

- Search result -> artifact path and match reason
- Catalog row -> component, table/column, evidence type, confidence, and best evidence
- Vulnerability result -> package/version/advisory source
- Blueprint -> parsed SQL, components, contexts, dependencies, and config/auth signals

This is important for a RAG showcase because trust comes from showing **why** something was retrieved and **what evidence** was used.

### When To Update The RAG Index

The repository scan follows a semantic freshness policy for Talend `.item` files. Talend Studio may change XML layout details, component coordinates, or visual metadata even when the ETL logic did not change. The RAG index should not be rebuilt for those layout-only changes.

The scanner therefore computes `source_hash` from parsed semantic evidence instead of raw file bytes:

- component types
- SQL signatures, tables, and columns
- context references
- URLs and endpoint evidence
- auth/config signals
- routine/code keywords
- child job dependencies

The intended policy:

```text
New .item file
  -> insert artifact
  -> summary_status = pending
  -> needs summary and embedding

Existing .item file with same semantic source_hash
  -> skip
  -> keep current summary, catalog evidence, and embeddings

Existing .item file with changed semantic source_hash
  -> update artifact metadata
  -> reset functional/connectivity hashes
  -> clear embedding text/vector/hash/model
  -> summary_status = pending
  -> downstream summary and embedding rebuild required
```

Layout-only Talend changes, such as moving a component on the design canvas, should keep the same semantic `source_hash` and avoid RAG invalidation.

This is the key operational rule for the RAG demo: **only meaningful Talend artifact changes should invalidate derived context.**

### Re-Indexing Logic

The RAG refresh process is intentionally staged:

```text
Scan Local Repositories
  -> discover .item files
  -> compute semantic source_hash
  -> insert new artifacts
  -> mark changed artifacts pending
  -> skip unchanged artifacts

Generate Summaries
  -> parse pending or semantically changed artifacts
  -> rebuild summary/search/embedding text
  -> rebuild evidence_json
  -> update functional/connectivity hashes
  -> preserve vulnerability evidence where applicable

Build Embeddings
  -> compute embedding source hash from embedding text
  -> skip embeddings when source text and model are unchanged
  -> update pgvector only when embedding input changed

Catalog Scan
  -> compute scan hash for catalog input
  -> skip when input scan hash is unchanged
  -> replace catalog findings when changed

Vulnerability Scan
  -> compute dependency/pom scan hash
  -> skip unchanged dependency inputs
  -> update findings when dependency evidence changes
```

This creates a practical RAG invalidation model:

- source behavior unchanged -> keep retrieved context
- parsed evidence changed -> regenerate summaries and evidence
- embedding text changed -> rebuild embeddings
- catalog input changed -> rebuild catalog findings
- dependency evidence changed -> rebuild vulnerability findings

The goal is to avoid expensive or noisy re-indexing while keeping the KB fresh when Talend logic actually changes.

### Why This Is RAG, Not Just Search

This project demonstrates the full RAG pattern:

```text
Retrieve
  Find relevant Talend artifacts, catalog rows, dependencies, and vulnerability evidence.

Augment
  Attach parsed context: SQL, tables, columns, components, contexts, auth/config signals, summaries, and graph relationships.

Generate
  Produce grounded summaries, match explanations, vulnerability views, and ETL blueprints.

Validate / Refresh
  Use semantic hashes and embedding hashes to decide when derived context must be rebuilt.
```

That makes the KB suitable for future agent workflows such as impact analysis, modernization planning, blueprint generation, and controlled code generation.

## Project Architecture

```text
talend-repo-agent/
  app/
    app.py                         Streamlit UI and page orchestration
    db/                            SQLAlchemy engine, session, schema initialization
    models/                        Artifact, catalog, and vulnerability tables
    parsers/                       Talend .item parsing and evidence extraction
    repositories/                  Database read/write/search functions
    services/                      Scan orchestration, summaries, semantic search
  catalog_scanner/                 Standalone data catalog scanner
  vulnerability_scanner/           Standalone dependency/vulnerability scanner
  scripts/                         CLI utilities for scans, embeddings, pgvector
  docker-compose.yml               Local Postgres + pgvector
  requirements.txt                 Python dependencies
```

### Application Data Flow

```text
Talend repo files / exported jobs / jars
        |
        v
Parsers and scanners
        |
        v
Structured evidence and source fingerprints
        |
        v
Postgres tables + optional pgvector embeddings
        |
        v
Streamlit UI: KB search, catalog, vulnerability results, blueprints
```

### Main Tables

- `artifacts`: scanned jobs, routines, joblets, source hashes, summaries, search text, dependency evidence, embeddings.
- `catalog_findings`: field/table/semantic/evidence findings for the data catalog.
- `catalog_scans`: catalog scan history.
- `vulnerability_findings`: dependency vulnerability findings.
- `vulnerability_scans`: vulnerability scan history.

## Local Setup

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Start Postgres with pgvector

```powershell
docker compose up -d
```

The default database settings match `docker-compose.yml`:

```text
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=talend_kb
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
```

### 4. Optional `.env`

Create a local `.env` file if you need custom settings. Do not commit it.

```text
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/talend_kb

# Optional LLM summaries
ENABLE_LLM_SUMMARIES=false
OPENAI_API_KEY=
OPENAI_SUMMARY_MODEL=gpt-4o-mini

# Optional embeddings
EMBEDDING_PROVIDER=local
SENTENCE_TRANSFORMER_MODEL=sentence-transformers/all-MiniLM-L6-v2
```

If `OPENAI_API_KEY` is present and `EMBEDDING_PROVIDER` is not set, the app can use OpenAI embeddings. Set `EMBEDDING_PROVIDER=local` to force local sentence-transformer embeddings.

### 5. Run the app

```powershell
streamlit run app/app.py
```

## Input Folders

These folders are intentionally ignored by Git:

```text
data/
exports/
```

Recommended local layout:

```text
data/
  repos/                  Talend repositories to scan
  vulnerability_scan/     Exported jobs, poms, or jars for standalone vulnerability scans
exports/                  CSV/JSON scan outputs
```

## App Workflows

### Knowledge Base

1. Put Talend repository content under `data/repos`.
2. Open the app.
3. Use **Scan Local Repositories** from the Knowledge Base page.
4. Review the scan result: inserted, updated, unchanged.
5. Generate summaries if needed.
6. Search by job name, component, table, URL, auth signal, context variable, SQL evidence, or semantic content.
7. Open an artifact detail page to review evidence, job preview, dependencies, and the generated ETL blueprint.

### Data Catalog

1. Put Talend repository content under `data/repos`.
2. Open **Data Catalog**.
3. Run **Catalog Scan**.
4. Search for terms like `customer`, `customer_id`, `email`, `dob`, `ssn`, table names, or semantic meanings.
5. Use:
   - `Search by`: `Text + Meaning`, `Meaning only`, or `Text only`
   - `Group by`: `Job`, `Table`, `Column`, `Match Type`, or `Evidence Type`

Catalog result colors:

- Green: exact column or table name match.
- Blue: partial column or table name match.
- Amber: related component/evidence/meaning match.
- Gray: filter-only match.

### Vulnerability Scan

From the app:

1. Open **Vulnerability Scan**.
2. Run either:
   - KB repository scan for poms found under `data/repos`
   - standalone input scan for files under `data/vulnerability_scan`

From CLI:

```powershell
python scripts/vulnerability_scan.py --input data/vulnerability_scan --output exports/vulnerability_scan_results.csv
```

To parse dependencies without querying OSV:

```powershell
python scripts/vulnerability_scan.py --input data/vulnerability_scan --no-osv
```

## CLI Utilities

Run catalog scan to CSV:

```powershell
python scripts/catalog_scan.py --input data/repos --output exports/talend_data_catalog.csv
```

Build missing embeddings:

```powershell
python scripts/build_embeddings.py --artifact-type All
```

Download the local sentence-transformer model:

```powershell
python scripts/download_embedding_model.py
```

Enable pgvector manually:

```powershell
.\scripts\enable_pgvector.ps1
```

## Search and Matching Notes

Catalog search has two related concepts:

- **Search mode** controls what qualifies as a result.
- **Group by** controls how qualified results are organized.

Examples:

- Searching `customer` with `Text + Meaning` can return `customer`, `customer_id`, `customer_name`, and semantically customer-related fields.
- Grouping by `Column` keeps `customer` and `customer_id` in separate buckets.
- Grouping by `Match Type` separates exact column/table matches from partial matches.
- A future `Meaning` grouping can roll related columns into business-level groups.

## Security and Repo Hygiene

- Do not commit `.env`.
- Do not commit `data/`.
- Do not commit local scan outputs, source repositories, database files, or vulnerability inputs.
- If an API key is accidentally committed, revoke/rotate the key and remove it from Git history before pushing.

The current `.gitignore` excludes local secrets and scan data:

```text
.env
data/
exports/
```

## Development Notes

- The app initializes and migrates expected database columns at startup through `app/db/init_db.py`.
- pgvector support is optional but recommended for persistent semantic search.
- If local sentence-transformer model loading fails, semantic search falls back to TF-IDF for in-memory candidate ranking.
- OSV lookups require network access. Use `--no-osv` for offline dependency parsing.

## Current Status

This project is in active development. The core product areas are working:

- Knowledge-base artifact scan and search
- Catalog scan and grouped relevance UI
- Vulnerability scan and export
- Optional semantic embeddings and LLM summaries

Next useful improvements:

- Semantic meaning grouping in the catalog
- More precise lineage/connection extraction between Talend components
- Better jar-only dependency identification when poms are absent
- Automated tests around scanners and catalog match classification
