import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict


BASE_REPO_PATH = Path("data/repos")


def scan_repositories() -> List[Dict]:
    artifacts = []

    if not BASE_REPO_PATH.exists():
        return artifacts

    # Level 1: Repos
    for repo_path in BASE_REPO_PATH.iterdir():
        if not repo_path.is_dir():
            continue

        repo_name = repo_path.name

        # Level 2: Projects
        for project_path in repo_path.iterdir():
            if not project_path.is_dir():
                continue

            project_name = project_path.name

            # Level 3: Scan files inside project (.item only)
            for file_path in project_path.rglob("*.item"):
                relative_path = file_path.relative_to(project_path).as_posix()

                artifact_type = classify_artifact(relative_path)

                if not artifact_type:
                    continue

                artifacts.append(
                    {
                        "artifact_id": f"{repo_name}-{project_name}-{file_path.stem}",
                        "artifact_type": artifact_type,
                        "name": file_path.stem,
                        "repo_name": repo_name,
                        "project_name": project_name,
                        "repo_path": str(repo_path),
                        "file_path": str(file_path),
                        "relative_path": relative_path,
                        "summary": "Discovered artifact (not parsed yet)",
                        "search_text": file_path.stem.lower(),
                        "component_types": "",
                        "source_hash": compute_file_hash(file_path),
                        "source_modified_at": datetime.fromtimestamp(file_path.stat().st_mtime),
                    }
                )

    return artifacts


def classify_artifact(relative_path: str) -> str | None:
    if relative_path.startswith("process/"):
        return "job"
    if relative_path.startswith("code/routines/"):
        return "routine"
    return None


def compute_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
