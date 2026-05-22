from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")

APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

from services.semantic_search_service import get_sentence_transformer_model_name  # noqa: E402


def main() -> int:
    model_name = get_sentence_transformer_model_name()
    print(f"Python executable: {sys.executable}")
    print(f"Downloading embedding model: {model_name}")
    print("HF_HUB_DISABLE_XET=1")

    try:
        from huggingface_hub import snapshot_download
    except Exception as exc:
        print(f"Could not import huggingface_hub: {exc}")
        return 1

    try:
        path = snapshot_download(
            repo_id=model_name,
            local_files_only=False,
        )
    except Exception as exc:
        print(f"Model download failed: {exc}")
        print("")
        print("If this is an SSL handshake/certificate issue, try:")
        print("  python -m pip install --upgrade certifi")
        print("  $env:SSL_CERT_FILE = (python -c \"import certifi; print(certifi.where())\")")
        print("  $env:REQUESTS_CA_BUNDLE = $env:SSL_CERT_FILE")
        print("")
        print("On managed Windows machines, also try:")
        print("  python -m pip install python-certifi-win32")
        print("")
        print("If you are behind a corporate proxy, set HTTPS_PROXY/HTTP_PROXY and retry.")
        return 1

    print(f"Model cached at: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
