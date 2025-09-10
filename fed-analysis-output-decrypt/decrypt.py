from __future__ import annotations
import json
import os
from pathlib import Path
from time import time
from typing import Dict, Any
import numpy as np
from concrete.ml.deployment.fhe_client_server import FHEModelClient


## Local dev paths (uncomment for local testing)
# REPO_DIR = Path.cwd()
# DEPLOYMENT_DIR = REPO_DIR / "deployment_files" / "model"    
# REPORT_PATH = DEPLOYMENT_DIR / "report.json"
# SERVER_RESULTS = (REPO_DIR / "server_results").resolve()    
# FHE_KEYS_DIR   = (REPO_DIR / ".fhe_keys").resolve()       

## Hardcoded paths (Docker-friendly)
DEPLOYMENT_DIR = Path("/app/deployment_files/model")
REPORT_PATH = Path("/app/deployment_files/model/report.json")
SERVER_RESULTS = Path("/app/server_results").resolve()
FHE_KEYS_DIR = Path("/app/.fhe_keys").resolve()

# -------- Helpers --------
def load_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        raise FileNotFoundError(f"Missing JSON: {p}")
    return json.loads(p.read_text())

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def find_default_client_id(root: Path) -> str:
    """Pick the first numerical subdirectory under `root`."""
    if not root.exists():
        raise FileNotFoundError(f"Missing directory: {root}")
    subs = [d for d in os.listdir(root) if (root / d).is_dir() and d.isdigit()]
    if not subs:
        raise ValueError(f"No numerical client_id subdirectory found in {root}")
    subs.sort()
    return subs[0]


# -------- Core decrypt --------
def decrypt_prediction(
    client_id: str,
    deployment_dir: Path = DEPLOYMENT_DIR,
    results_root: Path = SERVER_RESULTS,
) -> Dict[str, Any]:
    """
    Decrypt the encrypted prediction for `client_id` and return a report dict.
    """
    # 1) Resolve paths
    out_dir    = ensure_dir(results_root / client_id)
    enc_path   = out_dir / "encrypted_output"
    if not enc_path.exists():
        raise FileNotFoundError(f"Encrypted prediction not found: {enc_path}")

    # 2) Load report metadata (for target name, etc.)
    report     = load_json(deployment_dir / "report.json")
    target_col = report.get("target", "default_or_claim")

    # 3) Create a client with this client's secret key
    key_dir = ensure_dir(FHE_KEYS_DIR / client_id)
    client  = FHEModelClient(deployment_dir, key_dir=key_dir)

    # 4) Read ciphertext and decrypt/dequantize
    enc_bytes = enc_path.read_bytes()
    y_scores  = client.deserialize_decrypt_dequantize(enc_bytes)

    # Normalize output shape to (1, K)
    y_scores = np.array(y_scores)
    if y_scores.ndim == 1:
        y_scores = y_scores.reshape(1, -1)
    if y_scores.shape[0] != 1:
        raise RuntimeError(f"Expected a single prediction, got shape {y_scores.shape}")

    # 5) Argmax → predicted class (0/1 for binary target)
    y_hat = int(np.argmax(y_scores[0]))

    # 6) Domain-specific message (target: 1 = default/claim, 0 = no event)
    if y_hat == 1:
        verdict = f"{target_col}: adverse event predicted (default/claim = 1)"
    else:
        verdict = f"{target_col}: no adverse event predicted (default/claim = 0)"

    # For binary case: probability of default_or_claim (class 1)
    K = y_scores.shape[1]
    if K == 2:
        proba_y1 = float(y_scores[0][1])
    else:
        # fallback for K>2 (normalize to probabilities)
        row = y_scores[0]
        s = float(row.sum()) if row.sum() != 0 else 1.0
        proba_y1 = float((row / s)[int(np.argmax(row))])

    # 7) Persist a small plaintext report for auditing
    plain_report = {
        "client_id": client_id,
        "target": target_col,
        "pred_label": y_hat,
        "scores": y_scores[0].tolist(),
        "positive_class_proba": proba_y1,
        "verdict": verdict,
        "encrypted_output_file": str(enc_path.resolve()),
    }
    (out_dir / "decrypted_output.json").write_text(json.dumps(plain_report, indent=2))

    return plain_report


if __name__ == "__main__":
    client_id = find_default_client_id(SERVER_RESULTS)
    t0_dec = time()
    rep = decrypt_prediction(client_id=client_id)
    t1_dec = time()


    # Pretty print a human-friendly summary
    print(json.dumps({
        "client_id": rep["client_id"],
        "pred_label": rep["pred_label"],
        "scores": rep["scores"],
        "positive_class_proba": rep["positive_class_proba"],
        "verdict": rep["verdict"],
        "note": "label 1 means default_or_claim event; label 0 means no event",
        "decryption_time": round(t1_dec - t0_dec, 3)
    }, indent=2))
