from __future__ import annotations
import argparse
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Tuple
from concrete.fhe import Value, EvaluationKeys
from concrete.ml.deployment.fhe_client_server import FHEModelServer

## Hardcoded paths (Docker-friendly)
DEPLOYMENT_DIR = Path("/app/deployment_files/model")
REPORT_PATH = Path("/app/deployment_files/model/report.json")
SERVER_FILES = Path("/app/server_files").resolve()
SERVER_FILES.mkdir(parents=True, exist_ok=True)
SERVER_RESULTS = Path("/app/server_results").resolve()
SERVER_RESULTS.mkdir(parents=True, exist_ok=True)

## Local dev paths (uncomment for local testing)
# REPO_DIR = Path.cwd()
# DEPLOYMENT_DIR = REPO_DIR / "deployment_files" / "model"    
# REPORT_PATH = DEPLOYMENT_DIR / "report.json"
# SERVER_FILES = (REPO_DIR / "server_files").resolve()
# SERVER_FILES.mkdir(parents=True, exist_ok=True)
# SERVER_RESULTS = (REPO_DIR / "server_results").resolve()
# SERVER_RESULTS.mkdir(parents=True, exist_ok=True)

# ------------------------- Helpers -------------------------
def load_json(p: Path) -> Dict:
    if not p.exists():
        raise FileNotFoundError(f"Missing JSON: {p}")
    return json.loads(p.read_text())

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def wait_for_files(paths: List[Path], timeout_s: int, poll_s: float) -> None:
    """Block until all `paths` exist or timeout."""
    start = time.time()
    missing = [p for p in paths if not p.exists()]
    while missing and (time.time() - start) < timeout_s:
        time.sleep(poll_s)
        missing = [p for p in paths if not p.exists()]
    if missing:
        missing_str = "\n  ".join(str(m) for m in missing)
        raise FileNotFoundError(f"Timed out waiting for files:\n  {missing_str}")


# ------------------------- Server wrapper -------------------------

class MultiInputsFHEModelServer(FHEModelServer):
    """Thin wrapper to accept serialized inputs + eval key and return serialized output."""
    def run_serialized(self, serialized_inputs: Tuple[bytes, ...], serialized_eval_keys: bytes) -> bytes:
        assert self.server is not None, "Model has not been loaded (bad deployment path?)."
        vals = tuple(Value.deserialize(b) for b in serialized_inputs)
        ek = EvaluationKeys.deserialize(serialized_eval_keys)
        out = self.server.run(*vals, evaluation_keys=ek)
        return out.serialize()


# ------------------------- Main logic -------------------------

def infer_for_client(
    client_id: str,
    deployment_dir: Path,
    inbox_root: Path,
    outbox_root: Path,
    timeout_s: int = 600,
    poll_s: float = 0.25,
) -> Dict:
    """
    Collects all encrypted inputs for `client_id`, runs FHE, writes encrypted_output.
    Returns a small timing/report dict.
    """
    # 1) Load deployment metadata (party order / arity)
    report = load_json(deployment_dir / "report.json")
    party_order: List[str] = report["features"]["party_order"]
    n_inputs = len(party_order)

    # 2) Resolve file layout
    inbox = ensure_dir(inbox_root / client_id)      # where client dropped ciphertexts & eval key
    outbox = ensure_dir(outbox_root / client_id)    # where server writes result

    # Expected filenames
    eval_key_path = inbox / "evaluation_key"
    part_paths = [inbox / f"encrypted_inputs_{p}" for p in party_order]
    output_path = outbox / "encrypted_output"

    # 3) Wait until everything is there (or fail)
    wait_for_files([eval_key_path, *part_paths], timeout_s=timeout_s, poll_s=poll_s)

    # 4) Read bytes
    serialized_eval_key = eval_key_path.read_bytes()
    serialized_inputs = tuple(p.read_bytes() for p in part_paths)

    # 5) Load server and run
    server = MultiInputsFHEModelServer(deployment_dir)
    t0 = time.time()
    serialized_output = server.run_serialized(serialized_inputs, serialized_eval_key)
    fhe_time = time.time() - t0

    # 6) Persist output
    output_path.write_bytes(serialized_output)
    output_size_bytes = len(serialized_output)

    return {
        "client_id": client_id,
        "parties": party_order,
        "n_inputs": n_inputs,
        "inbox": str(inbox.resolve()),
        "outbox": str(outbox.resolve()),
        "fhe_time_s": round(fhe_time, 3),
        "output_file": str(output_path.resolve()),
        "output_size_bytes": output_size_bytes,
    }


# ------------------------- CLI -------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Run multi-input FHE inference for a client ID.")
    ap.add_argument("--timeout-s", type=int, default=600, help="Wait time for inputs before error.")
    ap.add_argument("--poll-s", type=float, default=0.25, help="Polling interval while waiting.")
    return ap.parse_args()


if __name__ == "__main__":
    client_id = None # 4091376614
    # If client_id is not specified, pick the first numerical subdirectory in SERVER_FILES
    if 'client_id' not in locals() or not client_id:
        subdirs = [d for d in os.listdir(SERVER_FILES) if (SERVER_FILES / d).is_dir() and d.isdigit()]
        if subdirs:
            client_id = subdirs[0]
        else:
            raise ValueError("No numerical client_id subdirectory found in SERVER_FILES.")

    args = parse_args()
    report = infer_for_client(
        client_id=client_id,
        deployment_dir=DEPLOYMENT_DIR,
        inbox_root=SERVER_FILES,
        outbox_root=SERVER_RESULTS,
        timeout_s=args.timeout_s,
        poll_s=args.poll_s,
    )
    print(json.dumps(report, indent=2))
