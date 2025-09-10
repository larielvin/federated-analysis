from __future__ import annotations
import argparse
import json
import os
import pickle
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import time
from datetime import datetime, timezone
from concrete.ml.deployment.fhe_client_server import FHEModelClient


DEPLOYMENT_DIR = Path("/app/deployment_files/model")
REPORT_PATH = Path("/app/deployment_files/model/report.json")

CLIENT_FILES = Path("/app/client_files").resolve()
CLIENT_FILES.mkdir(parents=True, exist_ok=True)

FHE_KEYS_DIR = Path("/app/.fhe_keys").resolve()
FHE_KEYS_DIR.mkdir(parents=True, exist_ok=True)


# --------- Small helpers ---------------------
def _short_hex(b: bytes, n: int = 500, shift: int = 100) -> str:
    return b[shift:shift + n].hex()

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def load_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        raise FileNotFoundError(f"Missing JSON at {p}")
    return json.loads(p.read_text())

def load_pkl(p: Path):
    # If path contains 'output', replace it with 'deployment_files'
    p_str = str(p)
    if "output" in p_str:
        p_str = p_str.replace("output", "deployment_files")
        p = Path(p_str)
    if not p.exists():
        raise FileNotFoundError(f"Missing pickle at {p}")
    with p.open("rb") as f:
        return pickle.load(f)

def to_bool(x) -> float:
    """Return 1.0/0.0 from diverse truthy/falsey tokens; raise on ambiguity."""
    if isinstance(x, (bool, np.bool_)):
        return 1.0 if bool(x) else 0.0
    s = str(x).strip().lower()
    if s in {"true","t","1","yes","y"}:  return 1.0
    if s in {"false","f","0","no","n"}:  return 0.0
    # numeric fallback (explicit)
    try:
        return 0.0 if float(s) == 0.0 else 1.0
    except Exception:
        raise ValueError(f"Boolean field not parseable: {x!r}")


# --------- Multi-input client (pads then encrypts one slice) ------------------
class MultiInputsFHEModelClient(FHEModelClient):
    def __init__(self, path_dir: Path, key_dir: Path, nb_inputs: int):
        self.nb_inputs = nb_inputs
        super().__init__(path_dir, key_dir=key_dir)

    @property
    def total_width(self) -> int:
        if not hasattr(self.model, "input_quantizers") or self.model.input_quantizers is None:
            raise RuntimeError("Model has no input_quantizers; ensure it was compiled.")
        return len(self.model.input_quantizers)

    def quantize_encrypt_slice(self, x_slice: np.ndarray, input_index: int, party_slice: slice) -> bytes:
        if x_slice.ndim != 2 or x_slice.shape[0] != 1:
            raise ValueError(f"x_slice must be (1, n_cols); got {x_slice.shape}")

        total = self.total_width
        start, stop = party_slice.start, party_slice.stop
        if start is None or stop is None:
            raise ValueError("party_slice must have start/stop.")
        if stop > total:
            raise ValueError(f"party_slice.stop={stop} exceeds model width {total}")
        if (stop - start) != x_slice.shape[1]:
            raise ValueError(f"Slice width mismatch: expects {stop-start}, got {x_slice.shape[1]}")

        pad = np.zeros((1, total), dtype=float)
        pad[:, party_slice] = x_slice

        q_full = self.model.quantize_input(pad)   # int64 quantized full vector
        q_slice = q_full[:, party_slice]

        q_inputs = [None] * self.nb_inputs
        q_inputs[input_index] = q_slice

        enc_tuple = self.client.encrypt(*q_inputs)
        return enc_tuple[input_index].serialize()


# --------- Verification using report["features"] ------------------------------
def verify_party_alignment(report: Dict[str, Any], party: str, preproc) -> slice:
    """Check that the current preprocessor names match saved names, return saved slice."""
    features = report["features"]
    per_party = features["per_party_features"]
    if party not in per_party:
        raise ValueError(f"Party '{party}' missing in features.per_party_features.")

    saved_names = per_party[party]["feature_names_out"]
    saved_start, saved_stop = per_party[party]["slice"]

    cols = (
        report["group_columns"][party]["numeric"]
        + report["group_columns"][party]["categorical"]
        + report["group_columns"][party]["boolean"]
    )
    try:
        names_now = preproc.get_feature_names_out().tolist()
    except Exception:
        # Fallback: transform a NA row to get width only, synthesize names
        df = pd.DataFrame([{c: np.nan for c in cols}], columns=cols)
        w = int(preproc.transform(df).shape[1])
        names_now = [f"col_{i}" for i in range(w)]

    if len(saved_names) != len(names_now) or saved_names != names_now:
        raise RuntimeError(
            f"[{party}] post-processed feature order drift detected.\n"
            f"Saved width={len(saved_names)}, now={len(names_now)}.\n"
            f"First few saved: {saved_names[:8]}\nFirst few now  : {names_now[:8]}"
        )
    return slice(saved_start, saved_stop)

def preprocess_encrypt_send_party(
    client_id: str,
    party: str,
    raw_row: Dict[str, Any],
    *,
    deployment_dir: Path = DEPLOYMENT_DIR,
) -> str:
    """
    Require ALL features for the party to be present. Refuse if any missing or extras.
    """
    report = load_json(deployment_dir / "report.json")
    parties = report["features"]["party_order"]
    if party not in parties:
        raise ValueError(f"Party '{party}' not in party_order: {parties}")

    nums = report["group_columns"][party]["numeric"]
    cats = report["group_columns"][party]["categorical"]
    bools = report["group_columns"][party]["boolean"]
    expected = nums + cats + bools

    # Check for missing/extras BEFORE coercion
    provided = list(raw_row.keys())
    missing = [c for c in expected if c not in raw_row]
    extras  = [c for c in provided if c not in expected]
    if missing or extras:
        msg = []
        if missing: msg.append(f"missing={missing}")
        if extras:  msg.append(f"unexpected={extras}")
        raise ValueError(f"[{party}] strict input check failed: " + "; ".join(msg))

    # Coerce types strictly; raise if any field cannot be parsed
    coerced: Dict[str, Any] = {}
    # numeric → float (no NaN allowed here)
    for c in nums:
        v = raw_row[c]
        try:
            coerced[c] = float(v)
        except Exception:
            raise ValueError(f"[{party}] numeric field '{c}' not parseable: {v!r}")
    # categorical → string (empty disallowed)
    for c in cats:
        v = raw_row[c]
        s = str(v).strip()
        if s == "":
            raise ValueError(f"[{party}] categorical field '{c}' is empty")
        coerced[c] = s
    # boolean → float in {0.0, 1.0}
    for c in bools:
        coerced[c] = to_bool(raw_row[c])

    # Load preprocessor and verify alignment/slice
    preproc = load_pkl(Path(report["preprocessors"][party]))
    party_slice = verify_party_alignment(report, party, preproc)

    # Preprocess exactly in training column order
    df_raw = pd.DataFrame([coerced], columns=expected)
    x_post = preproc.transform(df_raw)
    x_post = np.asarray(x_post, dtype=float)

    # Encrypt only this party slice
    key_dir = _ensure_dir(FHE_KEYS_DIR / client_id)
    client = MultiInputsFHEModelClient(deployment_dir, key_dir=key_dir, nb_inputs=len(parties))
    enc_bytes = client.quantize_encrypt_slice(
        x_slice=x_post,
        input_index=parties.index(party),
        party_slice=party_slice,
    )

    out_dir = _ensure_dir(CLIENT_FILES / client_id)
    out_path = out_dir / f"encrypted_inputs_{party}"
    with out_path.open("wb") as f:
        f.write(enc_bytes)

    print(
        f"[{party}] client_id={client_id} → {out_path.name} ({out_path.stat().st_size} bytes) | "
        f"slice={party_slice.start}:{party_slice.stop} (total={client.total_width})"
    )
    return _short_hex(enc_bytes)


# --------- Load sample rows from JSON ------------------------------
def _resolve_rows_json_path(cli_path: Optional[Path]) -> Path:
    """
    Pick a JSON file path using (in order):
      1) CLI --rows-json
      2) env ROWS_JSON
      3) /app/input/sample_input.json
    """
    candidates: List[Optional[Path]] = [
        cli_path,
        Path(os.environ["ROWS_JSON"]) if os.environ.get("ROWS_JSON") else None,
        Path("/app/sample_input.json"),
    ]
    for p in candidates:
        if p and p.exists():
            return p
    raise FileNotFoundError(
        "Could not find rows JSON. Provide --rows-json PATH, set ROWS_JSON, "
        "or place a file at /app/sample_input.json"
    )

def load_rows_from_json(json_path: Path, report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Accepts either of these shapes:

      A) { "agritech": {...}, "bank": {...}, "processor": {...}, "insurance": {...}, "government": {...} }

      B) { "rows": { "agritech": {...}, ... } }

    All parties present in report["features"]["party_order"] must be provided.
    """
    raw = load_json(json_path)
    rows = raw.get("rows") if isinstance(raw, dict) and "rows" in raw else raw
    if not isinstance(rows, dict):
        raise ValueError(f"Rows JSON at {json_path} must be an object mapping party -> row dict")

    party_order: List[str] = report["features"]["party_order"]
    missing = [p for p in party_order if p not in rows]
    extras  = [p for p in rows if p not in party_order]
    if missing or extras:
        msg = []
        if missing: msg.append(f"missing parties={missing}")
        if extras:  msg.append(f"unexpected parties={extras}")
        raise ValueError("Rows JSON party keys mismatch: " + "; ".join(msg))

    # Light shape sanity-check: each party should be a dict
    for p in party_order:
        if not isinstance(rows[p], dict):
            raise ValueError(f"Party '{p}' row must be an object/dict; got {type(rows[p]).__name__}")

    return rows


if __name__ == "__main__":
    # ---- args ----
    ap = argparse.ArgumentParser(description="Quantize & encrypt per-party inputs from JSON rows.")
    ap.add_argument("--rows-json", "-r", type=Path, required=False,
                    help="Path to JSON containing per-party rows. "
                         "If omitted, uses ROWS_JSON env or falls back to common defaults.")
    ap.add_argument("--client-id", "-c", type=str, required=False,
                    help="Numeric client_id directory under /app/client_files. "
                         "If omitted, the first numeric subdir is used.")
    args = ap.parse_args()

    report = load_json(REPORT_PATH)

    # Resolve client_id
    client_id = args.client_id
    if not client_id:
        subdirs = [d for d in os.listdir(CLIENT_FILES) if (CLIENT_FILES / d).is_dir() and d.isdigit()]
        if subdirs:
            client_id = subdirs[0]
        else:
            raise ValueError("No numerical client_id subdirectory found in CLIENT_FILES. "
                             "Create one, e.g., /app/client_files/4091376614")

    # Resolve and load rows JSON
    rows_json_path = _resolve_rows_json_path(args.rows_json)
    print(f"[info] Using rows JSON: {rows_json_path}")
    rows = load_rows_from_json(rows_json_path, report)

    party_order = report["features"]["party_order"]

    # ---- cycle timing: start ----
    start_dt = datetime.now(timezone.utc)
    t0 = time.perf_counter()

    previews: Dict[str, str] = {}
    sizes: Dict[str, Optional[int]] = {}
    per_party_elapsed: Dict[str, float] = {}
    per_party_throughput: Dict[str, Optional[float]] = {}   # bytes/sec
    for party in party_order:
        p_start = time.perf_counter()
        previews[party] = preprocess_encrypt_send_party(
            client_id=client_id,
            party=party,
            raw_row=rows[party],
        )
        p_end = time.perf_counter()
        per_party_elapsed[party] = max(0.0, p_end - p_start)
        # Measure size of the serialized ciphertext written by the function
        out_path = (CLIENT_FILES / str(client_id) / f"encrypted_inputs_{party}")
        try:
            sz = out_path.stat().st_size
            sizes[party] = sz
            # compute per-party throughput (bytes/sec); guard against zero time
            per_party_throughput[party] = (sz / per_party_elapsed[party]) if per_party_elapsed[party] > 0 else None
        except FileNotFoundError:
            sizes[party] = None
            per_party_throughput[party] = None
    # ---- cycle timing: end ----
    end_dt = datetime.now(timezone.utc)
    elapsed = max(0.0, time.perf_counter() - t0)
    print("\n[Encryption cycle timing]")
    print(f"  start_utc : {start_dt.isoformat()}")
    print(f"  end_utc   : {end_dt.isoformat()}")
    print(f"  elapsed_s : {elapsed:.3f}")

    print("\n[Encrypted payload sizes & per-party throughput]")
    total_bytes = 0
    for party in party_order:
        sz = sizes.get(party)
        if sz is None:
            print(f"  {party:10s}: <missing>")
            continue
        total_bytes += sz
        thr_bps = per_party_throughput.get(party)
        if thr_bps is None:
            print(f"  {party:10s}: {sz} bytes | t={per_party_elapsed[party]:.3f}s | thr=<n/a>")
        else:
            print(f"  {party:10s}: {sz} bytes | t={per_party_elapsed[party]:.3f}s "
                  f"| thr={thr_bps:,.0f} B/s ({thr_bps/1024/1024:.2f} MiB/s)")

    overall_thr = (total_bytes / elapsed) if elapsed > 0 else None
    print("\n[Overall]")
    print(f"  total_bytes : {total_bytes} bytes (~{total_bytes/1024/1024:.2f} MiB)")
    if overall_thr is None:
        print("  throughput  : <n/a>")
    else:
        print(f"  throughput  : {overall_thr:,.0f} B/s ({overall_thr/1024/1024:.2f} MiB/s)")
