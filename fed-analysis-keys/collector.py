import argparse
import datetime
import hashlib
import io
import os
import shlex
import socket
import struct
import tarfile
import tempfile
import shutil
from pathlib import Path
import threading

# =========================
# Optional self-bootstrap
# =========================
# - Installs missing deps to a local ".vendor" dir when anchoring is enabled
# - Disable via NO_AUTO_INSTALL=1 
import sys, subprocess, importlib

SCRIPT_DIR = Path(__file__).resolve().parent

AUTO_INSTALL = os.getenv("NO_AUTO_INSTALL", "0") != "1"

VENDOR_DIR = (SCRIPT_DIR / ".vendor")
VENDOR_DIR.mkdir(parents=True, exist_ok=True)
if str(VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(VENDOR_DIR))

def _have_pip() -> bool:
    for cmd in (
        [sys.executable, "-m", "pip", "--version"],
        ["pip3", "--version"],
        ["pip", "--version"],
    ):
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            pass
    return False

def _ensure_pip():
    if _have_pip():
        return
    try:
        subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        raise RuntimeError(
            "pip is not available and could not be bootstrapped. "
            "Install pip (e.g., apt install python3-pip) or set NO_AUTO_INSTALL=1."
        )

def _ensure_module(mod_name: str, pip_spec: str, *, needed: bool, logger=None):
    """Best-effort ensure a module is importable into this process."""
    if not needed:
        return
    try:
        importlib.import_module(mod_name)
        return
    except ImportError:
        if not AUTO_INSTALL:
            raise
        if logger:
            logger(f"[bootstrap] Installing missing dependency: {pip_spec}")
        _ensure_pip()
        cmd = [
            sys.executable, "-m", "pip", "install",
            "--disable-pip-version-check", "--no-cache-dir",
            "--target", str(VENDOR_DIR),
            pip_spec
        ]
        subprocess.check_call(cmd)
        importlib.invalidate_caches()
        importlib.import_module(mod_name)

# =========================

LOGFILE_NAME = "collector.log"
ENVFILE_NAME = "bundle.env"  # runtime outputs get written here (under outdir)
_env_lock = threading.Lock()

def log(outdir: Path, msg: str):
    line = f"{datetime.datetime.utcnow().isoformat()}Z {msg}"
    print(line, flush=True)
    try:
        with open(outdir / LOGFILE_NAME, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_probably_bundle(conn: socket.socket) -> int | None:
    try:
        hdr = conn.recv(8, socket.MSG_PEEK)
        if len(hdr) < 8:
            return None
        size = struct.unpack("!Q", hdr)[0]
        # treat as bundle if 1B <= size <= 64 GiB
        if 1 <= size <= (64 << 30):
            return size
    except Exception:
        return None
    return None

def safe_extract(tar: tarfile.TarFile, dest: Path):
    """
    Prevent path traversal by ensuring all members extract under 'dest'.
    """
    dest = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest) + os.sep) and member_path != dest:
            raise RuntimeError(f"Blocked unsafe path in tar: {member.name}")
    tar.extractall(dest)

def _read_env(env_path: Path) -> dict:
    kv = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k] = v.strip().strip("'").strip('"')
    return kv

# -------- Config loader (from local .env next to this script) --------
_CONFIG = None
def _load_config() -> dict:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = _read_env(SCRIPT_DIR / ".env")
    return _CONFIG

def _cfg(key: str, default: str = "") -> str:
    return _load_config().get(key, default)

def write_env_merge(outdir: Path, updates: dict):
    """write of key/value pairs to bundle.env."""
    env_path = outdir / ENVFILE_NAME
    tmp_path = env_path.with_suffix(".tmp")
    with _env_lock:
        kv = _read_env(env_path)
        kv.update({k: str(v) for k, v in updates.items()})
        with open(tmp_path, "w", encoding="utf-8") as f:
            for k, v in kv.items():
                f.write(f"{k}={shlex.quote(v)}\n")
        os.replace(tmp_path, env_path)

def _maybe_parse_bundle_hash_line(line: str, outdir: Path) -> bool:
    """
    Recognize enclave-reported bundle hash lines and persist to bundle.env.
    Expected format: 'BUNDLE_HASH sha256=<hex> bytes=<int>'
    Returns True if handled.
    """
    if not line.startswith("BUNDLE_HASH "):
        return False
    tokens = line[len("BUNDLE_HASH "):].split()
    parts = dict(tok.split("=", 1) for tok in tokens if "=" in tok)
    sha = parts.get("sha256", "").strip()
    by  = parts.get("bytes", "").strip()
    if sha:
        write_env_merge(outdir, {
            "ENCLAVE_BUNDLE_SHA256": sha,
            "ENCLAVE_BUNDLE_BYTES": by,
            "ENCLAVE_BUNDLE_TIMESTAMP": datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"),
        })
        log(outdir, f"[collector] recorded enclave bundle hash sha256={sha} bytes={by}")
        return True
    return False

# ----------------- Anchoring helpers (optional) -----------------

ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "bundleHash", "type": "bytes32"},
            {"internalType": "bytes",   "name": "pcr0",       "type": "bytes"},
            {"internalType": "string",  "name": "ipfsCid",    "type": "string"},
            {"internalType": "string",  "name": "bundleName", "type": "string"},
        ],
        "name": "anchor",
        "outputs": [{"internalType": "uint256", "name": "id", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "internalType": "address", "name": "sender",     "type": "address"},
            {"indexed": True,  "internalType": "bytes32", "name": "bundleHash", "type": "bytes32"},
            {"indexed": True,  "internalType": "bytes32", "name": "pcr0Hash",   "type": "bytes32"},
            {"indexed": False, "internalType": "bytes32", "name": "cidHash",    "type": "bytes32"},
            {"indexed": False, "internalType": "bytes",   "name": "pcr0",       "type": "bytes"},
            {"indexed": False, "internalType": "string",  "name": "ipfsCid",    "type": "string"},
            {"indexed": False, "internalType": "string",  "name": "bundleName", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "id",         "type": "uint256"},
        ],
        "name": "Anchored",
        "type": "event",
    },
]

def _human_bytes(n: int) -> str:
    try:
        f = float(n)
    except Exception:
        return "unknown"
    units = ["B","KB","MB","GB","TB"]
    i = 0
    while f >= 1024 and i < len(units)-1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}"

def _ensure_requests_if_needed(outdir: Path, needed: bool):
    _ensure_module("requests", "requests>=2.28,<3", needed=needed, logger=lambda m: log(outdir, m))

def _ensure_web3_if_needed(outdir: Path, needed: bool):
    _ensure_module("web3", "web3>=6,<7", needed=needed, logger=lambda m: log(outdir, m))
    _ensure_module("eth_account", "eth-account>=0.8,<0.10", needed=needed, logger=lambda m: log(outdir, m))

def _maybe_pin_to_ipfs(outdir: Path, file_path: Path, bundle_name: str) -> dict | None:
    # Read from local .env (not OS env)
    jwt = _cfg("PINATA_JWT_UPLOAD", "").strip()
    if not jwt:
        log(outdir, "[anchor] PINATA_JWT_UPLOAD not set in .env; skipping IPFS upload")
        return None

    # ensure requests if we actually need to upload
    try:
        _ensure_requests_if_needed(outdir, needed=True)
        import requests, time, json
    except Exception as e:
        log(outdir, f"[anchor] requests not available ({e}); skipping IPFS upload")
        return None

    endpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    total = file_path.stat().st_size
    headers = {"Authorization": f"Bearer {jwt}"}
    metadata = {"name": bundle_name}
    options = {"cidVersion": 1, "wrapWithDirectory": False}

    class _PF:
        def __init__(self, f, total: int): self.f=f; self.t=total; self.r=0; self.s=time.perf_counter()
        def __len__(self): return self.t
        def read(self, sz=-1):
            chunk = self.f.read(sz)
            if chunk: self.r += len(chunk)
            return chunk

    start_iso = datetime.datetime.utcnow().isoformat() + "Z"
    t0 = None
    t1 = None
    try:
        with file_path.open("rb") as fh:
            pf = _PF(fh, total)
            files = [
                ("file", (file_path.name, pf, "application/octet-stream")),
                ("pinataMetadata", (None, json.dumps(metadata), "application/json")),
                ("pinataOptions",  (None, json.dumps(options),  "application/json")),
            ]
            log(outdir, f"[anchor] IPFS upload start file={file_path.name} size={_human_bytes(total)}")
            t0 = time.perf_counter()
            resp = requests.post(endpoint, headers=headers, files=files, timeout=600)
            t1 = time.perf_counter()
        resp.raise_for_status()
        data = resp.json()
        cid = data.get("IpfsHash")
        pin_size = int(data.get("PinSize") or 0)
        elapsed = (t1 - t0) if (t0 and t1) else 0.0
        end_iso = datetime.datetime.utcnow().isoformat() + "Z"
        rate_mbps = (total / (1024**2)) / elapsed if elapsed > 0 else 0.0

        log(outdir, f"[anchor] IPFS upload ok cid={cid} pin_size={_human_bytes(pin_size)} "
                    f"elapsed={elapsed:.2f}s rate={rate_mbps:.2f} MB/s")

        return {
            "cid": cid,
            "pin_size": pin_size,
            "elapsed": elapsed,
            "start_iso": start_iso,
            "end_iso": end_iso,
            "rate_mbps": rate_mbps,
        }
    except Exception as e:
        end_iso = datetime.datetime.utcnow().isoformat() + "Z"
        log(outdir, f"[anchor] IPFS upload failed: {e}")
        return {
            "cid": "",
            "pin_size": 0,
            "elapsed": 0.0,
            "start_iso": start_iso,
            "end_iso": end_iso,
            "rate_mbps": 0.0,
            "error": str(e),
        }

def _hex_to_bytes48(s: str) -> bytes | None:
    if not s: return None
    h = s.lower().removeprefix("0x")
    if len(h) != 96:
        return None
    try:
        return bytes.fromhex(h)
    except Exception:
        return None

def _maybe_anchor_on_chain(outdir: Path, bundle_sha256_hex: str, bundle_name: str, ipfs_cid: str | None) -> dict | None:
    # All config from local .env
    rpc = _cfg("RPC_URL", "https://rpc-amoy.polygon.technology").strip()
    priv = _cfg("PRIVATE_KEY", "").strip()
    contract_addr = _cfg("CONTRACT_ADDRESS", "0x53Cd3BCE4F5058F5B6b5ee98F4c3439fDE1B301D").strip()
    chain_id = int(_cfg("CHAIN_ID", "80002"))
    tip_gwei = _cfg("TIP_GWEI", "60")
    maxfee_gwei = _cfg("MAXFEE_GWEI", "120")

    # PCR0 comes from runtime bundle.env (written by your other steps)
    env_kv = _read_env(outdir / "bundle.env")
    pcr0_hex = env_kv.get("PCR0", "").strip()

    # DEBUG: log what we see (length only, not value)
    try:
        _raw = pcr0_hex.strip().strip("'").strip('"').replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
        _raw = _raw[2:] if _raw.lower().startswith("0x") else _raw
        log(outdir, f"[anchor] DEBUG PCR0 present={bool(_raw)} len={len(_raw)} path={outdir / 'bundle.env'}")
    except Exception:
        pass

    if not (rpc and priv and contract_addr):
        log(outdir, "[anchor] RPC_URL/PRIVATE_KEY/CONTRACT_ADDRESS not fully set in .env; skipping on-chain anchor")
        return None

    # ensure web3/eth-account if we actually need to anchor
    try:
        _ensure_web3_if_needed(outdir, needed=True)
        from web3 import Web3
        from eth_account import Account
        import math, time as _t
    except Exception as e:
        log(outdir, f"[anchor] web3/eth_account not available ({e}); skipping on-chain anchor")
        return None

    w3 = Web3(Web3.HTTPProvider(rpc))
    acct = Account.from_key(priv)
    addr = acct.address
    notary = w3.eth.contract(address=Web3.to_checksum_address(contract_addr), abi=ABI)

    # bundle_hash as bytes32 from SHA-256 hex
    bundle_hash_hex = "0x" + bundle_sha256_hex.lower()
    bundle_hash_b32 = w3.to_bytes(hexstr=bundle_hash_hex)

    # PCR0 bytes (optional)
    pcr0_bytes = _hex_to_bytes48(pcr0_hex) or b""
    if not pcr0_bytes:
        log(outdir, "[anchor] PCR0 (48-byte hex) not found in bundle.env; anchoring with empty pcr0 bytes")

    ipfs_cid = ipfs_cid or ""

    tx_func = notary.functions.anchor(bundle_hash_b32, pcr0_bytes, ipfs_cid, bundle_name)
    nonce = w3.eth.get_transaction_count(addr, "pending")
    try:
        gas_est = tx_func.estimate_gas({"from": addr})
    except Exception as e:
        log(outdir, f"[anchor] gas estimation failed: {e}")
        return None

    gas_limit = int(math.ceil(gas_est * 1.20))
    max_priority = w3.to_wei(tip_gwei, "gwei")
    max_fee = w3.to_wei(maxfee_gwei, "gwei")

    tx = tx_func.build_transaction({
        "from": addr,
        "nonce": nonce,
        "chainId": chain_id,
        "type": 2,
        "gas": gas_limit,
        "maxPriorityFeePerGas": max_priority,
        "maxFeePerGas": max_fee,
    })

    start_iso = datetime.datetime.utcnow().isoformat() + "Z"
    t0 = _t.perf_counter()
    signed = w3.eth.account.sign_transaction(tx, private_key=priv)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw is None:
        log(outdir, "[anchor] could not obtain raw signed tx bytes")
        return None

    log(outdir, f"[anchor] sending tx … gas_limit={gas_limit} tip={tip_gwei}g maxFee={maxfee_gwei}g")
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    t1 = _t.perf_counter()
    end_iso = datetime.datetime.utcnow().isoformat() + "Z"

    elapsed = t1 - t0
    gas_used = int(receipt.gasUsed)
    eff_price = getattr(receipt, "effectiveGasPrice", None)
    if eff_price is None:
        tx_onchain = w3.eth.get_transaction(tx_hash)
        eff_price = int(tx_onchain.get("gasPrice", 0))
    cost_wei = gas_used * int(eff_price)
    cost_eth = float(Web3.from_wei(cost_wei, "ether"))
    anchored_id = None
    try:
        evts = notary.events.Anchored().process_receipt(receipt)
        if evts:
            anchored_id = int(evts[-1]["args"]["id"])
    except Exception:
        pass

    log(outdir, f"[anchor] mined block={receipt.blockNumber} status={receipt.status} tx={tx_hash.hex()} "
                f"elapsed={elapsed:.2f}s gas_used={gas_used} eff_gas_price={eff_price} "
                f"cost≈{cost_eth} ETH")

    return {
        "tx_hash": tx_hash.hex(),
        "block": int(receipt.blockNumber),
        "status": int(receipt.status),
        "gas_used": gas_used,
        "effective_gas_price": int(eff_price),
        "cost_eth": cost_eth,
        "id": anchored_id,
        "elapsed": elapsed,
        "start_iso": start_iso,
        "end_iso": end_iso,
        "chain_id": chain_id,
        "contract_address": Web3.to_checksum_address(contract_addr),
    }

def _maybe_anchor_pipeline(outdir: Path, final_tgz: Path, digest_hex: str):
    """
    If ANCHOR_ENABLE=1 (from local .env), try:
      1) Upload to IPFS via Pinata (optional).
      2) Anchor on-chain via Notary (optional).
    Persist any outputs to bundle.env, and log timings/results.
    """
    if _cfg("ANCHOR_ENABLE", "1").strip().lower() not in {"1", "true", "yes", "y"}:
        return

    bundle_name = _cfg("BUNDLE_NAME", final_tgz.name)

    # IPFS upload (timed + logged)
    ipfs = _maybe_pin_to_ipfs(outdir, final_tgz, bundle_name)
    cid = ipfs["cid"] if ipfs else ""
    if ipfs:
        write_env_merge(outdir, {
            "IPFS_CID": cid,
            "IPFS_PIN_SIZE": str(ipfs.get("pin_size", "")),
            "IPFS_UPLOAD_SECONDS": f"{ipfs.get('elapsed', 0.0):.3f}",
            "IPFS_START_ISO": ipfs.get("start_iso", ""),
            "IPFS_END_ISO": ipfs.get("end_iso", ""),
            "IPFS_RATE_MBPS": f"{ipfs.get('rate_mbps', 0.0):.3f}",
        })

    # On-chain anchor (timed + logged)
    anchor = _maybe_anchor_on_chain(outdir, digest_hex, bundle_name, cid)
    if anchor:
        write_env_merge(outdir, {
            "ANCHOR_TX_HASH": anchor["tx_hash"],
            "ANCHOR_BLOCK": str(anchor["block"]),
            "ANCHOR_STATUS": str(anchor["status"]),
            "ANCHOR_ENTRY_ID": str(anchor.get("id") or ""),
            "ANCHOR_GAS_USED": str(anchor["gas_used"]),
            "ANCHOR_EFFECTIVE_GAS_PRICE": str(anchor["effective_gas_price"]),
            "ANCHOR_COST_ETH": str(anchor["cost_eth"]),
            "ANCHOR_START_ISO": anchor.get("start_iso", ""),
            "ANCHOR_END_ISO": anchor.get("end_iso", ""),
            "ANCHOR_ELAPSED_S": f"{anchor.get('elapsed', 0.0):.3f}",
            "ANCHOR_CHAIN_ID": str(anchor.get("chain_id", "")),
            "ANCHOR_CONTRACT_ADDRESS": anchor.get("contract_address", ""),
            "ANCHOR_BUNDLE_SHA256": digest_hex,
            "ANCHOR_BUNDLE_NAME": bundle_name,
        })

# ----------------- main connection handler -----------------

def handle_conn(conn: socket.socket, peer, outdir: Path):
    cid, port = peer
    try:
        bundle_size = is_probably_bundle(conn)
        if bundle_size:
            _ = conn.recv(8)  # consume header
            ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".tgz")
            tmp_path = Path(tmpf.name)
            received = 0
            try:
                while received < bundle_size:
                    chunk = conn.recv(min(1 << 20, bundle_size - received))
                    if not chunk:
                        break
                    tmpf.write(chunk)
                    received += len(chunk)
            finally:
                tmpf.close()

            if received != bundle_size:
                log(outdir, f"[collector] WARNING: expected {bundle_size} bytes, got {received}")

            final_tgz = outdir / f"bundle_{ts}.tgz"
            shutil.move(str(tmp_path), final_tgz)

            # Collector-side hash too (so you can compare)
            h = hashlib.sha256()
            with open(final_tgz, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()

            write_env_merge(outdir, {
                "COLLECTOR_BUNDLE_SHA256": digest,
                "BUNDLE_FILE": str(final_tgz),
                "BUNDLE_BYTES": str(received),
                "BUNDLE_SAVED_AT": ts,
            })
            log(outdir, f"[collector] bundle saved -> {final_tgz} sha256={digest} bytes={received} ({_human_bytes(received)})")

            # Optional: IPFS + on-chain anchoring (timed + logged)
            _maybe_anchor_pipeline(outdir, final_tgz, digest)
            return

        # Otherwise treat as text logs, decode safely
        buf = bytearray()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)

        text = buf.decode("utf-8", errors="replace").rstrip("\n")
        for line in text.split("\n"):
            if not line.strip():
                continue
            # Special handling for enclave hash lines:
            if _maybe_parse_bundle_hash_line(line.strip(), outdir):
                continue
            # Normal log
            log(outdir, f"[log CID {cid}] {line}")

    except Exception as e:
        log(outdir, f"[collector] ERROR handling CID {cid}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7002)
    ap.add_argument("--out", default="./output")
    args = ap.parse_args()

    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, args.port))
    s.listen(128)  # backlog
    print(f"[collector] listening on vsock:*:{args.port}, writing to {outdir}", flush=True)

    try:
        while True:
            conn, (remote_cid, remote_port) = s.accept()
            # handle each connection in its own thread so large bundles don't block logs
            t = threading.Thread(
                target=handle_conn, args=(conn, (remote_cid, remote_port), outdir), daemon=True
            )
            t.start()
    finally:
        try:
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
