
# -------------------------------
# Self-bootstrap missing packages
# Disable with: NO_AUTO_INSTALL=1
# -------------------------------
import os, sys, subprocess, importlib
from pathlib import Path

AUTO_INSTALL = os.getenv("NO_AUTO_INSTALL", "0") != "1"
VENDOR_DIR = (Path(__file__).resolve().parent / ".vendor")
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
            "pip is not available and could not be bootstrapped.\n"
            "Install pip (e.g., apt install -y python3-pip) or set NO_AUTO_INSTALL=1."
        )

def _ensure_module(mod_name: str, pip_spec: str):
    try:
        importlib.import_module(mod_name)
        return
    except ImportError:
        if not AUTO_INSTALL:
            raise
        _ensure_pip()
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--disable-pip-version-check", "--no-cache-dir",
            "--target", str(VENDOR_DIR),
            pip_spec
        ])
        importlib.invalidate_caches()
        importlib.import_module(mod_name)

# Hard deps
_ensure_module("web3", "web3>=6,<7")
_ensure_module("dotenv", "python-dotenv>=1,<2")
_ensure_module("requests", "requests>=2.28,<3")

# -------------------------------
# script 
# -------------------------------
import argparse, time, requests, hashlib
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
CONTRACT_ADDRESS = Web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS", "0x53Cd3BCE4F5058F5B6b5ee98F4c3439fDE1B301D"))

ABI = [
    {"inputs":[{"internalType":"uint256","name":"id","type":"uint256"}],
     "name":"getEntry",
     "outputs":[
        {"internalType":"address","name":"sender","type":"address"},
        {"internalType":"bytes32","name":"bundleHash","type":"bytes32"},
        {"internalType":"bytes","name":"pcr0","type":"bytes"},
        {"internalType":"string","name":"ipfsCid","type":"string"},
        {"internalType":"string","name":"bundleName","type":"string"},
        {"internalType":"uint256","name":"timestamp","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"totalEntries","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"}
]

def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def human_bytes(n: int) -> str:
    if n is None: return "unknown"
    units = ["B","KB","MB","GB","TB"]
    i = 0; f = float(n)
    while f >= 1024 and i < len(units)-1:
        f /= 1024.0; i += 1
    return f"{f:.2f} {units[i]}"

def download_ipfs(cid: str, out_dir: Path, gateway: str, desired_filename: str = None,
                  timeout: int = 600, chunk_size: int = 1024*256) -> Path:
    url = gateway.rstrip("/") + f"/{cid}"
    log(f"Downloading from IPFS: {url}")
    t0 = time.perf_counter()

    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))

        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / (desired_filename or cid)

        sha256 = hashlib.sha256()
        written = 0
        last = t0

        with out_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk: continue
                f.write(chunk)
                sha256.update(chunk)
                written += len(chunk)
                now = time.perf_counter()
                if now - last >= 1.0:
                    pct = (written/total*100.0) if total else 0.0
                    rate = (written/1024**2) / (now - t0)
                    log(f"IPFS download: {pct:6.2f}% ({human_bytes(written)} / {human_bytes(total)}) @ {rate:.2f} MB/s")
                    last = now

    t1 = time.perf_counter()
    elapsed = t1 - t0
    rate = (written/1024**2)/elapsed if elapsed>0 else 0.0
    log(f"Download complete: {human_bytes(written)} in {elapsed:.2f}s ({rate:.2f} MB/s) -> {out_path}")

    download_ipfs.last_stats = {
        "bytes": written,
        "elapsed": elapsed,
        "sha256": sha256.hexdigest(),
        "path": str(out_path),
        "filename": out_path.name,
    }
    return out_path

def main():
    ap = argparse.ArgumentParser(description="Read Notary entry (latest by default) + download IPFS payload + timings")
    ap.add_argument("id", nargs="?", type=int, help="Notary index id. If omitted, uses newest (totalEntries).")
    ap.add_argument("--gateway", default=os.getenv("IPFS_GATEWAY", "https://gateway.pinata.cloud/ipfs"),
                    help="IPFS gateway base (default: Pinata gateway)")
    ap.add_argument("--out", default="./download/", help="Output directory (file saved as <out>/<bundleName>)")
    ap.add_argument("--timeout", type=int, default=600, help="Download timeout seconds")
    args = ap.parse_args()

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    c = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

    # Time totalEntries
    t0 = time.perf_counter()
    total = c.functions.totalEntries().call()
    t1 = time.perf_counter()
    log(f"RPC totalEntries: {total} (in {(t1-t0):.3f}s)")

    if total == 0:
        log("Contract has no entries yet.")
        return

    # Pick newest if id not supplied
    id_to_fetch = args.id if args.id is not None else total
    if id_to_fetch < 1 or id_to_fetch > total:
        raise SystemExit(f"id out of range (1..{total})")

    # Time getEntry
    t2 = time.perf_counter()
    sender, bundleHash, pcr0, ipfsCid, bundleName, ts = c.functions.getEntry(id_to_fetch).call()
    t3 = time.perf_counter()
    log(f"RPC getEntry({id_to_fetch}) in {(t3-t2):.3f}s")

    print("Entry", id_to_fetch)
    print("  sender     :", sender)
    print("  bundleHash :", bundleHash.hex())
    print("  pcr0       :", pcr0.hex())
    print("  ipfsCid    :", ipfsCid)
    print("  bundleName :", bundleName)
    print("  timestamp  :", ts)

    # Download from IPFS (if ipfsCid present)
    if not ipfsCid:
        log("No ipfsCid present; skipping download.")
        return

    out_dir = Path(args.out)
    out_path = download_ipfs(
        cid=ipfsCid,
        out_dir=out_dir,
        gateway=args.gateway,
        timeout=args.timeout,
        desired_filename=bundleName,
    )
    stats = download_ipfs.last_stats
    bytes_written, dl_time = stats["bytes"], stats["elapsed"]
    sha256_hex = stats["sha256"]

    # === SHA-256 verification (MATCHES on-chain bundleHash) ===
    onchain_hex = bundleHash.hex().lower() 
    status = "MATCH" if sha256_hex.lower() == onchain_hex else "MISMATCH"

    log(f"Saved file      : {stats['filename']} (at {stats['path']})")
    log(f"SHA-256(file)   : 0x{sha256_hex}")
    log(f"On-chain hash   : {bundleHash.hex()}")
    log(f"Verify          : {status}")
    log(f"IPFS summary    : size={human_bytes(bytes_written)}, time={dl_time:.2f}s, avg_rate={(bytes_written/1024**2/dl_time):.2f} MB/s")

if __name__ == "__main__":
    main()
