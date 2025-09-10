import os, argparse, time, requests, hashlib, re
from pathlib import Path
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
        {"internalType":"string","name":"bundleName","type":"string"},  # <-- added
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

# Keccak hashing helper (handles multiple backends)
def new_keccak256():
    try:
        from Crypto.Hash import keccak as _keccak  # PyCryptodome
        return _keccak.new(digest_bits=256)
    except Exception:
        try:
            import sha3  # pysha3
            return sha3.keccak_256()
        except Exception:
            from web3 import Web3
            class _W3Keccak:
                def __init__(self):
                    self._buf = bytearray()
                def update(self, data: bytes):
                    self._buf.extend(data)
                def hexdigest(self):
                    return Web3.keccak(bytes(self._buf)).hex()[2:]
            return _W3Keccak()

def download_ipfs(cid: str, out_dir: Path, gateway: str, desired_filename: str = None,
                  timeout: int = 600, chunk_size: int = 1024*256) -> Path:
    url = gateway.rstrip("/") + f"/{cid}"
    log(f"Downloading from IPFS: {url}")
    t0 = time.perf_counter()

    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))


        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / desired_filename

        sha256 = hashlib.sha256()
        keccak = new_keccak256()
        written = 0
        last = t0

        with out_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk: continue
                f.write(chunk)
                sha256.update(chunk)
                keccak.update(chunk)
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
        "keccak256": keccak.hexdigest(),
        "path": str(out_path),
        "filename": desired_filename,
    }
    return out_path

def main():
    ap = argparse.ArgumentParser(description="Read Notary entry (latest by default) + download IPFS payload + timings")
    ap.add_argument("id", nargs="?", type=int, help="Notary index id. If omitted, uses newest (totalEntries).")
    ap.add_argument("--gateway", default=os.getenv("IPFS_GATEWAY", "https://gateway.pinata.cloud/ipfs"),
                    help="IPFS gateway base (default: Pinata gateway)")
    ap.add_argument("--out", default="./output/", help="Output directory (file saved as <out>/<bundleName>)")
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
    sha256_hex, keccak_hex = stats["sha256"], stats["keccak256"]

    # Keccak-256 verification
    onchain_hex = bundleHash.hex()[2:]
    khex_32 = keccak_hex.rjust(64, "0")
    status = "MATCH" if onchain_hex.lower() == khex_32.lower() else "MISMATCH"
    log(f"Saved file     : {stats['filename']} (at {stats['path']})")
    log(f"Keccak-256(file): 0x{khex_32}")
    log(f"On-chain hash   : {bundleHash.hex()}")
    log(f"Verify          : {status}")
    log(f"File hashes     : sha256={sha256_hex}  keccak256={keccak_hex}")
    log(f"IPFS summary    : size={human_bytes(bytes_written)}, time={dl_time:.2f}s, avg_rate={(bytes_written/1024**2/dl_time):.2f} MB/s")

if __name__ == "__main__":
    main()
