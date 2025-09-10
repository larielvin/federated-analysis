import os, binascii, sys, json, requests, time, math
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3

load_dotenv()

# ---------- Config ----------
PINATA_JWT = os.getenv("PINATA_JWT_UPLOAD")  # JWT with write access
TAR_PATH = Path("/Users/elvin/Development/llm/dissertation-dev/fed-analysis-keys/output/evaluation_keys.tar.gz")
PINATA_ENDPOINT = "https://api.pinata.cloud/pinning/pinFileToIPFS"

RPC_URL = os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = Web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS", "0x53Cd3BCE4F5058F5B6b5ee98F4c3439fDE1B301D"))
CHAIN_ID = 80002  # Polygon Amoy
TIP_GWEI_DEFAULT = "60"
MAXFEE_GWEI_DEFAULT = "120"

DEFAULT_BUNDLE_NAME = TAR_PATH.name

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
        "inputs": [{"internalType": "uint256", "name": "id", "type": "uint256"}],
        "name": "getEntry",
        "outputs": [
            {"internalType": "address", "name": "sender",     "type": "address"},
            {"internalType": "bytes32", "name": "bundleHash", "type": "bytes32"},
            {"internalType": "bytes",   "name": "pcr0",       "type": "bytes"},
            {"internalType": "string",  "name": "ipfsCid",    "type": "string"},
            {"internalType": "string",  "name": "bundleName", "type": "string"},
            {"internalType": "uint256", "name": "timestamp",  "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getAllEntries",
        "outputs": [{
            "components": [
                {"internalType": "address", "name": "sender",     "type": "address"},
                {"internalType": "bytes32", "name": "bundleHash", "type": "bytes32"},
                {"internalType": "bytes",   "name": "pcr0",       "type": "bytes"},
                {"internalType": "string",  "name": "ipfsCid",    "type": "string"},
                {"internalType": "string",  "name": "bundleName", "type": "string"},
                {"internalType": "uint256", "name": "timestamp",  "type": "uint256"},
            ],
            "internalType": "struct Notary.Entry[]",
            "name": "all",
            "type": "tuple[]"
        }],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "totalEntries",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
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

# ---------- Helpers ----------
def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def human_bytes(n: int) -> str:
    if not n and n != 0:
        return "unknown"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.2f} {units[i]}"

class ProgressFile:
    def __init__(self, f, total: int, label: str = "Uploading", log_every: float = 1.0):
        self.f = f
        self.total = total
        self.read_so_far = 0
        self.start = time.perf_counter()
        self.last_log = self.start
        self.label = label
        self.log_every = log_every
    def __len__(self): return self.total
    def read(self, size: int = -1):
        chunk = self.f.read(size)
        if chunk:
            self.read_so_far += len(chunk)
            now = time.perf_counter()
            if now - self.last_log >= self.log_every or self.read_so_far == self.total:
                elapsed = now - self.start
                pct = (self.read_so_far / self.total) * 100 if self.total else 0.0
                rate = (self.read_so_far / 1024**2) / elapsed if elapsed > 0 else 0.0
                log(f"{self.label}: {pct:6.2f}% ({human_bytes(self.read_so_far)} / {human_bytes(self.total)}) @ {rate:.2f} MB/s")
                self.last_log = now
        return chunk

def ensure_priv():
    if not PRIVATE_KEY:
        sys.exit("Set PRIVATE_KEY env var (0x...)")

def ensure_hex_bytes48(s: str) -> bytes:
    h = s[2:] if s.lower().startswith("0x") else s
    if len(h) != 96:
        sys.exit(f"PCR0 must be 48 bytes (96 hex chars), got {len(h)} chars")
    try:
        return binascii.unhexlify(h)
    except Exception:
        sys.exit("PCR0 is not valid hex")

def to_bytes32_from_input(w3: Web3, s: str):
    if s.startswith("0x") and len(s) == 66:
        return w3.to_bytes(hexstr=s)
    return w3.keccak(text=s)

# ---------- Pinata upload ----------
def upload_tar_to_pinata(name: Optional[str] = None, wrap_with_directory: bool = False):
    jwt = PINATA_JWT 
    if not jwt:
        raise SystemExit("Set PINATA_JWT_UPLOAD to your Pinata JWT")
    if not TAR_PATH.is_file():
        raise FileNotFoundError(TAR_PATH)

    total_bytes = TAR_PATH.stat().st_size
    bundle_name = (name or DEFAULT_BUNDLE_NAME)
    log(f"Preparing upload: file={TAR_PATH.name} size={human_bytes(total_bytes)} bundleName={bundle_name}")

    headers = {"Authorization": f"Bearer {jwt}"}
    metadata = {"name": bundle_name}                 # <- name on Pinata
    options = {"cidVersion": 1, "wrapWithDirectory": wrap_with_directory}

    with TAR_PATH.open("rb") as base_f:
        pf = ProgressFile(base_f, total_bytes, label="IPFS upload")
        files = [
            ("file", (TAR_PATH.name, pf, "application/x-tar")),
            ("pinataMetadata", (None, json.dumps(metadata), "application/json")),
            ("pinataOptions", (None, json.dumps(options), "application/json")),
        ]
        t0 = time.perf_counter()
        resp = requests.post(PINATA_ENDPOINT, headers=headers, files=files, timeout=600)
        t1 = time.perf_counter()

    resp.raise_for_status()
    data = resp.json()
    elapsed = t1 - t0
    uploaded = total_bytes
    rate_mb_s = (uploaded / 1024**2) / elapsed if elapsed > 0 else 0.0

    cid = data.get("IpfsHash")
    pin_size = data.get("PinSize")
    timestamp = data.get("Timestamp")
    gateway = f"https://gateway.pinata.cloud/ipfs/{cid}" if cid else None

    log(f"Upload complete: elapsed={elapsed:.2f}s, avg_rate={rate_mb_s:.2f} MB/s, local_size={human_bytes(uploaded)}, pin_size={human_bytes(pin_size or 0)}")
    log(f"CID: {cid}  Gateway: {gateway}")

    return {
        "cid": cid, "size": pin_size, "timestamp": timestamp, "gateway": gateway,
        "elapsed": elapsed, "bytes": uploaded, "bundleName": bundle_name
    }

# ---------- Read helpers ----------
def get_entry(w3: Web3, notary, id_: int):
    return notary.functions.getEntry(id_).call()

def get_all_entries(w3: Web3, notary):
    return notary.functions.getAllEntries().call()

# ---------- Anchor on-chain ----------
def anchor_notary(cid: str, bundle_name: str, tip_gwei: str = TIP_GWEI_DEFAULT, maxfee_gwei: str = MAXFEE_GWEI_DEFAULT):
    ensure_priv()

    # demo placeholders – swap in real values as needed
    bundle_hash_in = "0x" + "12" * 32
    pcr0_hex = "0x" + "ab" * 48

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    acct = Account.from_key(PRIVATE_KEY)
    addr = acct.address
    notary = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

    bundle_hash = to_bytes32_from_input(w3, bundle_hash_in)
    pcr0_bytes = ensure_hex_bytes48(pcr0_hex)
    ipfs_cid = cid

    nonce = w3.eth.get_transaction_count(addr, "pending")
    tx_func = notary.functions.anchor(bundle_hash, pcr0_bytes, ipfs_cid, bundle_name)

    gas_est = tx_func.estimate_gas({"from": addr})
    gas_limit = int(math.ceil(gas_est * 1.20))

    max_priority = w3.to_wei(tip_gwei, "gwei")
    max_fee = w3.to_wei(maxfee_gwei, "gwei")

    tx = tx_func.build_transaction({
        "from": addr,
        "nonce": nonce,
        "chainId": CHAIN_ID,
        "type": 2,
        "gas": gas_limit,
        "maxPriorityFeePerGas": max_priority,
        "maxFeePerGas": max_fee,
    })

    # sign & send
    signed = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw is None:
        from eth_account import Account as EthAccount
        signed2 = EthAccount.sign_transaction(tx, private_key=PRIVATE_KEY)
        raw = getattr(signed2, "rawTransaction", None) or getattr(signed2, "raw_transaction", None)
    if raw is None:
        raise RuntimeError("Could not find raw transaction bytes on the signed tx object.")

    log(f"Sending anchor tx (gas_limit={gas_limit}, tip={tip_gwei} gwei, maxFee={maxfee_gwei} gwei)…")
    t0 = time.perf_counter()
    tx_hash = w3.eth.send_raw_transaction(raw)
    log(f"Tx sent: {tx_hash.hex()}  waiting for confirmation…")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    t1 = time.perf_counter()
    elapsed = t1 - t0

    gas_used = receipt.gasUsed
    eff_price = getattr(receipt, "effectiveGasPrice", None)
    if eff_price is None:
        tx_onchain = w3.eth.get_transaction(tx_hash)
        eff_price = tx_onchain.get("gasPrice", 0)

    cost_wei = gas_used * int(eff_price)
    cost_matic = Web3.from_wei(cost_wei, "ether")

    log(f"Anchor mined in block {receipt.blockNumber} (status={receipt.status})")
    log(f"On-chain time: {elapsed:.2f}s | gas_used={gas_used} | effective_gas_price={eff_price} wei | cost≈{cost_matic} MATIC")

    anchored_id = None

    # decode events safely
    try:
        evts = notary.events.Anchored().process_receipt(receipt)
    except Exception as e:
        log(f"Event decode error via process_receipt: {e}")
        evts = []

    if evts:
        for ev in evts:
            anchored_id = int(ev["args"]["id"])
            log("Anchored event:")
            log(f"  id         : {anchored_id}")
            log(f"  sender     : {ev['args']['sender']}")
            log(f"  bundleHash : {ev['args']['bundleHash'].hex()}")
            log(f"  pcr0Hash   : {ev['args']['pcr0Hash'].hex()}")
            log(f"  cidHash    : {ev['args']['cidHash'].hex()}")
            log(f"  ipfsCid    : {ev['args']['ipfsCid']}")
            log(f"  bundleName : {ev['args']['bundleName']}")
    else:
        # fallback: filter by topic0 for the updated signature
        topic0 = Web3.keccak(text="Anchored(address,bytes32,bytes32,bytes32,bytes,string,string,uint256)").hex()
        flt = {
            "fromBlock": receipt.blockNumber,
            "toBlock": receipt.blockNumber,
            "address": CONTRACT_ADDRESS,
            "topics": [topic0],
        }
        try:
            chain_logs = w3.eth.get_logs(flt)
            log(f"get_logs found {len(chain_logs)} Anchored log(s)")
            for lg in chain_logs:
                ev = notary.events.Anchored().process_log(lg)
                anchored_id = int(ev["args"]["id"])
                log("Anchored event (get_logs):")
                log(f"  id         : {anchored_id}")
                log(f"  sender     : {ev['args']['sender']}")
                log(f"  bundleHash : {ev['args']['bundleHash'].hex()}")
                log(f"  pcr0Hash   : {ev['args']['pcr0Hash'].hex()}")
                log(f"  cidHash    : {ev['args']['cidHash'].hex()}")
                log(f"  ipfsCid    : {ev['args']['ipfsCid']}")
                log(f"  bundleName : {ev['args']['bundleName']}")
        except Exception as e:
            log(f"get_logs failed: {e}")

    total_after = notary.functions.totalEntries().call()
    log(f"totalEntries now = {total_after}")

    return {
        "tx_hash": tx_hash.hex(),
        "block": receipt.blockNumber,
        "elapsed": elapsed,
        "gas_used": gas_used,
        "effective_gas_price": int(eff_price),
        "cost_matic": float(cost_matic),
        "total_entries": int(total_after),
        "status": int(receipt.status),
        "id": anchored_id,
        "bundleName": bundle_name,
    }

# ---------- Main ----------
if __name__ == "__main__":
    # 1) Upload 
    up = upload_tar_to_pinata(DEFAULT_BUNDLE_NAME)
    cid = up["cid"]

    # 2) Anchor 
    anchor_res = anchor_notary(cid, DEFAULT_BUNDLE_NAME)

    # 3) Summary 
    log("=== SUMMARY ===")
    log(f"Upload:  size={human_bytes(up['bytes'])}, time={up['elapsed']:.2f}s, avg_rate={(up['bytes']/1024**2/up['elapsed']):.2f} MB/s, CID={cid}, bundleName={up['bundleName']}")
    log(f"On-chain: time={anchor_res['elapsed']:.2f}s, gas_used={anchor_res['gas_used']}, "
        f"price={anchor_res['effective_gas_price']} wei, cost≈{anchor_res['cost_matic']} MATIC, "
        f"tx={anchor_res['tx_hash']}, id={anchor_res['id']}, bundleName={anchor_res['bundleName']}")

