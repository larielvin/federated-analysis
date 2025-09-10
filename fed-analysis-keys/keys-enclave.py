import os
import re
import socket, sys, traceback

_PARENT_CID = 3
COLLECTOR_PORT = 7002

LOG_LEVEL = "INFO"
LEVELS = {"DEBUG":10, "INFO":20, "WARN":30, "ERROR":40, "FATAL":50}

def _redact(s: str) -> str:
    # redact long hex/base64 tokens
    s = re.sub(r'([A-Fa-f0-9]{32,})', '[hex-redacted]', s)
    s = re.sub(r'([A-Za-z0-9+/]{40,}={0,2})', '[b64-redacted]', s)
    return s

def send_log(msg: str, level: str = "INFO"):
    if LEVELS.get(level, 20) < LEVELS.get(LOG_LEVEL, 20):
        return
    line = f"[{level}] {_redact(msg)}\n"
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((_PARENT_CID, COLLECTOR_PORT))
        s.sendall(line.encode("utf-8", errors="replace"))
        s.close()
    except Exception:
        try:
            print(line, end="", flush=True)
        except Exception:
            pass

def excepthook(exc_type, exc, tb):
    send_log(f"UNCAUGHT EXCEPTION: {exc_type.__name__}: {exc}\n{''.join(traceback.format_tb(tb))}", "FATAL")
    # default exception handler 
    sys.__excepthook__(exc_type, exc, tb)

sys.excepthook = excepthook

def report_errors(name):
    """Decorator to log start/ok/fail with traceback for any function."""
    def _wrap(fn):
        def _inner(*args, **kwargs):
            send_log(f"{name}: start")
            try:
                res = fn(*args, **kwargs)
                send_log(f"{name}: ok")
                return res
            except Exception as e:
                send_log(f"{name}: ERROR {type(e).__name__}: {e}\n{traceback.format_exc()}", "ERROR")
                raise
        return _inner
    return _wrap

# ---- report import failures ----
try:
    import datetime
    from pathlib import Path
    import numpy
    import shutil
    from typing import Tuple, List, Dict, Optional
    import subprocess
    import boto3
    import tarfile, tempfile, struct
    import base64, json, secrets, hashlib
    import cbor2
    import aws_nsm_interface

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from concrete.ml.deployment.fhe_client_server import FHEModelClient
except Exception as e:
    send_log(f"Import error: {type(e).__name__}: {e}\n{traceback.format_exc()}", "FATAL")
    raise


# ---- paths & setup ----
DEPLOYMENT_PATH = Path("/app/deployment_files/model")
FHE_KEYS       = Path("/app/.fhe_keys")
EVAL_KEYS   = Path("/app/evaluation_keys")
OUTPUT_FILES   = Path("/app/output")

POLICY_PATH = Path("/app/policy/recipients.json")
_BECH32_RE = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l0-9]+$")

for p in (FHE_KEYS, EVAL_KEYS, OUTPUT_FILES, OUTPUT_FILES / "shares"):
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        send_log(f"mkdir failed for {p}: {e}", "ERROR")
        raise

PROCESSED_INPUT_SHAPE = (1, 39)
CLIENT_TYPES = ["applicant", "bank", "credit_bureau"]

def assert_deployment_ok():
    if not DEPLOYMENT_PATH.exists():
        raise FileNotFoundError(f"Missing {DEPLOYMENT_PATH}")
    expected = ["client.zip"] 
    missing = [f for f in expected if not (DEPLOYMENT_PATH / f).exists()]
    if missing:
        raise FileNotFoundError(f"Missing deployment files: {missing}")


class MultiInputsFHEModelClient(FHEModelClient):
    def __init__(self, *args, nb_inputs=1, **kwargs):
        self.nb_inputs = nb_inputs
        super().__init__(*args, **kwargs)

    def quantize_encrypt_serialize_multi_inputs(
        self,
        x: numpy.ndarray,
        input_index: int,
        processed_input_shape: Tuple[int],
        input_slice: slice,
    ) -> bytes:
        x_padded = numpy.zeros(processed_input_shape)
        x_padded[:, input_slice] = x
        q_x_padded = self.model.quantize_input(x_padded)
        q_x = q_x_padded[:, input_slice]
        q_x_inputs = [None for _ in range(self.nb_inputs)]
        q_x_inputs[input_index] = q_x
        q_x_enc = self.client.encrypt(*q_x_inputs)
        q_x_enc_ser = q_x_enc[input_index].serialize()
        return q_x_enc_ser


@report_errors("clean_temporary_files")
def clean_temporary_files(n_keys=10):
    key_dirs = sorted(FHE_KEYS.iterdir(), key=os.path.getmtime)
    client_ids = []
    if len(key_dirs) > n_keys:
        n_keys_to_delete = len(key_dirs) - n_keys
        for key_dir in key_dirs[:n_keys_to_delete]:
            client_ids.append(key_dir.name)
            shutil.rmtree(key_dir)
    for directory in EVAL_KEYS.iterdir():
        for client_id in client_ids:
            if client_id in directory.name:
                shutil.rmtree(directory)

def _get_client(client_id):
    key_dir = FHE_KEYS / f"{client_id}"
    return MultiInputsFHEModelClient(DEPLOYMENT_PATH, key_dir=key_dir, nb_inputs=len(CLIENT_TYPES))

def _get_client_file_path(name, client_id, client_type=None):
    client_type_suffix = f"_{client_type}" if client_type else ""
    dir_path = EVAL_KEYS / f"{client_id}"
    dir_path.mkdir(exist_ok=True)
    return dir_path / f"{name}{client_type_suffix}"

def shorten_bytes_object(bytes_object, limit=500):
    shift = 100
    return bytes_object[shift : limit + shift].hex()               


@report_errors("keygen_send")
def keygen_send():
    clean_temporary_files(3)
    assert_deployment_ok()
    client_id = int(numpy.random.randint(0, 2**32))
    client = _get_client(client_id)
    client.generate_private_and_evaluation_keys(force=True)
    evaluation_key = client.get_serialized_evaluation_keys()
    file_name = "evaluation_key"
    evaluation_key_path = _get_client_file_path(file_name, client_id)
    with evaluation_key_path.open("wb") as f:
        f.write(evaluation_key)
    send_log(f"Client ID: {client_id}, eval key saved: {evaluation_key_path}")
    evaluation_key_short = shorten_bytes_object(evaluation_key)
    client_zip_path = DEPLOYMENT_PATH / "client.zip"
    if client_zip_path.exists():
        client_zip_path.unlink()
        send_log(f"Deployment file deleted: {client_zip_path}")
    return client_id, evaluation_key_short


@report_errors("archive_fhe_keys")
def archive_fhe_keys():
    archive_path = OUTPUT_FILES / "fhe_keys.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(FHE_KEYS, arcname=".fhe_keys")
    send_log(f"Archived FHE keys -> {archive_path}")
    if FHE_KEYS.exists():
        shutil.rmtree(FHE_KEYS)
        send_log(f"Deleted original FHE keys directory: {FHE_KEYS}")
    return archive_path


@report_errors("archive_evaluation_keys")
def archive_evaluation_keys():
    archive_path = OUTPUT_FILES / "evaluation_keys.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(EVAL_KEYS, arcname="evaluation_keys")
    send_log(f"Archived client files -> {archive_path}")
    if EVAL_KEYS.exists():
        shutil.rmtree(EVAL_KEYS)
        send_log(f"Deleted original client files directory: {EVAL_KEYS}")
    return archive_path


# ---------------- Shamir t-of-n ----------------
P = (1 << 521) - 1  # 2^521 - 1

def poly_eval(coeffs: List[int], x: int, mod: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % mod
    return acc

def encode_share(x: int, y: int) -> bytes:
    y_bytes = y.to_bytes((y.bit_length()+7)//8, "big")
    share = {"x": x, "y_b64": b64(y_bytes)}
    return json.dumps(share).encode()

@report_errors("shamir_split_secret")
def shamir_split_secret(secret_bytes: bytes, t: int, n: int) -> List[Tuple[int, int]]:
    s = int.from_bytes(secret_bytes, "big")
    if s >= P:
        raise ValueError("Secret too large for chosen prime field")
    coeffs = [s] + [secrets.randbelow(P) for _ in range(t-1)]
    shares = []
    for x in range(1, n+1):
        y = poly_eval(coeffs, x, P)
        shares.append((x, y))
    return shares


# ---------------- age wrapping ----------------
@report_errors("run_age_encrypt")
def run_age_encrypt(data: bytes, age_pubkey: str, out_path: Path):
    try:
        subprocess.run(["age", "-r", age_pubkey, "-o", str(out_path)],
                       input=data, check=True)
        return out_path, "age"
    except FileNotFoundError:
        msg = "age binary not found inside EIF; refusing to write raw share"
        send_log(msg, "ERROR")
        raise RuntimeError(msg)
    except subprocess.CalledProcessError as e:
        msg = f"age failed (rc={e.returncode}); refusing to write raw share"
        send_log(msg, "ERROR")
        raise

# ---------------- Helpers ----------------
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def generate_signing_key_in_memory():
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return sk, pk_raw

def write_pubkey(pubkey_raw: bytes, out_dir: Path) -> Path:
    pub_b64 = base64.b64encode(pubkey_raw).decode()
    out_path = out_dir / "enclave_pubkey.ed25519.b64"
    out_path.write_text(pub_b64 + "\n")
    return out_path

def sign_detached(sk: Ed25519PrivateKey, msg: bytes) -> bytes:
    return sk.sign(msg)


# --------- Attestation via /dev/nsm ---------
@report_errors("get_attestation_doc")
def get_attestation_doc(user_data: bytes, nonce_len: int = 32, public_key: Optional[bytes] = None) -> bytes:
    fd = os.open("/dev/nsm", os.O_RDWR | os.O_CLOEXEC)
    try:
        nonce = os.urandom(nonce_len)
        resp = aws_nsm_interface.get_attestation_doc(
            fd, user_data=user_data, nonce=nonce, public_key=public_key
        )
        return resp["document"]  # raw CBOR
    finally:
        os.close(fd)


def parse_pcr0_from_attestation_cbor(att_cbor: bytes) -> str:
    try:
        cose = cbor2.loads(att_cbor)             # [protected, unprotected, payload, signature]
        if not (isinstance(cose, list) and len(cose) >= 3):
            return ""
        payload = cose[2]
        payload_map = cbor2.loads(payload)       # CBOR map with keys incl. 'pcrs'
        pcrs = payload_map.get("pcrs") or {}
        if isinstance(pcrs, dict) and 0 in pcrs:
            return pcrs[0].hex()
        return ""
    except Exception:
        return ""


# ---------------- Core encryption workflow ----------------
@report_errors("encrypt_inside_enclave")
def encrypt_inside_enclave(
    fhekey_archive_path: Path,
    evaluation_archive_path: Path,
    client_id: int,
    recipients: List[Dict[str, str]],
    threshold_t: int
):
    n = len(recipients)
    if threshold_t < 1 or threshold_t > n:
        raise ValueError(f"threshold_t must be between 1 and n (got t={threshold_t}, n={n})")

    # 1) DEK
    dek = secrets.token_bytes(32)

    # 2) Encrypt archive (AES-256-GCM)
    fhekey_archive_path = Path(fhekey_archive_path)
    plaintext = fhekey_archive_path.read_bytes()
    nonce = secrets.token_bytes(12)
    aad = f"resource:{fhekey_archive_path.name}|sha256:{hashlib.sha256(plaintext).hexdigest()}".encode()
    aead = AESGCM(dek)
    ciphertext = aead.encrypt(nonce, plaintext, aad)

    enc_path = OUTPUT_FILES / "fhe_keys.enc"
    enc_path.write_bytes(ciphertext)

    if fhekey_archive_path.exists():
        fhekey_archive_path.unlink()
        send_log(f"Deleted original archive: {fhekey_archive_path}")

    # 3) Split DEK t-of-n
    shares = shamir_split_secret(dek, threshold_t, n)

    # Wrap each share
    share_entries = []
    for i, (recipient, (x, y)) in enumerate(zip(recipients, shares), start=1):
        share_raw = encode_share(x, y)
        rid = recipient.get("id") or f"user{i}"
        age_pub = recipient.get("age_pubkey")

        if age_pub:
            desired_path = OUTPUT_FILES / "shares" / f"share_{rid}.age"
            out_path, typ = run_age_encrypt(share_raw, age_pub, desired_path)
            share_ref = {"id": rid, "type": typ, "path": str(out_path.name)}
        else:
            out_path = OUTPUT_FILES / "shares" / f"share_{rid}.bin"
            out_path.write_bytes(share_raw)
            share_ref = {"id": rid, "type": "raw", "path": str(out_path.name)}

        share_entries.append(share_ref)

    # 4) Manifest (hash all artifacts)
    files_meta = []
    files_meta.append({
        "name": enc_path.name,
        "size": enc_path.stat().st_size,
        "sha256": sha256_file(enc_path),
    })
    files_meta.append({
        "name": evaluation_archive_path.name,
        "size": evaluation_archive_path.stat().st_size,
        "sha256": sha256_file(evaluation_archive_path),
    })
    for entry in share_entries:
        sp = OUTPUT_FILES / "shares" / entry["path"]
        files_meta.append({
            "name": entry["path"],
            "size": sp.stat().st_size,
            "sha256": sha256_file(sp),
        })

    recipients_commitment = sha256_bytes(
        canonical_json({"pubkeys": sorted([r.get("age_pubkey", "") for r in recipients])})
    )

    manifest = {
        "schema": "enc-manifest-v1",
        "cipher": {"alg": "AES-256-GCM",
                   "nonce_b64": b64(nonce),
                   "aad": aad.decode()},
        "ciphertext_file": enc_path.name,
        "evaluation_file": evaluation_archive_path.name,
        "threshold": {"t": threshold_t, "n": n},
        "shares_dir": "shares/",
        "shares": share_entries,
        "files": files_meta,
        "recipients_commitment": recipients_commitment,
        "client_id": client_id,
        "created_at": datetime.datetime.now().isoformat(),
    }
    manifest_path = OUTPUT_FILES / "manifest.v1.json"
    manifest_bytes = canonical_json(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2))

    # 5) Enclave signing key, attestation binding, signatures
    sk, pub_raw = generate_signing_key_in_memory()
    pub_path = write_pubkey(pub_raw, OUTPUT_FILES)

    user_data = b"ed25519-pubkey:" + pub_raw
    attestation_cbor = get_attestation_doc(user_data=user_data)  # via /dev/nsm
    att_path = OUTPUT_FILES / "attestation.document.cbor"
    att_path.write_bytes(attestation_cbor)
    pcr0_hex = parse_pcr0_from_attestation_cbor(attestation_cbor)

    manifest_sig = sign_detached(sk, manifest_bytes)
    (OUTPUT_FILES / "manifest.v1.json.sig").write_bytes(manifest_sig)

    enc_sig = sign_detached(sk, enc_path.read_bytes())
    (OUTPUT_FILES / f"{enc_path.name}.sig").write_bytes(enc_sig)

    receipt = {
        "schema": "enclave-receipt-v1",
        "ciphertext_sha256": files_meta[0]["sha256"],
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "recipients_commitment": recipients_commitment,
        "threshold": {"t": threshold_t, "n": n},
        "signer_pubkey_ed25519_b64": base64.b64encode(pub_raw).decode(),
        "attestation_cbor_sha256": sha256_file(att_path),
        "pcr0_image_sha384_hex": pcr0_hex,
    }
    receipt_bytes = canonical_json(receipt)
    receipt_sig = sign_detached(sk, receipt_bytes)
    (OUTPUT_FILES / "receipt.v1.json").write_text(json.dumps(receipt, indent=2))
    (OUTPUT_FILES / "receipt.v1.json.sig").write_bytes(receipt_sig)

    send_log(f"Encrypted archive: {enc_path}")
    send_log(f"Manifest: {manifest_path}")
    send_log(f"Signatures written: {manifest_path.name}.sig, {enc_path.name}.sig, receipt.v1.json(.sig)")
    send_log(f"Enclave public key: {pub_path}")
    send_log(f"Shares dir: {OUTPUT_FILES/'shares'}")
    return enc_path, manifest_path


# --------- Send outputs to parent over vsock ---------
@report_errors("send_output_dir_over_vsock")
def send_output_dir_over_vsock(output_dir: Path, port: int = COLLECTOR_PORT):
    # small text ping
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((_PARENT_CID, port))
        s.sendall(b"Hello, world!\n")
        s.close()
    except Exception as e:
        send_log(f"hello ping failed: {e}", "WARN")

    # bundle and stream
    output_dir = Path(output_dir)
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
        with tarfile.open(fileobj=tmp, mode="w:gz") as tf:
            tf.add(output_dir, arcname=".")
        bundle_path = Path(tmp.name)

    # compute sha256 of the bundle
    h = hashlib.sha256()
    with open(bundle_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    size = bundle_path.stat().st_size
    s1 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s1.settimeout(2)
    s1.connect((_PARENT_CID, port))
    s1.sendall(f"BUNDLE_HASH sha256={digest} bytes={size}\n".encode("utf-8", errors="replace"))
    s1.close()

    s2 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s2.settimeout(10)
    s2.connect((_PARENT_CID, port))
    # send 8B length prefix then bytes
    s2.sendall(struct.pack("!Q", size))
    with open(bundle_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            s2.sendall(chunk)
    s2.close()
    try:
        bundle_path.unlink(missing_ok=True)
    except Exception:
        pass
    send_log(f"sent {size} bytes to host collector")


def load_recipients_and_T(policy_path: Path = POLICY_PATH):
    raw = policy_path.read_bytes()
    # integrity pin set during docker build
    expected = os.getenv("RECIPIENTS_JSON_SHA256")
    if expected:
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise RuntimeError(
                f"recipients.json hash mismatch: expected {expected}, got {actual}"
            )
    doc = json.loads(raw)
    if doc.get("schema") != "recipients-v1":
        raise ValueError("recipients.json: unknown schema (expected 'recipients-v1')")
    recipients = doc.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("recipients.json: 'recipients' must be a non-empty array")
    # all entries have id + age_pubkey, unique keys, plausible format
    seen = set()
    for r in recipients:
        rid = r.get("id")
        k = r.get("age_pubkey", "")
        if not rid or not k:
            raise ValueError(f"bad recipient entry: {r}")
        if not _BECH32_RE.match(k):
            raise ValueError(f"invalid age_pubkey format for {rid}")
        if k in seen:
            raise ValueError(f"duplicate age_pubkey for {rid}")
        seen.add(k)

    T = len(recipients)  
    return recipients, T


# ---------------- main ----------------
if __name__ == "__main__":
    send_log("enclave app boot")

    try:
        h = hashlib.sha256(Path("/app/policy/recipients.json").read_bytes()).hexdigest()
        assert h == os.getenv("RECIPIENTS_JSON_SHA256"), "recipients.json hash mismatch"
        client_id, evaluation_key_short = keygen_send()
        send_log("Keys generated; evaluation key present")
        fhekeys_archive_path = archive_fhe_keys()
        evaluation_archive_path = archive_evaluation_keys()

        RECIPIENTS, T = load_recipients_and_T()

        encrypt_inside_enclave(Path(fhekeys_archive_path), Path(evaluation_archive_path), client_id, RECIPIENTS, T)
        send_output_dir_over_vsock(OUTPUT_FILES)
        send_log("Workflow completed inside enclave")
        print("Workflow completed inside enclave (local DEK + threshold shares)", flush=True)
    except Exception as e:
        send_log(f"main failed: {type(e).__name__}: {e}\n{traceback.format_exc()}", "FATAL")
        raise
