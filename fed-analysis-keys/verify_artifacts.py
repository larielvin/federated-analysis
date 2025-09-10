# --- self-bootstrap missing Python packages (vendor-local) -------------------
# Disable with NO_AUTO_INSTALL=1
import os, sys, subprocess, importlib

AUTO = os.getenv("NO_AUTO_INSTALL", "0") != "1"

# where to install wheels (next to this script)
VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".vendor")
os.makedirs(VENDOR_DIR, exist_ok=True)
if VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)

PIP_SPECS = {
    "cbor2": "cbor2>=5,<6",
    "cryptography": "cryptography>=41,<44",
}

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
        subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        raise RuntimeError(
            "pip is not available. On Ubuntu, run:\n"
            "  sudo apt update && sudo apt install -y python3-pip\n"
        )

def ensure_module(mod_name: str, pip_spec: str):
    try:
        importlib.import_module(mod_name)
        return
    except ImportError:
        if not AUTO:
            raise
        _ensure_pip()
        # Install into our vendor dir so we can import it reliably
        cmd = [
            sys.executable, "-m", "pip", "install",
            "--disable-pip-version-check", "--no-cache-dir",
            "--target", VENDOR_DIR, pip_spec
        ]
        print(f"[bootstrap] Installing missing dependency to .vendor: {pip_spec}", file=sys.stderr, flush=True)
        subprocess.check_call(cmd)
        importlib.invalidate_caches()
        importlib.import_module(mod_name)

for _mod, _spec in PIP_SPECS.items():
    ensure_module(_mod, _spec)
# ---------------------------------------------------------------------------





"""
Verify Nitro Enclave artifacts directly from the collector's bundle:
- Reads bundle.env in --dir to get BUNDLE_FILE and ENCLAVE_BUNDLE_SHA256
- Confirms bundle hash matches enclave-reported hash
- Extracts into --dir (overwriting files), with path traversal protection
- Verifies attestation.user_data pubkey, manifest & ciphertext signatures, and file hashes
"""
import argparse
import base64
import hashlib
import json
import os
import shlex
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import io, urllib.request, cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import subprocess, tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils



# ---- AWS Nitro Enclaves Root (G1) fetch & verify ----
NITRO_ROOT_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
# Published SHA-256 fingerprint of the Root-G1 certificate (colonless hex)
NITRO_ROOT_FP_SHA256_HEX = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

# -------------------- helpers: hashing, json, env --------------------

def ensure_nitro_root_pem(dest_path: Path) -> Path:
    """
    Ensure the Nitro Root PEM exists at dest_path.
    If missing, download official ZIP from AWS, extract PEM, verify fingerprint, then write it.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists():
        # Verify existing file fingerprint too (defense-in-depth)
        cert = x509.load_pem_x509_certificate(dest_path.read_bytes())
        fp = cert.fingerprint(hashes.SHA256()).hex()
        if fp.lower() != NITRO_ROOT_FP_SHA256_HEX:
            raise SystemExit(f"Nitro root at {dest_path} fingerprint mismatch")
        return dest_path

    # Download zip
    with urllib.request.urlopen(NITRO_ROOT_URL) as resp:
        zip_bytes = resp.read()

    # Extract PEM in-memory
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    pem_name = next(n for n in zf.namelist() if n.lower().endswith(".pem"))
    pem_bytes = zf.read(pem_name)

    # Verify fingerprint before trusting it
    cert = x509.load_pem_x509_certificate(pem_bytes)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    if fp.lower() != NITRO_ROOT_FP_SHA256_HEX:
        raise SystemExit("Downloaded Nitro root fingerprint mismatch")

    dest_path.write_bytes(pem_bytes)
    return dest_path



def canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def read_env_file(env_path: Path) -> Dict[str, str]:
    """
    Parse a simple KEY=VALUE .env file written by the collector.
    """
    kv: Dict[str, str] = {}
    if not env_path.exists():
        return kv
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        # unquote if the collector quoted it
        try:
            v = shlex.split(v)[0] if v else v
        except Exception:
            pass
        if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
            v = v[1:-1]
        kv[k] = v
    return kv

def parse_cose(att_bytes: bytes):
    # COSE_Sign1: [protected_bstr, unprotected_map, payload_bstr, signature_bstr]
    obj = cbor2.loads(att_bytes)
    if not (isinstance(obj, list) and len(obj) >= 4):
        raise ValueError("attestation is not COSE_Sign1")
    protected_bstr, _unprot, payload_bstr, sig = obj[0], obj[1], obj[2], obj[3]
    if not isinstance(protected_bstr, (bytes, bytearray)) or not isinstance(payload_bstr, (bytes, bytearray)):
        raise ValueError("unexpected COSE field types")
    return bytes(protected_bstr), bytes(payload_bstr), bytes(sig)

def extract_chain_from_payload(payload_map: dict):
    # AWS payload includes 'certificate' (leaf DER) and 'cabundle' (array of DER)
    leaf_der = payload_map.get("certificate")
    cabundle = payload_map.get("cabundle") or []
    if not isinstance(leaf_der, (bytes, bytearray)):
        raise ValueError("payload missing leaf certificate")
    inters = []
    for der in cabundle:
        if isinstance(der, (bytes, bytearray)):
            inters.append(bytes(der))
    return bytes(leaf_der), inters


def verify_chain_openssl(leaf_der: bytes, inters_der: list[bytes], nitro_root_pem_path: str):
    # Write temp files for OpenSSL path validation
    with tempfile.TemporaryDirectory() as td:
        leaf_pem_path = Path(td) / "leaf.pem"
        inter_pem_path = Path(td) / "inter.pem"

        # DER -> PEM using the correct Encoding enum
        leaf = x509.load_der_x509_certificate(leaf_der)
        leaf_pem_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))

        if inters_der:
            inter_pem_bytes = b"".join(
                x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM)
                for d in inters_der
            )
            inter_pem_path.write_bytes(inter_pem_bytes)
            cmd = [
                "openssl", "verify",
                "-CAfile", nitro_root_pem_path,
                "-untrusted", str(inter_pem_path),
                str(leaf_pem_path),
            ]
        else:
            # No intermediates
            cmd = [
                "openssl", "verify",
                "-CAfile", nitro_root_pem_path,
                str(leaf_pem_path),
            ]

        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



def verify_cose_es384(protected_bstr: bytes, payload_bstr: bytes, sig: bytes, leaf_der: bytes):
    """
    Verify COSE_Sign1 ES384 signature:
    - COSE uses raw (r||s). Convert to DER for cryptography.
    - Sig_structure = ["Signature1", protected, external_aad="", payload]
    """
    import cbor2
    # Build Sig_structure exactly per RFC 8152
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])

    # Convert raw (r||s) -> DER if needed. If it already looks like DER (0x30), keep as-is.
    if len(sig) in (96,):  # P-384 => 48-byte r + 48-byte s
        r = int.from_bytes(sig[:48], "big")
        s = int.from_bytes(sig[48:], "big")
        sig_der = utils.encode_dss_signature(r, s)
    elif sig and sig[0] == 0x30:
        sig_der = sig  # already DER
    else:
        # Try generic split for unexpected lengths (even length, split in half)
        if len(sig) % 2 != 0:
            raise SystemExit(f"Unexpected COSE ECDSA signature length: {len(sig)}")
        n = len(sig) // 2
        r = int.from_bytes(sig[:n], "big")
        s = int.from_bytes(sig[n:], "big")
        sig_der = utils.encode_dss_signature(r, s)

    # Optional sanity: protected header must indicate ES384 (alg = -35)
    try:
        protected_map = cbor2.loads(protected_bstr)
        if protected_map.get(1) not in (-35,):  # header param 1 = alg
            raise SystemExit(f"COSE alg header not ES384: {protected_map.get(1)!r}")
    except Exception:
        # If protected is empty or not decodable, we’ll still verify with ES384 below
        pass

    # Verify with leaf cert public key
    leaf = x509.load_der_x509_certificate(leaf_der)
    leaf.public_key().verify(sig_der, sig_structure, ec.ECDSA(hashes.SHA384()))


# -------------------- attestation & signatures --------------------

def load_attestation(att_path: Path) -> Dict[str, Any]:
    """
    Load AWS NSM attestation document and return the CBOR payload map.
    The file contains a COSE_Sign1 structure: [protected, unprotected, payload, signature].
    """
    obj = cbor2.loads(att_path.read_bytes())
    # COSE_Sign1: [protected, unprotected, payload, signature]
    if isinstance(obj, list) and len(obj) >= 3:
        payload = obj[2]
        # payload is CBOR-encoded bytes
        if isinstance(payload, (bytes, bytearray)):
            return cbor2.loads(payload)
        # some tools may already provide a decoded map here
        if isinstance(payload, dict):
            return payload
        raise ValueError("Unexpected COSE payload type in attestation")
    # Some pipelines may store just the decoded payload map directly
    if isinstance(obj, dict):
        return obj
    raise ValueError("Unrecognized attestation CBOR structure")

def extract_attested_pubkey(att_map: Dict[str, Any]) -> bytes:
    """
    user_data must be: b'ed25519-pubkey:' + 32 raw bytes.
    Returns raw 32-byte Ed25519 public key.
    """
    user_data = att_map.get("user_data", b"")
    if not isinstance(user_data, (bytes, bytearray)):
        raise ValueError("attestation user_data missing or not bytes")
    prefix = b"ed25519-pubkey:"
    if not user_data.startswith(prefix):
        raise ValueError("attestation user_data missing 'ed25519-pubkey:' prefix")
    pub_raw = bytes(user_data[len(prefix):])
    if len(pub_raw) != 32:
        raise ValueError(f"attested Ed25519 pubkey length != 32 bytes (got {len(pub_raw)})")
    return pub_raw

def get_pcr0_hex(att_map: Dict[str, Any]) -> str:
    """
    Return PCR0 (ImageSha384) as lowercase hex.
    """
    pcrs = att_map.get("pcrs") or {}
    if isinstance(pcrs, dict):
        val = pcrs.get(0) or pcrs.get("0")
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        if isinstance(val, str):
            return val.lower().replace("0x", "")
    return ""

def ed25519_verify(pub_raw: bytes, data: bytes, sig: bytes) -> None:
    pk = Ed25519PublicKey.from_public_bytes(pub_raw)
    pk.verify(sig, data)  # raises InvalidSignature if bad

def load_manifest(manifest_path: Path) -> Tuple[Dict[str, Any], bytes]:
    manifest_text = manifest_path.read_text()
    manifest = json.loads(manifest_text)
    return manifest, canonical_json(manifest)

def verify_manifest_files(manifest: Dict[str, Any], root: Path) -> List[str]:
    """
    Verify every entry in manifest["files"] by sha256. Supports manifests that
    list share files without the "shares/" prefix while physically placing them
    under shares_dir (e.g., "shares/").

    Returns a list of normalized relative paths that were verified.
    """
    def _norm_rel(p: Path) -> str:
        return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")

    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise ValueError("manifest['files'] must be a list")

    # Normalize shares_dir like "shares/" -> "shares"
    shares_dir = (manifest.get("shares_dir") or "").strip()
    shares_dir = shares_dir.lstrip("./").rstrip("/")

    verified_relpaths: List[str] = []

    for entry in files:
        rel = entry["name"]                   # e.g., "share_alice.age"
        expected = entry["sha256"]

        # Candidate locations to look for this file
        candidates = [root / rel]
        # If it's not already an explicit path and we have a shares_dir, try there
        if shares_dir and ("/" not in rel and "\\" not in rel):
            candidates.append(root / shares_dir / rel)

        # Pick the first existing candidate
        p = next((c for c in candidates if c.exists()), None)
        if p is None:
            raise FileNotFoundError(f"manifest listed file not found: {rel}")

        actual = sha256_file(p)
        if actual != expected:
            raise ValueError(f"sha256 mismatch for {rel}: expected {expected}, got {actual}")

        verified_relpaths.append(_norm_rel(p))

    return verified_relpaths


# -------------------- safe extraction (OVERWRITE) --------------------

def _ensure_within(dest_root: Path, target: Path) -> None:
    if not str(target.resolve()).startswith(str(dest_root.resolve())):
        raise RuntimeError(f"Blocked path traversal: {target}")

def extract_tar_overwrite(bundle: Path, dest: Path) -> None:
    with tarfile.open(bundle, "r:*") as tf:
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            _ensure_within(dest, target)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif m.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    target.unlink()
                fsrc = tf.extractfile(m)
                if fsrc is None:
                    raise RuntimeError(f"Failed to read member: {m.name}")
                with open(target, "wb") as fdst:
                    shutil.copyfileobj(fsrc, fdst, length=1 << 20)
                # permissions (best-effort)
                try:
                    os.chmod(target, m.mode & 0o777)
                except Exception:
                    pass
            else:
                # disallow symlinks, hardlinks, devices, etc.
                raise RuntimeError(f"Blocked non-regular member: {m.name} ({m.type})")

def extract_zip_overwrite(bundle: Path, dest: Path) -> None:
    with zipfile.ZipFile(bundle) as zf:
        for info in zf.infolist():
            name = info.filename
            target = (dest / name).resolve()
            _ensure_within(dest, target)
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target.unlink()
            with zf.open(info, "r") as fsrc, open(target, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst, length=1 << 20)
            # best-effort perms from external_attr (unix mode in high 16 bits)
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                try:
                    os.chmod(target, mode)
                except Exception:
                    pass

def extract_bundle_overwrite(bundle: Path, dest: Path) -> None:
    """
    Extract .tar.gz/.tgz/.tar OR .zip into dest, overwriting existing files.
    """
    suffixes = bundle.suffixes
    if suffixes[-2:] == [".tar", ".gz"] or bundle.suffix in (".tgz", ".tar"):
        extract_tar_overwrite(bundle, dest)
    elif bundle.suffix == ".zip":
        extract_zip_overwrite(bundle, dest)
    else:
        raise SystemExit(f"Unsupported bundle format: {bundle}")


# -------------------- main flow --------------------

def main():
    ap = argparse.ArgumentParser(description="Verify enclave artifacts from collector bundle")
    ap.add_argument("--dir", default="./output",
                    help="Collector output directory containing bundle.env and bundles (default: ./output)")
    ap.add_argument("--bundle", default="",
                    help="Optional explicit path to a bundle (.tgz/.tar/.zip). If omitted, uses bundle.env in --dir.")
    ap.add_argument("--pcr0-allow", default="",
                    help="Optional allow-listed PCR0 (ImageSha384) hex")
    ap.add_argument("--strict", action="store_true",
                    help="Fail if directory contains extra files not declared in manifest['files']")
    ap.add_argument(
        "--nitro-root",
        default="",
        help="Path to AWS Nitro Enclaves Root CA PEM. If omitted, auto-fetch to ./trust/AWS_NitroEnclaves_Root-G1.pem"
    )
    args = ap.parse_args()

    outdir = Path(args.dir).resolve()
    # If ./output is empty, use ./fed-analysis-keys/output instead
    if outdir == Path("./output").resolve() and (not outdir.exists() or not any(outdir.iterdir())):
        outdir = Path("./fed-analysis-keys/output").resolve()

    # ---- Resolve bundle and expected hash from bundle.env (or --bundle) ----
    bundle_path: Optional[Path] = None
    expected_sha: Optional[str] = None

    if args.bundle:
        bundle_path = Path(args.bundle).resolve()
        if not bundle_path.exists():
            raise SystemExit(f"--bundle not found: {bundle_path}")
        env_kv = read_env_file(outdir / "bundle.env")
        expected_sha = env_kv.get("ENCLAVE_BUNDLE_SHA256") or env_kv.get("COLLECTOR_BUNDLE_SHA256")
        if not expected_sha:
            print("[WARN] No ENCLAVE_BUNDLE_SHA256 in bundle.env; proceeding without enclave hash match")
    else:
        env_kv = read_env_file(outdir / "bundle.env")
        if not env_kv:
            raise SystemExit(f"bundle.env not found or empty in {outdir}. Provide --bundle explicitly.")
        bf = env_kv.get("BUNDLE_FILE", "")
        if not bf:
            raise SystemExit(f"bundle.env missing BUNDLE_FILE. Found keys: {sorted(env_kv.keys())}")
        bundle_path = Path(bf) if os.path.isabs(bf) else (outdir / Path(bf).name)
        if not bundle_path.exists():
            raise SystemExit(f"BUNDLE_FILE not found: {bundle_path}")
        expected_sha = env_kv.get("ENCLAVE_BUNDLE_SHA256")
        if not expected_sha:
            raise SystemExit("bundle.env missing ENCLAVE_BUNDLE_SHA256 (enclave-reported bundle hash)")

    # ---- Hash the bundle and compare to enclave-reported hash ----
    actual_sha = sha256_file(bundle_path)
    if expected_sha and actual_sha.lower() != expected_sha.lower():
        raise SystemExit(
            "Bundle hash mismatch:\n"
            f"  expected (enclave): {expected_sha}\n"
            f"  actual   (file)   : {actual_sha}\n"
            f"  file: {bundle_path}"
        )
    print(f"[OK] Bundle hash matches enclave: {actual_sha}")
    print(f"     Bundle file: {bundle_path}")

    # ---- Extract directly into --dir (OVERWRITE) ----
    extract_bundle_overwrite(bundle_path, outdir)
    print(f"[OK] Extracted bundle into {outdir} (overwrote existing files where necessary)")

    # ---- Verify artifacts in outdir ----
    root = outdir
    # Required files
    att_path = root / "attestation.document.cbor"
    pub_path = root / "enclave_pubkey.ed25519.b64"
    man_path = root / "manifest.v1.json"
    man_sig_path = root / "manifest.v1.json.sig"
    receipt_path = root / "receipt.v1.json"
    receipt_sig_path = root / "receipt.v1.json.sig"

    for p in [att_path, pub_path, man_path, man_sig_path, receipt_path, receipt_sig_path]:
        if not p.exists():
            raise SystemExit(f"Missing required artifact: {p.relative_to(root)}")


    att_bytes = att_path.read_bytes()
    protected_bstr, payload_bstr, sig = parse_cose(att_bytes)
    payload_map = cbor2.loads(payload_bstr)

    # Resolve Nitro Root PEM path (download+verify if not provided)
    if args.nitro_root:
        nitro_root_pem = Path(args.nitro_root).resolve()
    else:
        nitro_root_pem = ensure_nitro_root_pem(Path("./trust/AWS_NitroEnclaves_Root-G1.pem"))

    leaf_der, inters_der = extract_chain_from_payload(payload_map)
    verify_chain_openssl(leaf_der, inters_der, str(nitro_root_pem))
    verify_cose_es384(protected_bstr, payload_bstr, sig, leaf_der)
    print("[OK] Attestation X.509 chain and COSE ES384 signature verified")


    # 1) Attestation checks
    att = load_attestation(att_path)
    att_pub_raw = extract_attested_pubkey(att)
    pcr0 = get_pcr0_hex(att)
    in_pcro = ""

    if not pcr0 or int(pcr0, 16) == 0:
        raise SystemExit("PCR0 is zero")

    if args.pcr0_allow:
        in_pcro = args.pcr0_allow.lower()
    elif (env_kv := read_env_file(outdir / "bundle.env")):
        in_pcro = env_kv.get("PCR0", "").lower()
    else:
        print(f"[WARN] PCR0 allow-list not provided; observed PCR0 = {pcr0 or '<unknown>'}")
        raise SystemExit("PCR0 allow-list is required (pass --pcr0-allow=<ImageSha384>) or set PCR0 in bundle.env")
    if (pcr0).lower() != in_pcro:
        raise SystemExit(f"PCR0 mismatch: got {pcr0}, expected {in_pcro}")
    print(f"[OK] PCR0 matches allow-list: {pcr0}")




    # 2) Exported pubkey matches attested pubkey
    pub_b64 = pub_path.read_text().strip()
    try:
        exported_raw = base64.b64decode(pub_b64, validate=True)
    except Exception:
        raise SystemExit("Invalid base64 in enclave_pubkey.ed25519.b64")
    if exported_raw != att_pub_raw:
        raise SystemExit("Exported Ed25519 pubkey != attested pubkey in user_data")
    print("[OK] Attested pubkey matches exported pubkey")

    # 3) Manifest signature
    manifest, manifest_canon = load_manifest(man_path)
    try:
        ed25519_verify(att_pub_raw, manifest_canon, man_sig_path.read_bytes())
    except InvalidSignature:
        raise SystemExit("Manifest signature verification FAILED")
    print("[OK] Manifest signature valid")

    # 4) Ciphertext signature + manifest file hashes
    ct_name = manifest.get("ciphertext_file")
    if not ct_name:
        raise SystemExit("manifest missing 'ciphertext_file'")
    ct_path = root / ct_name
    ct_sig_path = root / f"{ct_name}.sig"
    if not ct_path.exists() or not ct_sig_path.exists():
        raise SystemExit("ciphertext or its .sig missing")
    try:
        ed25519_verify(att_pub_raw, ct_path.read_bytes(), ct_sig_path.read_bytes())
    except InvalidSignature:
        raise SystemExit("Ciphertext signature verification FAILED")
    print("[OK] Ciphertext signature valid")

    listed_files = verify_manifest_files(manifest, root)
    print(f"[OK] Verified hashes for {len(listed_files)} files from manifest")

    # 5) Receipt signature & bindings
    receipt = json.loads(receipt_path.read_text())
    receipt_canon = canonical_json(receipt)
    try:
        ed25519_verify(att_pub_raw, receipt_canon, receipt_sig_path.read_bytes())
    except InvalidSignature:
        raise SystemExit("Receipt signature verification FAILED")
    print("[OK] Receipt signature valid")

    signer_b64 = receipt.get("signer_pubkey_ed25519_b64", "")
    try:
        signer_raw = base64.b64decode(signer_b64, validate=True)
    except Exception:
        raise SystemExit("Receipt signer_pubkey_ed25519_b64 is not valid base64")

    if signer_raw != att_pub_raw:
        raise SystemExit("Receipt signer_pubkey_ed25519_b64 != attested Ed25519 pubkey")
    print("[OK] Receipt signer matches attested pubkey")

    if receipt.get("manifest_sha256") != sha256_bytes(manifest_canon):
        raise SystemExit("receipt.manifest_sha256 does not match actual manifest hash")
    if receipt.get("ciphertext_sha256") != sha256_file(ct_path):
        raise SystemExit("receipt.ciphertext_sha256 does not match ciphertext hash")
    if receipt.get("attestation_cbor_sha256") != sha256_file(att_path):
        raise SystemExit("receipt.attestation_cbor_sha256 does not match attestation hash")
    print("[OK] Receipt binds manifest, ciphertext, and attestation hashes")

    # Optional strict mode (note: since --dir may contain extra non-artifact files, strict can fail)
    if args.strict:
        declared = set(listed_files + [
            "manifest.v1.json", "manifest.v1.json.sig",
            "receipt.v1.json", "receipt.v1.json.sig",
            "attestation.document.cbor",
            "enclave_pubkey.ed25519.b64",
        ])
        actual = set()
        for p in root.rglob("*"):
            if p.is_file():
                actual.add(str(p.relative_to(root)).replace("\\", "/"))
        extra = sorted(actual - declared)
        if extra:
            raise SystemExit(f"Strict mode: found extra files not declared in manifest: {extra}")
        print("[OK] Strict mode: no extra files detected")

    print("\n[OK] All checks passed")
    print(f"   PCR0: {pcr0 or '<unknown>'}")
    print(f"   Bundle: {bundle_path.name} (sha256={actual_sha})")
    print(f"   Ciphertext: {ct_name}")
    print(f"   Files verified: {len(listed_files)}")


if __name__ == "__main__":
    main()
