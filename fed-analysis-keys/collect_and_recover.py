import argparse, base64, json, subprocess, time, hashlib
from pathlib import Path
from typing import Optional, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Prime field (must match the one used when splitting)
P = (1 << 521) - 1

def run(cmd: List[str], stdin: Optional[bytes] = None) -> bytes:
    p = subprocess.run(cmd, input=stdin, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(
            f"cmd failed: {' '.join(cmd)}\n"
            f"stdout:\n{p.stdout.decode(errors='replace')}\n"
            f"stderr:\n{p.stderr.decode(errors='replace')}"
        )
    return p.stdout

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def lagrange_f0(shares: List[Tuple[int, int]]) -> int:
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj % P)) % P
            den = (den * (xi - xj)) % P
        inv = pow(den % P, -1, P)
        s = (s + yi * num * inv) % P
    return s

def recover_dek_bytes(shares: List[Tuple[int, int]]) -> bytes:
    secret = lagrange_f0(shares)
    if secret.bit_length() > 256:
        raise SystemExit("Recovered secret > 256 bits — wrong shares?")
    return secret.to_bytes(32, "big")

def load_manifest(man_path: Path):
    m = json.loads(man_path.read_text())
    ct_name = m.get("ciphertext_file")
    if not ct_name:
        raise SystemExit("manifest missing ciphertext_file")
    cipher = m.get("cipher") or {}
    nonce = base64.b64decode(cipher.get("nonce_b64", ""), validate=True)
    if len(nonce) != 12:
        raise SystemExit("nonce must be 12 bytes")
    aad = (cipher.get("aad") or "").encode()
    return m, nonce, aad, ct_name

def decode_forwarded(json_bytes: bytes, expect_to: str):
    obj = json.loads(json_bytes.decode("utf-8"))
    if obj.get("schema") != "share-forward-v1":
        raise SystemExit("bad schema")
    if obj.get("to") != expect_to:
        raise SystemExit("forwarded share not addressed to '{}'".format(expect_to))
    sender = obj.get("from") or ""
    x = int(obj["x"])
    y = base64.b64decode(obj["y_b64"], validate=True)
    return sender, x, y  # <- keep raw bytes for share-size measurement

def main():
    ap = argparse.ArgumentParser(description="Collect rewrapped shares (to me) and decrypt fhe_keys.enc")
    ap.add_argument("--me", required=True, help="My recipient id (e.g., 'alice')")
    ap.add_argument("--my-age-key", required=True, help="My age identity (private key)")
    ap.add_argument("--in-dir", default="rewrapped", help="Directory containing */to_<me>.share.age files")
    ap.add_argument("--own-share-age", default="", help="(Optional) my original age share from enclave to include")
    ap.add_argument("--own-share-json", default="", help="(Optional) my share as decrypted JSON instead")
    ap.add_argument("--manifest", default="output/manifest.v1.json")
    ap.add_argument("--enc", default="", help="Override ciphertext path (else from manifest)")
    ap.add_argument("--out", default="output/fhe_keys.recovered.tar.gz")
    ap.add_argument("--receipt", default="output/receipt.v1.json", help="Used to check threshold t (optional)")
    args = ap.parse_args()

    summary = {
        "stage": "collect_and_recover",
        "share_collection": {
            "candidates_found": 0,
            "accepted_shares": 0,
            "duplicates_ignored": 0,
            "senders": [],
            "x_indices": [],
            "own_share_added": False,
            "one_share_y_bytes": None,
        },
        "threshold": {
            "threshold_t_claimed": 0,
            "threshold_met": None,
            "threshold_gap": None,
        },
        "dek_reconstruction": {
            "field_bits": 521,
            "num_shares_used": 0,
            "secret_bits": None,
            "dek_derivation_ok": None,
            "dek_size_bytes": None,
        },
        "ciphertext": {
            "ciphertext_file": None,
            "ciphertext_size_bytes": None,
            "nonce_len_bytes": None,
            "aad_len_bytes": None,
            "aead_decrypt_ok": None,
        },
        "recovered_archive": {
            "recovered_path": None,
            "recovered_size_bytes": None,
            "recovered_sha256": None,
        },
        "timing": {
            "t_decrypt_shares_s": None,
            "t_reconstruct_dek_s": None,
            "t_aesgcm_decrypt_s": None,
            "throughput_mb_s": None,
        },
        "warnings": [],
    }

    # 1) Decrypt incoming rewrapped shares that target me
    in_dir = Path(args.in_dir)
    files = list(in_dir.rglob(f"to_{args.me}.share.age"))
    summary["share_collection"]["candidates_found"] = len(files)

    if not files:
        raise SystemExit(f"No rewrapped shares found for {args.me} under {in_dir}")

    shares: List[Tuple[int, int]] = []
    seen_x = set()
    senders_set = set()
    first_share_y_len = None

    t0_dec = time.time()
    for f in files:
        pt = run(["age", "-d", "-i", args.my_age_key, str(f)])
        sender, x, y_bytes = decode_forwarded(pt, args.me)
        senders_set.add(sender)
        if x in seen_x:
            msg = f"duplicate x={x} (sender={sender}) — ignoring"
            print("[WARN]", msg)
            summary["share_collection"]["duplicates_ignored"] += 1
            summary["warnings"].append(msg)
            continue
        seen_x.add(x)
        # record size of the first accepted share's y payload (bytes)
        if first_share_y_len is None:
            first_share_y_len = len(y_bytes)
        shares.append((x, int.from_bytes(y_bytes, "big")))
        print(f"[OK] accepted share x={x} from {sender}")
    t1_dec = time.time()
    summary["timing"]["t_decrypt_shares_s"] = round(t1_dec - t0_dec, 6)
    summary["share_collection"]["one_share_y_bytes"] = first_share_y_len

    # 2) Add my own share (optional)
    if args.own_share_json:
        obj = json.loads(Path(args.own_share_json).read_text())
        x = int(obj["x"])
        y = int.from_bytes(base64.b64decode(obj["y_b64"], validate=True), "big")
        if x not in seen_x:
            shares.append((x, y))
            seen_x.add(x)
            summary["share_collection"]["own_share_added"] = True
            print(f"[OK] added my own share (json) x={x}")
    elif args.own_share_age:
        pt = run(["age", "-d", "-i", args.my_age_key, args.own_share_age])
        obj = json.loads(pt.decode("utf-8"))
        x = int(obj["x"])
        y = int.from_bytes(base64.b64decode(obj["y_b64"], validate=True), "big")
        if x not in seen_x:
            shares.append((x, y))
            seen_x.add(x)
            summary["share_collection"]["own_share_added"] = True
            print(f"[OK] added my own share (age) x={x}")

    summary["share_collection"]["accepted_shares"] = len(shares)
    summary["share_collection"]["senders"] = sorted(senders_set)
    summary["share_collection"]["x_indices"] = sorted(seen_x)

    # 3) Check threshold (optional)
    try:
        rec = json.loads(Path(args.receipt).read_text())
        t = int((rec.get("threshold") or {}).get("t") or 0)
        summary["threshold"]["threshold_t_claimed"] = t
        summary["threshold"]["threshold_met"] = (len(shares) >= t) if t else None
        summary["threshold"]["threshold_gap"] = (max(0, t - len(shares)) if t else None)
        if t and len(shares) < t:
            raise SystemExit(f"Need at least t={t} shares, have {len(shares)}")
    except FileNotFoundError:
        pass

    if len(shares) < 2:
        raise SystemExit("Need at least 2 shares to reconstruct")

    # 4) Reconstruct DEK and decrypt ciphertext
    t0_rec = time.time()
    dek = recover_dek_bytes(shares)
    t1_rec = time.time()
    summary["timing"]["t_reconstruct_dek_s"] = round(t1_rec - t0_rec, 6)
    summary["dek_reconstruction"]["num_shares_used"] = len(shares)
    summary["dek_reconstruction"]["dek_derivation_ok"] = True
    summary["dek_reconstruction"]["secret_bits"] = int.from_bytes(dek, "big").bit_length()
    # DEK size in bytes (should be 32)
    summary["dek_reconstruction"]["dek_size_bytes"] = len(dek)

    manifest, nonce, aad, ct_name = load_manifest(Path(args.manifest))
    enc_path = Path(args.enc) if args.enc else Path(args.manifest).parent / ct_name
    summary["ciphertext"]["ciphertext_file"] = ct_name
    summary["ciphertext"]["ciphertext_size_bytes"] = enc_path.stat().st_size
    summary["ciphertext"]["nonce_len_bytes"] = len(nonce)
    summary["ciphertext"]["aad_len_bytes"] = len(aad)

    ct = enc_path.read_bytes()
    t0_dec_aead = time.time()
    pt = AESGCM(dek).decrypt(nonce, ct, aad)
    t1_dec_aead = time.time()
    summary["timing"]["t_aesgcm_decrypt_s"] = round(t1_dec_aead - t0_dec_aead, 6)
    if summary["timing"]["t_aesgcm_decrypt_s"] > 0:
        summary["timing"]["throughput_mb_s"] = round(
            (len(ct) / (1024 * 1024)) / summary["timing"]["t_aesgcm_decrypt_s"], 3
        )
    summary["ciphertext"]["aead_decrypt_ok"] = True

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pt)
    print(f"[OK] decrypted → {out_path}  (size: {out_path.stat().st_size} bytes)")

    summary["recovered_archive"]["recovered_path"] = str(out_path)
    summary["recovered_archive"]["recovered_size_bytes"] = out_path.stat().st_size
    try:
        summary["recovered_archive"]["recovered_sha256"] = sha256_file(out_path)
    except Exception:
        summary["recovered_archive"]["recovered_sha256"] = None

    print("\n[Summary]")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
