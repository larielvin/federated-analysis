import argparse, base64, json, subprocess, time
from pathlib import Path
from typing import Optional, List, Tuple

def run(cmd: List[str], stdin: Optional[bytes] = None) -> bytes:
    p = subprocess.run(cmd, input=stdin, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(
            f"cmd failed: {' '.join(cmd)}\n"
            f"stdout:\n{p.stdout.decode(errors='replace')}\n"
            f"stderr:\n{p.stderr.decode(errors='replace')}"
        )
    return p.stdout

def load_recipients(recips_path: Path) -> List[Tuple[str, str]]:
    doc = json.loads(recips_path.read_text())
    if doc.get("schema") != "recipients-v1":
        raise SystemExit("recipients.json schema must be 'recipients-v1'")
    recips = doc.get("recipients") or []
    if not recips:
        raise SystemExit("recipients.json has no recipients")
    out: List[Tuple[str, str]] = []
    for r in recips:
        rid = r.get("id")
        pk = r.get("age_pubkey")
        if not rid or not pk:
            raise SystemExit("recipient missing id or age_pubkey")
        out.append((rid, pk))
    return out

def main():
    ap = argparse.ArgumentParser(description="Re-encrypt my decrypted Shamir share to all other recipients (age) with timing.")
    ap.add_argument("--recipients", required=True, help="recipients.json (schema: recipients-v1)")
    ap.add_argument("--my-id", required=True, help="Your recipient id (must exist in recipients.json)")
    ap.add_argument("--my-age-key", required=True, help="Path to your age identity (private key)")
    ap.add_argument("--in-share-age", required=True, help="Original share from enclave (e.g., output/shares/share_alice.age)")
    ap.add_argument("--out-dir", default="rewrapped", help="Directory to save rewrapped shares")
    ap.add_argument("--context", default="", help="Optional context tag (e.g., manifest hash)")
    args = ap.parse_args()

    recips = load_recipients(Path(args.recipients))
    ids = [rid for rid, _ in recips]
    if args.my_id not in ids:
        raise SystemExit(f"--my-id '{args.my_id}' not found in recipients.json")

    # -------------------- decrypt my share --------------------
    t0 = time.perf_counter()
    plain = run(["age", "-d", "-i", args.my_age_key, args.in_share_age])
    t1 = time.perf_counter()
    decrypt_time_s = t1 - t0

    try:
        share_json = json.loads(plain.decode("utf-8"))
        x = int(share_json["x"])
        y_b64 = share_json["y_b64"]
        base64.b64decode(y_b64, validate=True)  
    except Exception as e:
        raise SystemExit(f"Invalid share JSON after decrypt: {e}")

    base_envelope = {
        "schema": "share-forward-v1",
        "from": args.my_id,
        "x": x,
        "y_b64": y_b64,
    }
    if args.context:
        base_envelope["context"] = args.context

    outdir = Path(args.out_dir) / ("from_" + args.my_id)
    outdir.mkdir(parents=True, exist_ok=True)

    # -------------------- re-encrypt per recipient --------------------
    per_recipient_times: List[Tuple[str, float]] = []
    total_encrypt_start = time.perf_counter()

    for rid, age_pub in recips:
        env = dict(base_envelope)
        env["to"] = rid
        pt = json.dumps(env, separators=(",", ":"), sort_keys=True).encode("utf-8")

        start = time.perf_counter()
        out_path = outdir / f"to_{rid}.share.age"
        run(["age", "-r", age_pub, "-o", str(out_path)], stdin=pt)
        end = time.perf_counter()

        per_recipient_times.append((rid, end - start))
        print(f"[OK] wrote {out_path}  (encrypt_s={end - start:.3f})")

    total_encrypt_end = time.perf_counter()
    total_reencrypt_time_s = total_encrypt_end - total_encrypt_start

    n = len(per_recipient_times)
    per_vals = [t for _, t in per_recipient_times] or [0.0]
    avg = sum(per_vals) / max(1, n)
    min_v = min(per_vals)
    max_v = max(per_vals)

    print("\n[Timing Summary]")
    print(f"Recipients total              : {n}")
    print(f"Decrypt my share              : {decrypt_time_s:.3f} s")
    print(f"Re-encrypt ALL (wall-clock)   : {total_reencrypt_time_s:.3f} s")
    print(f"Re-encrypt per recipient      : avg {avg:.3f} s | min {min_v:.3f} s | max {max_v:.3f} s")
    if args.context:
        print(f"Context tag                   : {args.context}")

if __name__ == "__main__":
    main()
