import os, re, json, sqlite3, hashlib, time, argparse
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    raise SystemExit("Install requests: pip install requests")

# --- SQLite state tracking ---
def init_db(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            file_path TEXT PRIMARY KEY,
            checksum TEXT NOT NULL
        )""")

def uploaded(db_path: str, file_path: str, checksum: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM uploaded_files WHERE file_path=? AND checksum=?",
            (file_path, checksum)
        ).fetchone()
        return bool(row)

def mark_uploaded(db_path: str, file_path: str, checksum: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO uploaded_files (file_path, checksum) VALUES (?, ?)",
            (file_path, checksum)
        )

# --- Metadata extraction (filename / HL7) ---
PATTERNS = [
    re.compile(r"^(?P<p>[A-Za-z0-9]+)_(?P<t>[A-Za-z0-9]+)_(?P<d>\d{8})(?:_.*)?\.[^.]+$"),
    re.compile(r"^(?P<p>[A-Za-z0-9]+)_(?P<t>[A-Za-z0-9]+)_(?P<d>\d{4}-\d{2}-\d{2})(?:_.*)?\.[^.]+$")
]

def metadata_from_filename(path: Path):
    for rx in PATTERNS:
        m = rx.match(path.name)
        if m:
            d = m.group("d")
            if len(d) == 8:
                d = f"{d[:4]}-{d[4:6]}-{d[6:]}"
            return {"patient_id": m.group("p"), "doc_type": m.group("t"), "doc_date": d}
    return {"patient_id": "UNKNOWN", "doc_type": "UNKNOWN", "doc_date": datetime.utcnow().date().isoformat()}

def metadata_from_hl7(text: str):
    pid, doc = "UNKNOWN", "HL7_ADT"
    for line in text.splitlines():
        f = line.split("|")
        if f[0] == "MSH" and len(f) > 8:
            doc = f[8].replace("^", "_")
        elif f[0] == "PID" and len(f) > 3:
            pid = (f[3].split("^")[0]) or "UNKNOWN"
    return {"patient_id": pid, "doc_type": doc, "doc_date": datetime.utcnow().date().isoformat()}

# --- HTTP upload with retry ---
def post_with_retry(url, token, files, data, retries=3):
    headers = {"Authorization": f"Bearer {token}"}
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, headers=headers, files=files, data=data, timeout=30)
            if r.status_code >= 500 and attempt < retries:
                raise RuntimeError("server error")
            r.raise_for_status()
            return
        except Exception:
            if attempt == retries:
                raise
            time.sleep(2 ** (attempt - 1))

# --- Per-file processing ---
def process_file(path: Path, api_url: str, token: str, db_path: str):
    try:
        raw = path.read_bytes()
    except Exception as e:
        print(f"[READ-ERROR] {path}: {e}")
        return
    checksum = hashlib.sha256(raw).hexdigest()
    if uploaded(db_path, str(path), checksum):
        print(f"[SKIP] {path.name}")
        return
    meta = metadata_from_hl7(raw.decode(errors="ignore")) if path.suffix.lower() == ".hl7" else metadata_from_filename(path)
    meta.update({"filename": path.name, "checksum": checksum, "ingested_at": datetime.utcnow().isoformat()})
    try:
        post_with_retry(api_url, token,
                        {"file": (path.name, raw, "application/octet-stream")},
                        {"metadata": json.dumps(meta)})
        mark_uploaded(db_path, str(path), checksum)
        print(f"[OK] {path.name} patient={meta['patient_id']} type={meta['doc_type']}")
    except Exception as e:
        print(f"[UPLOAD-ERROR] {path.name}: {e}")

# --- Walk directory and upload ---
def main():
    p = argparse.ArgumentParser(description="QECS backload")
    p.add_argument("--source", required=True)
    p.add_argument("--api-url")
    p.add_argument("--token")
    p.add_argument("--db", default="backload_state.db")
    a = p.parse_args()

    api_url = a.api_url or os.environ.get("QECS_API_URL")
    token = a.token or os.environ.get("QECS_API_TOKEN")
    if not api_url or not token:
        raise SystemExit("Missing API URL or token.")
    src = Path(a.source)
    if not src.is_dir():
        raise SystemExit("Source not found.")

    init_db(a.db)
    count = 0
    for f in src.rglob("*"):
        if f.is_file() and not f.name.startswith("."):
            process_file(f, api_url, token, a.db)
            count += 1
    print(f"[DONE] {count} files processed.")

if __name__ == "__main__":
    main()