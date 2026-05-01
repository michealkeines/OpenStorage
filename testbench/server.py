"""
OpenStorage test backend — a tiny object-storage server with a UI.

Purpose
-------
Acts as a remote chunk backend for the OpenStorage engine via the
HTTP-backend plugin. It exposes:

- PUT/GET/HEAD/DELETE/LIST for opaque encrypted objects (the engine's
  ciphertext shards and a few vault-metadata blobs).
- A small HTML page with a "comments" box that operators can use to
  jot notes about the backend; comments live in the same on-disk dir
  so they round-trip through the same code path.

The on-disk layout is:

    <data_dir>/
        objects/<handle>            ← binary objects (one per ciphertext blob)
        comments.json               ← human comments

Every object has a random 16-byte handle (UUIDv7). The plugin sends a
plaintext-but-padded handle to identify the object.

Streaming is the whole point: the API streams uploads to disk in
chunks, and serves downloads from disk by streaming. That is how a
1 GB upload through the engine reaches the backend without anyone
holding it in memory.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Iterator, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
import uvicorn

LOG = logging.getLogger("openstorage-testbench")
DATA_DIR = Path(os.environ.get("TESTBENCH_DATA_DIR", "./testbench-data")).resolve()
OBJECTS_DIR = DATA_DIR / "objects"
COMMENTS_FILE = DATA_DIR / "comments.json"
INDEX_HTML = Path(__file__).parent / "static" / "index.html"

OBJECTS_DIR.mkdir(parents=True, exist_ok=True)
if not COMMENTS_FILE.exists():
    COMMENTS_FILE.write_text("[]")

app = FastAPI(title="OpenStorage testbench")


# ─── helpers ────────────────────────────────────────────────────────────────
def _handle_path(handle: str) -> Path:
    if not handle or "/" in handle or ".." in handle or len(handle) > 64:
        raise HTTPException(400, f"invalid handle: {handle!r}")
    return OBJECTS_DIR / handle


def _stream_iter(path: Path, chunk: int = 1 << 20) -> Iterator[bytes]:
    with path.open("rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            yield buf


def _compute_etag(path: Path) -> str:
    h = hashlib.blake2b(digest_size=32)
    with path.open("rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _read_comments() -> list[dict]:
    try:
        return json.loads(COMMENTS_FILE.read_text())
    except Exception:
        return []


def _write_comments(comments: list[dict]) -> None:
    tmp = COMMENTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(comments, indent=2))
    tmp.replace(COMMENTS_FILE)


# ─── object endpoints ──────────────────────────────────────────────────────
class PutResp(BaseModel):
    handle: str
    size: int
    etag: str
    stored_at: float


@app.post("/v1/objects", response_model=PutResp)
async def put_object(request: Request, replaces: Optional[str] = None) -> PutResp:
    """Stream the raw request body to a fresh handle. Optional ?replaces=H
    means: after writing the new handle, attempt to delete H."""
    handle = uuid.uuid4().hex
    path = _handle_path(handle)
    size = 0
    h = hashlib.blake2b(digest_size=32)
    with path.open("wb") as f:
        async for chunk in request.stream():
            if not chunk:
                continue
            f.write(chunk)
            h.update(chunk)
            size += len(chunk)
    etag = h.hexdigest()
    stored_at = time.time()

    if replaces:
        try:
            _handle_path(replaces).unlink(missing_ok=True)
        except Exception as exc:
            LOG.warning("failed to delete %s on replace: %s", replaces, exc)

    LOG.info("PUT %s size=%d etag=%s", handle, size, etag[:16])
    return PutResp(handle=handle, size=size, etag=etag, stored_at=stored_at)


@app.get("/v1/objects/{handle}")
def get_object(handle: str, request: Request):
    path = _handle_path(handle)
    if not path.exists():
        raise HTTPException(404, "not found")
    size = path.stat().st_size

    range_header = request.headers.get("range")
    if range_header and range_header.startswith("bytes="):
        # very small Range parser: bytes=START-END
        spec = range_header[len("bytes="):].split(",", 1)[0].strip()
        try:
            start_s, end_s = spec.split("-", 1)
            start = int(start_s) if start_s else 0
            end = int(end_s) if end_s else size - 1
        except Exception:
            raise HTTPException(416, "invalid range")
        if start > end or end >= size:
            raise HTTPException(416, "range not satisfiable")
        length = end - start + 1

        def gen():
            with path.open("rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    n = min(1 << 20, remaining)
                    buf = f.read(n)
                    if not buf:
                        break
                    remaining -= len(buf)
                    yield buf

        headers = {
            "Content-Length": str(length),
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Accept-Ranges": "bytes",
        }
        return StreamingResponse(gen(), status_code=206, media_type="application/octet-stream",
                                 headers=headers)

    return StreamingResponse(_stream_iter(path), media_type="application/octet-stream",
                             headers={"Content-Length": str(size), "Accept-Ranges": "bytes"})


@app.head("/v1/objects/{handle}")
def head_object(handle: str):
    path = _handle_path(handle)
    if not path.exists():
        raise HTTPException(404, "not found")
    st = path.stat()
    etag = _compute_etag(path)
    headers = {
        "Content-Length": str(st.st_size),
        "X-Stored-At": str(int(st.st_mtime)),
        "ETag": etag,
        "Accept-Ranges": "bytes",
    }
    return Response(status_code=200, headers=headers)


@app.delete("/v1/objects/{handle}")
def delete_object(handle: str):
    path = _handle_path(handle)
    if not path.exists():
        return JSONResponse({"outcome": "not_found"}, status_code=404)
    path.unlink()
    return {"outcome": "removed"}


@app.get("/v1/objects")
def list_objects(prefix: str = "", limit: int = 1000):
    items = []
    for p in sorted(OBJECTS_DIR.iterdir()):
        if not p.name.startswith(prefix):
            continue
        st = p.stat()
        items.append({"handle": p.name, "size": st.st_size, "stored_at": int(st.st_mtime)})
        if len(items) >= limit:
            break
    return {"objects": items}


@app.get("/v1/health")
def health():
    used = sum(p.stat().st_size for p in OBJECTS_DIR.iterdir() if p.is_file())
    return {
        "state": "healthy",
        "data_dir": str(DATA_DIR),
        "object_count": sum(1 for _ in OBJECTS_DIR.iterdir()),
        "used_bytes": used,
    }


# ─── comments ──────────────────────────────────────────────────────────────
class CommentIn(BaseModel):
    author: Optional[str] = None
    body: str


@app.post("/v1/comments")
def post_comment(c: CommentIn):
    comments = _read_comments()
    comments.append({
        "id": uuid.uuid4().hex,
        "author": c.author or "anonymous",
        "body": c.body,
        "at": int(time.time()),
    })
    _write_comments(comments)
    return {"ok": True, "count": len(comments)}


@app.get("/v1/comments")
def list_comments():
    return {"comments": list(reversed(_read_comments()))}


@app.delete("/v1/comments/{cid}")
def delete_comment(cid: str):
    comments = _read_comments()
    new = [c for c in comments if c["id"] != cid]
    if len(new) == len(comments):
        raise HTTPException(404, "comment not found")
    _write_comments(new)
    return {"ok": True}


# ─── UI ────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index():
    if INDEX_HTML.exists():
        return HTMLResponse(INDEX_HTML.read_text())
    return HTMLResponse("<h1>OpenStorage testbench</h1><p>UI not bundled.</p>")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    bind = os.environ.get("TESTBENCH_BIND", "127.0.0.1:9090")
    host, port = bind.rsplit(":", 1)
    LOG.info("openstorage testbench starting on %s data_dir=%s", bind, DATA_DIR)
    uvicorn.run(app, host=host, port=int(port), log_level="info")


if __name__ == "__main__":
    main()
