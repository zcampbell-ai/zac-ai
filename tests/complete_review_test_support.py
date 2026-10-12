"""Synthetic asset fixture byte repinning only; no backend/authority claim."""

import hashlib
import json


def repin_synthetic_tokenizer(installed, tokenizer):
    root, manifest_path, _, _ = installed
    manifest = json.loads(manifest_path.read_bytes())
    layer = next(row for row in manifest["layers"] if row.get("name") == "tokenizer.json")
    raw = tokenizer.to_str().encode()
    digest = hashlib.sha256(raw).hexdigest()
    (root / "blobs" / ("sha256-" + digest)).write_bytes(raw)
    layer.update(digest="sha256:" + digest, size=len(raw))
    raw_manifest = json.dumps(manifest).encode()
    manifest_path.write_bytes(raw_manifest)
    return root, manifest_path, hashlib.sha256(raw_manifest).hexdigest(), tokenizer
