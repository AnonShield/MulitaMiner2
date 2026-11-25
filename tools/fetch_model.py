"""Download the pinned v7 GGUF + Modelfile from Hugging Face into a directory."""
import hashlib
import sys
import urllib.request
from pathlib import Path

REPO = "Inari18/mulita-extractor-qwen2.5-1.5b"
REVISION = "69fcdf70e4c6f28cb103719c43eeed7af12da6cd"
GGUF = "mulita-extractor-v7.gguf"
GGUF_SHA256 = "76ff8228b119c460523dbb018e81e205d3c2dea7a29564a94f831cc50ae4957c"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(name: str, dest: Path) -> None:
    url = f"https://huggingface.co/{REPO}/resolve/{REVISION}/{name}"
    print(f"downloading {url}", flush=True)
    urllib.request.urlretrieve(url, dest)


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    gguf = out / GGUF
    if not (gguf.is_file() and sha256(gguf) == GGUF_SHA256):
        fetch(GGUF, gguf)
        if (got := sha256(gguf)) != GGUF_SHA256:
            gguf.unlink()
            sys.exit(f"{GGUF}: sha256 {got} does not match the pinned {GGUF_SHA256}")
    # The Modelfile is tiny and pinned by REVISION; always refresh it.
    fetch("Modelfile", out / "Modelfile")
    print("model ready", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/model"))
