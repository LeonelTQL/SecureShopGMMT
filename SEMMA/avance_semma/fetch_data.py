"""Download the pinned public source; no target application is launched."""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

REVISION = '10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17'
RAW = Path(__file__).resolve().parent / 'data/raw'


def download(url, destination):
    with urlopen(Request(url, headers={'User-Agent': 'SEMMA-academic-advance'}), timeout=120) as response:
        destination.write_bytes(response.read())


if __name__ == '__main__':
    RAW.mkdir(parents=True, exist_ok=True)
    archive = RAW / 'benchmark_java.zip'
    if not archive.exists():
        download(f'https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/zip/{REVISION}', archive)
    manifest = RAW / 'source_manifest.json'
    if manifest.exists():
        expected = json.loads(manifest.read_text(encoding='utf-8'))['archive_sha256']
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise ValueError('Archive checksum mismatch; preserve and inspect the download before proceeding.')
    commit = RAW / 'benchmark_commit.json'
    if not commit.exists():
        download(f'https://api.github.com/repos/OWASP-Benchmark/BenchmarkJava/commits/{REVISION}', commit)
    print(f'Public source available at {archive}')
