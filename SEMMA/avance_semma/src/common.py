import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 42


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clean_code(text):
    # Preserve string literals (URLs, SQL, algorithms); remove comments separately.
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*'
    text = re.sub(pattern, lambda m: "" if m[0].startswith(("/*", "//", "#")) else m[0], text)
    text = re.sub(r"BenchmarkTest\d+", "BenchmarkCase", text)
    text = re.sub(r'@WebServlet\([^)]*\)', '', text)
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip()).strip()


def structural_key(text):
    """Group literal/identifier variants before splitting; not a proof of no semantic overlap."""
    text = clean_code(text)
    text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', ' STR ', text)
    text = re.sub(r"\b\d+\b", " NUM ", text)
    text = re.sub(r"\b(?:param|var|result|value|name|cookie|bar)\d*\b", "LOCAL", text)
    return digest(re.sub(r"\s+", "", text))


def code_tokens(text):
    return re.findall(r"[A-Za-z_][A-Za-z_0-9]*|\d+|==|!=|<=|>=|&&|\|\||[^\s\w]", text.lower())
