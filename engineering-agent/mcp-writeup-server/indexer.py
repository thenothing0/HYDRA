"""
Writeup Corpus Indexer — Build searchable index from writeup sources.

Usage:
  python mcp-writeup-server/indexer.py --source ./writeups/ --output ./data/writeup_corpus/
"""

import argparse
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("hydra.writeup.indexer")


def parse_markdown_writeup(content: str, filename: str = "") -> Dict:
    """Parse a markdown writeup into structured data."""
    title = ""
    for line in content.split("\n"):
        if line.startswith("# "):
            title = line[2:].strip()
            break
    if not title:
        title = Path(filename).stem.replace("-", " ").replace("_", " ").title()

    category = "misc"
    for cat in ["ssrf", "xss", "idor", "sqli", "rce", "lfi", "oauth",
                "cors", "ssti", "xxe", "csrf", "open-redirect"]:
        if cat in content.lower() or cat in filename.lower():
            category = cat
            break

    severity = "medium"
    for sev in ["critical", "high", "medium", "low"]:
        if sev in content.lower():
            severity = sev
            break

    return {
        "title": title, "category": category, "severity": severity,
        "content": content[:5000], "filename": filename,
        "word_count": len(content.split()),
    }


def index_directory(source_dir: str, output_dir: str) -> int:
    """Index all writeups from a directory."""
    source = Path(source_dir)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    writeups: List[Dict] = []
    for ext in ["*.md", "*.txt", "*.json"]:
        for f in source.rglob(ext):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                if f.suffix == ".json":
                    data = json.loads(content)
                    if isinstance(data, dict):
                        writeups.append(data)
                    elif isinstance(data, list):
                        writeups.extend(data)
                else:
                    writeups.append(parse_markdown_writeup(content, f.name))
            except Exception as e:
                logger.warning(f"Failed to parse {f}: {e}")

    # Save corpus
    corpus_path = output / "corpus.json"
    corpus_path.write_text(json.dumps(writeups, indent=2), encoding="utf-8")
    logger.info(f"Indexed {len(writeups)} writeups → {corpus_path}")
    return len(writeups)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Index writeup corpus")
    parser.add_argument("--source", required=True, help="Source directory")
    parser.add_argument("--output", default="./data/writeup_corpus/")
    args = parser.parse_args()
    count = index_directory(args.source, args.output)
    print(f"Done: {count} writeups indexed")
