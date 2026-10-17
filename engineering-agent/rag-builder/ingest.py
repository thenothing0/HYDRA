"""RAG Builder — Ingest public writeup sources into searchable corpus."""

import argparse
import json
import logging
from pathlib import Path

logger = logging.getLogger("hydra.rag")


SOURCES = {
    "portswigger": "https://portswigger.net/web-security",
    "hacktricks": "https://book.hacktricks.xyz/",
    "payloadsallthethings": "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "pentesterland": "https://pentester.land/list-of-bug-bounty-writeups.html",
}


def ingest_from_directory(source_dir: str, output_dir: str) -> int:
    """Ingest writeups from a local directory."""
    from mcp_writeup_server.indexer import index_directory  # noqa
    return index_directory(source_dir, output_dir)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Ingest writeup sources")
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="./data/writeup_corpus/")
    args = parser.parse_args()
    count = ingest_from_directory(args.source, args.output)
    print(f"Ingested {count} writeups")
