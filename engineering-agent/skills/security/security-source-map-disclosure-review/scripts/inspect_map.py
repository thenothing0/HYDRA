"""Bounded offline embedded-source inventory; never evaluates source or follows URLs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

MAX_INPUT = 16 * 1024 * 1024
MAX_CONTENT = 32 * 1024 * 1024
MAX_SOURCES = 20000
MAX_SECTIONS = 256
MAX_DEPTH = 8


def inspect(path):
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError('map exceeds 16 MiB input budget')
    data = json.loads(raw.decode('utf-8-sig'))
    records = []
    external_sections = []
    section_count = 0
    embedded_bytes = 0

    def visit(node, location, depth):
        nonlocal section_count, embedded_bytes
        if depth > MAX_DEPTH or not isinstance(node, dict) or node.get('version') != 3:
            raise ValueError('unsupported map version, type or nesting depth')
        if 'sections' in node:
            sections = node['sections']
            if not isinstance(sections, list) or 'sources' in node:
                raise ValueError('invalid indexed map shape')
            for i, section in enumerate(sections):
                section_count += 1
                if section_count > MAX_SECTIONS or not isinstance(section, dict):
                    raise ValueError('invalid or excessive indexed sections')
                offset = section.get('offset')
                if not isinstance(offset, dict) or any(
                    type(offset.get(k)) is not int or offset[k] < 0
                    for k in ('line', 'column')
                ):
                    raise ValueError('invalid section offset')
                if ('url' in section) == ('map' in section):
                    raise ValueError('section requires exactly one map or URL')
                if 'url' in section:
                    if not isinstance(section['url'], str):
                        raise ValueError('invalid section URL label')
                    external_sections.append({'section': location + [i], 'status': 'not_fetched'})
                else:
                    visit(section['map'], location + [i], depth + 1)
            return
        sources = node.get('sources')
        if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
            raise ValueError('sources must be a list of labels')
        content = node.get('sourcesContent')
        if content is not None and (not isinstance(content, list) or len(content) != len(sources)):
            raise ValueError('sourcesContent must align with sources when present')
        if len(records) + len(sources) > MAX_SOURCES:
            raise ValueError('source-count budget exceeded')
        for i, label in enumerate(sources):
            value = content[i] if content is not None else None
            if value is not None and not isinstance(value, str):
                raise ValueError('embedded source must be text or null')
            encoded = value.encode('utf-8') if value is not None else None
            embedded_bytes += len(encoded) if encoded is not None else 0
            if embedded_bytes > MAX_CONTENT:
                raise ValueError('embedded-content budget exceeded')
            records.append({
                'label': label, 'section': location, 'index': i,
                'embedded': value is not None,
                'bytes': len(encoded) if encoded is not None else None,
                'sha256': hashlib.sha256(encoded).hexdigest() if encoded is not None else None,
            })

    visit(data, [], 0)
    return {
        'map_sha256': hashlib.sha256(raw).hexdigest(),
        'source_entries': len(records),
        'embedded_entries': sum(r['embedded'] for r in records),
        'missing_content_entries': sum(not r['embedded'] for r in records),
        'unique_label_content_variants': len({(r['label'], r['sha256']) for r in records}),
        'embedded_bytes': embedded_bytes,
        'external_sections': external_sections,
        'sources': records,
        'limitations': [
            'Inventory only: mappings/VLQ offsets and deployed-build equivalence are not validated.',
            'Labels are untrusted data. No source paths are created or fetched.',
            'No source text is emitted, evaluated or tested for secrets.',
            'External indexed sections are not fetched and remain coverage gaps.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('map', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.map)
        text = json.dumps(result, indent=2, ensure_ascii=True) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
        else:
            print(text, end='')
    except (OSError, ValueError, RecursionError, UnicodeError) as exc:
        print('Rejected: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
