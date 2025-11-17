import os


def find_latest_nrd_file() -> str:
    candidates = []
    backend_dir = os.path.dirname(__file__)

    nrdtemp_base = os.path.join(backend_dir, '..', 'nrdtemp')
    if os.path.isdir(nrdtemp_base):
        for entry in os.listdir(nrdtemp_base):
            sub = os.path.join(nrdtemp_base, entry)
            candidate = os.path.join(sub, 'domain-names.txt')
            if os.path.isfile(candidate):
                candidates.append(candidate)

    nrd_dump = os.path.join(backend_dir, '..', 'nrd-file-dump')
    if os.path.isdir(nrd_dump):
        for entry in os.listdir(nrd_dump):
            candidate = os.path.join(nrd_dump, entry)
            if os.path.isfile(candidate) and entry.lower().endswith('.txt'):
                candidates.append(candidate)

    latest_path = ''
    latest_mtime = 0
    for c in candidates:
        try:
            m = os.path.getmtime(c)
            if m > latest_mtime:
                latest_mtime = m
                latest_path = c
        except Exception:
            continue

    return latest_path


def read_domains_from_file(filepath: str) -> list:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines
    except Exception:
        return []


def read_domains_from_file_slice(filepath: str, offset: int = 0, limit: int | None = None) -> tuple:
    results = []
    total = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if total >= offset and (limit is None or len(results) < limit):
                    results.append(line)
                total += 1
        return results, total
    except Exception:
        return [], 0


def get_latest_nrd_domains(limit: int | None = None, offset: int = 0) -> tuple:
    path = find_latest_nrd_file()
    if not path:
        return ('', [], 0)
    filename = os.path.basename(path)
    if limit is None and offset == 0:
        domains = read_domains_from_file(path)
        return (filename, domains, len(domains))
    else:
        domains_slice, total = read_domains_from_file_slice(path, offset=offset, limit=limit)
        return (filename, domains_slice, total)
