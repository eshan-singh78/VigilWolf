import os


def find_latest_nrd_file() -> str:
    import logging
    logger = logging.getLogger(__name__)
    
    candidates = []
    
    # Get the backend directory (where the script runs from)
    # In Docker, this will be /app
    backend_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    logger.info(f"Searching for NRD files in backend_dir: {backend_dir}")
    
    # ONLY check nrd-file-dump directory for timestamped files
    # This is where nrd-fix-portable.sh saves the final timestamped files
    nrd_dump = os.path.join(backend_dir, 'nrd-file-dump')
    if os.path.isdir(nrd_dump):
        logger.info(f"Checking nrd-file-dump directory: {nrd_dump}")
        for entry in os.listdir(nrd_dump):
            # Only consider files that match the pattern: nrd-YYYY-MM-DD_HH-MM-SS.txt
            if entry.startswith('nrd-') and entry.endswith('.txt') and '_' in entry:
                candidate = os.path.join(nrd_dump, entry)
                if os.path.isfile(candidate):
                    candidates.append(candidate)
                    logger.info(f"Found timestamped NRD file: {entry}")
    else:
        logger.warning(f"nrd-file-dump directory does not exist: {nrd_dump}")
    
    if not candidates:
        logger.warning("No timestamped NRD files found in nrd-file-dump")
        return ''
    
    # Find the most recently modified file (should be the latest dump)
    latest_path = ''
    latest_mtime = 0
    for c in candidates:
        try:
            m = os.path.getmtime(c)
            logger.info(f"Candidate: {os.path.basename(c)}, mtime: {m}")
            if m > latest_mtime:
                latest_mtime = m
                latest_path = c
        except Exception as e:
            logger.warning(f"Error checking {c}: {e}")
            continue
    
    logger.info(f"Selected latest NRD file: {os.path.basename(latest_path) if latest_path else 'None'}")
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
