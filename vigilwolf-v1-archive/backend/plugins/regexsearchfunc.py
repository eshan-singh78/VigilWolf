import re


def regex_search_with_info(pattern: str, filepath: str) -> list:
    results = []
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if compiled.search(line):
                    match = compiled.search(line)
                    matched_text = match.group(0) if match else ''
                    results.append({'domain': line, 'matched_text': matched_text})
    except FileNotFoundError:
        pass

    results.sort(key=lambda x: x['domain'])
    return results


def regex_search(pattern, filepath, return_list=False):
    results = []
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        if not return_list:
            print(f'Invalid regex pattern: {pattern}')
        return [] if return_list else None

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if compiled.search(line):
                    if return_list:
                        results.append(line)
                    else:
                        print(line)
    except FileNotFoundError:
        if not return_list:
            print('Nothing found')

    if return_list:
        return results
    return None
