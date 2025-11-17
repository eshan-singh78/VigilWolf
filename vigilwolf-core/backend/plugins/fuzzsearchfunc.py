import re


def fuzzy_search_with_score(pattern: str, filepath: str) -> list:
    try:
        from difflib import SequenceMatcher
    except ImportError:
        return []

    pattern_norm = re.sub(r'[^a-z0-9]', '', pattern.lower())
    results = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                label = line.lower().split('.')[0]
                label_norm = re.sub(r'[^a-z0-9]', '', label)

                try:
                    score = int(SequenceMatcher(None, pattern_norm, label_norm).ratio() * 100)
                    if score > 0:
                        results.append({'domain': line, 'score': score})
                except Exception:
                    pass

    except FileNotFoundError:
        pass

    results.sort(key=lambda x: x['score'], reverse=True)
    return results


def fuzzy_search(pattern, filepath, maxchange=1, return_list=False):
    results = []
    try:
        from fuzzysearch import find_near_matches
        has_fuzzysearch = True
    except ImportError:
        has_fuzzysearch = False

    if not has_fuzzysearch:
        return fuzzy_search_with_score(pattern, filepath)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    matches = find_near_matches(pattern, line, max_l_dist=maxchange)
                    if matches:
                        if return_list:
                            results.append(line)
                        else:
                            print(line)
                except Exception:
                    pass
    except FileNotFoundError:
        if not return_list:
            print(f'File not found: {filepath}')

    if return_list:
        return results
    return None
