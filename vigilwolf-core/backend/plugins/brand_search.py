from difflib import SequenceMatcher
import re

from .fuzzsearchfunc import fuzzy_search_with_score
from .regexsearchfunc import regex_search_with_info


def brand_search(brand: str, filepath: str) -> list:
    if not brand or not isinstance(brand, str):
        return []

    fuzzy_results = fuzzy_search_with_score(brand, filepath)
    regex_results = regex_search_with_info(re.escape(brand), filepath)

    fuzzy_map = {r['domain']: r['score'] for r in fuzzy_results}
    regex_set = {r['domain'] for r in regex_results}

    combined = set()
    combined.update(fuzzy_map.keys())
    combined.update(regex_set)

    results = []
    for domain in combined:
        results.append({
            'domain': domain,
            'fuzzyScore': fuzzy_map.get(domain, 0),
            'regexHit': domain in regex_set,
        })

    results.sort(key=lambda r: (r['fuzzyScore'], r['regexHit']), reverse=True)

    return results
