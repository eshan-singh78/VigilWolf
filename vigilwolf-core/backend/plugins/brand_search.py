from difflib import SequenceMatcher
import re
from typing import Optional, Dict, Any

from .fuzzsearchfunc import fuzzy_search_with_score
from .regexsearchfunc import regex_search_with_info


def brand_search(brand: str, filepath: str, limit: Optional[int] = None, offset: int = 0) -> Dict[str, Any]:
    if not brand or not isinstance(brand, str):
        return {"results": [], "total": 0}

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

    total = len(results)
    if limit is None:
        sliced = results[offset:]
    else:
        sliced = results[offset: offset + limit]

    return {"results": sliced, "total": total}
