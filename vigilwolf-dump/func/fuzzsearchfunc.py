from fuzzysearch import find_near_matches

def fuzzy_search(pattern, filepath, maxchange=1, return_list=False):
    results = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                matches = find_near_matches(pattern, line, max_l_dist=maxchange)
                if matches:
                    if return_list:
                        results.append(line)
                    else:
                        print(line)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    if return_list:
        return results
