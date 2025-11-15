import re

def regex_search(pattern, filepath, return_list=False):
    results = []
    compiled = re.compile(pattern, re.IGNORECASE)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if compiled.search(line):
                    if return_list:
                        results.append(line)
                    else:
                        print(line)
    except FileNotFoundError:
        print("Nothing found")
    if return_list:
        return results
