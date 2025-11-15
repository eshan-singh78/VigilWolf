import subprocess
from datetime import datetime
from func.fuzzsearchfunc import fuzzy_search
from func.regexsearchfunc import regex_search

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")


subprocess.run(["bash", "./nrd-fix-portable.sh"], capture_output=True, text=True)
print("Download Successful")

search_pattern = input("Enter the search string: ")
nrd_file = "nrd-7days-free.txt"
output_file = f"{search_pattern}_search_results_{timestamp}.txt"


regex_results = regex_search(search_pattern, nrd_file, return_list=True)
fuzzy_results = fuzzy_search(search_pattern, nrd_file, maxchange=1, return_list=True)

with open(output_file, "w", encoding="utf-8") as f:
    f.write("Regex Search Results:\n")
    f.write("\n".join(regex_results))
    f.write("\n\nFuzzy Search Results:\n")
    f.write("\n".join(fuzzy_results))

print(f"Search results written to {output_file}")
