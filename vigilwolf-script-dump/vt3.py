import requests

url2 = "https://www.virustotal.com/ui/urls/e2e43c50ed187b3adc68bf141c064c29dffc98e1b0647e2daaf20ca5862aeeea/network_location"

headers2 = {
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "sec-ch-ua-platform": "\"Android\"",
    "Referer": "https://www.virustotal.com/",
    "sec-ch-ua": "\"Chromium\";v=\"142\", \"Brave\";v=\"142\", \"Not_A Brand\";v=\"99\"",
    "X-VT-Anti-Abuse-Header": "MTI2NDAyNTI2NjctWkc5dWRDQmlaU0JsZG1scy0xNzYzMzEwNjgyLjMwMg==",
    "sec-ch-ua-mobile": "?1",
    "X-Tool": "vt-ui-main",
    "x-app-version": "v1x496x0",
    "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
    "accept": "application/json",
    "Content-Type": "application/json"
}

# --------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------
response2 = requests.get(url2, headers=headers2)
data = response2.json().get("data", {})
attr = data.get("attributes", {})

# --------------------------------------------------------------------
# Extract fields
# --------------------------------------------------------------------

# Registrar
registrar = None
entities = attr.get("rdap", {}).get("entities", [])
for e in entities:
    if "registrar" in e.get("roles", []):
        registrar = e.get("vcard_array", [])[1][3]["values"][0] if len(e.get("vcard_array", [])) > 1 else None

# Nameservers
nameservers = [ns["ldh_name"] for ns in attr.get("rdap", {}).get("nameservers", [])]

# A record (VirusTotal stores this under "last_analysis_results" sometimes, but for domains it's in "resolutions")
a_record = None
resolutions = attr.get("last_dns_records", []) or attr.get("last_dns_records", [])
# Fallback to RDAP if needed
if resolutions:
    for r in resolutions:
        if r.get("type") == "A":
            a_record = r.get("value")

# WHOIS redacted?
whois_text = attr.get("whois", "")
whois_redacted = "REDACTED" in whois_text.upper()

# Domain creation date
creation_ts = attr.get("creation_date")
creation_date = None
if creation_ts:
    from datetime import datetime
    creation_date = datetime.utcfromtimestamp(creation_ts).strftime("%Y-%m-%d %H:%M:%S")

# Certificate last seen (use last_https_certificate → validity → not_before)
cert = attr.get("last_https_certificate", {})
cert_seen = cert.get("validity", {}).get("not_before")

# --------------------------------------------------------------------
# Print results
# --------------------------------------------------------------------
print("\n================ Extracted Info ================")
print("Registrar:", registrar)
print("Nameservers:", nameservers)
print("A Record:", a_record)
print("WHOIS Redacted:", whois_redacted)
print("Domain Creation Date:", creation_date)
print("Certificate Last Seen:", cert_seen)
print("================================================\n")
