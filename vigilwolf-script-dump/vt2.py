import requests
# ---------------------------
# Second request
# ---------------------------
url2 = "https://www.virustotal.com/ui/urls/e2e43c50ed187b3adc68bf141c064c29dffc98e1b0647e2daaf20ca5862aeeea/network_location"

headers2 = {
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
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

response2 = requests.get(url2, headers=headers2)
print("\n----- Second Response -----")
print(response2.status_code)
print(response2.text)
