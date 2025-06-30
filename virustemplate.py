import requests
import time

# --- Nastavení API klíčů ---
VT_API_KEYS = [
    "VT_API_KEY_1_HERE",
    "VT_API_KEY_2_HERE"
]

GSB_API_KEY = "GSB_API_KEY_HERE"

# --- URL pro kontrolu ---
URL_TO_CHECK = "http://example.com"  # zadej URL k testu


def check_virustotal(url):
    """
    Zkontroluje URL pomocí VirusTotal API s podporou dvou API klíčů
    a přepne klíče při přetížení.
    """
    headers = {"x-apikey": None}
    scan_url = "https://www.virustotal.com/api/v3/urls"
    # VirusTotal vyžaduje URL v base64 bez paddingu
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    for api_key in VT_API_KEYS:
        headers["x-apikey"] = api_key

        # nejdřív se podíváme, jestli už VT nemá analyzu uloženou
        r = requests.get(analysis_url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return True  # nebezpečná
            else:
                return False  # čistá
        elif r.status_code == 429:
            print("VT API key přetížen, zkouším další...")
            time.sleep(1)
            continue
        else:
            print(f"VT API chyba: {r.status_code} {r.text}")
            return None
    return None


def check_gsb(url):
    """
    Zkontroluje URL pomocí Google Safe Browsing API (ThreatMatches)
    """
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    r = requests.post(gsb_url, json=payload)
    if r.status_code == 200:
        data = r.json()
        if "matches" in data:
            return True  # je tam nebezpečí
        else:
            return False
    else:
        print(f"GSB API chyba: {r.status_code} {r.text}")
        return None


def main():
    print(f"Kontrola URL: {URL_TO_CHECK}")

    vt_result = check_virustotal(URL_TO_CHECK)
    if vt_result is None:
        print("VirusTotal nedostupný, zkouším Google Safe Browsing...")
        gsb_result = check_gsb(URL_TO_CHECK)
        if gsb_result is None:
            print("Nebylo možné URL zkontrolovat.")
        elif gsb_result:
            print("NEBEZPEČNÁ STRÁNKA (Google Safe Browsing)")
        else:
            print("Stránka se jeví jako bezpečná (Google Safe Browsing).")
    elif vt_result:
        print("NEBEZPEČNÁ STRÁNKA (VirusTotal)")
    else:
        print("Stránka se jeví jako bezpečná (VirusTotal).")


if __name__ == "__main__":
    main()
