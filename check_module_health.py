"""
Module health check -- pings each configured source's cheapest real
endpoint to confirm auth/connectivity still works, without running a
full collection pass.

Built after Shodan and Censys were both found silently broken (paid
membership lapsed, deprecated API) and Hudson Rock was found silently
discarding real data -- all undetected until an unrelated investigation
happened to stumble onto them. There was no automated way to know if a
"configured" source had quietly stopped working. This is that check.

Run: python check_module_health.py
Exits 0 if everything configured is healthy, 1 if anything failed --
safe to chain after a scheduled collection run.
"""
import sys
import requests

import military_osint_tool_v2 as m

TIMEOUT = 15


def _check_shodan():
    key = m.CONFIG.get("shodan_api_key", "")
    if not key:
        return None
    r = requests.get("https://api.shodan.io/api-info", params={"key": key}, timeout=TIMEOUT)
    if r.status_code == 200 and r.json().get("query_credits", 0) > 0:
        return True, f"OK ({r.json().get('query_credits')} query credits)"
    return False, f"HTTP {r.status_code}: {r.text[:150]}"


def _check_censys():
    token = m.CONFIG.get("censys_api_id", "")
    if not token:
        return None
    r = requests.get("https://api.platform.censys.io/v3/global/asset/host/1.1.1.1",
                      headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_zoomeye():
    key = m.CONFIG.get("zoomeye_api_key", "")
    if not key:
        return None
    import base64
    qb64 = base64.b64encode(b'app:"nginx"').decode()
    r = requests.post("https://api.zoomeye.ai/v2/search", json={"qbase64": qb64, "page": 1},
                       headers={"API-KEY": key}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_netlas():
    key = m.CONFIG.get("netlas_api_key", "")
    if not key:
        return None
    r = requests.get("https://app.netlas.io/api/responses/", params={"q": "host:cloudflare.com"},
                      headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_leakix():
    key = m.CONFIG.get("leakix_api_key", "")
    if not key:
        return None
    r = requests.get("https://leakix.net/search", params={"scope": "service", "q": "+geoip.country_iso_code:US"},
                      headers={"api-key": key, "Accept": "application/json"}, timeout=TIMEOUT)
    return (r.status_code in (200, 401)) and r.status_code == 200, f"HTTP {r.status_code}"


def _check_grayhatwarfare():
    key = m.CONFIG.get("grayhatwarfare_api_key", "")
    if not key:
        return None
    r = requests.get(f"https://buckets.grayhatwarfare.com/api/v2/files",
                      params={"keywords": "test", "limit": 1, "access_token": key}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_github():
    token = m.CONFIG.get("github_token", "")
    if not token:
        return None
    r = requests.get("https://api.github.com/rate_limit",
                      headers={"Authorization": f"token {token}"}, timeout=TIMEOUT)
    if r.status_code == 200:
        remaining = r.json().get("resources", {}).get("core", {}).get("remaining", "?")
        return True, f"OK ({remaining} API calls remaining this hour)"
    return False, f"HTTP {r.status_code}: {r.text[:150]}"


def _check_otx():
    key = m.CONFIG.get("otx_api_key", "")
    if not key:
        return None
    r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                      headers={"X-OTX-API-KEY": key}, params={"limit": 1}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_virustotal():
    key = m.CONFIG.get("virustotal_api_key", "")
    if not key:
        return None
    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
                      headers={"x-apikey": key}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_breachdirectory():
    key = m.CONFIG.get("breachdirectory_api_key", "")
    if not key:
        return None
    r = requests.get("https://breachdirectory.p.rapidapi.com/",
                      params={"func": "auto", "term": "test@example.com"},
                      headers={"X-RapidAPI-Key": key, "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"},
                      timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_tavily():
    key = m.CONFIG.get("tavily_api_key", "")
    if not key:
        return None
    r = requests.post("https://api.tavily.com/search",
                       json={"query": "test", "search_depth": "basic", "max_results": 1},
                       headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_urlscan():
    key = m.CONFIG.get("urlscan_api_key", "")
    if not key:
        return None
    r = requests.get("https://urlscan.io/api/v1/search/", params={"q": "page.domain:cloudflare.com", "size": 1},
                      headers={"API-Key": key}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}: {r.text[:150]}"


def _check_hudson_rock():
    # Always free/keyless -- checks reachability, not auth. Deliberately
    # NOT example.com -- confirmed live (see chat) that domain alone
    # times out at 30s+ (presumably pathological data volume for such a
    # universally-hit placeholder domain), while every real target domain
    # answers in 1-2s. A real target domain is the honest cheap check.
    r = requests.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
                      params={"domain": "mod.gov.in"}, headers={"User-Agent": "MilOSINT/2.0"}, timeout=TIMEOUT)
    return (r.status_code == 200), f"HTTP {r.status_code}"


def _check_ollama():
    url = m.CONFIG.get("ollama_url", "")
    if not url:
        return None
    try:
        r = requests.get(f"{url}/api/tags", timeout=5)
        return (r.status_code == 200), f"HTTP {r.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "not running (connection refused)"


CHECKS = [
    ("Shodan", _check_shodan),
    ("Censys", _check_censys),
    ("ZoomEye", _check_zoomeye),
    ("Netlas", _check_netlas),
    ("LeakIX", _check_leakix),
    ("GrayhatWarfare", _check_grayhatwarfare),
    ("GitHub", _check_github),
    ("OTX AlienVault", _check_otx),
    ("VirusTotal", _check_virustotal),
    ("BreachDirectory", _check_breachdirectory),
    ("Tavily", _check_tavily),
    ("URLScan.io", _check_urlscan),
    ("Hudson Rock", _check_hudson_rock),
    ("Ollama (local)", _check_ollama),
]


def main():
    print(f"{'Source':<20} {'Status':<8} Detail")
    print("-" * 70)
    any_failed = False
    any_checked = False
    for name, check_fn in CHECKS:
        try:
            result = check_fn()
        except Exception as e:
            result = (False, f"exception: {e}")
        if result is None:
            print(f"{name:<20} {'SKIP':<8} not configured")
            continue
        ok, detail = result
        any_checked = True
        status = "OK" if ok else "FAIL"
        if not ok:
            any_failed = True
        print(f"{name:<20} {status:<8} {detail}")

    print("-" * 70)
    if not any_checked:
        print("Nothing configured to check.")
    elif any_failed:
        print("One or more configured sources FAILED health check.")
        sys.exit(1)
    else:
        print("All configured sources healthy.")


if __name__ == "__main__":
    main()
