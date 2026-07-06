"""
Military Cyber Threat OSINT Collection Tool — v2 (Refined)
Collects intelligence from deep/dark web sources across T1-T8 categories.

WHAT CHANGED FROM v1 (military_osint_tool.py) — see chat for full writeup:
  1. Centralised relevance engine (STRONG/CONTRACTOR/APT/WEAK/NEGATIVE term
     tiers + domain-suffix gate) shared by every text-search module, instead
     of ad-hoc per-module keyword lists that drift out of sync.
  2. GitHub module now fetches the raw file content for each candidate hit
     and requires an actual secret-shaped pattern (API key / password
     assignment / private key block) before calling it CRITICAL — a bare
     keyword match (e.g. a Google-dork wordlist mentioning "army.mil") is
     kept but downgraded, not reported as a credential leak.
  3. GrayhatWarfare queries are split into STRONG (army.mil, siprnet, itar...)
     and SOFT (pentagon, bundeswehr...) tiers; SOFT hits additionally require
     a sensitive file extension and no icon/meme/clipart filename noise.
  4. VirusTotal is now an ENRICHMENT pass over IOCs this run actually found
     (ThreatFox/MalwareBazaar/OTX hashes & domains) instead of a fixed list
     of invented-looking "APT domains" that repeated unchanged every run.
  5. Removed the DoD-InternetDB "guess /8 gateway IPs" module — it duplicates
     the InternetDB enrichment that correlate_and_enrich() already runs on
     every IP IOC discovered this run, and its sampling had no real basis.
  6. Merged the old fetch_vulners()/fetch_nvd_cves() duplication into one
     NVD module and added the vendor-match gate to the query set that
     previously had none (it was returning any high-CVSS Windows RDP CVE
     regardless of military relevance).
  7. category_name is now pulled from one CATEGORY_NAMES table instead of
     being hand-typed (and drifting) per module.
  8. Dedup store is version-stamped (FILTER_VERSION) so a future filter
     change can force re-evaluation instead of silently suppressing rows
     forever.
  9. New --clean mode: re-filters an EXISTING CSV (e.g. an old merged file)
     using the same engine, targeting exactly the three sources that produce
     keyword false positives (HIBP, GitHub, GrayhatWarfare). Everything else
     passes through untouched. This is how you fix a CSV you already have.
 10. API keys can be overridden via MILOSINT_<KEY_NAME> environment variables
     so they don't have to live in this file if you ever put it in git.

CSV schema is unchanged from v1 — this is a drop-in replacement.

HOW TO USE:
  python military_osint_tool_v2.py                  # normal collection run
  python military_osint_tool_v2.py --clean IN.csv OUT.csv   # clean an old CSV

  pip install requests
  Optional: pip install requests[socks]   (Tor .onion crawling)
  Optional: pip install telethon          (Telegram private channel monitoring)
"""

import csv
import json
import os
import re
import sys
import time
import base64
import hashlib
import logging
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

FILTER_VERSION = "2.0"


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no python-dotenv dependency) — sets os.environ from
    a local KEY=VALUE file so real API keys never have to be hardcoded in this
    script. Real environment variables (if already set) take priority and are
    never overwritten. Silently does nothing if no .env file exists."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()

# ─────────────────────────────────────────────
#  CONFIG
#  Leave a key as "" to skip that module. Keys marked FREE need no payment.
#  Any value here can be overridden without editing the file by exporting
#  an environment variable named MILOSINT_<KEY_UPPER>, e.g.
#     MILOSINT_GITHUB_TOKEN=ghp_xxx python military_osint_tool_v2.py
# ─────────────────────────────────────────────
CONFIG = {
    # PAID — leave "" to skip
    "shodan_api_key":          "",   # free registered account — T3: shodan.io
    "hibp_api_key":            "",   # $3.50/mo — T1: per-email lookup (not used by the free /breaches endpoint)
    "intelx_api_key":          "",   # ~$100/mo — T2: intelx.io
    "dehashed_email":          "",   # $15/mo  — T1: dehashed.com
    "dehashed_api_key":        "",   # $15/mo
    "securitytrails_api_key":  "",   # $50/mo  — T3
    "censys_api_id":           "",   # new single-key format
    "censys_api_secret":       "",

    # FREE-TIER — sign up, paste key
    "otx_api_key":             "",
    "virustotal_api_key":      "",
    "grayhatwarfare_api_key":  "",
    "github_token":            "",
    "leakix_api_key":          "",
    "threatfox_api_key":       "",
    "criminal_ip_api_key":     "",

    # DEEP / DARK WEB — FREE tier (key needed)
    "zoomeye_api_key":         "",
    "vulners_api_key":         "",  # not required by NVD; kept for future use
    "onyphe_api_key":          "",

    # DEEP / DARK WEB — PAID (stubs ready, activate by pasting key)
    "darkowl_api_key":         "",
    "flashpoint_api_key":      "",
    "recorded_future_key":     "",
    "binaryedge_api_key":      "",
    "snusbase_api_key":           "",
    "cybersixgill_client_id":     "",
    "cybersixgill_client_secret": "",
    "kela_radark_api_key":        "",
    "spycloud_api_key":           "",
    "digital_shadows_key":        "",
    "digital_shadows_secret":     "",

    # FREE — no key needed. Used by both Hudson Rock and SpyCloud.
    # Expanded beyond just US .mil: T1 (Personnel/Identity) was the thinnest
    # category in the compiled dataset (32 rows, all from one source) — the
    # US-only list meant allied-nation and defence-contractor infostealer
    # victims were never even queried, not that none exist.
    "hudson_rock_domains": [
        "army.mil", "navy.mil", "af.mil", "marines.mil", "disa.mil",
        "socom.mil", "nato.int", "defense.gov", "nsa.gov", "dia.mil",
        # Allied nations' defence ministries
        "mod.uk", "bundeswehr.de", "defence.gov.au", "forces.gc.ca",
        # India — all domains verified live (see chat) before adding
        "indianarmy.nic.in", "indiannavy.gov.in", "indianairforce.nic.in",
        "mod.gov.in", "drdo.gov.in",
        # Prime defence contractors — infostealer logs on employees here
        # are exactly the personnel-risk signal T1 was missing
        "lockheedmartin.com", "rtx.com", "northropgrumman.com",
        "baesystems.com", "leidos.com", "l3harris.com", "generaldynamics.com",
        # Indian defence PSUs
        "hal-india.co.in", "bel-india.in", "bdl-india.com",
        "mazagondock.in", "grse.in", "bemlindia.in",
        # Pakistan — verified live: pakistanarmy.gov.pk, paknavy.gov.pk,
        # paf.gov.pk, mod.gov.pk, ispr.gov.pk, hit.com.pk
        "pakistanarmy.gov.pk", "paknavy.gov.pk", "paf.gov.pk",
        "mod.gov.pk", "ispr.gov.pk", "hit.com.pk",
        # China — verified live: mod.gov.cn, norinco.cn, spacechina.com,
        # avic.com, cetc.com.cn
        "mod.gov.cn", "norinco.cn", "spacechina.com", "avic.com", "cetc.com.cn",
        # New allied/priority nations — all domains verified live before adding
        "mod.gov.il", "idf.il", "defense.gouv.fr", "mod.go.jp",
        "mnd.go.kr", "army.mil.kr", "mnd.gov.tw",
        "mod.gov.ua", "zsu.gov.ua", "gur.gov.ua",
        # More defence contractors — infostealer logs on employees here
        # are the same personnel-risk signal as the US/UK primes above
        "rafael.co.il", "iai.co.il", "dassault-aviation.com", "naval-group.com",
    ],
    "breachdirectory_api_key": "",

    # Tor .onion crawling — requires Tor Browser (or a standalone Tor daemon)
    # to actually be running; the module verifies real routing via
    # check.torproject.org and falls back to the clearnet mirror if not.
    "tor_enabled":    True,
    "tor_socks_port": 9050,  # standalone daemon (TorDaemon_Background task), not Tor Browser's 9150

    # Telethon — Telegram PRIVATE channel monitoring
    "telegram_api_id":          "",
    "telegram_api_hash":        "",
    "telegram_phone":           "",
    "telegram_private_channels": [],

    # FAA NOTAM (GPS interference)
    "faa_client_id":           "",
    "faa_client_secret":       "",

    # Telegram PUBLIC channels to monitor (no key needed)
    "telegram_channels": [
        "rybar", "intel_slava_z", "osintua", "CyberSecAlert",
        "RALee85", "militaryreview",
    ],

    # ALERTS
    "discord_webhook_url":     "",
    "twilio_account_sid":      "",
    "twilio_auth_token":       "",
    "whatsapp_to":             "",
    "twilio_whatsapp_from":    "whatsapp:+14155238886",

    # SETTINGS
    "output_csv":              "military_osint_data_v2_{ts}.csv",
    "dedup_file":              "seen_threats_v2.json",
    "master_csv":              "military_osint_master.csv",  # accumulates unique findings across all runs
    "dashboard_html":          "osint_dashboard.html",        # refreshed with the master dataset embedded after every run
    "stix_export":             True,
    "request_delay_sec":       1.5,
    "urlscan_api_key":         "",
    "nvd_api_key":             "",
    "whatsapp_alert_threshold": "high",
    "whatsapp_alert_mode":      "digest",
    "weekly_delta_report":      True,
    "generate_task_xml":        True,
}


def _env_override(cfg: dict) -> dict:
    """Let MILOSINT_<KEY_UPPER> env vars override any CONFIG value without editing this file."""
    for k in list(cfg.keys()):
        env_val = os.environ.get(f"MILOSINT_{k.upper()}")
        if env_val is not None:
            cfg[k] = env_val
    return cfg


CONFIG = _env_override(CONFIG)


def key_available(key_name: str) -> bool:
    val = CONFIG.get(key_name, "")
    return bool(val) and not str(val).upper().startswith("YOUR_")


# ─────────────────────────────────────────────
#  CSV SCHEMA — unchanged from v1 (drop-in compatible)
# ─────────────────────────────────────────────
CSV_COLUMNS = [
    "threat_id", "threat_name", "category_code", "category_name",
    "source_layer", "source", "post_text", "post_url", "timestamp",
    "location", "severity", "confidence", "ioc_type", "ioc_value", "tags",
]

CATEGORY_NAMES = {
    "T1": "Personnel & Identity Threats",
    "T2": "Data & Document Leakage",
    "T3": "Communication & Network Attacks",
    "T4": "Navigation Positioning & EW",
    "T5": "Critical Infrastructure Attacks",
    "T6": "Malware & Advanced Cyber Attacks",
    "T7": "Emerging & Autonomous System Threats",
    "T8": "Information Operations & Influence Threats",
}

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(stream=sys.stdout),
        logging.FileHandler("osint_tool_v2.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  CSV WRITER
# ─────────────────────────────────────────────
class CSVWriter:
    def __init__(self, path: str):
        self.path = Path(path)
        self._init_file()

    def _init_file(self):
        if not self.path.exists():
            with open(self.path, "w", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()
            log.info(f"Created CSV: {self.path}")

    def write(self, row: dict):
        clean = {col: row.get(col, "") for col in CSV_COLUMNS}
        with open(self.path, "a", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow(clean)

    def write_many(self, rows: list):
        for row in rows:
            self.write(row)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_id(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:12]


# ═════════════════════════════════════════════════════════════════════════
#  RELEVANCE ENGINE — the core fix for "specific keywords load a lot of junk"
#
#  Every module that searches free text (breach descriptions, filenames,
#  bucket paths, forum posts, RSS text) runs its hits through relevance_check()
#  instead of hand-rolling its own keyword list. A hit only survives if it
#  clears one of three tiers:
#    domain  — the artefact is actually hosted on / addressed to a military
#              domain (army.mil, nato.int, mod.uk, ...). Strongest signal.
#    strong  — the text contains a specific multi-word military phrase, a
#              named defence contractor, or a named APT group. A single hit
#              is enough because these strings essentially never appear by
#              coincidence in unrelated content.
#    weak    — only generic single words (military, army, defence, weapon...)
#              were found. These match constantly in unrelated news/gaming/
#              retail content, so we require several independent hits before
#              trusting them, and even then confidence is capped at MEDIUM.
#  A NEGATIVE_TERMS hit (icon/meme/dork-wordlist/cheatsheet/...) rejects the
#  row outright unless a real domain match overrides it.
# ═════════════════════════════════════════════════════════════════════════

MIL_DOMAIN_SUFFIXES = (
    ".mil", ".gov", ".nato.int", ".mod.uk", ".bundeswehr.de",
    ".army.mil", ".navy.mil", ".af.mil", ".marines.mil",
    ".disa.mil", ".socom.mil", ".dia.mil", ".nsa.gov",
    ".defence.gov.au", ".forces.gc.ca",
    # India — specific hostnames only, never bare ".gov.in"/".nic.in": both are
    # shared by thousands of unrelated Indian government sites (state govts,
    # municipal bodies, tax dept...) and would reproduce the exact ".gov"
    # over-broad-match bug already found and fixed in RansomWatch.
    ".indianarmy.nic.in", ".indiannavy.gov.in", ".indianairforce.nic.in",
    ".mod.gov.in", ".drdo.gov.in",
    # Pakistan — all verified live (403-WAF-blocked but real, or confirmed via
    # multiple independent sources when directly unreachable from this network).
    ".pakistanarmy.gov.pk", ".paknavy.gov.pk", ".paf.gov.pk",
    ".mod.gov.pk", ".ispr.gov.pk",
    # China — verified live (eng.mod.gov.cn, en.norinco.cn, spacechina.com,
    # avic.com, cetc.com.cn all confirmed reachable).
    ".mod.gov.cn", ".norinco.cn", ".spacechina.com", ".avic.com", ".cetc.com.cn",
    # Israel — verified live (mod.gov.il, idf.il both confirmed reachable).
    ".mod.gov.il", ".idf.il",
    # France — verified live (defense.gouv.fr confirmed reachable).
    ".defense.gouv.fr",
    # Japan — verified live (mod.go.jp confirmed reachable).
    ".mod.go.jp",
    # South Korea — verified live (mnd.go.kr, army.mil.kr both confirmed reachable).
    ".mnd.go.kr", ".army.mil.kr",
    # Taiwan — verified live (mnd.gov.tw confirmed reachable).
    ".mnd.gov.tw",
    # Ukraine — verified live (mod.gov.ua corrected after initial 404 on wrong
    # guess "mil.gov.ua"; zsu.gov.ua and gur.gov.ua confirmed via search).
    ".mod.gov.ua", ".zsu.gov.ua", ".gur.gov.ua",
)

STRONG_MIL_TERMS = {
    "department of defense", "dod breach", "us army", "u.s. army",
    "us navy", "u.s. navy", "us air force", "u.s. air force",
    "air force records", "nato breach", "pentagon", "ministry of defence",
    "disa", "socom", "nsa breach", "military database", "armed forces",
    "defence contractor", "defense contractor", "cyber command", "uscybercom",
    "siprnet", "niprnet", "noforn", "fouo", "itar",
}

MIL_CONTRACTORS = {
    "lockheed martin", "lockheed", "raytheon", "northrop grumman", "northrop",
    "boeing defense", "general dynamics", "bae systems", "leidos", "l3harris",
    "saic", "mantech", "booz allen", "caci", "peraton", "gdit",
    "curtiss-wright", "elbit", "rheinmetall", "leonardo", "thales", "saab",
    "kongsberg", "hanwha", "oshkosh defense", "parsons", "mitre",
    "rand corporation", "palantir",
}

APT_GROUPS = {
    "apt28", "fancy bear", "sofacy", "x-agent", "x agent",
    "apt29", "cozy bear", "sunburst", "teardrop",
    "apt41", "barium", "winnti",
    "lazarus", "bluenoroff", "andariel", "kimsuky",
    "sandworm", "notpetya", "industroyer", "crashoverride", "cadet blizzard",
    "turla", "snake", "uroburos", "carbon", "mosquito",
    "equation group", "doublefantasy", "triplefantasy",
    "volt typhoon", "salt typhoon", "silk typhoon", "muddywater",
    "shadowpad", "plugx",
    # Pakistan-linked — previously absent despite China/Russia/NK/Iran all
    # being represented here
    "transparent tribe", "apt36", "sidecopy", "operation c-major",
    # A few more well-documented Chinese groups beyond what was already here
    "apt40", "mustang panda", "apt10", "stone panda", "menupass",
}

MIL_VENDOR_TERMS = {
    "cisco", "fortinet", "palo alto", "juniper", "f5", "pulse secure",
    "ivanti", "sonicwall", "citrix", "checkpoint",
    "siemens", "rockwell", "allen-bradley", "honeywell", "ge digital",
    "schneider electric", "abb", "emerson", "yokogawa", "beckhoff",
    "inductive automation", "aveva",
    "microsoft", "oracle", "vmware", "solarwinds", "bmc software",
    "openssl", "apache", "nginx",
    "viasat", "hughes", "iridium", "inmarsat",
}

WEAK_MIL_TERMS = {
    "military", "army", "navy", "air force", "defence", "defense",
    "warfare", "weapon", "drone", "uav", "satellite",
    "intelligence agency", "government", "federal", "national security",
}

NEGATIVE_TERMS = {
    "icon", "medal", "clipart", "clip art", "wallpaper", "meme", "logo",
    "favicon", "thumbnail", "wordpress theme", "google dork", "dork list",
    "ghdb", "google hacking database", "wordlist", "word list",
    "cheatsheet", "cheat sheet", "awesome-", "bug bounty", "bugbounty",
    "pentest", "hack the box", "tryhackme", "ctf writeup", "writeup",
    "how to hack",
}


import functools


@functools.lru_cache(maxsize=None)
def _compiled_term_pattern(terms_key: tuple):
    """Word-boundary regex for a term set, cached per unique set of terms."""
    return re.compile(r"\b(?:" + "|".join(re.escape(t) for t in terms_key) + r")\b", re.IGNORECASE)


def _has_any(text: str, terms) -> bool:
    """
    Word-boundary containment check.
    A live spot-check of the first v2 run found "disa" in STRONG_MIL_TERMS
    (meant to catch the acronym DISA) silently matching inside "disability",
    "disaster", "disappointed" — a plain `t in text` substring check has no
    concept of word edges. That single bug misclassified a childcare-software
    breach, a gambling-site breach, and a guitar-lesson-site breach as
    military credential leaks. Same class of bug as the "ot"/CISA and
    ".gov"/RansomWatch fixes above; fixing it once here at the engine level
    instead of per-term (also catches "mitre" vs "mitre saw", "parsons" vs
    the surname, "leonardo" vs the name, "carbon" vs "carbon footprint",
    "saic" vs "SAIC Motor" the Chinese automaker — all real, all latent).
    """
    if not terms:
        return False
    pattern = _compiled_term_pattern(tuple(sorted(terms)))
    return pattern.search(text or "") is not None


def _count_matches(text: str, terms) -> int:
    """Count how many distinct terms in the set have a word-boundary hit."""
    if not terms:
        return 0
    low = text or ""
    return sum(1 for t in terms if _compiled_term_pattern((t,)).search(low))


def has_mil_domain(value: str) -> bool:
    """
    Suffix match, PLUS exact match against the bare domain (e.g. "mod.gov.in"
    itself, not just "*.mod.gov.in") — a value exactly equal to a listed
    domain is shorter than ".mod.gov.in" so v.endswith(...) alone would
    silently reject it. Pre-existing gap for every entry here, not just the
    newly-added Indian ones (e.g. a bare "nato.int" HIBP breach domain never
    matched either); fixing it once at the engine level.
    """
    v = (value or "").lower()
    return any(v.endswith(s) or v == s.lstrip(".") for s in MIL_DOMAIN_SUFFIXES)


# Country-specific (not just true/false) version of the same suffix logic, for
# fetch functions that need to record WHICH country a matched domain belongs
# to (dashboard "location"/map field) rather than just whether it's military.
# Specific multi-label suffixes are listed before generic ones so a country
# domain is never miscategorized by a broader fallback checked earlier.
_DOMAIN_COUNTRY_SUFFIXES = (
    (".mod.uk", "United Kingdom"),
    (".bundeswehr.de", "Germany"),
    (".defence.gov.au", "Australia"),
    (".forces.gc.ca", "Canada"),
    (".indianarmy.nic.in", "India"), (".indiannavy.gov.in", "India"),
    (".indianairforce.nic.in", "India"), (".mod.gov.in", "India"), (".drdo.gov.in", "India"),
    (".pakistanarmy.gov.pk", "Pakistan"), (".paknavy.gov.pk", "Pakistan"),
    (".paf.gov.pk", "Pakistan"), (".mod.gov.pk", "Pakistan"), (".ispr.gov.pk", "Pakistan"),
    (".mod.gov.cn", "China"), (".norinco.cn", "China"), (".spacechina.com", "China"),
    (".avic.com", "China"), (".cetc.com.cn", "China"),
    (".mod.gov.il", "Israel"), (".idf.il", "Israel"),
    (".defense.gouv.fr", "France"),
    (".mod.go.jp", "Japan"),
    (".mnd.go.kr", "South Korea"), (".army.mil.kr", "South Korea"),
    (".mnd.gov.tw", "Taiwan"),
    (".mod.gov.ua", "Ukraine"), (".zsu.gov.ua", "Ukraine"), (".gur.gov.ua", "Ukraine"),
    (".nato.int", "NATO"),
    (".mil", "United States"), (".nsa.gov", "United States"),
)


def domain_to_country(value: str) -> str:
    """Maps a hostname/domain (e.g. crt.sh cert CN, urlscan page domain) to a
    country name for the dashboard's map view. Returns 'Unknown' rather than
    guessing when nothing matches — silently defaulting to a specific country
    is exactly the location-mislabeling bug this function replaces."""
    v = (value or "").lower()
    for suffix, country in _DOMAIN_COUNTRY_SUFFIXES:
        if v.endswith(suffix) or v == suffix.lstrip("."):
            return country
    return "Unknown"


def relevance_check(text: str, domain_value: str = "", weak_terms=None, min_weak: int = 2):
    """
    Shared relevance gate. Returns (passes: bool, tier: str, reason: str).
    tier is one of "domain" / "strong" / "weak" / "reject".
    """
    low = (text or "").lower()
    if has_mil_domain(domain_value):
        return True, "domain", "military-domain-match"
    if _has_any(low, NEGATIVE_TERMS):
        return False, "reject", "negative-term-no-domain-evidence"
    if _has_any(low, STRONG_MIL_TERMS) or _has_any(low, MIL_CONTRACTORS) or _has_any(low, APT_GROUPS):
        return True, "strong", "strong-term-match"
    wt = weak_terms if weak_terms is not None else WEAK_MIL_TERMS
    n = _count_matches(low, wt)
    if n >= min_weak:
        return True, "weak", f"{n}-weak-term-matches"
    return False, "reject", "insufficient-evidence"


# ── GitHub secret-content verification (used by fetch_github_leaks) ────────
_SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["\']?[A-Za-z0-9+/_\-\.]{10,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(r'-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'),
]

_DORK_FILE_PATTERNS = {"dork", "ghdb", "wordlist", "payload-list", "cheatsheet", "cheat-sheet"}

_NOISE_REPO_PATTERNS = {
    "awesome-", "osint-", "-dork", "ghdb", "-pentest",
    "hacking-", "security-hardening", "cheatsheet", "wordlist",
    "bugbounty", "-recon", "exploit-db", "payload-", "ctf-",
    "pagodo", "googledork", "shodan-dork", "censys-",
    "hack-the-box", "tryhackme", "writeup",
}

_DOC_EXTS = {".md", ".rst", ".txt", ".adoc", ".wiki"}
_DOC_NAMES = {"readme", "changelog", "contributing", "license", "authors",
              "history", "notice", "todo", "faq", "news"}


def _looks_like_secret(content: str) -> bool:
    return any(p.search(content) for p in _SECRET_PATTERNS)


def _fetch_raw_github_content(html_url: str) -> str:
    """Best-effort raw file fetch for secret verification. Empty string on any failure."""
    try:
        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        r = requests.get(raw_url, timeout=8, headers={"User-Agent": "MilOSINT/2.0"})
        if r.ok and len(r.text) < 200_000:
            return r.text
    except Exception:
        pass
    return ""


# ── GrayhatWarfare tiered queries (used by fetch_grayhatwarfare) ───────────
_GHW_STRONG_QUERIES = [
    "army.mil", "navy.mil", "af.mil", "disa.mil", "socom.mil", "cybercom.mil",
    "nato.int", "mod.uk", "noforn", "fouo", "siprnet", "niprnet", "itar",
    "indianarmy.nic.in", "indiannavy.gov.in", "indianairforce.nic.in",
    "mod.gov.in", "drdo.gov.in",
    "pakistanarmy.gov.pk", "paknavy.gov.pk", "paf.gov.pk", "mod.gov.pk", "ispr.gov.pk",
    "mod.gov.cn", "norinco.cn", "spacechina.com", "avic.com", "cetc.com.cn",
    "forces.gc.ca",
    "mod.gov.il", "idf.il", "defense.gouv.fr", "mod.go.jp",
    "mnd.go.kr", "mnd.gov.tw", "mod.gov.ua",
]
_GHW_SOFT_QUERIES = ["pentagon", "bundeswehr", "defence.gov.au"]

_GHW_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".svg",
    ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".mp3", ".wav",
    ".aac", ".ogg", ".ico", ".cur", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".map",
}
_GHW_SENSITIVE_EXTS = {
    ".env", ".sql", ".db", ".bak", ".config", ".conf", ".key", ".pem",
    ".csv", ".xlsx", ".xls", ".docx", ".doc", ".pdf", ".json", ".zip",
    ".7z", ".rar", ".ini", ".yaml", ".yml", ".tf", ".kubeconfig",
    ".sqlite", ".mdb", ".ppk",
}
_GHW_NEG_FILENAME_TERMS = {
    "icon", "medal", "clipart", "wallpaper", "meme", "logo",
    "thumbnail", "favicon", "banner", "badge",
}

# ═════════════════════════════════════════════════════════════════════════
#  T1 | PERSONNEL & IDENTITY THREATS
# ═════════════════════════════════════════════════════════════════════════

def fetch_hibp_breaches(api_key: str = "") -> list:
    """HaveIBeenPwned /breaches — free, no key needed. Filters to breaches that
    are either hosted on a military/government domain or whose name/description
    contains a specific military phrase, and only if passwords/tokens/PII were
    actually in the breach (not just email addresses)."""
    rows = []
    headers = {"user-agent": "MilOSINT/2.0"}
    if api_key:
        headers["hibp-api-key"] = api_key
    _HIBP_BLOCKLIST = {
        "armyforceonline", "hackforums", "cdek", "dodonew", "livejournal",
        "forbes", "catho", "james", "notsocradar", "socradar", "itarmy", "it army",
    }
    MIN_PWNED = 10_000
    try:
        resp = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers=headers, timeout=10)
        resp.raise_for_status()
        for b in resp.json():
            name = b.get("Name", "")
            name_lower = name.lower()
            desc_lower = b.get("Description", "").lower()
            domain = b.get("Domain", "")
            pwn_count = b.get("PwnCount") or 0
            data_classes = [c.lower() for c in (b.get("DataClasses") or [])]

            if pwn_count < MIN_PWNED:
                continue
            if any(bl in name_lower for bl in _HIBP_BLOCKLIST):
                continue
            _valuable = {"passwords", "auth tokens", "military records",
                         "security questions and answers", "pins"}
            if not any(c in data_classes for c in _valuable):
                continue

            passes, tier, reason = relevance_check(name_lower + " " + desc_lower, domain_value=domain)
            if not passes:
                continue

            rows.append({
                "threat_id":     f"T1-HIBP-{short_id(name)}",
                "threat_name":   "Military/Govt Credential Leak",
                "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                "source_layer":  "Deep Web", "source": "HaveIBeenPwned",
                "post_text":     f"Breach: {name} | Domain: {domain} | PwnCount: {pwn_count:,} | "
                                 f"DataClasses: {', '.join(b.get('DataClasses') or [])} | "
                                 f"{b.get('Description', '')[:200]}",
                "post_url":      f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                "timestamp":     b.get("BreachDate", now_utc()) + "T00:00:00Z",
                "location":      domain_to_country(domain),
                "severity":      "CRITICAL" if tier == "domain" else ("HIGH" if b.get("IsSensitive") else "MEDIUM"),
                "confidence":    "HIGH" if tier == "domain" else "MEDIUM",
                "ioc_type":      "domain", "ioc_value": domain,
                "tags":          f"credential-leak;personnel;hibp;{reason}",
            })
        log.info(f"HIBP: {len(rows)} military-related breaches found")
    except Exception as e:
        log.error(f"HIBP error: {e}")
    return rows


def fetch_dehashed(email: str, api_key: str) -> list:
    """T1 — PAID $15/mo at dehashed.com. Searches .mil email credentials."""
    rows = []
    queries = ["@.mil", "@army.mil", "@navy.mil", "@af.mil", "@marines.mil", "nato.int"]
    creds = base64.b64encode(f"{email}:{api_key}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}
    try:
        for q in queries:
            resp = requests.get(f"https://api.dehashed.com/search?query=email:{requests.utils.quote(q)}&size=5",
                                 headers=headers, timeout=15)
            resp.raise_for_status()
            for entry in resp.json().get("entries") or []:
                em = entry.get("email") or ""
                rows.append({
                    "threat_id":     f"T1-DHD-{short_id(em + entry.get('id',''))}",
                    "threat_name":   "Military Email Credential in Breach Database",
                    "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                    "source_layer":  "Deep Web", "source": "DeHashed",
                    "post_text":     f"Email: {em} | Username: {entry.get('username','')} | "
                                     f"Source: {entry.get('database_name','')} | Hash type: {entry.get('hashing_algorithm','')}",
                    "post_url":      f"https://dehashed.com/search?query={requests.utils.quote(q)}",
                    "timestamp":     now_utc(), "location": "Unknown",
                    "severity":      "CRITICAL", "confidence": "HIGH",
                    "ioc_type":      "email", "ioc_value": em,
                    "tags":          "credential-leak;dehashed;breach;military-email",
                })
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"DeHashed error: {e}")
    log.info(f"DeHashed: {len(rows)} military credential records found")
    return rows


def fetch_github_leaks(token: str) -> list:
    """T1/T2 — FREE GitHub token. Filename-scoped dork queries for leaked .mil
    credentials/configs. Candidate hits are additionally content-verified: the
    raw file is fetched and scanned for an actual secret-shaped pattern before
    being called CRITICAL. A bare keyword match without a real secret pattern
    (e.g. a dork wordlist mentioning army.mil) is downgraded, not dropped."""
    rows = []
    queries = [
        '"@army.mil" OR "@navy.mil" OR "@af.mil" filename:.env',
        '"@army.mil" OR "@dod.gov" OR "@navy.mil" filename:config',
        '"@disa.mil" OR "@socom.mil" OR "@cybercom.mil" password OR secret',
        'filename:.env "dod.gov" OR "army.mil" OR "navy.mil"',
        'filename:config.json "army.mil" OR "dod.gov" api_key OR token OR secret',
        'filename:config.yaml "army.mil" OR "disa.mil" OR "af.mil" password OR secret',
        'filename:secrets.yaml "army.mil" OR "dod.gov" OR "nato.int"',
        'filename:application.properties "army.mil" OR "dod.gov" password',
        'extension:pem "army.mil" OR "navy.mil" OR "dod.gov"',
        'extension:key "army.mil" OR "disa.mil" PRIVATE',
        'extension:sql "army.mil" OR "navy.mil" OR "dod.gov" INSERT',
        'filename:.htpasswd "mil" OR "dod" OR "nato"',
        'filename:kubeconfig "army.mil" OR "dod.gov" OR "nato.int"',
        'extension:tf "army.mil" OR "dod.gov" secret OR password',
        # Allied nations — the original list was entirely US-.mil-focused,
        # so a UK/German/NATO credential leak would never even be searched for.
        # Australia added here too (was previously missing from this module entirely).
        '"@mod.uk" OR "@bundeswehr.de" OR "@forces.gc.ca" OR "@defence.gov.au" filename:.env',
        'filename:config.json "mod.uk" OR "bundeswehr.de" OR "nato.int" api_key OR token OR secret',
        'extension:pem "mod.uk" OR "bundeswehr.de" OR "nato.int" OR "defence.gov.au"',
        # India — verified real domains: indianarmy.nic.in, indiannavy.gov.in,
        # indianairforce.nic.in, mod.gov.in, drdo.gov.in (all confirmed live).
        '"@indianarmy.nic.in" OR "@indiannavy.gov.in" OR "@indianairforce.nic.in" OR "@mod.gov.in" filename:.env',
        'filename:config.json "drdo.gov.in" OR "mod.gov.in" api_key OR token OR secret',
        'extension:pem "indianarmy.nic.in" OR "drdo.gov.in" OR "mod.gov.in"',
        # Pakistan — verified real domains (see chat): pakistanarmy.gov.pk,
        # paknavy.gov.pk, paf.gov.pk, mod.gov.pk, ispr.gov.pk
        '"@pakistanarmy.gov.pk" OR "@paknavy.gov.pk" OR "@paf.gov.pk" OR "@mod.gov.pk" filename:.env',
        'extension:pem "pakistanarmy.gov.pk" OR "mod.gov.pk" OR "ispr.gov.pk"',
        # China — verified real domains: mod.gov.cn, norinco.cn, spacechina.com,
        # avic.com, cetc.com.cn
        'filename:config.json "mod.gov.cn" OR "norinco.cn" OR "avic.com" api_key OR token OR secret',
        'extension:pem "mod.gov.cn" OR "spacechina.com" OR "cetc.com.cn"',
        # New countries (Israel/France/Japan/S.Korea/Taiwan/Ukraine) — kept to ONE
        # consolidated query (not one per country) to control this module's
        # already-heavy runtime under GitHub's ~10/min code-search rate limit.
        '"@mod.gov.il" OR "@defense.gouv.fr" OR "@mod.go.jp" OR "@mnd.go.kr" OR "@mnd.gov.tw" OR "@mod.gov.ua" filename:.env',
    ]
    headers = {
        "Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json",
        "User-Agent": "MilOSINT/2.0", "X-GitHub-Api-Version": "2022-11-28",
    }
    seen_urls: set = set()
    verified = 0
    MAX_CONTENT_VERIFICATIONS = 20
    try:
        for q in queries:
            url = f"https://api.github.com/search/code?q={requests.utils.quote(q)}&per_page=5&sort=indexed"
            try:
                resp = requests.get(url, headers=headers, timeout=20)
                if resp.status_code == 403:
                    log.warning("GitHub: rate limited, backing off 60s")
                    time.sleep(60)
                    continue
                if resp.status_code == 422:
                    time.sleep(2)
                    continue
                resp.raise_for_status()
            except Exception as req_e:
                log.warning(f"GitHub [{q[:50]}]: {req_e}")
                time.sleep(5)
                continue

            for item in resp.json().get("items") or []:
                html_url = item.get("html_url") or ""
                if not html_url or html_url in seen_urls:
                    continue
                repo = item.get("repository", {})
                repo_name = repo.get("full_name", "").lower()
                repo_desc = (repo.get("description") or "").lower()
                file_name = (item.get("name") or "").lower()
                file_path = (item.get("path") or "").lower()

                if any(pat in repo_name or pat in repo_desc for pat in _NOISE_REPO_PATTERNS):
                    continue
                if any(pat in file_name or pat in file_path for pat in _DORK_FILE_PATTERNS):
                    continue
                file_stem = Path(file_name).stem.lower()
                file_ext = Path(file_name).suffix.lower()
                if file_ext in _DOC_EXTS and file_stem in _DOC_NAMES:
                    continue

                seen_urls.add(html_url)

                # Content verification: does the file actually contain a secret-shaped
                # pattern, or did the query just match a keyword coincidentally?
                confidence, severity, evidence = "MEDIUM", "MEDIUM", "keyword-match-only (content not verified)"
                if verified < MAX_CONTENT_VERIFICATIONS:
                    content = _fetch_raw_github_content(html_url)
                    verified += 1
                    if content:
                        if _looks_like_secret(content):
                            confidence, severity, evidence = "HIGH", "CRITICAL", "secret-pattern-confirmed-in-content"
                        else:
                            confidence, severity, evidence = "LOW", "MEDIUM", "no-secret-pattern-found-in-content"

                rows.append({
                    "threat_id":     f"T1-GH-{short_id(html_url)}",
                    "threat_name":   "GitHub Credential/Config Leak — Military",
                    "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                    "source_layer":  "Surface Web", "source": "GitHub (public repo)",
                    "post_text":     f"File: {item.get('name','')} | Repo: {repo.get('full_name','')} | "
                                     f"Path: {item.get('path','')} | Query: {q[:80]} | Evidence: {evidence}",
                    "post_url":      html_url,
                    "timestamp":     repo.get("updated_at") or now_utc(),
                    "location":      "Global", "severity": severity, "confidence": confidence,
                    "ioc_type":      "url", "ioc_value": html_url,
                    "tags":          f"github;credential-leak;dork;military;{evidence.split(' ')[0]}",
                })
            # GitHub code search is rate-limited to 10 req/min regardless of the
            # general 5000/hr token limit — v1's "+2" (3.5s) spacing was still
            # fast enough to trip 403s across 14 queries. 7s keeps every run
            # under that limit instead of burning a 60s backoff mid-run.
            time.sleep(max(CONFIG["request_delay_sec"] + 2, 7))
    except Exception as e:
        log.error(f"GitHub dorking error: {e}")
    log.info(f"GitHub leaks: {len(rows)} leaked files found ({verified} content-verified)")
    return rows


def fetch_hudson_rock() -> list:
    """T1 — FREE. Infostealer-compromised .mil accounts via Hudson Rock Cavalier."""
    rows = []
    domains = CONFIG.get("hudson_rock_domains") or ["army.mil", "navy.mil", "af.mil"]
    base = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
    try:
        for domain in domains:
            try:
                resp = requests.get(base, params={"domain": domain},
                                     headers={"User-Agent": "MilOSINT/2.0"}, timeout=20)
                if resp.status_code == 429:
                    time.sleep(30)
                    continue
                if resp.status_code in (401, 403):
                    break
                resp.raise_for_status()
                data = resp.json()
                container = data.get("stealerLogsResults", data)
                employees = container.get("employees") if isinstance(container, dict) else None
                users = container.get("users") if isinstance(container, dict) else None
                if not isinstance(employees, list):
                    employees = []
                if not isinstance(users, list):
                    users = []
                for record in (employees + users)[:10]:
                    username = record.get("username") or record.get("email") or ""
                    rows.append({
                        "threat_id":     f"T1-HR-{short_id(username + domain)}",
                        "threat_name":   f"Infostealer Victim — {domain} — {record.get('stealer_family','Unknown')}",
                        "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                        "source_layer":  "Dark Web", "source": "Hudson Rock Cavalier (infostealer intelligence)",
                        "post_text":     f"Domain: {domain} | User: {username} | Computer: {record.get('computer_name','')} | "
                                         f"Stealer: {record.get('stealer_family','Unknown')} | "
                                         f"Credentials stolen: {record.get('total_corporate_credentials') or record.get('num_credentials') or 0} | "
                                         f"Date compromised: {record.get('date_compromised') or record.get('date') or now_utc()}",
                        "post_url":      f"{base}?domain={domain}",
                        "timestamp":     str(record.get("date_compromised") or record.get("date") or now_utc()),
                        "location":      record.get("country") or "Unknown",
                        "severity":      "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "email", "ioc_value": username,
                        "tags":          f"infostealer;dark-web-market;credential-theft;{domain}",
                    })
                time.sleep(CONFIG["request_delay_sec"] + 1)
            except Exception as inner_e:
                log.warning(f"Hudson Rock [{domain}]: {inner_e}")
    except Exception as e:
        log.error(f"Hudson Rock error: {e}")
    log.info(f"Hudson Rock: {len(rows)} infostealer-compromised .mil accounts found")
    return rows


def fetch_breachdirectory(api_key: str) -> list:
    """T1/T2 — FREE via RapidAPI. Dark web breach dump search for .mil emails."""
    rows = []
    targets = [("@army.mil", "US Army"), ("@navy.mil", "US Navy"),
               ("@af.mil", "US Air Force"), ("@nato.int", "NATO"),
               ("@marines.mil", "US Marines"), ("@mod.uk", "UK Ministry of Defence"),
               ("@bundeswehr.de", "German Bundeswehr"), ("@lockheedmartin.com", "Lockheed Martin"),
               ("@indianarmy.nic.in", "Indian Army"), ("@mod.gov.in", "Indian Ministry of Defence"),
               ("@mod.gov.pk", "Pakistan Ministry of Defence"), ("@mod.gov.cn", "China Ministry of National Defense"),
               ("@defence.gov.au", "Australia Defence"), ("@forces.gc.ca", "Canadian Armed Forces"),
               ("@mod.gov.il", "Israel Ministry of Defense"), ("@mod.gov.ua", "Ukraine Ministry of Defense")]
    headers = {"X-RapidAPI-Key": api_key, "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
               "Accept": "application/json"}
    try:
        for term, label in targets:
            try:
                resp = requests.get("https://breachdirectory.p.rapidapi.com/",
                                     params={"func": "auto", "term": term}, headers=headers, timeout=15)
                if resp.status_code == 401:
                    break
                if resp.status_code == 429:
                    break
                resp.raise_for_status()
                for r in (resp.json().get("result") or [])[:5]:
                    email = r.get("email") or r.get("username") or term
                    rows.append({
                        "threat_id":     f"T1-BD-{short_id(email + str(r.get('sources') or []))}",
                        "threat_name":   f"BreachDirectory — {label} Credential in Dark Web Dump",
                        "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                        "source_layer":  "Dark Web", "source": "BreachDirectory (dark web breach dumps)",
                        "post_text":     f"Email: {email} | Breach sources: {(r.get('sources') or [])[:3]} | "
                                         f"Has password/hash: {bool(r.get('password') or r.get('hash'))}",
                        "post_url":      f"https://breachdirectory.org/?query={email}",
                        "timestamp":     now_utc(), "location": "Unknown",
                        "severity":      "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "email", "ioc_value": email,
                        "tags":          f"breach-dump;dark-web;credential;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"BreachDirectory [{term}]: {inner_e}")
    except Exception as e:
        log.error(f"BreachDirectory error: {e}")
    log.info(f"BreachDirectory: {len(rows)} military credentials found in dark web dumps")
    return rows


def fetch_paste_leaks() -> list:
    """T1/T2 — FREE. psbdmp paste archive search for .mil credential leaks.

    Live-verified BOTH mirrors are dead: psbdmp.cc's homepage now reads
    "That's all folks." (an explicit shutdown notice) and forwards to
    psbdmp.ws, which no longer resolves via DNS at all. No quickly-verifiable
    replacement paste-search engine was found (the alternatives researched are
    paste-HOSTING services with creation APIs, not cross-paste search, or
    require their own separate account/setup) — flagging this honestly rather
    than forcing an unverified integration. The probe below used to treat ANY
    status < 500 (including psbdmp.cc's 404 on the actual search endpoint) as
    "this mirror is active", which is why this silently reported "0 found"
    instead of "source is dead" in every run."""
    rows = []
    PASTE_BASE_URLS = ["https://psbdmp.cc/api/v3/search", "https://psbdmp.ws/api/v3/search"]
    PASTE_QUERIES = [
        (".mil password", "Military Password Leak"),
        (".mil credentials", "Military Credential Exposure"),
        ("army.mil", "US Army Data in Pastes"),
        ("navy.mil", "US Navy Data in Pastes"),
        ("af.mil", "US Air Force Data in Pastes"),
        ("pentagon classified", "Pentagon Classified Data"),
        ("dod.gov api_key", "DoD API Key Exposure"),
        ("nato.int password", "NATO Credential Exposure"),
    ]
    active_base = None
    for candidate in PASTE_BASE_URLS:
        try:
            probe = requests.get(candidate, params={"q": "test", "limit": 1},
                                  headers={"User-Agent": "MilOSINT/2.0"}, timeout=8)
            # Require an actual 200 — a 404 (like psbdmp.cc's dead search
            # endpoint) used to pass this check since 404 < 500, making a
            # confirmed-dead mirror look "active" and silently return 0 rows.
            if probe.status_code == 200:
                active_base = candidate
                break
        except Exception:
            continue
    if not active_base:
        log.warning("Paste monitor: psbdmp.cc and psbdmp.ws are both dead (shutdown/unresolvable) — "
                    "0 found reflects a discontinued source, not an empty archive")
        return []
    try:
        for q, label in PASTE_QUERIES:
            try:
                resp = requests.get(active_base, params={"q": q, "limit": 8},
                                     headers={"User-Agent": "MilOSINT/2.0"}, timeout=12)
                if resp.status_code == 404:
                    continue
                if resp.status_code == 429:
                    time.sleep(30)
                    continue
                resp.raise_for_status()
                data = resp.json()
                items = data if isinstance(data, list) else (data.get("data") or data.get("results") or [])
                for item in items:
                    paste_id = item.get("id") or item.get("hash") or short_id(str(item))
                    snippet = str(item.get("text") or item.get("snippet") or "")
                    paste_host = active_base.split("/api/")[0]
                    paste_url = f"{paste_host}/{paste_id}"
                    rows.append({
                        "threat_id":     f"T1-PASTE-{short_id(paste_id + q)}",
                        "threat_name":   f"Paste Leak — {label}",
                        "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                        "source_layer":  "Deep Web", "source": "Paste Monitor (psbdmp)",
                        "post_text":     f"Query: {q} | Paste ID: {paste_id} | Snippet: {snippet[:250]}",
                        "post_url":      paste_url,
                        "timestamp":     str(item.get("time") or item.get("date") or now_utc()),
                        "location":      "Global", "severity": "CRITICAL", "confidence": "MEDIUM",
                        "ioc_type":      "url", "ioc_value": paste_url,
                        "tags":          f"paste;credential-leak;deep-web;military;{q.replace(' ','-')}",
                    })
            except Exception as inner_e:
                log.warning(f"Paste monitor [{q}]: {inner_e}")
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"Paste monitor error: {e}")
    log.info(f"Paste monitor: {len(rows)} paste leaks found")
    return rows


def fetch_snusbase(api_key: str) -> list:
    """T1/T2 — PAID ~$20/mo at snusbase.com. Dark web breach dump indexer."""
    rows = []
    targets = [("@army.mil", "US Army"), ("@navy.mil", "US Navy"), ("@af.mil", "US Air Force"),
               ("@marines.mil", "US Marines"), ("@nato.int", "NATO"), ("@defense.gov", "US Defense")]
    headers = {"Auth": api_key, "Content-Type": "application/json", "User-Agent": "MilOSINT/2.0"}
    try:
        for term, label in targets:
            try:
                resp = requests.post("https://api.snusbase.com/v3/search", headers=headers,
                                      json={"terms": [term], "types": ["email"], "wildcard": True}, timeout=15)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                for breach_name, entries in list((resp.json().get("results") or {}).items())[:3]:
                    for entry in (entries or [])[:3]:
                        email = entry.get("email") or term
                        rows.append({
                            "threat_id":     f"T1-SNS-{short_id(email + breach_name)}",
                            "threat_name":   f"Snusbase Dark Web Dump — {label}",
                            "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                            "source_layer":  "Dark Web", "source": "Snusbase (dark web breach dump indexer)",
                            "post_text":     f"Email: {email} | Breach: {breach_name} | "
                                             f"Has plaintext pw/hash: {bool(entry.get('password') or entry.get('hash'))}",
                            "post_url":      "https://snusbase.com",
                            "timestamp":     now_utc(), "location": "Unknown",
                            "severity":      "CRITICAL", "confidence": "HIGH",
                            "ioc_type":      "email", "ioc_value": email,
                            "tags":          f"snusbase;breach-dump;dark-web;{label.lower().replace(' ','-')}",
                        })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Snusbase [{term}]: {inner_e}")
    except Exception as e:
        log.error(f"Snusbase error: {e}")
    log.info(f"Snusbase: {len(rows)} military credentials in dark web dumps")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T2 | DATA & DOCUMENT LEAKAGE
# ═════════════════════════════════════════════════════════════════════════

def fetch_grayhatwarfare(api_key: str) -> list:
    """T2 — FREE signup at buckets.grayhatwarfare.com. Exposed cloud buckets.
    STRONG queries (army.mil, siprnet, itar...) are kept whenever the file
    isn't obvious media/web-asset junk. SOFT queries (pentagon, bundeswehr...)
    additionally require a sensitive file extension and no icon/meme/logo
    filename noise — this is what stops "Military-Medal.png" or a random
    news photo captioned "military parade" from being reported as a leak."""
    rows = []
    seen_urls: set = set()
    try:
        for tier, queries in (("strong", _GHW_STRONG_QUERIES), ("soft", _GHW_SOFT_QUERIES)):
            for q in queries:
                url = (f"https://buckets.grayhatwarfare.com/api/v2/files"
                       f"?keywords={requests.utils.quote(q)}&limit=10&access_token={api_key}")
                try:
                    resp = requests.get(url, timeout=15, headers={"User-Agent": "MilOSINT/2.0"})
                    resp.raise_for_status()
                except Exception as req_e:
                    log.warning(f"GrayhatWarfare [{q}]: {req_e}")
                    time.sleep(CONFIG["request_delay_sec"])
                    continue

                for f in resp.json().get("files") or []:
                    fname = f.get("filename") or ""
                    bucket = f.get("bucket") or ""
                    furl = f.get("url") or ""
                    # Live-verified the real API field is "size", not "filesize" —
                    # the old key name meant `size` was always 0, so the very next
                    # line (`if int(size) == 0: continue`) silently discarded
                    # EVERY result, before the extension/filename relevance
                    # filters ever got a chance to run. This is why this module
                    # reported 0 files found in every run tonight despite the API
                    # itself working fine and returning real matches (verified:
                    # 62 results for a plain "army.mil" keyword search).
                    size = f.get("size") or 0
                    raw_modified = f.get("lastModified")
                    if isinstance(raw_modified, (int, float)):
                        fdate = datetime.fromtimestamp(raw_modified, tz=timezone.utc).isoformat()
                    else:
                        fdate = f.get("date") or now_utc()

                    if furl and furl in seen_urls:
                        continue
                    try:
                        if int(size) == 0:
                            continue
                    except Exception:
                        pass
                    ext = Path(fname.lower()).suffix if fname else ""
                    if ext in _GHW_SKIP_EXTS:
                        continue
                    fname_low = fname.lower()
                    if any(t in fname_low for t in _GHW_NEG_FILENAME_TERMS):
                        continue
                    if tier == "soft" and ext not in _GHW_SENSITIVE_EXTS:
                        continue

                    if furl:
                        seen_urls.add(furl)

                    rows.append({
                        "threat_id":     f"T2-GHW-{short_id(furl or fname + bucket)}",
                        "threat_name":   "Exposed Cloud Bucket — Military/Defence File",
                        "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                        "source_layer":  "Deep Web", "source": "GrayhatWarfare",
                        "post_text":     f"File: {fname} | Bucket: {bucket} | Size: {size} bytes | Keyword: {q} | Tier: {tier}",
                        "post_url":      furl or f"https://buckets.grayhatwarfare.com/files?keywords={q}",
                        "timestamp":     str(fdate), "location": "Cloud",
                        "severity":      "HIGH" if tier == "strong" else "MEDIUM",
                        "confidence":    "HIGH" if tier == "strong" else "MEDIUM",
                        "ioc_type":      "url", "ioc_value": furl,
                        "tags":          f"cloud-bucket;exposed-data;{q.replace(' ','-')};grayhatwarfare;{tier}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"GrayhatWarfare error: {e}")
    log.info(f"GrayhatWarfare: {len(rows)} exposed bucket files found")
    return rows


def fetch_intelx_pastes(api_key: str, query: str = ".mil") -> list:
    """T2 — PAID ~$100/mo at intelx.io. Dark web paste/leak archive search."""
    rows = []
    try:
        payload = {"term": query, "maxresults": 20, "media": 0, "sort": 4}
        headers = {"x-key": api_key}
        resp = requests.post("https://2.intelx.io/intelligent/search", json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        search_id = resp.json().get("id")
        if not search_id:
            return rows
        time.sleep(2)
        resp2 = requests.get("https://2.intelx.io/intelligent/search/result",
                              params={"id": search_id, "limit": 20}, headers=headers, timeout=15)
        resp2.raise_for_status()
        for r in resp2.json().get("records", []):
            rows.append({
                "threat_id":     f"T2-IX-{short_id(r.get('systemid', ''))}",
                "threat_name":   "Defence Document/Data Leakage",
                "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                "source_layer":  "Deep Web", "source": "IntelligenceX",
                "post_text":     r.get("name", "")[:500],
                "post_url":      f"https://intelx.io/?did={r.get('systemid', '')}",
                "timestamp":     r.get("date", now_utc()), "location": r.get("bucket", "Unknown"),
                "severity":      "CRITICAL", "confidence": "MEDIUM",
                "ioc_type":      "file", "ioc_value": r.get("name", ""),
                "tags":          "document-leak;classified;intelx",
            })
        log.info(f"IntelX: {len(rows)} records for query '{query}'")
    except Exception as e:
        log.error(f"IntelX error: {e}")
    return rows


def fetch_leakix(api_key: str) -> list:
    """T2/T3 — FREE signup at leakix.net. Domain-gated: every query is filtered
    to a specific military host, so results only include that domain's assets."""
    rows = []
    _seen_services: set = set()
    LEAKIX_TARGETS = [
        ("host:army.mil", "US Army", "T2"), ("host:navy.mil", "US Navy", "T2"),
        ("host:af.mil", "US Air Force", "T2"), ("host:cybercom.mil", "US Cyber Command", "T3"),
        ("host:disa.mil", "DISA", "T3"), ("host:pentagon.mil", "Pentagon", "T2"),
        ("host:socom.mil", "US SOCOM", "T2"), ("host:dla.mil", "Defense Logistics Agency", "T3"),
        ("host:nsa.gov", "NSA / Intelligence", "T3"), ("host:nato.int", "NATO", "T2"),
        ("host:defense.gov", "US Defense.gov", "T2"), ("host:mod.uk", "UK Ministry of Defence", "T2"),
        ("host:bundeswehr.de", "German Bundeswehr", "T2"),
        ("host:indianarmy.nic.in", "Indian Army", "T2"), ("host:indiannavy.gov.in", "Indian Navy", "T2"),
        ("host:indianairforce.nic.in", "Indian Air Force", "T2"),
        ("host:mod.gov.in", "Indian Ministry of Defence", "T2"), ("host:drdo.gov.in", "DRDO", "T3"),
        ("host:pakistanarmy.gov.pk", "Pakistan Army", "T2"), ("host:paknavy.gov.pk", "Pakistan Navy", "T2"),
        ("host:paf.gov.pk", "Pakistan Air Force", "T2"), ("host:mod.gov.pk", "Pakistan Ministry of Defence", "T2"),
        ("host:mod.gov.cn", "China Ministry of National Defense", "T2"),
        ("host:forces.gc.ca", "Canadian Armed Forces", "T2"),
        ("host:mod.gov.il", "Israel Ministry of Defense", "T2"), ("host:idf.il", "Israel Defense Forces", "T2"),
        ("host:defense.gouv.fr", "France Ministry of Defense", "T2"),
        ("host:mod.go.jp", "Japan Ministry of Defense", "T2"),
        ("host:mnd.go.kr", "South Korea Ministry of National Defense", "T2"),
        ("host:mnd.gov.tw", "Taiwan Ministry of National Defense", "T2"),
        ("host:mod.gov.ua", "Ukraine Ministry of Defense", "T2"),
    ]
    headers = {"api-key": api_key, "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}
    try:
        for q, label, cat in LEAKIX_TARGETS:
            for scope in ("leak", "service"):
                url = f"https://leakix.net/search?scope={scope}&q={requests.utils.quote(q)}"
                try:
                    resp = requests.get(url, headers=headers, timeout=15)
                    if resp.status_code == 401:
                        return rows
                    if resp.status_code == 429:
                        time.sleep(5)
                        continue
                    resp.raise_for_status()
                    if not resp.text.strip():
                        continue  # LeakIX returns an empty 200 body (not "[]") for zero results — not an error
                    items = resp.json() or []
                    if not isinstance(items, list):
                        continue
                    target_domain = q.split("host:", 1)[1].strip() if "host:" in q else ""

                    for item in items[:4]:
                        plugin = item.get("plugin") or ""
                        summary = item.get("summary") or ""
                        host = item.get("host") or ""
                        ip = item.get("ip") or ""
                        port = item.get("port") or ""
                        country = (item.get("geoip") or {}).get("country_name") or "Unknown"
                        severity_raw = (item.get("severity") or "medium").upper()
                        sev = severity_raw if severity_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
                        cat_name = "Data & Document Leakage" if cat == "T2" else CATEGORY_NAMES["T3"]

                        if target_domain and target_domain not in host.lower():
                            continue
                        svc_key = f"{host}:{port}:{plugin}:{scope}"
                        if svc_key in _seen_services:
                            continue
                        _seen_services.add(svc_key)

                        cve_ids = re.findall(r"CVE-\d{4}-\d+", summary + " " + plugin, re.IGNORECASE)
                        if cve_ids:
                            sev = "CRITICAL"
                        summary_lower = summary.lower()
                        plugin_lower = plugin.lower()
                        finding_tags = []
                        # word-boundary: a bare "git" substring check matches inside
                        # "digital", "legitimate" etc.
                        if _has_any(summary_lower, {"git", "git-upload-pack"}) or _has_any(plugin_lower, {"git", "git-upload-pack"}) \
                           or ".git" in summary_lower or ".git" in plugin_lower:
                            finding_tags.append("git-exposure")
                        if any(k in summary_lower or k in plugin_lower for k in ("swagger", "openapi", "api-docs")):
                            finding_tags.append("api-spec-exposed")
                        if "phpinfo" in summary_lower:
                            finding_tags.append("phpinfo-exposed")
                        if any(k in summary_lower or k in plugin.lower() for k in ("kibana", "elasticsearch", "opensearch")):
                            finding_tags.append("search-engine-exposed")
                        if ".env" in summary_lower:
                            finding_tags.append("env-file-exposed")
                        if any(k in summary_lower for k in ("directory listing", "index of")):
                            finding_tags.append("directory-listing")

                        rows.append({
                            "threat_id":     f"{cat}-LIX-{short_id(host+str(port)+scope)}",
                            "threat_name":   f"LeakIX {scope.title()} — {label} — {plugin or 'Unknown Service'}",
                            "category_code": cat, "category_name": cat_name,
                            "source_layer":  "Deep Web", "source": "LeakIX",
                            "post_text":     f"Target: {label} | Host: {host}:{port} | Plugin: {plugin} | {summary[:250]}",
                            "post_url":      f"https://leakix.net/host/{ip}" if ip else "https://leakix.net",
                            "timestamp":     str(item.get("time") or now_utc()), "location": country,
                            "severity":      sev, "confidence": "HIGH",
                            "ioc_type":      "ip", "ioc_value": ip,
                            "tags":          (f"leakix;{scope};{label.lower().replace(' ','-')};military-infra"
                                               + (f";{';'.join(finding_tags)}" if finding_tags else "")
                                               + (";cve-tagged" if cve_ids else "")),
                        })
                    time.sleep(CONFIG["request_delay_sec"])
                except Exception as inner_e:
                    log.warning(f"LeakIX [{scope}] {q}: {inner_e}")
    except Exception as e:
        log.error(f"LeakIX error: {e}")
    log.info(f"LeakIX: {len(rows)} exposed services/leaks found")
    return rows


_TIER1_MIL_DOMAINS = (".mil", ".mod.uk", ".bundeswehr.de", ".nato.int",
                       ".defence.gov.au", ".forces.gc.ca", ".army.mil", ".navy.mil",
                       ".indianarmy.nic.in", ".indiannavy.gov.in", ".indianairforce.nic.in",
                       ".mod.gov.in", ".drdo.gov.in",
                       ".pakistanarmy.gov.pk", ".paknavy.gov.pk", ".paf.gov.pk",
                       ".mod.gov.pk", ".ispr.gov.pk",
                       ".mod.gov.cn", ".norinco.cn", ".spacechina.com", ".avic.com", ".cetc.com.cn",
                       ".mod.gov.il", ".idf.il", ".defense.gouv.fr", ".mod.go.jp",
                       ".mnd.go.kr", ".army.mil.kr", ".mnd.gov.tw",
                       ".mod.gov.ua", ".zsu.gov.ua", ".gur.gov.ua")
_TIER3_GENERIC_GOV_MARKER = ".gov"
_TIER2_CONTRACTORS = [
    "lockheed", "raytheon", "northrop", "boeing defense", "general dynamics",
    "bae systems", "leidos", "l3harris", "saic", "mantech", "booz allen",
    "caci", "peraton", "gdit", "curtiss-wright", "elbit", "rheinmetall",
    "leonardo", "thales", "saab", "kongsberg", "hanwha", "oshkosh defense",
    "parsons", "mitre", "rand corporation", "palantir", "csra", "dxc technology",
    "engility", "aecom federal", "pentagon", "ministry of defence",
    "armed forces", "cyber command", "defense intelligence", "naval air", "army corps",
    # Indian defence PSUs — full names used deliberately, not 3-4 letter
    # acronyms (hal/bel/bdl/grse) that would be far more collision-prone
    # even with word-boundary matching
    "hindustan aeronautics", "bharat electronics", "bharat dynamics",
    "mazagon dock", "garden reach shipbuilders", "beml limited",
    # Pakistani and Chinese defence contractors/SOEs — full names again,
    # avoiding short ambiguous acronyms (norinco/avic/cetc kept since they're
    # already distinctive enough proper nouns, unlike hal/bel/bdl were)
    "heavy industries taxila", "pakistan ordnance factories",
    "norinco", "china north industries", "china aerospace science and technology",
    "aviation industry corporation of china", "china electronics technology group",
    # New allied nations' defence contractors/ministries — full distinctive
    # names used deliberately, matching the established pattern above
    "rafael advanced defense", "israel aerospace industries", "dassault aviation",
    "naval group", "ministere des armees",
]


def fetch_ransomwatch() -> list:
    """T2 — FREE, no key. Ransomware leak-site victims, filtered to military/
    defence domains or known prime defence contractors.

    Was previously sourced from github.com/joshhighet/ransomwatch's posts.json.
    The user found the RansomWatch site "not working" and asked how we were
    still getting data from it — investigation found the GitHub repo itself
    is ARCHIVED (read-only) with no new posts since June 2025, over a year
    stale. Every "fresh" row from that source in every run this session was
    silently re-serving the same frozen historical snapshot, not live intel.
    Replaced with ransomware.live's public API, actively updated (verified
    live: victims discovered as recently as yesterday). Same tier logic as
    before; a live spot-check of the first full v2 run found bare ".gov"
    substring matching here was pulling in county tax offices, city transport
    authorities, and the US Federal Reserve as "CRITICAL Government/Military"
    — 41 of 158 CRITICAL rows in that run were exactly this, not military.
    Generic .gov victims are their own MEDIUM tier, clearly labeled as
    non-military, instead of being conflated with real military/defence hits."""
    rows = []
    _HIGH_PRIORITY_GROUPS = {
        "lockbit", "alphv", "blackcat", "clop", "cl0p", "revil", "darkside",
        "conti", "hive", "blackbasta", "akira", "play", "royal", "bianlian",
        "scattered spider", "ragnarlocker", "cuba", "lazarus", "volt typhoon",
        "salt typhoon", "silk typhoon", "vice society", "lorenz", "snatch",
        "rhysida", "medusa", "qilin", "wallstreet", "hunters international",
    }
    try:
        resp = requests.get("https://api.ransomware.live/v2/recentvictims",
                             headers={"User-Agent": "MilOSINT/2.0"}, timeout=25)
        resp.raise_for_status()
        posts = resp.json()
        if not isinstance(posts, list):
            return rows
        for post in posts:
            victim_name = post.get("victim") or ""
            domain      = (post.get("domain") or "").lower()
            title       = (victim_name + " " + domain).lower()
            group       = (post.get("group") or "Unknown").lower()
            display_group = post.get("group") or "Unknown"
            raw_ts      = post.get("discovered") or post.get("attackdate") or now_utc()

            if not any(g in group for g in _HIGH_PRIORITY_GROUPS):
                continue
            tier1_mil = any(d in title for d in _TIER1_MIL_DOMAINS)
            # word-boundary: "mitre"/"parsons"/"leonardo" are also a woodworking
            # tool, a common surname, and a common first name respectively
            tier2_contractor = _has_any(title, _TIER2_CONTRACTORS)
            tier3_generic_gov = (not tier1_mil) and (not tier2_contractor) and (
                _TIER3_GENERIC_GOV_MARKER in title or (post.get("activity") or "").lower() == "government"
            )
            if not (tier1_mil or tier2_contractor or tier3_generic_gov):
                continue

            if tier1_mil:
                sev, conf, tier_label, tag = "CRITICAL", "HIGH", "Military/Defence", "gov-military"
            elif tier2_contractor:
                sev, conf, tier_label, tag = "HIGH", "MEDIUM", "Defence Contractor", "contractor"
            else:
                sev, conf, tier_label, tag = "MEDIUM", "MEDIUM", "Government (non-military)", "government-sector"

            rows.append({
                "threat_id":     f"T2-RW-{short_id(victim_name + group)}",
                "threat_name":   f"Ransomware Victim — {display_group}",
                "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                "source_layer":  "Dark Web", "source": "ransomware.live (ransomware leak sites)",
                "post_text":     f"Ransomware Group: {display_group} | Victim: {victim_name} | "
                                 f"Tier: {tier_label} | Sector: {post.get('activity','')} | "
                                 f"Country: {post.get('country','')} | Discovered: {raw_ts}",
                "post_url":      post.get("url") or "https://www.ransomware.live/",
                "timestamp":     str(raw_ts), "location": post.get("country") or "Unknown",
                "severity":      sev, "confidence": conf,
                "ioc_type":      "url", "ioc_value": post.get("url") or f"darkweb://{group.replace(' ','-')}/{short_id(victim_name)}",
                "tags":          f"ransomware;dark-web;leak-site;{tag};{group.replace(' ','-')}",
            })
    except Exception as e:
        log.error(f"ransomware.live error: {e}")
    log.info(f"ransomware.live: {len(rows)} defense-sector ransomware victims found")
    return rows


def fetch_darkowl(api_key: str) -> list:
    """T2 — PAID enterprise at darkowl.com. Dark web content database."""
    rows = []
    QUERIES = [
        ("military classified leak", "Military Classified Data"),
        ("army navy airforce credentials", "Military Credentials"),
        ("NATO secret document", "NATO Classified Documents"),
        ("pentagon hack breach", "Pentagon Breach"),
        ("dod vulnerability exploit", "DoD Vulnerability"),
        ("defense contractor data dump", "Defense Contractor Leak"),
    ]
    try:
        for q, label in QUERIES:
            try:
                resp = requests.get("https://api.darkowl.com/api/v1/search",
                                     params={"query": q, "type": "text", "max_records": 5},
                                     headers={"X-DarkOwl-API-Key": api_key, "User-Agent": "MilOSINT/2.0"}, timeout=20)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                for r in resp.json().get("results") or []:
                    url_found = r.get("crawl_url") or r.get("url") or ""
                    rows.append({
                        "threat_id":     f"T2-DOW-{short_id(url_found + q)}",
                        "threat_name":   f"DarkOwl Dark Web Intel — {label}",
                        "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                        "source_layer":  "Dark Web", "source": "DarkOwl (dark web monitoring)",
                        "post_text":     f"Network: {r.get('network','dark_web')} | Query: {q} | "
                                         f"Snippet: {(r.get('text_snippet') or r.get('snippet') or '')[:300]}",
                        "post_url":      url_found or "https://app.darkowl.com",
                        "timestamp":     str(r.get("found_date") or r.get("first_observed") or now_utc()),
                        "location":      "Dark Web", "severity": "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": url_found,
                        "tags":          f"darkowl;dark-web;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"DarkOwl [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"DarkOwl error: {e}")
    log.info(f"DarkOwl: {len(rows)} dark web military mentions found")
    return rows


def fetch_flashpoint(api_key: str) -> list:
    """T2 — PAID enterprise at flashpoint.io. Closed hacker forums & markets."""
    rows = []
    QUERIES = [
        ("military cyber breach", "Military Cyber Breach"),
        ("army credentials for sale", "Military Credentials Market"),
        ("nato classified documents", "NATO Intel on Forums"),
        ("dod hack pentagon", "DoD/Pentagon Breach Forum"),
        ("defense contractor insider", "Defense Contractor Threat"),
        ("military supply chain attack", "Military Supply Chain"),
    ]
    try:
        for q, label in QUERIES:
            try:
                resp = requests.get("https://fp.tools/api/v4/documents",
                                     params={"query": q, "size": 5, "sort_date": "desc"},
                                     headers={"Authorization": f"Bearer {api_key}", "User-Agent": "MilOSINT/2.0"}, timeout=20)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                for item in resp.json().get("hits") or []:
                    doc_id = item.get("_id") or ""
                    src = item.get("_source") or {}
                    title = src.get("title") or src.get("container", {}).get("title") or q
                    rows.append({
                        "threat_id":     f"T2-FP-{short_id(doc_id + q)}",
                        "threat_name":   f"Flashpoint Dark Web — {label}",
                        "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                        "source_layer":  "Dark Web", "source": "Flashpoint (dark web intelligence)",
                        "post_text":     f"Title: {title[:100]} | Category: {src.get('site_tags') or []} | "
                                         f"{(src.get('body', {}).get('text/plain') or src.get('summary') or '')[:300]}",
                        "post_url":      f"https://app.flashpoint.io/documents/{doc_id}",
                        "timestamp":     str(src.get("date_extracted") or src.get("timestamp") or now_utc()),
                        "location":      "Dark Web", "severity": "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": f"flashpoint://{doc_id}",
                        "tags":          f"flashpoint;dark-web;forum;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Flashpoint [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"Flashpoint error: {e}")
    log.info(f"Flashpoint: {len(rows)} dark web military intelligence entries")
    return rows


_TORCH_RESULT_RE = re.compile(
    r'<td><b><a href="([^"]+)">(.*?)</a></b><br>\s*<small>(.*?)</small>', re.DOTALL
)


def fetch_tor_onion() -> list:
    """T2/T6 — FREE. Torch (.onion search engine) dark web search via local
    Tor SOCKS5 proxy — requires Tor to be running (Torch has no legitimate
    clearnet mirror).

    Replaced the previous Ahmia-based version of this module after live
    verification found EVERY query to https://ahmia.fi/search/?q=... (and the
    equivalent .onion path) returns a 302 redirect straight to the homepage
    regardless of query content — confirmed with high-volume generic terms
    ("market", "wiki") that would certainly have real matches if search were
    functioning. Ahmia's public search has evidently been disabled/gated
    against non-browser clients; this is why this module found 0 results in
    EVERY historical run (not query specificity — a real, longstanding gap in
    a tool that's supposed to be dark-web-focused). Torch's Omega CGI search
    interface was live-verified instead: returns real indexed results
    (tested "market": ~59,767 matches; "pentagon leak": ~40 matches,
    including an actual dark-web forum thread about a Pentagon security leak).
    Torch is uncensored/uncurated (unlike Ahmia's moderated index), so results
    go through the same relevance_check() gate as every other keyword-search
    module here, not just the AND-matched query terms."""
    rows = []
    tor_enabled = CONFIG.get("tor_enabled", False)
    tor_port = int(CONFIG.get("tor_socks_port", 9050))
    if not tor_enabled:
        log.warning("Dark web search: tor_enabled is False — Torch has no clearnet mirror, skipping")
        return rows
    proxies = {"http": f"socks5h://127.0.0.1:{tor_port}", "https": f"socks5h://127.0.0.1:{tor_port}"}
    try:
        chk = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=15)
        if not chk.json().get("IsTor", False):
            log.warning("Tor: proxy responding but NOT routing through Tor — skipping dark web search")
            return rows
        log.info(f"Tor: verified real routing via exit node {chk.json().get('IP','?')}")
    except Exception as tor_chk_e:
        log.warning(f"Tor: cannot reach SOCKS5 on port {tor_port} ({tor_chk_e}) — skipping dark web search")
        return rows

    QUERIES = [
        ("army.mil credentials", "T1", "Military Credential Exposure"),
        ("nato classified leak", "T2", "NATO Classified Leak"),
        ("pentagon hack breach", "T2", "Pentagon Breach Mention"),
        ("military apt nation state", "T6", "Nation-State APT Mention"),
        ("defense contractor database", "T2", "Defense Contractor Data"),
        ("dod.gov exploit", "T7", "DoD Exploit Mention"),
    ]
    TORCH_URL = "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega"
    seen_urls: set = set()
    for q, cat, label in QUERIES:
        try:
            resp = requests.get(TORCH_URL, params={"P": q}, proxies=proxies,
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
                                 timeout=50)
            resp.raise_for_status()
            kept = 0
            for link, raw_title, raw_snippet in _TORCH_RESULT_RE.findall(resp.text):
                if kept >= 4:
                    break
                if link in seen_urls:
                    continue
                title = re.sub(r'<[^>]+>', '', raw_title).strip()
                snippet = re.sub(r'<[^>]+>', '', raw_snippet).strip()
                # min_weak=2: Torch is a fully uncurated/uncensored index (unlike
                # the defense-specific RSS outlets elsewhere in this tool), so a
                # single incidental term match is weak evidence — e.g. a Tor-
                # mirrored investigative-journalism piece that happens to
                # mention "national security" once. Strong-tier matches
                # (military domains, contractor/APT names) are unaffected —
                # they bypass this threshold entirely.
                passes, tier, reason = relevance_check(title + " " + snippet, min_weak=2)
                if not passes:
                    continue
                seen_urls.add(link)
                kept += 1
                rows.append({
                    "threat_id":     f"{cat}-TOR-{short_id(link + q)}",
                    "threat_name":   f"Dark Web Search (Torch .onion) — {label}",
                    "category_code": cat, "category_name": CATEGORY_NAMES.get(cat, CATEGORY_NAMES["T2"]),
                    "source_layer":  "Dark Web", "source": "Torch dark web search (.onion)",
                    "post_text":     f"Query: {q} | Title: {(title or link)[:100]} | Snippet: {snippet[:200]} | URL: {link[:120]}",
                    "post_url":      link, "timestamp": now_utc(), "location": "Dark Web",
                    "severity":      "HIGH" if tier == "strong" else "MEDIUM",
                    "confidence":    "HIGH" if tier == "strong" else "MEDIUM",
                    "ioc_type":      "url", "ioc_value": link,
                    "tags":          f"dark-web;torch;onion-search;{reason};{q.replace(' ','-')}",
                })
            time.sleep(CONFIG["request_delay_sec"] + 2)
        except Exception as inner_e:
            log.warning(f"Tor/Torch [{q}]: {inner_e}")
    log.info(f"Dark web search (Torch .onion): {len(rows)} military-relevant results found")
    return rows


def fetch_telethon_private() -> list:
    """T2/T8 — FREE with a Telegram account + API credentials (my.telegram.org).
    Reads PRIVATE Telegram channels the public t.me scraper cannot access.
    Only add channels you have legitimate access to."""
    try:
        from telethon.sync import TelegramClient  # type: ignore
    except ImportError:
        log.warning("Telethon SKIPPED — install with: pip install telethon")
        return []

    api_id = CONFIG.get("telegram_api_id", "")
    api_hash = CONFIG.get("telegram_api_hash", "")
    phone = CONFIG.get("telegram_phone", "")
    channels = CONFIG.get("telegram_private_channels", [])
    if not all([api_id, api_hash, phone]) or not channels:
        log.warning("Telethon SKIPPED — fill telegram_api_id/hash/phone + telegram_private_channels in CONFIG")
        return []

    session_file = "osint_telegram_v2"
    if not Path(session_file + ".session").exists() and not sys.stdin.isatty():
        log.warning("Telethon SKIPPED — no session file. Run once from a terminal to authenticate.")
        return []

    rows = []
    try:
        client = TelegramClient(session_file, int(api_id), api_hash)
        client.connect()
        if not client.is_user_authorized():
            client.send_code_request(phone)
            code = input("Telegram verification code (check your app/SMS): ").strip()
            client.sign_in(phone, code)

        for channel in channels:
            try:
                entity = client.get_entity(channel)
                messages = client.get_messages(entity, limit=40)
                chan_name = getattr(entity, "title", str(channel))
                chan_user = getattr(entity, "username", str(channel))
                for msg in messages:
                    if not msg.text:
                        continue
                    passes, tier, reason = relevance_check(msg.text, weak_terms=WEAK_MIL_TERMS, min_weak=2)
                    if not passes:
                        continue
                    sev = "CRITICAL" if any(k in msg.text.lower() for k in
                          ("breach", "credentials", "leak", "dump", "classified", "zero day")) else "HIGH"
                    rows.append({
                        "threat_id":     f"T2-TGP-{short_id(str(msg.id) + str(channel))}",
                        "threat_name":   f"Telegram Private — {chan_name[:40]}",
                        "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
                        "source_layer":  "Dark Web", "source": f"Telegram Private (Telethon) — {chan_name}",
                        "post_text":     f"Channel: {chan_name} | Sender: {msg.sender_id or 'Unknown'} | {msg.text[:400]}",
                        "post_url":      f"https://t.me/{chan_user}",
                        "timestamp":     str(msg.date) if msg.date else now_utc(),
                        "location":      "Unknown", "severity": sev, "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": f"tg://{chan_user}",
                        "tags":          f"telegram-private;telethon;dark-web;{reason}",
                    })
                time.sleep(2)
            except Exception as chan_e:
                log.warning(f"Telethon [{channel}]: {chan_e}")
        client.disconnect()
    except Exception as e:
        log.error(f"Telethon error: {e}")
    log.info(f"Telethon private channels: {len(rows)} military-relevant messages found")
    return rows


def fetch_cybersixgill(client_id: str, client_secret: str) -> list:
    """T2 — PAID enterprise at cybersixgill.com. 6,000+ dark web sources."""
    rows = []
    try:
        token_resp = requests.post("https://api.cybersixgill.com/auth/token",
                                    json={"client_id": client_id, "client_secret": client_secret},
                                    headers={"User-Agent": "MilOSINT/2.0"}, timeout=15)
        if token_resp.status_code in (401, 403):
            return rows
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token", "")
        if not token:
            return rows
        headers = {"Authorization": f"Bearer {token}", "User-Agent": "MilOSINT/2.0", "Content-Type": "application/json"}
        QUERIES = [
            ("army.mil OR navy.mil OR pentagon classified", "T2", "Military Classified Data"),
            ("NATO military breach credentials sale", "T1", "NATO Credential Leak"),
            ("dod.gov defense contractor hack dump", "T2", "DoD/Contractor Breach"),
            ("military apt exploit zero-day nation state", "T6", "Military APT Activity"),
        ]
        for q, cat, label in QUERIES:
            try:
                resp = requests.post("https://api.cybersixgill.com/intel/v2/items", headers=headers,
                                      json={"query": q, "limit": 5, "sort": "date", "order": "desc"}, timeout=20)
                resp.raise_for_status()
                for item in resp.json().get("items") or []:
                    item_id = item.get("id") or ""
                    site = (item.get("source") or {}).get("name") or "Unknown"
                    rows.append({
                        "threat_id":     f"{cat}-CSG-{short_id(item_id + q)}",
                        "threat_name":   f"Cybersixgill — {label}",
                        "category_code": cat, "category_name": CATEGORY_NAMES.get(cat, CATEGORY_NAMES["T2"]),
                        "source_layer":  "Dark Web", "source": f"Cybersixgill ({site})",
                        "post_text":     f"Source: {site} | Title: {(item.get('title') or q)[:100]} | {(item.get('content') or '')[:300]}",
                        "post_url":      f"https://portal.cybersixgill.com/dashboard/items/{item_id}",
                        "timestamp":     str(item.get("date") or now_utc()), "location": "Dark Web",
                        "severity":      "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": f"cybersixgill://{item_id}",
                        "tags":          f"cybersixgill;dark-web;closed-forum;{site.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Cybersixgill [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"Cybersixgill error: {e}")
    log.info(f"Cybersixgill: {len(rows)} dark web military intel items found")
    return rows


def fetch_kela_radark(api_key: str) -> list:
    """T2/T6 — PAID enterprise at ke-la.com. Eastern European dark web forums."""
    rows = []
    QUERIES = [
        ("military credentials", "T1", "Military Credentials on Dark Web"),
        ("NATO breach classified", "T2", "NATO Classified Breach"),
        ("army.mil navy.mil", "T2", "US Military Domain Exposure"),
        ("apt nation state military", "T6", "Nation-State APT Activity"),
        ("defense contractor data dump", "T2", "Defense Contractor Data Leak"),
    ]
    headers = {"Authorization": f"token {api_key}", "User-Agent": "MilOSINT/2.0", "Accept": "application/json"}
    try:
        for q, cat, label in QUERIES:
            try:
                resp = requests.get("https://api.ke-la.com/v1/search",
                                     params={"q": q, "limit": 5, "sort": "-date"}, headers=headers, timeout=20)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                for item in resp.json().get("results") or []:
                    item_id = item.get("id") or ""
                    source = item.get("source") or "Unknown"
                    rows.append({
                        "threat_id":     f"{cat}-KELA-{short_id(item_id + q)}",
                        "threat_name":   f"KELA RaDark — {label}",
                        "category_code": cat, "category_name": CATEGORY_NAMES.get(cat, CATEGORY_NAMES["T2"]),
                        "source_layer":  "Dark Web", "source": f"KELA RaDark ({source})",
                        "post_text":     f"Source: {source} | Title: {(item.get('title') or q)[:100]} | "
                                         f"{(item.get('snippet') or item.get('content') or '')[:300]}",
                        "post_url":      f"https://radar.ke-la.com/item/{item_id}",
                        "timestamp":     str(item.get("date") or item.get("timestamp") or now_utc()),
                        "location":      "Dark Web", "severity": "CRITICAL", "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": f"kela://{item_id}",
                        "tags":          f"kela;radark;dark-web;eastern-european;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"KELA [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"KELA RaDark error: {e}")
    log.info(f"KELA RaDark: {len(rows)} Eastern European dark web intel items found")
    return rows


def fetch_spycloud(api_key: str) -> list:
    """T1 — PAID ~$500+/mo at spycloud.com. Infostealer log recapture."""
    rows = []
    domains = CONFIG.get("hudson_rock_domains") or ["army.mil", "navy.mil", "af.mil"]
    headers = {"X-API-Key": api_key, "User-Agent": "MilOSINT/2.0", "Accept": "application/json"}
    try:
        for domain in domains:
            try:
                resp = requests.get(f"https://api.spycloud.io/enterprise-v2/breach/data/domains/{domain}",
                                     headers=headers, params={"severity_filter": 25, "since": "90d", "limit": 5}, timeout=20)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                for r in resp.json().get("results") or []:
                    email = r.get("email") or r.get("username") or ""
                    severity = r.get("severity") or 0
                    rows.append({
                        "threat_id":     f"T1-SPC-{short_id(email + (r.get('source_id') or ''))}",
                        "threat_name":   f"SpyCloud Breach Record — {domain}",
                        "category_code": "T1", "category_name": CATEGORY_NAMES["T1"],
                        "source_layer":  "Dark Web", "source": "SpyCloud (dark web breach recapture)",
                        "post_text":     f"Domain: {domain} | Email: {email} | "
                                         f"Has pw/cookie: {bool(r.get('password') or r.get('target_url'))} | "
                                         f"Breach source ID: {r.get('source_id','')} | Severity: {severity}/100",
                        "post_url":      "https://portal.spycloud.com",
                        "timestamp":     str(r.get("breach_date") or r.get("spycloud_publish_date") or now_utc()),
                        "location":      "Unknown", "severity": "CRITICAL" if severity >= 50 else "HIGH",
                        "confidence":    "HIGH", "ioc_type": "email", "ioc_value": email,
                        "tags":          f"spycloud;infostealer;dark-web;breach;{domain};severity-{severity}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"SpyCloud [{domain}]: {inner_e}")
    except Exception as e:
        log.error(f"SpyCloud error: {e}")
    log.info(f"SpyCloud: {len(rows)} military breach records recaptured from dark web")
    return rows


def fetch_digital_shadows(api_key: str, api_secret: str) -> list:
    """T2/T8 — PAID ~$800+/mo (ReliaQuest SearchLight). Dark web org-mention monitor."""
    rows = []
    creds = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "User-Agent": "MilOSINT/2.0",
               "Accept": "application/json", "Content-Type": "application/json"}
    QUERIES = [
        ("army.mil", "T2", "US Army Domain Mention"),
        ("nato classified", "T2", "NATO Classified Mention"),
        ("pentagon breach", "T2", "Pentagon Breach Mention"),
        ("defense contractor hack", "T2", "Defense Contractor Hack"),
    ]
    try:
        for q, cat, label in QUERIES:
            try:
                resp = requests.post("https://api.searchlight.app/v1/incidents", headers=headers,
                                      json={"filter": {"fullText": q}, "pagination": {"size": 5}}, timeout=20)
                if resp.status_code in (401, 403):
                    return rows
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("content") or data.get("incidents") or []:
                    item_id = item.get("id") or ""
                    sev_ds = (item.get("severity") or {}).get("type") or "medium"
                    sev = "CRITICAL" if "very_high" in sev_ds.lower() else ("HIGH" if "high" in sev_ds.lower() else "MEDIUM")
                    rows.append({
                        "threat_id":     f"{cat}-DS-{short_id(str(item_id) + q)}",
                        "threat_name":   f"Digital Shadows — {label}",
                        "category_code": cat, "category_name": CATEGORY_NAMES["T2"],
                        "source_layer":  "Dark Web", "source": "Digital Shadows SearchLight",
                        "post_text":     f"Type: {item.get('type') or item.get('classification') or 'Unknown'} | "
                                         f"Title: {(item.get('title') or item.get('description') or q)[:150]} | Severity: {sev_ds}",
                        "post_url":      f"https://portal.searchlight.app/incidents/{item_id}",
                        "timestamp":     str(item.get("occurred") or item.get("raised") or now_utc()),
                        "location":      "Dark Web", "severity": sev, "confidence": "HIGH",
                        "ioc_type":      "url", "ioc_value": f"searchlight://{item_id}",
                        "tags":          f"digital-shadows;dark-web;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Digital Shadows [{q}]: {inner_e}")
    except Exception as e:
        log.error(f"Digital Shadows error: {e}")
    log.info(f"Digital Shadows: {len(rows)} dark web military mentions found")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T3 | COMMUNICATION & NETWORK ATTACKS
# ═════════════════════════════════════════════════════════════════════════

def fetch_shodan_military(api_key: str) -> list:
    """T3 — PAID $69/mo at shodan.io. Exposed military network infrastructure."""
    rows = []
    queries = [
        ('org:"US Army"', "US Army exposed infrastructure"),
        ('org:"US Navy"', "US Navy exposed infrastructure"),
        ('org:"Ministry of Defence"', "UK MoD exposed infrastructure"),
        ('ssl.cert.subject.cn:*.mil port:443', "Military TLS/HTTPS endpoints"),
        ('product:"Cisco AnyConnect" org:"Department of Defense"', "DoD VPN endpoints"),
    ]
    for q, label in queries:
        try:
            resp = requests.get("https://api.shodan.io/shodan/host/search",
                                 params={"key": api_key, "query": q, "limit": 10}, timeout=15)
            resp.raise_for_status()
            for m in resp.json().get("matches", []):
                ip = m.get("ip_str", "")
                rows.append({
                    "threat_id":     f"T3-SHD-{short_id(ip + str(m.get('port','')))}",
                    "threat_name":   label,
                    "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                    "source_layer":  "Deep Web", "source": "Shodan",
                    "post_text":     f"Org: {m.get('org','')} | Port: {m.get('port','')} | Banner: {str(m.get('data',''))[:300]}",
                    "post_url":      f"https://www.shodan.io/host/{ip}",
                    "timestamp":     m.get("timestamp", now_utc()),
                    "location":      m.get("location", {}).get("country_name", "Unknown"),
                    "severity":      "HIGH", "confidence": "HIGH",
                    "ioc_type":      "ip", "ioc_value": ip,
                    "tags":          "network;exposed;shodan",
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"Shodan error [{q}]: {e}")
    log.info(f"Shodan: {len(rows)} exposed military assets found")
    return rows


def fetch_securitytrails(api_key: str) -> list:
    """T3 — PAID $50/mo at securitytrails.com. Military subdomain/DNS intel."""
    rows = []
    domains = ["army.mil", "navy.mil", "af.mil", "marines.mil", "dod.gov", "nato.int",
               "mod.uk", "bundeswehr.de", "defence.gov.au", "forces.gc.ca",
               "mod.gov.in", "mod.gov.pk", "mod.gov.cn",
               "mod.gov.il", "defense.gouv.fr", "mod.go.jp", "mnd.go.kr", "mnd.gov.tw", "mod.gov.ua"]
    headers = {"APIKEY": api_key, "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}
    try:
        for domain in domains:
            resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                                 f"?children_only=false&include_inactive=true", headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            subdomains = data.get("subdomains") or []
            total = data.get("subdomain_count") or len(subdomains)
            for sub in subdomains[:10]:
                fqdn = f"{sub}.{domain}"
                rows.append({
                    "threat_id":     f"T3-STR-{short_id(fqdn)}",
                    "threat_name":   f"Military Domain Intelligence — {domain}",
                    "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                    "source_layer":  "Deep Web", "source": "SecurityTrails",
                    "post_text":     f"Subdomain: {fqdn} | Parent: {domain} | Total subdomains found: {total}",
                    "post_url":      f"https://securitytrails.com/domain/{domain}/dns",
                    "timestamp":     now_utc(), "location": domain_to_country(domain),
                    "severity":      "MEDIUM", "confidence": "HIGH",
                    "ioc_type":      "domain", "ioc_value": fqdn,
                    "tags":          f"dns;subdomain;military-infra;securitytrails;{domain}",
                })
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"SecurityTrails error: {e}")
    log.info(f"SecurityTrails: {len(rows)} military subdomains/DNS records found")
    return rows


def fetch_censys(api_id: str, api_secret: str = "") -> list:
    """T3 — FREE 250 queries/mo at censys.io. Military ASN internet scan."""
    rows = []
    if api_id.startswith("censys_"):
        creds = base64.b64encode(f"{api_id}:".encode()).decode()
    else:
        creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json", "User-Agent": "MilOSINT/2.0"}
    queries = [
        ('autonomous_system.organization: "US Army"', "US Army"),
        ('autonomous_system.organization: "US Navy"', "US Navy"),
        ('autonomous_system.organization: "US Air Force"', "US Air Force"),
        ('autonomous_system.organization: "NATO"', "NATO"),
        ('services.tls.certificates.leaf_data.subject.organization: "U.S. Army"', "US Army TLS"),
    ]
    try:
        for query, label in queries:
            resp = requests.post("https://search.censys.io/api/v2/hosts/search", headers=headers,
                                  json={"q": query, "per_page": 10,
                                        "fields": ["ip", "services.port", "services.service_name",
                                                   "location.country", "autonomous_system.organization"]},
                                  timeout=20)
            resp.raise_for_status()
            for hit in resp.json().get("result", {}).get("hits") or []:
                ip = hit.get("ip") or ""
                services = hit.get("services") or []
                org = (hit.get("autonomous_system") or {}).get("organization") or label
                svc_str = ", ".join(f"{s.get('service_name','?')}:{s.get('port','?')}" for s in services[:5])
                rows.append({
                    "threat_id":     f"T3-CNS-{short_id(ip)}",
                    "threat_name":   f"Exposed Military Network Asset — {org}",
                    "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                    "source_layer":  "Deep Web", "source": "Censys",
                    "post_text":     f"IP: {ip} | Org: {org} | Services: {svc_str} | Query: {label}",
                    "post_url":      f"https://search.censys.io/hosts/{ip}",
                    "timestamp":     now_utc(), "location": (hit.get("location") or {}).get("country") or "Unknown",
                    "severity":      "HIGH", "confidence": "HIGH",
                    "ioc_type":      "ip", "ioc_value": ip,
                    "tags":          f"exposed-asset;network;censys;military-infra;{label.lower().replace(' ','-')}",
                })
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"Censys error: {e}")
    log.info(f"Censys: {len(rows)} exposed military network assets found")
    return rows


# Module-level (not local to fetch_crtsh) so clean_existing_csv() can also
# retroactively drop personal DoD CAC certificate names (e.g.
# "KUBIK.WILLIAM.III.1022938017") that leaked into the master CSV from before
# this filter existed — those are personal identifiers, not infrastructure
# findings, and don't belong in a certificate-transparency threat feed.
_PERSONAL_CERT_RE = re.compile(r'^[A-Z][A-Z.\-]+\.[A-Z]+\.\d{7,}$')


def fetch_crtsh() -> list:
    """T3 — FREE, no key. Certificate transparency logs for .mil/.gov domains —
    reveals hidden subdomains/attack surface not discoverable via plain DNS."""
    rows = []
    targets = [
        ("%.af.mil", "Air Force Subdomains"), ("%.navy.mil", "Navy Subdomains"),
        ("%.army.mil", "Army Subdomains"), ("%.disa.mil", "DISA (Defence Info Systems)"),
        ("%.cybercom.mil", "US Cyber Command"), ("%.socom.mil", "SOCOM Subdomains"),
        # India — adds ~2-3 min to this module's runtime (crt.sh's own
        # rate-limit backoff makes each domain slow), but this was the only
        # source with zero India targeting at all before this pass.
        ("%.indianarmy.nic.in", "Indian Army Subdomains"),
        ("%.indiannavy.gov.in", "Indian Navy Subdomains"),
        ("%.indianairforce.nic.in", "Indian Air Force Subdomains"),
        ("%.mod.gov.in", "Indian MoD Subdomains"),
        ("%.drdo.gov.in", "DRDO Subdomains"),
        # Pakistan/China — kept to 2 domains each (not the full 5, like India
        # got) specifically to limit how much further this already-slow
        # module's runtime grows; crt.sh's own rate-limit backoff is the
        # bottleneck, not anything on our end.
        ("%.pakistanarmy.gov.pk", "Pakistan Army Subdomains"),
        ("%.mod.gov.pk", "Pakistan MoD Subdomains"),
        ("%.mod.gov.cn", "China MoD Subdomains"),
        ("%.avic.com", "AVIC Subdomains"),
        # Coverage-gap fill (Canada/Australia/Germany already have MIL_DOMAIN_SUFFIXES
        # entries but were missing from this source) + 6 new countries — kept to
        # ONE domain per country to bound this already rate-limited module's runtime.
        ("%.forces.gc.ca", "Canada Forces Subdomains"),
        ("%.defence.gov.au", "Australia Defence Subdomains"),
        ("%.bundeswehr.de", "Germany Bundeswehr Subdomains"),
        ("%.mod.gov.il", "Israel MoD Subdomains"),
        ("%.defense.gouv.fr", "France Defense Subdomains"),
        ("%.mod.go.jp", "Japan MoD Subdomains"),
        ("%.mnd.go.kr", "South Korea MND Subdomains"),
        ("%.mnd.gov.tw", "Taiwan MND Subdomains"),
        ("%.mod.gov.ua", "Ukraine MoD Subdomains"),
    ]

    def _crtsh_fetch(q: str) -> list:
        for attempt in range(3):
            try:
                r = requests.get("https://crt.sh/", params={"q": q, "output": "json"},
                                  headers={"User-Agent": "MilOSINT/2.0", "Accept": "application/json"}, timeout=40)
                if r.status_code == 404:
                    return []
                if r.status_code in (429, 500, 502, 503, 504):
                    if attempt < 2:
                        time.sleep(10 if r.status_code == 429 else 5)
                        continue
                    return []
                r.raise_for_status()
                if "json" not in r.headers.get("Content-Type", ""):
                    if attempt < 2:
                        time.sleep(6)
                        continue
                    return []
                return r.json() or []
            except (requests.exceptions.Timeout, requests.exceptions.JSONDecodeError):
                if attempt < 2:
                    time.sleep(5)
                    continue
                return []
            except Exception as exc:
                log.warning(f"crt.sh error for {q!r}: {type(exc).__name__}: {exc}")
                return []
        return []

    _SENSITIVE_PREFIXES = {
        "vpn", "remote", "portal", "gateway", "citrix", "rdweb", "gitlab", "github",
        "git", "confluence", "jira", "wiki", "kibana", "jenkins", "sonarqube", "nexus",
        "artifactory", "admin", "internal", "intranet", "mgmt", "management", "mail",
        "webmail", "owa", "exchange", "smtp", "api", "dev", "staging", "test", "qa",
        "uat", "sso", "idp", "ldap", "auth", "login", "ftp", "sftp", "backup",
        "archive", "camera", "cctv", "scada", "ics", "plc",
    }
    _today = datetime.now(timezone.utc).date()

    for domain, label in targets:
        try:
            certs = _crtsh_fetch(domain)
            if not certs:
                continue
            seen_cn = set()
            for cert in certs[:200]:
                cn = (cert.get("common_name") or cert.get("name_value") or "").split("\n")[0].strip()
                if cn in seen_cn or not cn:
                    continue
                if "EMAIL CA" in (cert.get("issuer_name") or "") or _PERSONAL_CERT_RE.match(cn):
                    continue
                seen_cn.add(cn)

                expires = cert.get("not_after") or ""
                is_wild = cn.startswith("*.")
                subdomain = cn.split(".")[0].lower().lstrip("*").lstrip(".")
                is_sensitive = subdomain in _SENSITIVE_PREFIXES
                is_expired = False
                if expires:
                    try:
                        is_expired = datetime.fromisoformat(expires.replace("Z", "+00:00")).date() < _today
                    except Exception:
                        pass

                if is_wild:
                    sev, note = "CRITICAL", "WILDCARD CERT — leaked private key would be catastrophic"
                elif is_expired:
                    sev, note = "HIGH", f"EXPIRED CERT (expired {expires[:10]}) — misconfiguration on military host"
                elif is_sensitive:
                    sev, note = "HIGH", f"SENSITIVE SUBDOMAIN ({subdomain}) — exposed attack surface"
                else:
                    sev, note = "MEDIUM", ""

                cert_id = str(cert.get("id") or short_id(cn))
                rows.append({
                    "threat_id":     f"T3-CRT-{short_id(cert_id + cn)}",
                    "threat_name":   f"Cert Transparency — {label}",
                    "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                    "source_layer":  "Surface Web", "source": "crt.sh (Certificate Transparency)",
                    "post_text":     (f"Domain: {cn} | Issued: {cert.get('not_before') or now_utc()} | Expires: {expires} | "
                                      f"Issuer: {(cert.get('issuer_name') or '')[:80]} | Wildcard: {is_wild} | "
                                      f"Expired: {is_expired} | {note}"),
                    "post_url":      f"https://crt.sh/?id={cert_id}",
                    "timestamp":     str(cert.get("not_before") or now_utc()), "location": domain_to_country(cn),
                    "severity":      sev, "confidence": "HIGH" if (is_wild or is_sensitive or is_expired) else "MEDIUM",
                    "ioc_type":      "domain", "ioc_value": cn,
                    "tags":          (f"ssl;certificate;military-domain;crtsh;"
                                      f"{'wildcard' if is_wild else ''}{'expired' if is_expired else ''}"
                                      f"{'sensitive-subdomain' if is_sensitive else ''}").rstrip(";"),
                })
                if len(seen_cn) >= 20:
                    break
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"crt.sh parse error [{label}]: {e}")
    log.info(f"crt.sh: {len(rows)} military SSL certificates/subdomains found")
    return rows


def fetch_zoomeye(api_key: str) -> list:
    """T3 — FREE-tier internet-wide scanner (zoomeye.ai).

    Rewritten after live verification found the old api.zoomeye.org/host/search
    (GET, plaintext query) endpoint outright rejects requests with "this
    service not aviliable in your area, please use api.zoomeye.ai instead" —
    ZoomEye has migrated to a new domain and a new v2 API (POST to
    api.zoomeye.ai/v2/search with a base64-encoded query in a "qbase64" field,
    response data under a "data" array — confirmed against ZoomEye's own
    current API docs). The old code could never have worked regardless of
    credits; it was hitting a dead endpoint.
    Caveat: this account's own /resources-info endpoint reports 3000 free
    search credits available this month, yet /v2/search still returns
    "credits_insufficient" even for the simplest possible query — that
    contradiction is an account-side ZoomEye issue to check directly on their
    dashboard/support, not something fixable here. So while the endpoint/
    request format is now confirmed correct, the response-parsing below is
    best-effort (based on documented field names, not a verified live
    response) since no successful response was obtainable to test against."""
    rows = []
    TARGETS = [
        ('hostname:"army.mil"', "US Army", "US"), ('hostname:"navy.mil"', "US Navy", "US"),
        ('hostname:"af.mil"', "US Air Force", "US"), ('hostname:"cybercom.mil"', "US Cyber Command", "US"),
        ('hostname:"disa.mil"', "DISA", "US"), ('hostname:"nato.int"', "NATO", "EU"),
        ('hostname:"mod.uk"', "UK MoD", "GB"),
        ('hostname:"indianarmy.nic.in"', "Indian Army", "IN"),
        ('hostname:"mod.gov.in"', "Indian MoD", "IN"),
        ('hostname:"drdo.gov.in"', "DRDO", "IN"),
        ('hostname:"pakistanarmy.gov.pk"', "Pakistan Army", "PK"),
        ('hostname:"mod.gov.pk"', "Pakistan MoD", "PK"),
        ('hostname:"mod.gov.cn"', "China MoD", "CN"),
        ('hostname:"bundeswehr.de"', "German Bundeswehr", "DE"),
        ('hostname:"forces.gc.ca"', "Canadian Armed Forces", "CA"),
        ('hostname:"defence.gov.au"', "Australia Defence", "AU"),
        ('hostname:"mod.gov.il"', "Israel MoD", "IL"),
        ('hostname:"defense.gouv.fr"', "France MoD", "FR"),
        ('hostname:"mod.go.jp"', "Japan MoD", "JP"),
        ('hostname:"mnd.go.kr"', "South Korea MND", "KR"),
        ('hostname:"mnd.gov.tw"', "Taiwan MND", "TW"),
        ('hostname:"mod.gov.ua"', "Ukraine MoD", "UA"),
    ]
    headers = {"API-KEY": api_key, "User-Agent": "MilOSINT/2.0",
               "Content-Type": "application/json", "Accept": "application/json"}
    try:
        for query, label, geo in TARGETS:
            try:
                qb64 = base64.b64encode(query.encode()).decode()
                resp = requests.post("https://api.zoomeye.ai/v2/search",
                                      json={"qbase64": qb64, "page": 1}, headers=headers, timeout=20)
                if resp.status_code in (401, 403):
                    break
                if resp.status_code == 402:
                    log.warning(f"ZoomEye: credits_insufficient (account shows free quota available — "
                                f"check zoomeye.ai dashboard) — stopping after [{label}]")
                    break
                resp.raise_for_status()
                for m in (resp.json().get("data") or [])[:6]:
                    ip = m.get("ip") or ""
                    port = m.get("port") or ""
                    country = m.get("country") or m.get("country_name") or geo
                    rows.append({
                        "threat_id":     f"T3-ZY-{short_id(ip + str(port))}",
                        "threat_name":   f"ZoomEye Exposed Asset — {label}",
                        "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                        "source_layer":  "Deep Web", "source": "ZoomEye (Knownsec)",
                        "post_text":     (f"IP: {ip}:{port} | Hostname: {m.get('hostname') or m.get('domain') or ''} | "
                                          f"Product: {m.get('product','')} | Title: {str(m.get('title',''))[:200]} | Target: {label}"),
                        "post_url":      f"https://www.zoomeye.ai/searchResult?q={requests.utils.quote(query)}",
                        "timestamp":     str(m.get("update_time") or m.get("timestamp") or now_utc()), "location": country,
                        "severity":      "HIGH", "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": ip,
                        "tags":          f"zoomeye;internet-scan;exposed-asset;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"] + 0.5)
            except Exception as inner_e:
                log.warning(f"ZoomEye [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"ZoomEye error: {e}")
    log.info(f"ZoomEye: {len(rows)} exposed military assets found")
    return rows


def fetch_onyphe(api_key: str) -> list:
    """T3 — FREE 100 calls/mo at onyphe.io. Strong EU/NATO scan coverage."""
    rows = []
    TARGETS = [
        ("army.mil", "US Army"), ("navy.mil", "US Navy"), ("nato.int", "NATO"),
        ("mod.uk", "UK Ministry of Defence"), ("bundeswehr.de", "German Bundeswehr"),
        ("defense.gov", "US Defense.gov"), ("forces.gc.ca", "Canadian Armed Forces"),
        ("defence.gov.au", "Australia Defence"),
        ("mod.gov.in", "Indian Ministry of Defence"), ("drdo.gov.in", "DRDO"),
        ("mod.gov.pk", "Pakistan Ministry of Defence"), ("mod.gov.cn", "China Ministry of National Defense"),
        ("mod.gov.il", "Israel Ministry of Defense"), ("defense.gouv.fr", "France Ministry of Defense"),
        ("mod.go.jp", "Japan Ministry of Defense"), ("mnd.go.kr", "South Korea Ministry of National Defense"),
        ("mnd.gov.tw", "Taiwan Ministry of National Defense"), ("mod.gov.ua", "Ukraine Ministry of Defense"),
    ]
    headers = {"Authorization": f"apikey {api_key}", "User-Agent": "MilOSINT/2.0", "Content-Type": "application/json"}
    try:
        for domain, label in TARGETS:
            try:
                resp = requests.get(f"https://www.onyphe.io/api/v2/simple/datascan/hostname:{domain}",
                                     headers=headers, timeout=20)
                if resp.status_code in (401, 403, 429):
                    break
                resp.raise_for_status()
                for r in (resp.json().get("results") or [])[:5]:
                    ip = r.get("ip") or ""
                    vuln = r.get("cve") or []
                    rows.append({
                        "threat_id":     f"T3-ONY-{short_id(ip + str(r.get('port','')) + domain)}",
                        "threat_name":   f"Onyphe Exposed Asset — {label}",
                        "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                        "source_layer":  "Deep Web", "source": "Onyphe (internet scanner)",
                        "post_text":     f"IP: {ip}:{r.get('port','')} | Domain: {domain} | Product: {r.get('product','')} | CVEs: {vuln[:3]}",
                        "post_url":      f"https://www.onyphe.io/asset/{ip}",
                        "timestamp":     str(r.get("@timestamp") or now_utc()),
                        "location":      (r.get("location") or {}).get("country_name") or "Unknown",
                        "severity":      "CRITICAL" if vuln else "HIGH", "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": ip,
                        "tags":          f"onyphe;internet-scan;{label.lower().replace(' ','-')};{domain}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Onyphe [{domain}]: {inner_e}")
    except Exception as e:
        log.error(f"Onyphe error: {e}")
    log.info(f"Onyphe: {len(rows)} military infrastructure assets found")
    return rows


def fetch_criminalip(api_key: str) -> list:
    """T3 — FREE 100 searches/day at criminalip.io. Risk-scored IP/asset intel."""
    rows = []
    TARGETS = [
        ('country:"US" hostname:".mil"', "US Military Exposed Assets", "T3"),
        ('tag:"c2" country:"RU"', "Russian C2 Infrastructure", "T6"),
        ('tag:"c2" country:"CN"', "Chinese C2 Infrastructure", "T6"),
        ('tag:"c2" country:"KP"', "North Korean C2", "T6"),
        ('tag:"c2" country:"PK"', "Pakistani C2 Infrastructure", "T6"),
        ('country:"IN" hostname:".gov.in"', "Indian Government Exposed Assets", "T3"),
        ('tag:"scanner" label:"malicious"', "Active Malicious Scanners", "T3"),
        ('tag:"vpn_breach"', "Breached VPN Infrastructure", "T3"),
        ('tag:"c2" tag:"botnet"', "Active Botnet C2", "T6"),
    ]
    headers = {"x-api-key": api_key, "User-Agent": "MilOSINT/2.0", "Accept": "application/json"}
    try:
        for query, label, cat in TARGETS:
            try:
                resp = requests.get("https://api.criminalip.io/v1/asset/ip/search",
                                     params={"query": query, "offset": 0}, headers=headers, timeout=20)
                if resp.status_code in (401, 403, 429):
                    break
                resp.raise_for_status()
                for r in ((resp.json().get("data") or {}).get("result") or [])[:5]:
                    ip = r.get("ip_address") or ""
                    score = r.get("score", {}).get("inbound") or 0
                    sev = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "MEDIUM")
                    cat_name = CATEGORY_NAMES["T3"] if cat == "T3" else CATEGORY_NAMES["T6"]
                    rows.append({
                        "threat_id":     f"{cat}-CIP-{short_id(ip + label)}",
                        "threat_name":   f"Criminal IP — {label}",
                        "category_code": cat, "category_name": cat_name,
                        "source_layer":  "Deep Web", "source": "Criminal IP (threat intelligence)",
                        "post_text":     (f"IP: {ip} | Hostname: {(r.get('hostname') or [{}])[0].get('domain','')} | "
                                          f"Risk Score: {score}/100 | Country: {r.get('country','Unknown')} | "
                                          f"Ports: {[str(p.get('open_port_no','')) for p in (r.get('port') or [])[:5]]}"),
                        "post_url":      f"https://www.criminalip.io/asset/report/{ip}",
                        "timestamp":     now_utc(), "location": r.get("country") or "Unknown",
                        "severity":      sev, "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": ip,
                        "tags":          f"criminalip;threat-intel;score-{score}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Criminal IP [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"Criminal IP error: {e}")
    log.info(f"Criminal IP: {len(rows)} malicious/military-exposed IPs found")
    return rows


def fetch_binaryedge(api_key: str) -> list:
    """T3 — PAID $50/mo at binaryedge.io. Alternative internet scanner."""
    rows = []
    TARGETS = [
        ("domain:army.mil", "US Army Exposed Services"), ("domain:navy.mil", "US Navy Exposed Services"),
        ("domain:af.mil", "US Air Force Exposed Services"), ("domain:nato.int", "NATO Exposed Services"),
        ("domain:mod.uk", "UK MoD Exposed Services"), ("domain:bundeswehr.de", "German Bundeswehr Exposed"),
    ]
    headers = {"X-Key": api_key, "User-Agent": "MilOSINT/2.0", "Accept": "application/json"}
    try:
        for query, label in TARGETS:
            try:
                resp = requests.get("https://api.binaryedge.io/v2/query/ip/search",
                                     params={"query": query, "page": 1, "pagesize": 5}, headers=headers, timeout=20)
                if resp.status_code in (401, 403, 429):
                    break
                resp.raise_for_status()
                for r in resp.json().get("events") or []:
                    target = r.get("target") or {}
                    ip = target.get("ip") or ""
                    origin = r.get("origin") or {}
                    rows.append({
                        "threat_id":     f"T3-BE-{short_id(ip + str(target.get('port','')) + label)}",
                        "threat_name":   f"BinaryEdge — {label}",
                        "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                        "source_layer":  "Deep Web", "source": "BinaryEdge (internet scanner)",
                        "post_text":     f"IP: {ip}:{target.get('port','')} | {label} | Country: {origin.get('country','Unknown')}",
                        "post_url":      f"https://app.binaryedge.io/services/query?ip={ip}",
                        "timestamp":     str(origin.get("ts") or now_utc()), "location": origin.get("country") or "Unknown",
                        "severity":      "HIGH", "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": ip,
                        "tags":          f"binaryedge;internet-scan;exposed-service;{label.lower().replace(' ','-')}",
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"BinaryEdge [{label}]: {inner_e}")
    except Exception as e:
        log.error(f"BinaryEdge error: {e}")
    log.info(f"BinaryEdge: {len(rows)} military infrastructure assets found")
    return rows


def fetch_urlscan(api_key: str = "") -> list:
    """T3 — FREE 1000 searches/day at urlscan.io. Live scans of military domains
    — catches exposed admin panels and phishing pages mimicking military sites."""
    rows = []
    queries = [
        ("page.domain:army.mil", "US Army"), ("page.domain:navy.mil", "US Navy"),
        ("page.domain:af.mil", "US Air Force"), ("page.domain:disa.mil", "DISA"),
        ("page.domain:cybercom.mil", "USCYBERCOM"), ("page.domain:nato.int", "NATO"),
        ("page.domain:mod.uk", "UK MoD"),
        ("page.domain:indianarmy.nic.in", "Indian Army"), ("page.domain:indiannavy.gov.in", "Indian Navy"),
        ("page.domain:mod.gov.in", "Indian MoD"), ("page.domain:drdo.gov.in", "DRDO"),
        ("page.domain:pakistanarmy.gov.pk", "Pakistan Army"), ("page.domain:mod.gov.pk", "Pakistan MoD"),
        ("page.domain:mod.gov.cn", "China MoD"),
        ("page.domain:forces.gc.ca", "Canada Forces"), ("page.domain:defence.gov.au", "Australia Defence"),
        ("page.domain:bundeswehr.de", "Germany Bundeswehr"),
        ("page.domain:mod.gov.il", "Israel MoD"), ("page.domain:defense.gouv.fr", "France Defense"),
        ("page.domain:mod.go.jp", "Japan MoD"), ("page.domain:mnd.go.kr", "South Korea MND"),
        ("page.domain:mnd.gov.tw", "Taiwan MND"), ("page.domain:mod.gov.ua", "Ukraine MoD"),
        ('page.url:pentagon AND (login OR admin OR api)', "Pentagon sensitive path"),
    ]
    headers = {"API-Key": api_key} if api_key else {}
    headers["User-Agent"] = "MilOSINT/2.0"
    _SENSITIVE_PATH_PATTERNS = {
        "admin", "login", "portal", "vpn", "api", "kibana", "jenkins", "gitlab",
        "confluence", "jira", "sonarqube", "swagger", "phpmyadmin", "shell", "upload", "config",
    }
    seen_urls: set = set()
    for q, label in queries:
        try:
            resp = requests.get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 20},
                                 headers=headers, timeout=20)
            if resp.status_code == 429:
                time.sleep(30)
                continue
            resp.raise_for_status()
            for r in resp.json().get("results", []):
                page = r.get("page", {})
                url = page.get("url", "")
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                status = page.get("status", 200)
                is_sensitive = any(p in url.lower() for p in _SENSITIVE_PATH_PATTERNS)
                is_error = status in (401, 403, 500, 502, 503) if isinstance(status, int) else False
                sev = "HIGH" if is_sensitive else ("MEDIUM" if is_error else "LOW")
                tags = f"urlscan;web-exposure;{label.lower().replace(' ', '-')}"
                if is_sensitive:
                    tags += ";sensitive-path"
                if is_error:
                    tags += f";http-{status}"
                rows.append({
                    "threat_id":     f"T3-US-{short_id(url)}",
                    "threat_name":   f"URLScan — {label} Web Exposure",
                    "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                    "source_layer":  "Surface Web", "source": "URLScan.io",
                    "post_text":     f"Domain: {page.get('domain','')} | URL: {url[:200]} | Status: {status}",
                    "post_url":      f"https://urlscan.io/result/{r.get('_id','')}/",
                    "timestamp":     str(r.get("task", {}).get("time", now_utc())), "location": domain_to_country(page.get("domain", "")),
                    "severity":      sev, "confidence": "MEDIUM",
                    "ioc_type":      "url", "ioc_value": url[:300],
                    "tags":          tags,
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"URLScan [{label}]: {e}")
    log.info(f"URLScan: {len(rows)} military domain scans found")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T4 | NAVIGATION, POSITIONING & ELECTRONIC WARFARE
# ═════════════════════════════════════════════════════════════════════════

def fetch_gps_ew_data() -> list:
    """T4 — FREE, no key. OpenSky Network ADS-B flight states — reports
    aircraft-traffic volume in known GPS-contested regions.

    Previously flagged aircraft with the ADS-B "SPI" bit set as "GPS Spoofing/
    EW Anomaly Detected" at HIGH severity. Verified this is wrong: SPI
    ("Special Position Identification") is the transponder pulse a PILOT
    triggers by pressing the IDENT button when ATC requests "squawk ident"
    for routine traffic identification/handoffs — it lasts ~18 seconds and has
    no connection to GPS spoofing or jamming whatsoever. It's normal,
    cooperative ATC compliance, if anything the OPPOSITE signature of a
    spoofing aircraft. This produced 22 HIGH-severity false-positive rows in
    the master CSV. Removed the SPI check entirely rather than keep a
    confirmed-wrong signal or rush a replacement heuristic (e.g. comparing
    reported position against expected track) without being able to properly
    validate it tonight — the region-traffic-volume monitoring below is
    unaffected and still honest."""
    rows = []
    regions = [
        {"name": "Eastern Europe (Ukraine/Russia)", "bbox": (44.0, 22.0, 52.0, 40.0)},
        {"name": "Middle East (Israel/Lebanon/Syria)", "bbox": (29.0, 33.0, 37.0, 42.0)},
        {"name": "Baltic Region", "bbox": (53.0, 14.0, 60.0, 28.0)},
        {"name": "Black Sea", "bbox": (40.5, 27.5, 46.5, 41.5)},
        # Covers the India-Pakistan border (Punjab/Rajasthan/Kashmir) and the
        # India-China LAC (Ladakh, Arunachal Pradesh) — both have documented
        # GPS jamming/spoofing incidents, same as the other conflict zones here.
        {"name": "South Asia (India/Pakistan/China border)", "bbox": (24.0, 69.0, 36.0, 97.0)},
        # Taiwan Strait — documented GPS jamming/spoofing tied to PLA exercises
        # around Taiwan; Korean Peninsula — North Korea has repeatedly jammed
        # GPS into South Korean airspace/shipping. Both free (OpenSky, no key).
        {"name": "Taiwan Strait", "bbox": (21.0, 118.0, 26.0, 123.0)},
        {"name": "Korean Peninsula", "bbox": (33.0, 124.0, 43.0, 131.0)},
    ]
    for region in regions:
        lamin, lomin, lamax, lomax = region["bbox"]
        try:
            resp = requests.get("https://opensky-network.org/api/states/all",
                                 params={"lamin": lamin, "lomin": lomin, "lamax": lamax, "lomax": lomax}, timeout=20)
            resp.raise_for_status()
            states = resp.json().get("states", []) or []
            rows.append({
                "threat_id":     f"T4-OSK-{short_id(region['name'])}",
                "threat_name":   "GPS/EW Region Monitored",
                "category_code": "T4", "category_name": CATEGORY_NAMES["T4"],
                "source_layer":  "Surface Web", "source": "OpenSky Network",
                "post_text":     f"Region scanned: {region['name']} | {len(states)} aircraft tracked",
                "post_url":      "https://opensky-network.org/",
                "timestamp":     now_utc(), "location": region["name"],
                "severity":      "LOW", "confidence": "HIGH",
                "ioc_type":      "coordinates", "ioc_value": f"{lamin},{lomin},{lamax},{lomax}",
                "tags":          "gps;ew;opensky;monitor",
            })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"OpenSky error [{region['name']}]: {e}")
    log.info(f"OpenSky: {len(rows)} GPS/EW regions monitored")
    return rows


# SATCAT's OWNER column is just a launching country/entity code, not a
# military-vs-civilian flag. For the US specifically this is nearly
# meaningless on its own: a live run showed 20/20 "US Military Satellites"
# rows were actually 19 Starlink birds + 1 SiriusXM radio satellite — 0
# genuine military hits. Exclude known commercial mega-constellations from
# the owner-code buckets (not from the GPS/GLONASS/COSMOS name buckets,
# which are already specific and unaffected by this). Module-level so
# clean_existing_csv() can re-apply the same check retroactively.
_COMMERCIAL_SAT_EXCLUDE = (
    "STARLINK", "ONEWEB", "IRIDIUM", "GLOBALSTAR", "ORBCOMM", "PLANET",
    "SIRIUS", "SXM-", "SPACEWAY", "INTELSAT", "EUTELSAT", "TELESAT", "O3B",
    "KUIPER", "SPACEMOBILE",
)
# Raw SATCAT OWNER codes normalized to a country name for the dashboard map —
# the name-matched buckets (GPS/GLONASS/COSMOS) aren't owner-filtered, so the
# actual per-satellite owner can be RU/USSR/IND etc, not just the bucket label.
_SATCAT_OWNER_NAME = {"US": "United States", "PRC": "China", "CIS": "Russia",
                      "RU": "Russia", "USSR": "Russia", "IND": "India"}


def fetch_celestrak() -> list:
    """T4 — FREE, no key. Celestrak SATCAT — GPS/GLONASS constellations,
    Cosmos ASAT debris, and Chinese/Russian/US military satellites."""
    import io
    rows = []
    SATCAT_URLS = ["https://celestrak.org/pub/satcat.csv", "https://celestrak.com/pub/satcat.csv"]
    FILTERS = [
        ("GPS Constellation", None, ["GPS"], "LOW"),
        ("GLONASS (Russian NavSat)", None, ["GLONASS"], "MEDIUM"),
        ("Cosmos Series (ASAT Risk)", None, ["COSMOS"], "HIGH"),
        ("Chinese Military Satellites", {"PRC"}, None, "HIGH"),
        ("Russian Military Satellites", {"CIS", "RU", "USSR"}, None, "HIGH"),
        ("US Military Satellites", {"US"}, None, "LOW"),
        # India — mixed civil/military program like GLONASS (NavIC dual-use
        # navigation, GSAT-7-series dedicated military comsats, RISAT-class
        # reconnaissance radar satellites, alongside purely civilian ISRO
        # science/earth-observation missions) — MEDIUM, not HIGH, to reflect that.
        ("Indian Satellites (ISRO/Military)", {"IND"}, None, "MEDIUM"),
    ]
    try:
        resp = None
        for _url in SATCAT_URLS:
            try:
                resp = requests.get(_url, timeout=60,
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                resp.raise_for_status()
                break
            except Exception as _mirror_e:
                log.warning(f"Celestrak mirror {_url} failed: {_mirror_e} — trying next")
                resp = None
        if resp is None:
            log.error("Celestrak: all mirrors failed")
            return []

        reader = csv.DictReader(io.StringIO(resp.text))
        reader.fieldnames = [f.strip().lstrip("﻿") for f in (reader.fieldnames or [])]
        all_objects = [r for r in reader if not r.get("DECAY_DATE", "").strip()]

        seen_norads = set()
        for label, owner_set, name_kw, base_sev in FILTERS:
            matched = []
            for obj in all_objects:
                owner = (obj.get("OWNER") or obj.get("COUNTRY") or "").strip().upper()
                name = (obj.get("OBJECT_NAME") or "").strip().upper()
                owner_match = owner_set and owner in owner_set and not any(c in name for c in _COMMERCIAL_SAT_EXCLUDE)
                name_match = name_kw and any(k.upper() in name for k in name_kw)
                if not (owner_match or name_match):
                    continue
                norad_id = (obj.get("NORAD_CAT_ID") or "").strip()
                if norad_id in seen_norads:
                    continue
                seen_norads.add(norad_id)
                matched.append(obj)

            for obj in matched[-20:]:
                norad_id = (obj.get("NORAD_CAT_ID") or "").strip()
                name = (obj.get("OBJECT_NAME") or "").strip()
                owner = (obj.get("OWNER") or "Unknown").strip()
                obj_type = (obj.get("OBJECT_TYPE") or "").strip()
                launch = (obj.get("LAUNCH_DATE") or now_utc()).strip()
                is_debris = "DEB" in obj_type.upper() or "DEB" in name.upper()
                sev = "CRITICAL" if (is_debris and base_sev == "HIGH") else base_sev
                rows.append({
                    "threat_id":     f"T4-CTK-{short_id(norad_id + name)}",
                    "threat_name":   f"Satellite Intelligence — {label}",
                    "category_code": "T4", "category_name": CATEGORY_NAMES["T4"],
                    "source_layer":  "Deep Web", "source": "Celestrak SATCAT (US Space Command)",
                    "post_text":     (f"Object: {name} | NORAD: {norad_id} | Owner: {owner} | Type: {obj_type} | "
                                      f"Status: {(obj.get('OPS_STATUS_CODE') or '+').strip()} | "
                                      f"Apogee: {(obj.get('APOGEE') or '').strip()}km | "
                                      f"Perigee: {(obj.get('PERIGEE') or '').strip()}km | "
                                      f"Inclination: {(obj.get('INCLINATION') or '').strip()}° | "
                                      f"Launch: {launch} | Category: {label}"),
                    "post_url":      f"https://celestrak.org/satcat/search.php?CATNR={norad_id}",
                    "timestamp":     launch, "location": f"Orbit — {_SATCAT_OWNER_NAME.get(owner.upper(), owner)}",
                    "severity":      sev, "confidence": "HIGH",
                    "ioc_type":      "satellite", "ioc_value": f"NORAD-{norad_id}",
                    "tags":          f"satellite;space;{owner.lower()};{obj_type.lower().replace(' ','-')};celestrak",
                })
    except Exception as e:
        log.error(f"Celestrak SATCAT error: {e}")
    log.info(f"Celestrak: {len(rows)} satellite objects tracked")
    return rows


def fetch_faa_notams(client_id: str, client_secret: str) -> list:
    """T4 — FREE registration at api.faa.gov. GPS jamming/interference NOTAMs."""
    rows = []
    gps_keywords = ["gps", "gnss", "navigation", "jamming", "spoofing", "interference",
                    "satellite", "unreliable", "unavailable", "degraded"]
    try:
        token_resp = requests.post("https://api.faa.gov/oauth/token",
                                    data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
                                    headers={"Accept": "application/json", "User-Agent": "MilOSINT/2.0"}, timeout=20)
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token") or token_resp.json().get("token")
        if not token:
            return rows
        auth_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}
        resp = requests.get("https://external-api.faa.gov/notamapi/v1/notams?notamType=GPS&pageSize=50&pageNum=1",
                             headers=auth_headers, timeout=20)
        resp.raise_for_status()
        for n in resp.json().get("items") or []:
            props = n.get("properties") or {}
            core = props.get("coreNOTAMData") or {}
            notam_text = core.get("notam", {}).get("text") or props.get("notamText") or ""
            if not any(k in notam_text.lower() for k in gps_keywords):
                continue
            notam_id = core.get("notam", {}).get("id") or short_id(notam_text)
            rows.append({
                "threat_id":     f"T4-FAA-{short_id(str(notam_id))}",
                "threat_name":   "FAA NOTAM — GPS/Navigation Interference Alert",
                "category_code": "T4", "category_name": CATEGORY_NAMES["T4"],
                "source_layer":  "Deep Web", "source": "FAA NOTAM API",
                "post_text":     (f"NOTAM {notam_id} | Location: {props.get('location','')} | "
                                  f"Effective: {props.get('effectiveStart') or props.get('issued') or now_utc()} | "
                                  f"Expires: {props.get('effectiveEnd','')} | {notam_text[:300]}"),
                "post_url":      "https://notams.aim.faa.gov/notamSearch/",
                "timestamp":     str(props.get("issued") or now_utc()), "location": "USA",
                "severity":      "HIGH", "confidence": "HIGH",
                "ioc_type":      "coordinates", "ioc_value": props.get("location", ""),
                "tags":          "gps;notam;interference;navigation;faa",
            })
    except Exception as e:
        log.error(f"FAA NOTAM error: {e}")
    log.info(f"FAA NOTAM: {len(rows)} GPS interference notices found")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T5 | CRITICAL INFRASTRUCTURE ATTACKS
# ═════════════════════════════════════════════════════════════════════════

def fetch_cisa_ics_advisories() -> list:
    """T5 — FREE, no key. CISA Known Exploited Vulnerabilities filtered to
    ICS/SCADA/critical-infrastructure/defence-relevant entries."""
    rows = []
    # v1 matched "ot" as a bare substring, which silently matches "software",
    # "protocol", "bot", "photo", "Motorola"... — against the live CISA KEV
    # feed that alone produced 173 of 221 "matches", i.e. it was almost pure
    # noise. Word-boundary matching cuts that same feed to 15 genuine hits.
    _CISA_DEFENCE_RE = re.compile(
        r"\b(scada|ics|industrial|defence|defense|military|critical infrastructure|plc|ot)\b"
    )
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        resp.raise_for_status()
        for v in resp.json().get("vulnerabilities", []):
            notes = (v.get("notes", "") + v.get("product", "") + v.get("vendorProject", "")).lower()
            if not _CISA_DEFENCE_RE.search(notes):
                continue
            rows.append({
                "threat_id":     f"T5-CISA-{v.get('cveID', short_id(v.get('vulnerabilityName','')))}",
                "threat_name":   "Defence Critical Infrastructure Cyber Attack",
                "category_code": "T5", "category_name": CATEGORY_NAMES["T5"],
                "source_layer":  "Surface Web", "source": "CISA KEV",
                "post_text":     f"{v.get('vulnerabilityName','')} | {v.get('shortDescription','')}",
                "post_url":      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "timestamp":     v.get("dateAdded", now_utc()) + "T00:00:00Z", "location": "United States",
                "severity":      "CRITICAL", "confidence": "HIGH",
                "ioc_type":      "cve", "ioc_value": v.get("cveID", ""),
                "tags":          "ics;scada;critical-infra;cisa;cve",
            })
    except Exception as e:
        log.error(f"CISA KEV error: {e}")
    log.info(f"CISA: {len(rows)} ICS/defence-related KEVs found")
    return rows


def fetch_packetstorm() -> list:
    """T5/T7 — FREE, no key. PacketStorm Security advisory/exploit RSS filtered
    for ICS/SCADA/military relevance. v1 matched short tokens like "ics"/"ot"/
    "dod"/"government" as bare substrings — the same bug just found in the
    CISA module, which would match "topics", "custody", "dodge", "governmental
    website contact form"... This version requires a word-boundary match and
    drops the broadest, least specific tokens (government/federal/aviation)."""
    rows = []
    _PS_KW_RE = re.compile(
        r"\b(scada|ics|industrial control|military|defense|defence|nato|"
        r"critical infrastructure|power grid|energy sector|water treatment|"
        r"supervisory control|plc|hmi|dnp3|modbus|profinet|siemens|schneider|"
        r"rockwell|ge digital|honeywell|fortinet|palo alto|cisco asa|vpn breach)\b"
    )
    try:
        resp = requests.get("https://packetstormsecurity.com/files.rss",
                             headers={"User-Agent": "MilOSINT/2.0"}, timeout=15)
        resp.raise_for_status()
        # PacketStorm now redirects RSS requests through a "/tos/<signed-token>"
        # anti-bot interstitial (confirmed live: even hitting their new
        # packetstorm.news domain directly still gates behind this, with a
        # fresh token every request) that returns an HTML page, not the feed.
        # This isn't a bypassable cookie/header issue — it's a deliberate gate,
        # so the honest fix is detecting it and saying so, not working around
        # it. Previously this silently fell through to "0 found" every run,
        # indistinguishable from genuine scarcity.
        if "/tos/" in resp.url or "text/html" in resp.headers.get("Content-Type", ""):
            log.warning("PacketStorm: RSS feed is now gated behind an anti-bot ToS "
                        "redirect (not reachable via automated requests) — 0 found "
                        "reflects a blocked source, not an empty feed")
            return rows
        items_raw = []
        try:
            root = ET.fromstring(resp.content)
            channel = root.find("channel")
            if channel is not None:
                items_raw = [
                    {"title": it.findtext("title") or "", "desc": it.findtext("description") or "",
                     "link": it.findtext("link") or "", "pub": it.findtext("pubDate") or now_utc()}
                    for it in channel.findall("item")[:50]
                ]
        except ET.ParseError:
            for block in re.findall(r"<item>(.*?)</item>", resp.text, re.DOTALL)[:50]:
                def _tag(t):
                    m = re.search(rf"<{t}[^>]*>(.*?)</{t}>", block, re.DOTALL)
                    return m.group(1).strip() if m else ""
                items_raw.append({
                    "title": re.sub(r"<[^>]+>", "", _tag("title")),
                    "desc": re.sub(r"<[^>]+>", "", _tag("description")),
                    "link": _tag("link"), "pub": _tag("pubDate") or now_utc(),
                })
        for item in items_raw:
            title, desc, link, pub = item["title"], item["desc"], item["link"], item["pub"]
            if not _PS_KW_RE.search((title + " " + desc).lower()):
                continue
            rows.append({
                "threat_id":     f"T5-PS-{short_id(link)}",
                "threat_name":   f"PacketStorm Security Advisory — {title[:60]}",
                "category_code": "T5", "category_name": CATEGORY_NAMES["T5"],
                "source_layer":  "Surface Web", "source": "PacketStorm Security",
                "post_text":     f"{title} | {desc[:300]}",
                "post_url":      link, "timestamp": str(pub), "location": "Global",
                "severity":      "HIGH", "confidence": "HIGH",
                "ioc_type":      "url", "ioc_value": link,
                "tags":          "packetstorm;ics;scada;critical-infra",
            })
        time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"PacketStorm error: {e}")
    log.info(f"PacketStorm: {len(rows)} ICS/military security advisories found")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T6 | MALWARE & ADVANCED CYBER ATTACKS
# ═════════════════════════════════════════════════════════════════════════

def fetch_otx_pulses(api_key: str) -> list:
    """T6 — FREE signup at otx.alienvault.com. APT/nation-state threat pulses,
    gated on named APT-group attribution OR a military context term (a bare
    "nation-state" tag is too broad — it includes groups hitting finance/telecom)."""
    rows = []
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": "MilOSINT/2.0"}
    tags = ["military", "apt", "nation-state", "defence", "espionage"]
    consecutive_failures = 0
    for tag in tags:
        if consecutive_failures >= 2:
            log.warning("OTX: 2 consecutive failures — skipping remaining tags")
            break
        try:
            resp = requests.get(f"https://otx.alienvault.com/api/v1/search/pulses?q={tag}&limit=8",
                                 headers=headers, timeout=15)
            resp.raise_for_status()
            consecutive_failures = 0
            for p in resp.json().get("results", []):
                name_lower = (p.get("name") or "").lower()
                desc_lower = (p.get("description") or "").lower()
                adversary = (p.get("adversary") or "").lower()
                combined = name_lower + " " + desc_lower + " " + adversary
                passes, tier, reason = relevance_check(combined, weak_terms=WEAK_MIL_TERMS, min_weak=1)
                if not passes:
                    continue
                indicators = p.get("indicators", [])
                ioc_type = indicators[0].get("type", "hash") if indicators else "hash"
                ioc_value = indicators[0].get("indicator", "") if indicators else ""
                rows.append({
                    "threat_id":     f"T6-OTX-{short_id(p.get('id',''))}",
                    "threat_name":   p.get("name", "APT/Malware Activity")[:100],
                    "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                    "source_layer":  "Surface Web", "source": "OTX AlienVault",
                    "post_text":     f"Pulse: {p.get('name','')} | Adversary: {p.get('adversary','Unknown')} | {desc_lower[:400]}",
                    "post_url":      f"https://otx.alienvault.com/pulse/{p.get('id','')}",
                    "timestamp":     p.get("created", now_utc()),
                    "location":      ", ".join(p.get("targeted_countries", ["Unknown"])),
                    "severity":      "CRITICAL" if tier == "strong" else "HIGH",
                    "confidence":    "HIGH" if tier in ("domain", "strong") else "MEDIUM",
                    "ioc_type":      ioc_type, "ioc_value": ioc_value,
                    "tags":          f"apt;malware;otx;{tag};{reason}",
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.warning(f"OTX [{tag}]: {e}")
            consecutive_failures += 1
    log.info(f"OTX: {len(rows)} military/APT pulses found")
    return rows


def fetch_threatfox_iocs() -> list:
    """T6 — FREE key from abuse.ch. APT/nation-state malware family IOCs
    from the last 7 days, cross-checked against a curated APT-family list
    or an explicit apt/nation-state/military tag."""
    if not key_available("threatfox_api_key"):
        log.warning("ThreatFox SKIPPED — free API key required: bazaar.abuse.ch -> Profile -> API Key")
        return []
    rows = []
    api_key = CONFIG.get("threatfox_api_key", "")
    _MIL_APT_FAMILIES = {
        "cobalt strike", "cobalt_strike", "cobaltstrike", "turla", "snake", "uroburos",
        "sandworm", "notpetya", "industroyer", "crashoverride", "fancy bear", "apt28",
        "sofacy", "x-agent", "x agent", "cozy bear", "apt29", "sunburst", "teardrop",
        "equation group", "doublefantasy", "triplefantasy", "lazarus", "bluenoroff",
        "andariel", "kimsuky", "winnti", "apt41", "barium", "volt typhoon", "salt typhoon",
        "silk typhoon", "shadowpad", "shadow pad", "plugx", "plug x", "empire",
        "powershell empire", "mimikatz", "triton", "trisis", "industroyer2",
        "blackenergy", "black energy", "carbon", "mosquito", "agonizing serpent", "cadet blizzard",
        "transparent tribe", "apt36", "sidecopy", "apt40", "mustang panda", "apt10",
    }
    _REQUIRED_TAGS = {"apt", "nation-state", "nation_state", "targeted", "military"}
    try:
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                              json={"query": "get_iocs", "days": 7}, timeout=20,
                              headers={"User-Agent": "MilOSINT/2.0", "Auth-Key": api_key})
        resp.raise_for_status()
        for item in resp.json().get("data") or []:
            family = (item.get("malware_printable") or item.get("malware") or "").lower()
            threat_type = (item.get("threat_type") or "").lower()
            item_tags = [t.lower() for t in (item.get("tags") or [])]
            combined = family + " " + threat_type + " " + " ".join(item_tags)
            family_match = _has_any(combined, _MIL_APT_FAMILIES)
            tag_match = any(t in item_tags for t in _REQUIRED_TAGS)
            if not (family_match or tag_match):
                continue
            first_seen_str = item.get("first_seen") or ""
            if first_seen_str:
                try:
                    fs = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - fs).days > 30:
                        continue
                except Exception:
                    pass
            confidence = item.get("confidence_level") or 50
            rows.append({
                "threat_id":     f"T6-TFX-{short_id(item.get('ioc') or item.get('ioc_value') or '')}",
                "threat_name":   f"APT/Nation-State IOC — {item.get('malware_printable','Unknown')}",
                "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                "source_layer":  "Deep Web", "source": "ThreatFox (abuse.ch)",
                "post_text":     (f"Malware: {item.get('malware_printable','')} | Type: {item.get('threat_type','')} | "
                                  f"Tags: {','.join(item.get('tags') or [])} | Confidence: {confidence}%"),
                "post_url":      f"https://threatfox.abuse.ch/ioc/{item.get('id','')}",
                "timestamp":     first_seen_str or now_utc(), "location": "Global",
                "severity":      "CRITICAL" if confidence >= 90 else "HIGH",
                "confidence":    "HIGH" if confidence >= 75 else "MEDIUM" if confidence >= 50 else "LOW",
                "ioc_type":      item.get("ioc_type") or "unknown",
                "ioc_value":     item.get("ioc") or item.get("ioc_value") or "",
                "tags":          f"apt;nation-state;threatfox;{family.replace(' ','-')}",
            })
    except Exception as e:
        log.error(f"ThreatFox error: {e}")
    log.info(f"ThreatFox: {len(rows)} APT IOCs found")
    return rows


def fetch_feodo_c2() -> list:
    """T6 — FREE, no key. Feodo Tracker active botnet C2 IPs."""
    rows = []
    try:
        resp = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                             timeout=20, headers={"User-Agent": "MilOSINT/2.0"})
        resp.raise_for_status()
        for item in (resp.json() or [])[:50]:
            ip = item.get("ip_address") or ""
            status = item.get("status") or "offline"
            rows.append({
                "threat_id":     f"T6-C2-{short_id(ip + str(item.get('port','')))}",
                "threat_name":   f"Active Botnet C2 Server — {item.get('malware','Unknown')}",
                "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                "source_layer":  "Deep Web", "source": "Feodo Tracker (abuse.ch)",
                "post_text":     (f"C2 IP: {ip}:{item.get('port','')} | Malware: {item.get('malware','Unknown')} | "
                                  f"Status: {status} | Last Online: {item.get('last_online','')}"),
                "post_url":      f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                "timestamp":     item.get("first_seen") or now_utc(), "location": item.get("country") or "Unknown",
                "severity":      "CRITICAL" if status == "online" else "HIGH", "confidence": "HIGH",
                "ioc_type":      "ip", "ioc_value": f"{ip}:{item.get('port','')}",
                "tags":          f"c2;botnet;{(item.get('malware') or '').lower().replace(' ','-')};feodo",
            })
    except Exception as e:
        log.error(f"Feodo Tracker error: {e}")
    log.info(f"Feodo Tracker: {len(rows)} botnet C2 IPs found")
    return rows


_MIL_MALWARE_TAGS = {
    "cobalt strike", "cobaltstrike", "metasploit", "emotet", "qakbot", "qbot",
    "bazarloader", "bazar", "icedid", "apt", "nation-state", "wiper",
    "industroyer", "triton", "trisis", "lazarus", "turla", "sandworm",
    "apt28", "apt29", "shadowpad", "plugx",
}
_ADVERSARY_TLDS = {".ru", ".cn", ".kp", ".ir", ".by"}
_MIL_URL_TARGETS = {".mil", ".gov", "dod.", "army.", "navy.", "pentagon", "nato"}


def fetch_urlhaus_malware() -> list:
    """T6 — FREE, no key. URLhaus CSV feed, gated on military-adjacent malware
    families OR (adversary-nation TLD AND a .mil/.gov-looking URL target)."""
    rows = []
    try:
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=30,
                             headers={"User-Agent": "MilOSINT/2.0"})
        resp.raise_for_status()
        data_lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
        count = 0
        for row_data in csv.reader(data_lines):
            if len(row_data) < 8:
                continue
            url_id, date_added, url_val, status, _, threat, tags_raw, urlhaus_link, *_ = row_data + [""] * 9
            if status.lower() != "online":
                continue
            combined = url_val.lower() + " " + tags_raw.lower() + " " + threat.lower()
            # word-boundary: bare "apt" in _MIL_MALWARE_TAGS was matching inside
            # "adapter"/"adapters", a common path segment in unrelated repo
            # URLs — a live check against the real feed found 27 of 31 matches
            # were exactly this (a generic SmartLoader campaign hosted on
            # throwaway GitHub repos, nothing APT/military about it).
            family_match = _has_any(combined, _MIL_MALWARE_TAGS)
            try:
                from urllib.parse import urlparse
                host = urlparse(url_val).netloc.lower()
                adversary_match = any(host.endswith(t) for t in _ADVERSARY_TLDS) and \
                                   any(t in url_val.lower() for t in _MIL_URL_TARGETS)
            except Exception:
                adversary_match = False
            if not (family_match or adversary_match):
                continue
            rows.append({
                "threat_id":     f"T6-UH-{short_id(url_val)}",
                "threat_name":   f"Active Malware URL — {threat or 'Unknown Threat'}",
                "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                "source_layer":  "Surface Web", "source": "URLhaus (abuse.ch)",
                "post_text":     f"URL: {url_val} | Status: {status} | Threat: {threat} | Tags: {tags_raw}",
                "post_url":      urlhaus_link or "https://urlhaus.abuse.ch/",
                "timestamp":     date_added, "location": "Unknown",
                "severity":      "CRITICAL" if adversary_match else "HIGH", "confidence": "HIGH",
                "ioc_type":      "url", "ioc_value": url_val,
                "tags":          f"malware;url;urlhaus;active;{threat.lower().replace(' ','-')}",
            })
            count += 1
            if count >= 30:
                break
    except Exception as e:
        log.error(f"URLhaus CSV error: {e}")
    log.info(f"URLhaus: {len(rows)} malicious URL entries found")
    return rows


def fetch_malwarebazaar() -> list:
    """T6 — Uses the abuse.ch key shared with ThreatFox. Recent malware samples
    tagged APT/RAT/loader/stealer, gated on a curated military-APT family list
    or an explicit apt/nation-state/targeted tag."""
    rows = []
    abuse_key = CONFIG.get("threatfox_api_key", "").strip()
    mb_headers = {"User-Agent": "MilOSINT/2.0"}
    if abuse_key:
        mb_headers["Auth-Key"] = abuse_key
    queries = [
        ({"query": "get_taginfo", "tag": "APT", "limit": "20"}, "APT Malware"),
        ({"query": "get_taginfo", "tag": "RAT", "limit": "15"}, "Remote Access Trojans"),
        ({"query": "get_taginfo", "tag": "loader", "limit": "15"}, "Malware Loaders"),
        ({"query": "get_taginfo", "tag": "stealer", "limit": "10"}, "Credential Stealers"),
        ({"query": "get_recent", "selector": "time", "limit": "10"}, "Recent Submissions"),
    ]
    _MIL_MB_FAMILIES = {
        "cobalt strike", "cobaltstrike", "cobalt_strike", "turla", "carbon", "mosquito",
        "sandworm", "notpetya", "industroyer", "apt28", "apt29", "apt41", "lazarus",
        "kimsuky", "shadowpad", "plugx", "plugx_v2", "mimikatz", "empire", "triton",
        "trisis", "emotet", "qakbot", "bazarloader", "icedid",
        "transparent tribe", "sidecopy", "apt36", "apt40", "mustang panda", "apt10",
    }
    for payload, label in queries:
        try:
            resp = requests.post("https://mb-api.abuse.ch/api/v1/", data=payload, headers=mb_headers, timeout=20)
            if resp.status_code == 401:
                log.warning("MalwareBazaar: 401 Unauthorized — check threatfox_api_key")
                break
            resp.raise_for_status()
            for item in resp.json().get("data") or []:
                sha256 = item.get("sha256_hash") or ""
                tags_mb = item.get("tags") or []
                family = (item.get("signature") or "Unknown").lower()
                tags_lower = [t.lower() for t in tags_mb]
                combined = family + " " + " ".join(tags_lower)
                apt_family = _has_any(combined, _MIL_MB_FAMILIES)
                apt_tag = any(t in tags_lower for t in ["apt", "nation-state", "targeted"])
                if not (apt_family or apt_tag):
                    continue
                downloads = int((item.get("intelligence") or {}).get("downloads") or 0)
                if downloads == 0 and not apt_family:
                    continue
                is_targeted = downloads < 10 and apt_family
                rows.append({
                    "threat_id":     f"T6-MB-{short_id(sha256)}",
                    "threat_name":   f"MalwareBazaar APT Sample — {label}",
                    "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                    "source_layer":  "Deep Web", "source": "MalwareBazaar (abuse.ch)",
                    "post_text":     (f"File: {item.get('file_name','unknown')} | SHA256: {sha256[:32]}... | "
                                      f"Family: {family} | Type: {item.get('file_type','')} | "
                                      f"Tags: {','.join(tags_mb)} | Downloads: {downloads} | "
                                      f"Reporter: {item.get('reporter','anonymous')}"),
                    "post_url":      f"https://bazaar.abuse.ch/sample/{sha256}/",
                    "timestamp":     str(item.get("first_seen") or now_utc()),
                    "location":      "Unknown",
                    "severity":      "CRITICAL" if is_targeted else "HIGH",
                    # "LOW-DETECTION (targeted)" used to be written here — not a
                    # valid confidence value (HIGH/MEDIUM/LOW only), same class
                    # of bug as CIRCL CVE's "UNKNOWN" severity found earlier
                    # tonight. Hadn't triggered in any run yet (0 occurrences in
                    # the master CSV), but is_targeted (rare APT family + <10
                    # downloads) is exactly the highest-value alert this module
                    # produces, so it was a live landmine, not dead code. The
                    # low-detection signal is preserved as a tag instead.
                    "confidence":    "HIGH",
                    "ioc_type":      "hash", "ioc_value": sha256,
                    "tags":          (f"malware;{';'.join(tags_mb[:4])};malwarebazaar;{family.replace(' ','-')}"
                                      + (";low-detection-targeted" if is_targeted else "")),
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"MalwareBazaar error [{label}]: {e}")
    log.info(f"MalwareBazaar: {len(rows)} malware samples found")
    return rows


def fetch_recorded_future(api_key: str) -> list:
    """T6 — PAID enterprise (~$25k+/yr) at recordedfuture.com. Risk-scored APT infra."""
    rows = []
    try:
        resp = requests.get("https://api.recordedfuture.com/v2/ip/search",
                             params={"fields": "intelCard,risk,threatLists,location,entity",
                                     "risklist": "Recently Active Threat Actors", "limit": 25},
                             headers={"X-RFToken": api_key, "User-Agent": "MilOSINT/2.0"}, timeout=20)
        if resp.status_code in (401, 403):
            return rows
        resp.raise_for_status()
        for item in (resp.json().get("data") or {}).get("results") or []:
            ip = (item.get("entity") or {}).get("name") or ""
            risk = (item.get("risk") or {}).get("score") or 0
            threats = [t.get("name") for t in (item.get("threatLists") or []) if t.get("name")]
            sev = "CRITICAL" if risk >= 75 else ("HIGH" if risk >= 50 else "MEDIUM")
            rows.append({
                "threat_id":     f"T6-RF-{short_id(ip)}",
                "threat_name":   "Recorded Future — High-Risk APT Infrastructure",
                "category_code": "T6", "category_name": CATEGORY_NAMES["T6"],
                "source_layer":  "Dark Web", "source": "Recorded Future",
                "post_text":     f"IP: {ip} | Risk Score: {risk}/100 | Threat Groups: {threats[:5]} | "
                                 f"Country: {(item.get('location') or {}).get('country','Unknown')}",
                "post_url":      f"https://app.recordedfuture.com/live/sc/entity/ip:{ip}",
                "timestamp":     now_utc(), "location": (item.get("location") or {}).get("country") or "Unknown",
                "severity":      sev, "confidence": "HIGH",
                "ioc_type":      "ip", "ioc_value": ip,
                "tags":          f"recorded-future;apt;threat-intel;risk-{risk};" + ";".join(t.lower().replace(" ", "-") for t in threats[:3]),
            })
    except Exception as e:
        log.error(f"Recorded Future error: {e}")
    log.info(f"Recorded Future: {len(rows)} high-risk APT infrastructure entries")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T7 | EMERGING & AUTONOMOUS SYSTEM THREATS (CVE / vulnerability intel)
# ═════════════════════════════════════════════════════════════════════════

def fetch_osv_cves() -> list:
    """T7 — FREE, no key. CIRCL CVE API, last 50 CVEs, filtered to CVSS >= 9.0
    AND a military-supply-chain vendor match. Cross-references CISA KEV."""
    rows = []
    _kev_cves: set = set()
    try:
        kev_resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                                 timeout=15, headers={"User-Agent": "MilOSINT/2.0"})
        if kev_resp.ok:
            _kev_cves = {v.get("cveID", "") for v in (kev_resp.json().get("vulnerabilities") or [])}
    except Exception:
        pass
    try:
        resp = requests.get("https://cve.circl.lu/api/last/50", timeout=25, headers={"User-Agent": "MilOSINT/2.0"})
        resp.raise_for_status()
        all_cves = resp.json() or []
        if not isinstance(all_cves, list):
            return rows
        for item in all_cves:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("id") or item.get("CVE") or ""
            summary = item.get("summary") or item.get("description") or item.get("Summary") or ""
            cvss_raw = item.get("cvss") or item.get("cvss3") or item.get("CVSS") or 0
            cpes = " ".join(item.get("vulnerable_configuration_cpe_2_2") or []).lower()
            try:
                score_f = float(str(cvss_raw)) if cvss_raw else None
            except Exception:
                score_f = None
            if score_f is not None and score_f < 9.0:
                continue
            summary_lower = summary.lower()
            # word-boundary match — a bare substring check would let "f5" match
            # inside any stray hex/version string in a CVE summary
            if not (_has_any(summary_lower, MIL_VENDOR_TERMS) or _has_any(cpes, MIL_VENDOR_TERMS)):
                continue
            in_kev = cve_id in _kev_cves
            severity = "CRITICAL" if (in_kev or (score_f and score_f >= 9.5)) else "HIGH"
            rows.append({
                "threat_id":     f"T7-CIRCL-{short_id(cve_id or summary[:20])}",
                "threat_name":   f"Critical CVE — Military Supply Chain{'  ★KEV' if in_kev else ''}",
                "category_code": "T7", "category_name": CATEGORY_NAMES["T7"],
                "source_layer":  "Deep Web", "source": "CIRCL CVE API",
                "post_text":     (f"{cve_id} | CVSS {score_f if score_f is not None else 'N/A'}"
                                  f"{' | IN CISA KEV (actively exploited)' if in_kev else ''} | {summary[:350]}"),
                "post_url":      f"https://cve.circl.lu/cve/{cve_id}",
                "timestamp":     str(item.get("Published") or item.get("published") or item.get("date") or now_utc()),
                "location":      "Global", "severity": severity, "confidence": "HIGH",
                "ioc_type":      "cve", "ioc_value": cve_id,
                "tags":          f"cve;critical;military-supply-chain;{'kev;actively-exploited' if in_kev else 'high-cvss'}",
            })
    except Exception as e:
        log.error(f"CIRCL CVE error: {e}")
    log.info(f"CIRCL CVE: {len(rows)} high-severity CVEs found")
    return rows


def fetch_nvd_cves() -> list:
    """T7 — FREE (NVD REST API). Replaces the old duplicated fetch_vulners() +
    fetch_nvd_cves() pair from v1: one query set, one vendor gate applied
    consistently, results de-duplicated by CVE id. The old fetch_vulners had
    NO vendor gate on some keywords (e.g. "windows rdp remote code execution"),
    which let through high-CVSS CVEs with no actual military relevance."""
    rows = []
    NVD_KEYWORDS = [
        "cisco ios xe", "fortinet fortigate", "palo alto pan-os", "juniper junos",
        "f5 big-ip", "siemens simatic", "rockwell studio 5000", "honeywell experion",
        "schneider modicon", "ge cimplicity", "scada industrial control",
        "satellite gps firmware", "ivanti pulse secure", "vmware vcenter",
    ]
    _kev_ids: set = set()
    try:
        kev_resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
        kev_resp.raise_for_status()
        for v in kev_resp.json().get("vulnerabilities", []):
            _kev_ids.add(v.get("cveID", "").upper())
    except Exception as e:
        log.warning(f"NVD: CISA KEV fetch failed: {e}")

    api_key = CONFIG.get("nvd_api_key", "")
    headers = {"apiKey": api_key} if api_key else {}
    headers["User-Agent"] = "MilOSINT/2.0"
    seen_cves: set = set()

    for kw in NVD_KEYWORDS:
        try:
            resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params={"keywordSearch": kw, "resultsPerPage": 20}, headers=headers, timeout=30)
            if resp.status_code == 429:
                time.sleep(30)
                continue
            resp.raise_for_status()
            for item in resp.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                if not cid or cid in seen_cves:
                    continue

                cvss_data = (cve.get("metrics", {}).get("cvssMetricV31") or
                             cve.get("metrics", {}).get("cvssMetricV30") or [])
                score_f, vector = 0.0, ""
                if cvss_data:
                    cv = cvss_data[0].get("cvssData", {})
                    score_f = float(cv.get("baseScore", 0))
                    vector = cv.get("vectorString", "")
                if score_f < 9.0:
                    continue

                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                if not _has_any(desc.lower(), MIL_VENDOR_TERMS):
                    continue
                seen_cves.add(cid)

                in_kev = cid.upper() in _kev_ids
                sev = "CRITICAL" if in_kev else "HIGH"
                rows.append({
                    "threat_id":     f"T7-NVD-{short_id(cid)}",
                    "threat_name":   f"{'★KEV ' if in_kev else ''}NVD {cid} (CVSS {score_f:.1f}) — {kw.title()}",
                    "category_code": "T7", "category_name": CATEGORY_NAMES["T7"],
                    "source_layer":  "Surface Web", "source": "NVD (NIST)",
                    "post_text":     f"CVSS: {score_f} | Vector: {vector} | KEV: {in_kev} | {desc[:300]}",
                    "post_url":      f"https://nvd.nist.gov/vuln/detail/{cid}",
                    "timestamp":     cve.get("published", now_utc())[:10],
                    "location":      "Global", "severity": sev, "confidence": "HIGH",
                    "ioc_type":      "cve", "ioc_value": cid,
                    "tags":          f"nvd;cve;cvss-{score_f};{'kev;' if in_kev else ''}{kw.replace(' ','-')}",
                })
            time.sleep(12 if not api_key else 0.6)
        except Exception as e:
            log.error(f"NVD [{kw}]: {e}")
    log.info(f"NVD: {len(rows)} critical military-vendor CVEs found")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  T8 | INFORMATION OPERATIONS & INFLUENCE THREATS
# ═════════════════════════════════════════════════════════════════════════

def fetch_defence_news_rss() -> list:
    """T8 — FREE, no key. Defence/security RSS feeds, gated through the shared
    relevance engine instead of a flat single-generic-word keyword list."""
    rows = []
    # Defence-specific outlets: everything they publish is already
    # military/defence-adjacent by definition of the outlet, so one
    # incidental weak-term hit is enough evidence.
    # General cybersecurity/news outlets cover far more than military
    # topics (product updates, consumer malware, generic proxy botnets...),
    # so they need 2+ hits — a live run at min_weak=1 pulled in a Claude
    # product-relaunch article and a Microsoft Outlook bugfix note purely
    # from stray word coincidences, plus general ransomware/malware stories
    # with no military angle at all.
    feeds = [
        ("https://www.defensenews.com/arc/outboundfeeds/rss/", "Defense News", 1),
        ("https://feeds.bbci.co.uk/news/world/middle_east/rss.xml", "BBC World/Defence", 2),
        ("https://thewarzone.com/feed/", "The War Zone", 1),
        ("https://defensescoop.com/feed/", "Defense Scoop", 1),
        ("https://cyberscoop.com/feed/", "CyberScoop", 2),
        ("https://www.bleepingcomputer.com/feed/", "BleepingComputer", 2),
        ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News", 2),
        # Added for T8 coverage — all verified live before adding (each returns
        # a real RSS/XML feed, not a redirect or 404). All defence-specific
        # outlets, so min_weak=1 like Defense News/War Zone/Defense Scoop.
        ("https://breakingdefense.com/feed/", "Breaking Defense", 1),
        ("https://www.c4isrnet.com/arc/outboundfeeds/rss/", "C4ISRNET", 1),
        ("https://www.armytimes.com/arc/outboundfeeds/rss/", "Army Times", 1),
        ("https://www.navytimes.com/arc/outboundfeeds/rss/", "Navy Times", 1),
        ("https://www.airforcetimes.com/arc/outboundfeeds/rss/", "Air Force Times", 1),
        # India — only one of several Indian defence outlets tried actually
        # serves a working RSS feed (idrw.org, The Print, ANI, Financial
        # Express, Defence Aviation Post all returned HTML/404/403 at every
        # path tried); verified live before adding.
        ("https://www.livefistdefence.com/feed/", "Livefist Defence", 1),
        # New countries — each verified live AND content-checked (actual
        # defence articles in the response, not a redirect/placeholder) before
        # adding. Every German outlet tried (ESUT, bundeswehr-journal.de,
        # hartpunkt.de — incl. their fake "/en/" paths, which silently serve
        # the same German content) publishes German-only; since the relevance
        # engine's keyword lists are English-only, a German feed would pass
        # zero articles ever — dead weight, not real coverage, so skipped.
        # Same reasoning ruled out Israel/Japan/South Korea/Taiwan/Canada:
        # candidates were either dead, or general-news firehoses mislabeled as
        # "defense" feeds (UPI's Defense-News RSS is just its generic feed).
        # Left as gaps rather than adding noise or non-functional entries.
        ("https://www.militarnyi.com/en/feed/", "Militarnyi (Ukraine)", 1),
        ("https://opex360.com/feed/", "Zone Militaire / Opex360 (France)", 1),
        ("https://asiapacificdefencereporter.com/feed/", "Asia-Pacific Defence Reporter (Australia/APAC)", 1),
    ]
    _RSS_WEAK_TERMS = WEAK_MIL_TERMS | {
        "disinformation", "propaganda", "psyop", "deepfake", "influence operation",
        "cyber attack", "hack", "breach", "espionage", "apt", "ransomware",
        "drone", "uav", "gps spoof", "jamming", "electronic warfare",
        "missile", "nuclear", "classified", "leak", "intelligence",
    }
    for feed_url, source_name, feed_min_weak in feeds:
        try:
            resp = requests.get(feed_url, timeout=15, headers={"User-Agent": "MilOSINT/2.0"})
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            items = root.findall(".//item") or root.findall(".//atom:entry", ns)
            for item in items[:10]:
                def get_text(tag, alt_tag=None):
                    node = item.find(tag)
                    if node is None and alt_tag:
                        node = item.find(alt_tag, ns)
                    return (node.text or "").strip() if node is not None else ""
                title = get_text("title")
                link = get_text("link") or get_text("atom:link", "atom:link")
                pub = get_text("pubDate") or get_text("atom:published", "atom:published")
                desc = get_text("description") or get_text("atom:summary", "atom:summary")
                passes, tier, reason = relevance_check(title + " " + desc, weak_terms=_RSS_WEAK_TERMS, min_weak=feed_min_weak)
                if not passes:
                    continue
                rows.append({
                    "threat_id":     f"T8-RSS-{short_id(link or title)}",
                    "threat_name":   "Defence/InfoOp News Intelligence",
                    "category_code": "T8", "category_name": CATEGORY_NAMES["T8"],
                    "source_layer":  "Surface Web", "source": source_name,
                    "post_text":     f"{title} | {desc[:300]}",
                    "post_url":      link, "timestamp": pub or now_utc(), "location": "Global",
                    "severity":      "MEDIUM", "confidence": "MEDIUM" if tier == "weak" else "HIGH",
                    # The feed's own domain used to sit here as a placeholder
                    # "IOC" — harmless on its own, but append_to_master()'s
                    # secondary dedup key (ioc_value+category_code) then
                    # treated every article from the same feed as a duplicate
                    # of the first one ever merged, capping each RSS source at
                    # exactly 1 row in the master file forever. The article
                    # link is both a more honest IOC and genuinely unique.
                    "ioc_type":      "url", "ioc_value": link or f"https://{feed_url.split('/')[2]}",
                    "tags":          f"info-ops;disinformation;defence-news;rss;{reason}",
                })
            time.sleep(1)
        except Exception as e:
            log.error(f"RSS error [{source_name}]: {e}")
    log.info(f"Defence RSS: {len(rows)} relevant articles found")
    return rows


def fetch_telegram_channels() -> list:
    """T8 — FREE, no key. Public Telegram channel scraper (t.me/s/{channel}).
    Keyword-density scoring (unchanged from v1 — it was already solid): a
    single high-value hit or several context hits are required, and posts
    with zero forwards on non-OSINT channels are treated as background noise."""
    rows = []
    channels = CONFIG.get("telegram_channels") or []
    _HIGH_VALUE_KW = [
        "missile", "classified", "breach", "espionage", "cyber attack",
        "coordinates", "nato", "apt", "hack", "intercept", "warfare",
        "operation", "strike", "weapon system", "radar", "sonar",
        "satellite imagery", "signal intelligence", "sigint", "humint",
        "special forces", "socom", "pentagon", "mod", "bundeswehr",
        # Russian — "rybar" and "intel_slava_z" (both in telegram_channels)
        # post almost entirely in Russian; an English-only keyword list means
        # these channels could NEVER score above 0 regardless of actual
        # content, silently producing zero rows forever. Live-tested against
        # real rybar messages: these terms correctly scored real matches
        # (several posts scored 3-7) where the English-only list scored 0 on
        # every single message. Word stems (not full words) since Russian is
        # heavily inflected — "ракет" matches ракета/ракету/ракетный/etc.
        "ракет", "секретн", "утечк", "шпионаж", "кибератак", "координат",
        "нато", "взлом", "перехват", "спецназ", "пентагон", "радар",
        "сигинт", "истребител",
    ]
    _CONTEXT_KW = ["military", "drone", "uav", "attack", "intelligence", "army",
                   "navy", "weapon", "defence", "defense", "warfare", "satellite",
                   "военн", "дрон", "беспилотник", "атак", "армия", "флот",
                   "оружи", "оборон", "войн", "спутник", "удар", "разведк", "фронт"]
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "Accept-Language": "en-US,en;q=0.9",
    }
    for channel in channels:
        try:
            resp = requests.get(f"https://t.me/s/{channel}", headers=headers, timeout=15)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            html = resp.text
            msg_blocks = re.findall(r'<div class="tgme_widget_message_wrap[^"]*">(.*?)</div>\s*</div>\s*</div>',
                                     html, re.DOTALL)
            for block in msg_blocks[:15]:
                text_match = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', block, re.DOTALL)
                raw_text = text_match.group(1) if text_match else ""
                clean_text = re.sub(r'<[^>]+>', '', raw_text).strip()[:600]
                if not clean_text:
                    continue
                text_lower = clean_text.lower()
                high_hits = sum(1 for k in _HIGH_VALUE_KW if k in text_lower)
                context_hits = sum(1 for k in _CONTEXT_KW if k in text_lower)
                density_score = (high_hits * 3) + context_hits
                if density_score < 3:
                    continue
                fwd_match = re.search(r'(\d[\d,]*)\s*(?:forward|view|repost)', block, re.IGNORECASE)
                fwd_count = int(fwd_match.group(1).replace(",", "")) if fwd_match else 0
                osint_channels = {"osintdefender", "militaryosint", "csis_canada", "intelslava"}
                if fwd_count == 0 and channel.lower() not in osint_channels and density_score < 6:
                    continue
                dt_match = re.search(r'datetime="([^"]+)"', block)
                url_match = re.search(r'href="(https://t\.me/[^"]+)"', block)
                msg_url = url_match.group(1) if url_match else f"https://t.me/s/{channel}"
                if density_score >= 9 or fwd_count >= 100:
                    sev = "HIGH"
                elif density_score >= 6 or fwd_count >= 20:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
                rows.append({
                    "threat_id":     f"T8-TG-{short_id(msg_url)}",
                    "threat_name":   f"Telegram Intelligence — @{channel}",
                    "category_code": "T8", "category_name": CATEGORY_NAMES["T8"],
                    "source_layer":  "Deep Web", "source": f"Telegram @{channel}",
                    "post_text":     f"[Score:{density_score} Fwd:{fwd_count}] {clean_text}",
                    "post_url":      msg_url,
                    "timestamp":     dt_match.group(1) if dt_match else now_utc(),
                    "location":      "Global", "severity": sev,
                    "confidence":    "MEDIUM" if fwd_count >= 20 else "LOW",
                    # Same channel-level-IOC issue as RSS (see fetch_defence_news_rss) —
                    # a per-channel ioc_value caps each channel at 1 row in the
                    # master file forever. Use the actual per-message URL.
                    "ioc_type":      "url", "ioc_value": msg_url,
                    "tags":          f"telegram;info-ops;{channel};density-{density_score}",
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"Telegram error [{channel}]: {e}")
    log.info(f"Telegram: {len(rows)} relevant posts found across {len(channels)} channels")
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  ENRICHMENT PASSES — run over rows already collected this run, not
#  standalone collectors. This is where v1's fetch_virustotal() moved to.
# ═════════════════════════════════════════════════════════════════════════

def fetch_epss_enrichment(cve_list: list) -> dict:
    """Enrich CVE ids with EPSS exploit-prediction scores from FIRST.org. Free, no key."""
    if not cve_list:
        return {}
    scores = {}
    try:
        chunk_size = 100
        for i in range(0, len(cve_list), chunk_size):
            chunk = cve_list[i:i + chunk_size]
            resp = requests.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(chunk)}, timeout=15)
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                scores[entry.get("cve", "")] = {
                    "epss": float(entry.get("epss", 0)), "percentile": float(entry.get("percentile", 0))
                }
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.warning(f"EPSS enrichment error: {e}")
    return scores


def fetch_greynoise_enrichment(ip_list: list) -> dict:
    """Enrich IPs with GreyNoise community classification (malicious/benign/unknown).
    Free, no key — but the unauthenticated community endpoint is capped at
    25 requests/WEEK (confirmed live: api.greynoise.io/v3/community/<ip> returns
    429 with "rate_limit":"25-W" well before 50 IPs). The old retry-with-sleep
    logic wasted up to 10s PER REMAINING IP after the quota was already
    exhausted (e.g. 50 IPs all 429ing = ~8+ minutes of pure dead sleep for zero
    classifications) — this is exactly what made this step the single slowest
    part of a full collection run while contributing nothing. Now breaks out
    entirely on the first 429 instead of grinding through the rest."""
    if not ip_list:
        return {}
    results = {}
    for ip in ip_list[:50]:
        try:
            resp = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=10)
            if resp.status_code == 404:
                results[ip] = {"classification": "unknown", "name": "", "riot": False}
                continue
            if resp.status_code == 429:
                log.warning(f"GreyNoise: weekly free-tier quota (25/week) exhausted after {len(results)} IPs — stopping")
                break
            resp.raise_for_status()
            d = resp.json()
            results[ip] = {"classification": d.get("classification", "unknown"),
                           "name": d.get("name", ""), "riot": d.get("riot", False)}
            time.sleep(0.2)
        except Exception as e:
            log.debug(f"GreyNoise [{ip}]: {e}")
    return results


def enrich_with_virustotal(api_key: str, rows: list) -> None:
    """
    VirusTotal enrichment (v2 redesign). v1's fetch_virustotal() returned a
    fixed list of invented-looking "APT domains" (e.g. apt28-login.outlook-
    secure.net) that repeated unchanged on every single run regardless of what
    was actually happening — decorative, not real intelligence. This version
    instead looks up VT reputation for hash/domain IOCs that OTHER modules
    (ThreatFox, MalwareBazaar, OTX, URLhaus) actually found THIS run, and
    boosts severity/confidence when VT confirms detections. No fabricated data.
    """
    if not api_key:
        return
    headers = {"x-apikey": api_key, "User-Agent": "MilOSINT/2.0"}
    hash_rows = {r["ioc_value"]: r for r in rows if r.get("ioc_type") == "hash" and r.get("ioc_value")}
    domain_rows = {r["ioc_value"]: r for r in rows
                   if r.get("ioc_type") == "domain" and r.get("ioc_value") and r.get("category_code") == "T6"}
    checked = 0
    MAX_CHECKS = 25
    for sha256, row in list(hash_rows.items()):
        if checked >= MAX_CHECKS:
            break
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=15)
            checked += 1
            if resp.status_code == 429:
                # Same fix as GreyNoise below: if the key's quota is exhausted,
                # every remaining IOC would otherwise sleep 30s and hit 429
                # again — up to 25*30s = 12.5 minutes of dead time. Stop
                # instead of grinding through the rest.
                log.warning("VirusTotal: rate limit hit — stopping hash enrichment for this run")
                break
            if resp.status_code == 200:
                attrs = (resp.json().get("data") or {}).get("attributes") or {}
                malicious = (attrs.get("last_analysis_stats") or {}).get("malicious", 0)
                if malicious >= 5:
                    row["severity"] = "CRITICAL"
                row["post_text"] = row.get("post_text", "") + f" | [VT] {malicious} AV engines flag malicious"
                row["tags"] = row.get("tags", "") + f";vt-checked;vt-malicious-{malicious}"
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.debug(f"VT hash enrich [{sha256[:12]}]: {e}")
    for domain, row in list(domain_rows.items()):
        if checked >= MAX_CHECKS:
            break
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=15)
            checked += 1
            if resp.status_code == 429:
                log.warning("VirusTotal: rate limit hit — stopping domain enrichment for this run")
                break
            if resp.status_code == 200:
                attrs = (resp.json().get("data") or {}).get("attributes") or {}
                malicious = (attrs.get("last_analysis_stats") or {}).get("malicious", 0)
                if malicious >= 2:
                    row["severity"] = "CRITICAL"
                row["post_text"] = row.get("post_text", "") + f" | [VT] {malicious} AV engines flag malicious"
                row["tags"] = row.get("tags", "") + f";vt-checked;vt-malicious-{malicious}"
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.debug(f"VT domain enrich [{domain}]: {e}")
    log.info(f"VirusTotal enrichment: checked {checked} real IOCs found this run")


# ═════════════════════════════════════════════════════════════════════════
#  POST-PROCESSING — dedup, IOC normalisation, correlation, module health
# ═════════════════════════════════════════════════════════════════════════

_SEEN_TTL_DAYS = 30


def load_seen_threats() -> dict:
    """Dedup store, version-stamped: entries written under an older
    FILTER_VERSION are dropped so a filter-logic change forces re-evaluation
    instead of silently suppressing rows forever."""
    path = Path(CONFIG.get("dedup_file", "seen_threats_v2.json"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=_SEEN_TTL_DAYS)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for tid, rec in raw.items():
        if isinstance(rec, str):
            rec = {"ts": rec, "filter_version": FILTER_VERSION}
        if rec.get("filter_version") != FILTER_VERSION:
            continue
        ts = rec.get("ts", "")
        try:
            if datetime.fromisoformat(ts.replace("Z", "+00:00")) < cutoff:
                continue
        except Exception:
            continue
        out[tid] = rec
    return out


def save_seen_threats(seen: dict):
    Path(CONFIG.get("dedup_file", "seen_threats_v2.json")).write_text(
        json.dumps(seen, indent=2, sort_keys=True), encoding="utf-8")


def deduplicate_rows(rows: list, seen: dict) -> tuple:
    new_rows = []
    for row in rows:
        tid = row.get("threat_id", "")
        if tid and tid in seen:
            continue
        new_rows.append(row)
        if tid:
            seen[tid] = {"ts": now_utc(), "filter_version": FILTER_VERSION}
    return new_rows, len(rows) - len(new_rows)


def append_to_master(new_rows: list, master_path: str) -> int:
    """
    Append this run's already-deduplicated new_rows to the persistent master
    CSV, creating it with a header if it doesn't exist yet. Guards against
    threat_id AND ioc_value+category_code collisions against the existing
    master (not just against new_rows), so re-running after a manual edit to
    the master file can't reintroduce something already recorded there.
    Returns the number of rows actually appended.
    """
    path = Path(master_path)
    seen_ids: set = set()
    seen_ioc: set = set()
    if path.exists():
        with open(path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                tid = (row.get("threat_id") or "").strip().lower()
                ioc = (row.get("ioc_value") or "").strip().lower()
                cat = (row.get("category_code") or "").strip().lower()
                if tid:
                    seen_ids.add(tid)
                if ioc:
                    seen_ioc.add(f"{cat}|{ioc}")
    else:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()

    to_append = []
    for row in new_rows:
        tid = (row.get("threat_id") or "").strip().lower()
        ioc = (row.get("ioc_value") or "").strip().lower()
        cat = (row.get("category_code") or "").strip().lower()
        ioc_key = f"{cat}|{ioc}"
        if tid and tid in seen_ids:
            continue
        if ioc and ioc_key in seen_ioc:
            continue
        if tid:
            seen_ids.add(tid)
        if ioc:
            seen_ioc.add(ioc_key)
        to_append.append(row)

    if to_append:
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            for row in to_append:
                w.writerow({col: row.get(col, "") for col in CSV_COLUMNS})

    log.info(f"Master CSV: {len(to_append)} rows appended -> {master_path} "
             f"({len(seen_ids)} threat_ids tracked total)")
    return len(to_append)


_EMBED_START_MARKER = "/*__EMBEDDED_DATA_START__*/"
_EMBED_END_MARKER = "/*__EMBEDDED_DATA_END__*/"


def export_dashboard_snapshot(master_csv_path: str, dashboard_path: str) -> None:
    """
    Refresh the dashboard HTML in place with the current master dataset
    embedded directly in the page, so opening the file shows the latest
    data immediately — no manual CSV upload needed. Only replaces the JSON
    array between the two marker comments; everything else in the dashboard
    (styling, filters, map, compare tab) is untouched. Safe to call even if
    the dashboard file doesn't exist yet or the markers are missing (skips
    with a warning instead of corrupting anything).
    """
    dash_path = Path(dashboard_path)
    master_path = Path(master_csv_path)
    if not dash_path.exists():
        log.warning(f"Dashboard export skipped — {dashboard_path} not found")
        return
    if not master_path.exists():
        log.warning(f"Dashboard export skipped — {master_csv_path} not found")
        return

    with open(master_path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    html = dash_path.read_text(encoding="utf-8")
    start = html.find(_EMBED_START_MARKER)
    end = html.find(_EMBED_END_MARKER)
    if start == -1 or end == -1:
        log.warning("Dashboard export skipped — embed markers not found (dashboard may be an older version)")
        return
    start += len(_EMBED_START_MARKER)

    payload = json.dumps(rows, ensure_ascii=False)
    new_html = html[:start] + " " + payload + " " + html[end:]
    dash_path.write_text(new_html, encoding="utf-8")
    log.info(f"Dashboard snapshot refreshed: {len(rows)} rows embedded -> {dashboard_path}")


_HEALTH_FILE = "module_health_v2.json"
_ZERO_RUN_ALERT_THRESHOLD = 3


def load_module_health() -> dict:
    p = Path(_HEALTH_FILE)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_module_health(health: dict):
    Path(_HEALTH_FILE).write_text(json.dumps(health, indent=2, sort_keys=True), encoding="utf-8")


def update_module_health(health: dict, module_name: str, row_count: int) -> str:
    rec = health.get(module_name, {"consecutive_zeros": 0, "last_results": 0, "last_run": ""})
    rec["consecutive_zeros"] = 0 if row_count else rec.get("consecutive_zeros", 0) + 1
    rec["last_results"], rec["last_run"] = row_count, now_utc()
    health[module_name] = rec
    if rec["consecutive_zeros"] >= _ZERO_RUN_ALERT_THRESHOLD:
        return (f"MODULE HEALTH: {module_name} has returned 0 results for "
                f"{rec['consecutive_zeros']} consecutive runs — check API key/quota/endpoint")
    return ""


_QUOTA_FILE = "api_quota_v2.json"


def load_quota() -> dict:
    p = Path(_QUOTA_FILE)
    today = datetime.now().strftime("%Y-%m-%d")
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("date") == today:
                return data
        except Exception:
            pass
    return {"date": today, "calls": {}}


def save_quota(quota: dict):
    Path(_QUOTA_FILE).write_text(json.dumps(quota, indent=2), encoding="utf-8")


def increment_quota(quota: dict, module_name: str, n: int = 1):
    quota.setdefault("calls", {})[module_name] = quota["calls"].get(module_name, 0) + n


_RE_IPV4 = re.compile(
    r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_RE_DOMAIN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_RE_CVE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def normalise_ioc(ioc_type: str, ioc_value: str) -> tuple:
    if not ioc_value or ioc_value.strip() in ("", "N/A", "Unknown", "n/a"):
        return ioc_type or "unknown", ""
    v = ioc_value.strip()
    # ThreatFox reports "sha1_hash"/"sha256_hash"/"md5_hash" rather than the
    # plain "hash" this used to check for, so those slipped through unnormalised
    # and showed up as their own separate ioc_type values in the CSV instead of
    # being unified under "hash" like every other hash IOC.
    if ioc_type in ("hash", "") or "hash" in ioc_type or _RE_MD5.match(v):
        if _RE_SHA256.match(v) or _RE_SHA1.match(v) or _RE_MD5.match(v):
            return "hash", v.lower()
    if ioc_type == "cve" or v.upper().startswith("CVE-"):
        return "cve", v.upper()
    if ioc_type == "url" or v.startswith(("http://", "https://", "ftp://")):
        return "url", v[:500]
    if ioc_type == "ip" or _RE_IPV4.match(v.split(":")[0]):
        raw_ip = v.split(":")[0].strip()
        if _RE_IPV4.match(raw_ip):
            return "ip", raw_ip
    if ioc_type == "domain":
        d = v.lower().rstrip(".").split("/")[0]
        if _RE_DOMAIN.match(d):
            return "domain", d
    return ioc_type or "unknown", v


def normalise_rows(rows: list) -> list:
    for row in rows:
        norm_type, norm_val = normalise_ioc(row.get("ioc_type", ""), row.get("ioc_value", ""))
        row["ioc_type"], row["ioc_value"] = norm_type, norm_val
    return rows


def correlate_and_enrich(rows: list) -> list:
    """Cross-source correlation (same IOC in 3+ sources -> escalate to CRITICAL)
    plus free Shodan InternetDB enrichment for every IP IOC found this run.
    This also replaces v1's standalone fetch_dod_internetdb() module, whose
    "guess a handful of /8 gateway IPs" sampling had no real basis for recall
    — any IP actually worth checking already flows through here."""
    from collections import defaultdict
    ioc_sources: dict = defaultdict(set)
    for row in rows:
        ioc = (row.get("ioc_value") or "").strip()
        if ioc and ioc not in ("", "N/A", "Unknown"):
            ioc_sources[ioc].add(row.get("source") or "")
    correlated_iocs = {ioc for ioc, srcs in ioc_sources.items() if len(srcs) >= 3}
    if correlated_iocs:
        log.info(f"Correlation: {len(correlated_iocs)} IOCs appeared in 3+ sources -> escalated to CRITICAL")

    enriched_ips: dict = {}
    ip_rows = [r for r in rows if r.get("ioc_type") == "ip" and r.get("ioc_value")]
    unique_ips = list({r["ioc_value"] for r in ip_rows})[:30]
    for ip in unique_ips:
        if not ip or not ip.replace(".", "").isdigit():
            continue
        try:
            resp = requests.get(f"https://internetdb.shodan.io/{ip}",
                                 headers={"User-Agent": "MilOSINT/2.0", "Accept": "application/json"}, timeout=8)
            if resp.status_code == 200:
                enriched_ips[ip] = resp.json()
            time.sleep(0.5)
        except Exception:
            pass
    if enriched_ips:
        log.info(f"InternetDB: enriched {len(enriched_ips)} IPs with Shodan data")

    for row in rows:
        ioc = (row.get("ioc_value") or "").strip()
        if ioc in correlated_iocs:
            row["severity"] = "CRITICAL"
            row["tags"] = row.get("tags", "") + ";correlated;multi-source"
            row["post_text"] = "[CORRELATED MULTI-SOURCE] " + row.get("post_text", "")
        if row.get("ioc_type") == "ip" and ioc in enriched_ips:
            idb = enriched_ips[ioc]
            ports, vulns = idb.get("ports") or [], idb.get("vulns") or []
            row["post_text"] = (row.get("post_text", "") +
                                 f" | [Shodan InternetDB] Ports: {ports[:8]} | CVEs: {vulns[:5]} | "
                                 f"Hostnames: {(idb.get('hostnames') or [])[:3]} | Tags: {(idb.get('tags') or [])[:4]}")
            if vulns:
                row["severity"] = "CRITICAL"
                row["tags"] = row.get("tags", "") + ";shodan-vulns;" + ";".join(v.lower() for v in vulns[:3])
    return rows


# ═════════════════════════════════════════════════════════════════════════
#  ALERTS
# ═════════════════════════════════════════════════════════════════════════

def send_whatsapp_alert(rows: list, run_ts: str):
    sid = CONFIG.get("twilio_account_sid", "").strip()
    token = CONFIG.get("twilio_auth_token", "").strip()
    to = CONFIG.get("whatsapp_to", "").strip()
    frm = CONFIG.get("twilio_whatsapp_from", "whatsapp:+14155238886").strip()
    if not (sid and token and to):
        return
    if not to.startswith("whatsapp:"):
        to = f"whatsapp:{to}"
    alert_threshold = CONFIG.get("whatsapp_alert_threshold", "high").lower()
    critical = [r for r in rows if r.get("severity") == "CRITICAL"]
    high = [r for r in rows if r.get("severity") == "HIGH"]
    if alert_threshold == "critical_only":
        alert_rows = critical
        if not alert_rows:
            return
    else:
        alert_rows = critical + high
        if not alert_rows:
            return
    lines = [
        f"{'🔴' if critical else '🟠'} *Military OSINT Alert — {run_ts}*", "─" * 30,
        f"🔴 Critical: *{len(critical)}* | 🟠 High: *{len(high)}*", f"Total rows: {len(rows)}", "─" * 30,
    ]
    for r in alert_rows[:8]:
        em = "🔴" if r.get("severity") == "CRITICAL" else "🟠"
        lines.append(f"{em} [{r.get('category_code','')}] {(r.get('threat_name') or '')[:45]}")
        ioc = (r.get("ioc_value") or "")[:35]
        if ioc:
            lines.append(f"   `{ioc}` — {(r.get('source') or '')[:25]}")
    if len(alert_rows) > 8:
        lines.append(f"\n_+{len(alert_rows)-8} more — open the CSV for full details_")
    try:
        resp = requests.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                              auth=(sid, token), data={"From": frm, "To": to, "Body": "\n".join(lines)}, timeout=15)
        resp.raise_for_status()
        log.info(f"WhatsApp: alert sent -> {to} ({len(critical)} CRITICAL, {len(high)} HIGH)")
    except Exception as e:
        log.error(f"WhatsApp alert failed: {e}")


def send_discord_alert(rows: list, run_ts: str):
    webhook_url = CONFIG.get("discord_webhook_url", "").strip()
    if not webhook_url:
        return
    critical = [r for r in rows if r.get("severity") == "CRITICAL"]
    high = [r for r in rows if r.get("severity") == "HIGH"]
    if not critical and not high:
        return
    fields = []
    for r in (critical + high)[:8]:
        sev = r.get("severity", "")
        fields.append({
            "name": f"{'🔴' if sev == 'CRITICAL' else '🟠'} {sev} — {(r.get('threat_name') or r.get('category_name') or 'Threat')[:50]}",
            "value": f"`{(r.get('ioc_value') or '')[:80]}`\n{r.get('source','')}\n{(r.get('post_text') or '')[:200]}",
            "inline": False,
        })
    payload = {
        "username": "MilOSINT Alert",
        "embeds": [{
            "title": f"Military OSINT Alert — {run_ts}",
            "description": f"**{len(critical)} CRITICAL** | **{len(high)} HIGH** threats found\nTotal rows this run: {len(rows)}",
            "color": 0xFF0000 if critical else 0xFF8C00, "fields": fields,
            "footer": {"text": "military_osint_tool_v2.py — MilOSINT"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        log.info(f"Discord: alert sent — {len(critical)} CRITICAL, {len(high)} HIGH threats")
    except Exception as e:
        log.error(f"Discord alert failed: {e}")


# ═════════════════════════════════════════════════════════════════════════
#  STIX 2.1 EXPORT
# ═════════════════════════════════════════════════════════════════════════

def export_stix_bundle(rows: list, ts: str):
    if not CONFIG.get("stix_export", True):
        return
    objects = []
    IOC_TYPE_MAP = {
        "ip": "network-traffic", "domain": "domain-name", "url": "url",
        "hash": "file", "email": "email-addr",
    }
    for row in rows:
        ioc_type = (row.get("ioc_type") or "").lower()
        ioc_value = (row.get("ioc_value") or "").strip()
        desc = (row.get("post_text") or "")[:500]
        tags = [t for t in (row.get("tags") or "").split(";") if t]

        if ioc_type == "cve" or ioc_value.upper().startswith("CVE-"):
            cve_id = ioc_value.upper()
            objects.append({
                "type": "vulnerability", "spec_version": "2.1", "id": f"vulnerability--{short_id(cve_id)}",
                "created": now_utc(), "modified": now_utc(), "name": cve_id, "description": desc,
                "external_references": [{"source_name": "cve", "external_id": cve_id}], "labels": tags[:5],
            })
            continue
        if ioc_type not in IOC_TYPE_MAP or not ioc_value:
            continue
        pattern_map = {
            "ip": f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ioc_value}']",
            "domain": f"[domain-name:value = '{ioc_value}']",
            "url": f"[url:value = '{ioc_value}']",
            "hash": f"[file:hashes.SHA-256 = '{ioc_value}']",
            "email": f"[email-message:from_ref.value = '{ioc_value}']",
        }
        confidence_map = {"HIGH": 85, "MEDIUM": 60, "LOW": 40}
        ind_id = f"indicator--{short_id(ioc_value + ioc_type)}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now_utc(), "modified": now_utc(),
            "name": (row.get("threat_name") or "Military Threat")[:100], "description": desc,
            "pattern": pattern_map[ioc_type], "pattern_type": "stix",
            "valid_from": row.get("timestamp") or now_utc(),
            "confidence": confidence_map.get(row.get("confidence", "MEDIUM"), 60),
            "labels": tags[:5],
            "external_references": [{"source_name": row.get("source", "MilOSINT"), "url": row.get("post_url", "")}],
        })

    report_obj = {
        "type": "report", "spec_version": "2.1", "id": f"report--{short_id(ts)}",
        "created": now_utc(), "modified": now_utc(),
        "name": f"Military OSINT Collection — {ts}",
        "description": f"Automated military cyber threat intelligence collection. {len(rows)} total rows, {len(objects)} STIX objects.",
        "published": now_utc(), "object_refs": [o["id"] for o in objects],
        "labels": ["military", "osint", "threat-intelligence"],
    }
    objects.append(report_obj)
    bundle = {"type": "bundle", "id": f"bundle--{hashlib.md5(ts.encode()).hexdigest()}", "objects": objects}
    out_path = Path(f"military_osint_stix_v2_{ts}.json")
    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    log.info(f"STIX 2.1: exported {len(objects)-1} objects -> {out_path}")


# ═════════════════════════════════════════════════════════════════════════
#  WEEKLY DELTA REPORT
# ═════════════════════════════════════════════════════════════════════════

def generate_weekly_delta(current_rows: list, ts: str):
    snapshot_path = Path("weekly_snapshot_v2.json")
    now_dt = datetime.now(timezone.utc)
    week_ago = now_dt - timedelta(days=7)
    old_ids: set = set()
    old_by_cat: dict = {}
    if snapshot_path.exists():
        try:
            snap = json.loads(snapshot_path.read_text(encoding="utf-8"))
            snap_dt = datetime.fromisoformat(snap.get("timestamp", "2000-01-01").replace("Z", "+00:00"))
            if snap_dt >= week_ago:
                old_ids = set(snap.get("threat_ids", []))
                old_by_cat = snap.get("by_category", {})
        except Exception:
            pass
    new_ids = set(r.get("threat_id", "") for r in current_rows) - old_ids
    curr_by_cat: dict = {}
    for r in current_rows:
        curr_by_cat[r.get("category_code", "?")] = curr_by_cat.get(r.get("category_code", "?"), 0) + 1

    lines = [
        "Military OSINT Weekly Delta Report", f"Generated: {now_utc()}", "=" * 50,
        f"New threats vs last week: {len(new_ids)}", f"Total this run: {len(current_rows)}",
        "", "By Category (this run vs last week):",
    ]
    for cat in sorted(set(list(curr_by_cat.keys()) + list(old_by_cat.keys()))):
        curr, prev = curr_by_cat.get(cat, 0), old_by_cat.get(cat, 0)
        delta = curr - prev
        lines.append(f"  {cat}: {curr} ({'+' if delta >= 0 else ''}{delta} vs last week)")
    lines += ["", "Severity breakdown (this run):"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"  {sev}: {sum(1 for r in current_rows if r.get('severity') == sev)}")

    Path(f"weekly_delta_v2_{ts}.txt").write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Weekly delta report written ({len(new_ids)} new threats vs last week)")
    snapshot_path.write_text(json.dumps({
        "timestamp": now_utc(),
        "threat_ids": sorted(r.get("threat_id", "") for r in current_rows),
        "by_category": curr_by_cat,
    }, indent=2), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════
#  WINDOWS TASK SCHEDULER XML
# ═════════════════════════════════════════════════════════════════════════

def generate_task_scheduler_xml(script_path: str, ts: str):
    if not CONFIG.get("generate_task_xml", True):
        return
    python_exe = sys.executable.replace("\\", "\\\\")
    script_abs = str(Path(script_path).resolve()).replace("\\", "\\\\")
    work_dir = str(Path(script_path).parent.resolve()).replace("\\", "\\\\")
    xml_text = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Military OSINT v2 daily intelligence collection (auto-generated {ts})</Description>
    <Author>MilOSINT</Author>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T06:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{python_exe}</Command>
      <Arguments>"{script_abs}"</Arguments>
      <WorkingDirectory>{work_dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""
    out = Path(f"MilOSINT_v2_Task_{ts}.xml")
    out.write_text(xml_text, encoding="utf-16")
    log.info(f"Task Scheduler XML: {out}")


# ═════════════════════════════════════════════════════════════════════════
#  --clean MODE — re-filter an existing CSV (e.g. an old merged file) using
#  the same relevance engine as live collection, without running any network
#  calls. Targets exactly the three sources that produce keyword false
#  positives in v1 output: HaveIBeenPwned, GitHub, GrayhatWarfare. Every
#  other row (CVE feeds, IP scans, malware hashes, satellite data...) is
#  gated upstream by vendor/domain/CVSS checks already, so it passes through
#  untouched — this mode does not try to be a universal junk detector.
# ═════════════════════════════════════════════════════════════════════════

def clean_existing_csv(input_path: str, output_path: str):
    # utf-8-sig strips a leading BOM if present — without it, a BOM silently
    # merges into the first header name (﻿threat_id) and every row's
    # threat_id then reads back empty.
    with open(input_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))

    kept, dropped = [], []
    github_verified = 0
    MAX_GITHUB_VERIFICATIONS = 60
    for row in rows:
        source = row.get("source") or ""
        text = row.get("post_text") or ""

        if source == "HaveIBeenPwned":
            # Deliberately exclude threat_name: it's a fixed per-source label
            # ("Military Credential Leak") that contains the word "military"
            # on every single row, which would silently satisfy one of the
            # two required weak-term hits regardless of the actual breach.
            breach_m = re.search(r"Breach:\s*([^\|]+)\|", text)
            breach_name = breach_m.group(1).strip() if breach_m else ""
            domain_m = re.search(r"Domain:\s*([^\|]+)\|", text)
            domain = domain_m.group(1).strip() if domain_m else (row.get("ioc_value") or row.get("location") or "")
            ok, _, reason = relevance_check(breach_name + " " + text, domain_value=domain)
            # Retroactive fix: older rows carry the raw domain as "location"
            # (same bug just fixed in fetch_hibp) instead of a country name.
            row["location"] = domain_to_country(domain)
        elif source == "crt.sh (Certificate Transparency)":
            cn_val = row.get("ioc_value") or ""
            if _PERSONAL_CERT_RE.match(cn_val):
                # Personal DoD CAC certificate name (e.g. "SMITH.JOHN.A.1234567890")
                # that leaked in before this exclusion existed in fetch_crtsh —
                # a personal identifier, not an infrastructure finding.
                ok, reason = False, "personal-cac-certificate-not-infrastructure"
            else:
                # Retroactive fix: older rows have "location" hardcoded to "USA"
                # regardless of which country's domain actually matched (same bug
                # just fixed in fetch_crtsh) — ioc_value is the matched hostname.
                row["location"] = domain_to_country(cn_val)
                ok, reason = True, "kept"
        elif source == "URLScan.io":
            # Retroactive fix: older rows have "location" set to the raw
            # scanned-page domain (same bug just fixed in fetch_urlscan).
            dom_m = re.search(r"Domain:\s*([^\|]+)\|", text)
            row["location"] = domain_to_country(dom_m.group(1).strip() if dom_m else "")
            ok, reason = True, "kept"
        elif source == "GitHub (public repo)":
            low = text.lower()
            if any(p in low for p in _DORK_FILE_PATTERNS) or any(p in low for p in _NOISE_REPO_PATTERNS):
                ok, reason = False, "dork-or-noise-repo-pattern"
            else:
                ok, reason = True, "kept"
                # Old CSVs (like the one this mode was built for) were written
                # before content verification existed: every hit was stamped
                # CRITICAL/MEDIUM purely because a keyword string matched
                # somewhere in the file, including unrelated docs (e.g. a
                # validation-library API.md that happens to mention
                # "army.mil" and "password" as separate, unrelated words).
                # Re-verify by fetching the real file content here too.
                html_url = row.get("post_url") or ""
                if html_url and github_verified < MAX_GITHUB_VERIFICATIONS:
                    content = _fetch_raw_github_content(html_url)
                    github_verified += 1
                    if content:
                        if _looks_like_secret(content):
                            row["severity"], row["confidence"] = "CRITICAL", "HIGH"
                            reason = "secret-pattern-confirmed-in-content"
                        else:
                            row["severity"], row["confidence"] = "MEDIUM", "LOW"
                            reason = "no-secret-pattern-found-in-content"
        elif source == "GrayhatWarfare":
            size_m = re.search(r"Size:\s*(\d+)\s*bytes", text)
            file_m = re.search(r"File:\s*([^\|]+)\|", text)
            size = int(size_m.group(1)) if size_m else 1
            fname = file_m.group(1).strip().lower() if file_m else ""
            ext = Path(fname).suffix
            if size == 0 or ext in _GHW_SKIP_EXTS or any(t in fname for t in _GHW_NEG_FILENAME_TERMS):
                ok, reason = False, "zero-byte-or-media-file"
            else:
                ok, reason = True, "kept"
        elif source == "Celestrak SATCAT (US Space Command)":
            # "US Military Satellites" used to be any object with owner code
            # "US" — mostly Starlink/Kuiper/SpaceMobile. Drop those; every
            # other Celestrak category (GPS/GLONASS/COSMOS/Chinese/Russian)
            # is name- or owner-gated in a way this bug didn't affect.
            obj_m = re.search(r"Object:\s*([^\|]+)\|", text)
            cat_m = re.search(r"Category:\s*(.+)$", text)
            obj_name = obj_m.group(1).strip().upper() if obj_m else ""
            category = cat_m.group(1).strip() if cat_m else ""
            if "US Military Satellites" in category and any(c in obj_name for c in _COMMERCIAL_SAT_EXCLUDE):
                ok, reason = False, "commercial-satellite-mislabeled-as-military"
            else:
                ok, reason = True, "kept"
        elif source == "URLhaus (abuse.ch)":
            # Bare "apt" in the malware-family list matched inside "adapter"/
            # "adapters" — extremely common in software repo URL paths.
            url_m = re.search(r"URL:\s*([^\|]+)\|", text)
            tags_m = re.search(r"Tags:\s*(.*)$", text)
            threat_m = re.search(r"Threat:\s*([^\|]+)\|", text)
            url_val = url_m.group(1).strip().lower() if url_m else ""
            combined = (url_val + " " + (tags_m.group(1).strip().lower() if tags_m else "")
                        + " " + (threat_m.group(1).strip().lower() if threat_m else ""))
            family_match = _has_any(combined, _MIL_MALWARE_TAGS)
            try:
                from urllib.parse import urlparse
                host = urlparse(url_val).netloc
                adversary_match = (any(host.endswith(t) for t in _ADVERSARY_TLDS)
                                    and any(t in url_val for t in _MIL_URL_TARGETS))
            except Exception:
                adversary_match = False
            if not (family_match or adversary_match):
                ok, reason = False, "apt-in-adapter-false-positive"
            else:
                ok, reason = True, "kept"
        elif source in ("RansomWatch (ransomware leak sites)", "ransomware.live (ransomware leak sites)"):
            # Very old rows from this source predate ANY government/military
            # filter (e.g. a random Massachusetts electrical contractor
            # recorded as "CRITICAL" purely for being a ransomware victim at
            # all). Re-apply the current tier logic; downgrade or drop rows
            # with no military/contractor/government evidence.
            tier_m = re.search(r"Tier:\s*([^\|]+)\|", text)
            if tier_m:
                # Rows written by the current fetcher already embed the tier
                # it computed FROM THE ACTUAL DOMAIN (which the live fetcher
                # has access to but this retroactive check does not) — trust
                # it rather than re-deriving from just the victim's display
                # name below, which will never contain ".gov" even when the
                # organization's real domain does (e.g. "Edgewood Police
                # Department" was wrongly dropped by the old name-only check
                # despite being a correctly-tiered government victim).
                tier_label = tier_m.group(1).strip()
                if "Military" in tier_label:
                    ok, reason = True, "kept"
                elif "Contractor" in tier_label:
                    ok, reason = True, "kept"
                    row["severity"], row["confidence"] = "HIGH", "MEDIUM"
                elif "Government" in tier_label:
                    ok, reason = True, "kept"
                    row["severity"], row["confidence"] = "MEDIUM", "MEDIUM"
                else:
                    ok, reason = False, "no-military-govt-contractor-evidence"
            else:
                victim_m = re.search(r"Victim:\s*([^\|]+)\|", text)
                victim = victim_m.group(1).strip().lower() if victim_m else ""
                tier1_mil = any(d in victim for d in _TIER1_MIL_DOMAINS)
                tier2_contractor = _has_any(victim, _TIER2_CONTRACTORS)
                tier3_gov = (not tier1_mil) and (not tier2_contractor) and (_TIER3_GENERIC_GOV_MARKER in victim)
                if not (tier1_mil or tier2_contractor or tier3_gov):
                    ok, reason = False, "no-military-govt-contractor-evidence"
                else:
                    ok, reason = True, "kept"
                    if tier3_gov:
                        row["severity"], row["confidence"] = "MEDIUM", "MEDIUM"
                    elif tier2_contractor:
                        row["severity"], row["confidence"] = "HIGH", "MEDIUM"
        elif source == "LeakIX":
            # An older, pre-"STRICT GATE" version of this module searched
            # LeakIX with generic keywords instead of a host:<military-domain>
            # filter. A dashboard review of the compiled master file found
            # 79 of 111 LeakIX rows (71%) were completely unrelated exposed
            # services — a car-insurance quote site, random personal Apache
            # status pages — with no "Target:" military label at all. Current
            # rows always start with "Target: <label> | Host: <host>"; if
            # that host doesn't actually end in a military domain, drop it.
            host_m = re.search(r"Host:\s*([^\s:|]+)", text)
            host = host_m.group(1).strip().lower() if host_m else ""
            if not has_mil_domain(host):
                ok, reason = False, "pre-strict-gate-non-military-host"
            else:
                ok, reason = True, "kept"
        elif source == "CIRCL CVE API" and row.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            # An older version of this module (back when it wrote "High-Severity
            # CVE — Potential Autonomous/Embedded System Threat" instead of the
            # current "Critical CVE — Military Supply Chain" threat_name) left
            # severity as the literal string "UNKNOWN" on every row — invalid
            # for the dashboard's severity filter/color-coding. All rows from
            # this source were already pre-filtered to CVSS >= 9.0 at collection
            # time, so "HIGH" (this module's current default/floor) is a safe,
            # defensible correction — not a guess pulled from nothing.
            row["severity"] = "HIGH"
            ok, reason = True, "kept"
        elif source == "OpenSky Network" and "GPS Spoofing" in (row.get("threat_name") or ""):
            # Confirmed the ADS-B "SPI" bit this old row-type was based on is
            # just a pilot's transponder IDENT pulse (routine ATC-requested
            # "squawk ident" for traffic identification, ~18 seconds, triggered
            # by the PILOT) — completely unrelated to GPS spoofing/jamming.
            # fetch_gps_ew_data() no longer generates this row type; drop the
            # historical false positives rather than leave a confirmed-wrong
            # HIGH-severity claim in the master file.
            ok, reason = False, "spi-is-atc-ident-not-gps-spoofing-mischaracterization"
        else:
            ok, reason = True, "unaffected-source (not a keyword-search module)"

        (kept if ok else dropped).append((row, source, reason))

    out_path = Path(output_path)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for row, _, _ in kept:
            w.writerow({col: row.get(col, "") for col in CSV_COLUMNS})

    print(f"Cleaned {input_path} -> {output_path}")
    print(f"  Input rows : {len(rows)}")
    print(f"  Kept       : {len(kept)}")
    print(f"  Dropped    : {len(dropped)}")
    by_source: dict = {}
    for _, src, _ in dropped:
        by_source[src] = by_source.get(src, 0) + 1
    for src, n in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    - {src}: {n} dropped")


# ═════════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════

def run_collection():
    log.info("=" * 60)
    log.info("Military Cyber Threat OSINT Collection v2 — Starting")
    log.info("=" * 60)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    CONFIG["output_csv"] = CONFIG["output_csv"].replace("{ts}", ts)

    def status(*key_names):
        if not key_names:
            return "ACTIVE (free — no key needed)"
        missing = [k for k in key_names if not key_available(k)]
        return "ACTIVE" if not missing else f"SKIPPED — set {', '.join(missing)}"

    log.info("Module status:")
    log.info(f"  [T1] HIBP (credential breaches)        : ACTIVE (free)")
    log.info(f"  [T1] DeHashed (breach DB .mil emails)  : {status('dehashed_email','dehashed_api_key')}")
    log.info(f"  [T1] GitHub Dorking (leaked creds)     : {status('github_token')}")
    log.info(f"  [T2] GrayhatWarfare (exposed buckets)  : {status('grayhatwarfare_api_key')}")
    log.info(f"  [T2] IntelligenceX (dark web docs)     : {status('intelx_api_key')}")
    log.info(f"  [T2] LeakIX (exposed services/leaks)   : {status('leakix_api_key')}")
    log.info(f"  [T3] Shodan (network scan)             : {status('shodan_api_key')}")
    log.info(f"  [T3] SecurityTrails (DNS intel)        : {status('securitytrails_api_key')}")
    censys_ready = key_available("censys_api_id") and (
        CONFIG.get("censys_api_id", "").startswith("censys_") or key_available("censys_api_secret"))
    log.info(f"  [T3] Censys (internet scan)            : {'ACTIVE' if censys_ready else 'SKIPPED — set censys_api_id(+secret)'}")
    log.info(f"  [T3] ZoomEye (internet scan)           : {status('zoomeye_api_key')}")
    log.info(f"  [T3] Onyphe (EU/NATO scan)              : {status('onyphe_api_key')}")
    log.info(f"  [T3] Criminal IP (malicious IP intel)  : {status('criminal_ip_api_key')}")
    log.info(f"  [T3] BinaryEdge (internet scan)        : {status('binaryedge_api_key')}")
    log.info(f"  [T3] crt.sh (certificate transparency) : ACTIVE (free)")
    log.info(f"  [T3] URLScan.io (web exposure scan)    : ACTIVE (free)")
    log.info(f"  [T4] OpenSky Network (GPS/EW)          : ACTIVE (free)")
    log.info(f"  [T4] Celestrak (satellite/ASAT)        : ACTIVE (free)")
    log.info(f"  [T4] FAA NOTAM (GPS interference)      : {status('faa_client_id','faa_client_secret')}")
    log.info(f"  [T5] CISA KEV (ICS/SCADA)              : ACTIVE (free)")
    log.info(f"  [T5] PacketStorm (ICS advisories)      : ACTIVE (free)")
    log.info(f"  [T6] OTX AlienVault (APT pulses)       : {status('otx_api_key')}")
    log.info(f"  [T6] ThreatFox (APT IOCs)              : {status('threatfox_api_key')}")
    log.info(f"  [T6] Feodo Tracker (botnet C2 IPs)     : ACTIVE (free)")
    log.info(f"  [T6] URLhaus (malware URLs)            : ACTIVE (free)")
    log.info(f"  [T6] MalwareBazaar (malware samples)   : ACTIVE (free)")
    log.info(f"  [T6] Recorded Future (APT infra)       : {status('recorded_future_key')}")
    log.info(f"  [T7] CIRCL CVE API (high-severity CVEs): ACTIVE (free)")
    log.info(f"  [T7] NVD (vendor-gated critical CVEs)  : ACTIVE (free)")
    log.info(f"  [T8] Defence RSS feeds                 : ACTIVE (free)")
    log.info(f"  [T8] Telegram channels                 : ACTIVE (free — {len(CONFIG.get('telegram_channels',[]))} channels)")
    log.info(f"  [--] VirusTotal enrichment              : {status('virustotal_api_key')}")
    log.info(f"  [--] Discord alerts                    : {'ACTIVE' if CONFIG.get('discord_webhook_url') else 'DISABLED'}")
    wa_ready = CONFIG.get("twilio_account_sid") and CONFIG.get("twilio_auth_token") and CONFIG.get("whatsapp_to")
    log.info(f"  [--] WhatsApp alerts (Twilio)          : {'ACTIVE' if wa_ready else 'DISABLED'}")
    log.info(f"  [--] STIX 2.1 export                   : {'ACTIVE' if CONFIG.get('stix_export') else 'DISABLED'}")
    log.info("=" * 60)

    seen_threats = load_seen_threats()
    module_health = load_module_health()
    run_quota = load_quota()
    all_rows = []
    writer = CSVWriter(CONFIG["output_csv"])

    def run(label, fn, *args):
        log.info(label)
        try:
            r = fn(*args)
        except Exception as e:
            log.error(f"{label} — unhandled error: {e}")
            r = []
        all_rows.extend(r)
        writer.write_many(r)
        return r

    # ── T1 ──
    run("[T1] Fetching credential breaches from HIBP...", fetch_hibp_breaches, CONFIG.get("hibp_api_key", ""))
    if key_available("dehashed_email") and key_available("dehashed_api_key"):
        run("[T1] Searching military email credentials in DeHashed...", fetch_dehashed,
            CONFIG["dehashed_email"], CONFIG["dehashed_api_key"])
    if key_available("github_token"):
        run("[T1/T2] Dorking GitHub for leaked military credentials/configs...", fetch_github_leaks, CONFIG["github_token"])

    # ── T2 ──
    if key_available("grayhatwarfare_api_key"):
        run("[T2] Searching exposed cloud buckets via GrayhatWarfare...", fetch_grayhatwarfare, CONFIG["grayhatwarfare_api_key"])
    if key_available("intelx_api_key"):
        run("[T2] Fetching document/paste leaks from IntelligenceX...", fetch_intelx_pastes, CONFIG["intelx_api_key"], ".mil")
        run("[T2] Fetching document/paste leaks from IntelligenceX (classified)...", fetch_intelx_pastes,
            CONFIG["intelx_api_key"], "classified defence")
    if key_available("leakix_api_key"):
        run("[T2/T3] Searching exposed services and data leaks via LeakIX...", fetch_leakix, CONFIG["leakix_api_key"])

    # ── T3 ──
    if key_available("shodan_api_key"):
        run("[T3] Scanning exposed military infrastructure via Shodan...", fetch_shodan_military, CONFIG["shodan_api_key"])
    if key_available("securitytrails_api_key"):
        run("[T3] Fetching military DNS intelligence via SecurityTrails...", fetch_securitytrails, CONFIG["securitytrails_api_key"])
    if censys_ready:
        run("[T3] Scanning exposed military network assets via Censys...", fetch_censys,
            CONFIG["censys_api_id"], CONFIG.get("censys_api_secret", ""))
    run("[T3] Querying crt.sh certificate transparency for military domains...", fetch_crtsh)
    if key_available("zoomeye_api_key"):
        run("[T3] Scanning military infrastructure via ZoomEye...", fetch_zoomeye, CONFIG["zoomeye_api_key"])
    if key_available("onyphe_api_key"):
        run("[T3] Scanning NATO/EU military infrastructure via Onyphe...", fetch_onyphe, CONFIG["onyphe_api_key"])
    if key_available("criminal_ip_api_key"):
        run("[T3/T6] Fetching malicious IPs via Criminal IP...", fetch_criminalip, CONFIG["criminal_ip_api_key"])
    if key_available("binaryedge_api_key"):
        run("[T3] Scanning military exposed services via BinaryEdge...", fetch_binaryedge, CONFIG["binaryedge_api_key"])
    urlscan_rows = run("[T3] Scanning military domain web exposures via URLScan.io...", fetch_urlscan, CONFIG.get("urlscan_api_key", ""))
    _health_warn = update_module_health(module_health, "URLScan", len(urlscan_rows))
    if _health_warn:
        log.warning(_health_warn)

    # ── T4 ──
    run("[T4] Scanning GPS/EW anomalies via OpenSky Network...", fetch_gps_ew_data)
    run("[T4] Fetching satellite tracking data from Celestrak...", fetch_celestrak)
    if key_available("faa_client_id") and key_available("faa_client_secret"):
        run("[T4] Fetching GPS interference NOTAMs from FAA...", fetch_faa_notams, CONFIG["faa_client_id"], CONFIG["faa_client_secret"])

    # ── T5 ──
    run("[T5] Fetching CISA ICS/SCADA advisories...", fetch_cisa_ics_advisories)
    run("[T5] Fetching ICS/military advisories from PacketStorm...", fetch_packetstorm)

    # ── T6 ──
    if key_available("otx_api_key"):
        run("[T6] Fetching APT pulses from OTX AlienVault...", fetch_otx_pulses, CONFIG["otx_api_key"])
    run("[T6] Fetching APT IOCs from ThreatFox...", fetch_threatfox_iocs)
    run("[T6] Fetching active botnet C2 IPs from Feodo Tracker...", fetch_feodo_c2)
    run("[T6] Fetching malware URLs from URLhaus...", fetch_urlhaus_malware)
    run("[T6] Fetching malware samples from MalwareBazaar...", fetch_malwarebazaar)
    if key_available("recorded_future_key"):
        run("[T6] Fetching high-risk APT infrastructure from Recorded Future...", fetch_recorded_future, CONFIG["recorded_future_key"])

    # ── T7 ──
    run("[T7] Fetching high-severity CVEs from CIRCL...", fetch_osv_cves)
    nvd_rows = run("[T7] Fetching critical military-vendor CVEs from NVD...", fetch_nvd_cves)
    _health_warn = update_module_health(module_health, "NVD", len(nvd_rows))
    if _health_warn:
        log.warning(_health_warn)

    # ── T8 ──
    run("[T8] Fetching defence news and info-op intelligence from RSS...", fetch_defence_news_rss)
    run(f"[T8] Monitoring {len(CONFIG.get('telegram_channels',[]))} public Telegram channels...", fetch_telegram_channels)

    # ── Dark web round 2 — free ──
    run("[T2] Monitoring ransomware group dark web leak sites...", fetch_ransomwatch)
    run("[T1/T2] Scanning public paste archives for .mil credential leaks...", fetch_paste_leaks)
    run("[T1] Querying Hudson Rock Cavalier for infostealer-compromised .mil accounts...", fetch_hudson_rock)
    run("[T2/T6] Searching dark web via Torch (.onion) for military-relevant content...", fetch_tor_onion)
    if key_available("breachdirectory_api_key"):
        run("[T1/T2] Searching dark web breach dumps via BreachDirectory...", fetch_breachdirectory, CONFIG["breachdirectory_api_key"])
    if CONFIG.get("telegram_api_id") and CONFIG.get("telegram_api_hash") and CONFIG.get("telegram_private_channels"):
        run("[T2/T8] Monitoring private Telegram channels via Telethon...", fetch_telethon_private)

    # ── Dark web round 2 — paid stubs ──
    if key_available("snusbase_api_key"):
        run("[T1] Searching dark web breach dump indexer via Snusbase...", fetch_snusbase, CONFIG["snusbase_api_key"])
    if key_available("cybersixgill_client_id") and key_available("cybersixgill_client_secret"):
        run("[T2] Querying dark web sources via Cybersixgill...", fetch_cybersixgill,
            CONFIG["cybersixgill_client_id"], CONFIG["cybersixgill_client_secret"])
    if key_available("kela_radark_api_key"):
        run("[T2/T6] Querying Eastern European dark web forums via KELA RaDark...", fetch_kela_radark, CONFIG["kela_radark_api_key"])
    if key_available("spycloud_api_key"):
        run("[T1] Recapturing military breach records via SpyCloud...", fetch_spycloud, CONFIG["spycloud_api_key"])
    if key_available("digital_shadows_key") and key_available("digital_shadows_secret"):
        run("[T2] Monitoring dark web org mentions via Digital Shadows...", fetch_digital_shadows,
            CONFIG["digital_shadows_key"], CONFIG["digital_shadows_secret"])
    if key_available("darkowl_api_key"):
        run("[T2] Querying DarkOwl dark web database...", fetch_darkowl, CONFIG["darkowl_api_key"])
    if key_available("flashpoint_api_key"):
        run("[T2] Querying Flashpoint dark web forums...", fetch_flashpoint, CONFIG["flashpoint_api_key"])

    # ── POST-PROCESSING ──
    log.info("[POST] Normalising IOC values...")
    all_rows = normalise_rows(all_rows)

    cve_ids = [r["ioc_value"] for r in all_rows if r.get("ioc_type") == "cve" and r.get("ioc_value")]
    if cve_ids:
        log.info(f"[POST] Fetching EPSS scores for {len(cve_ids)} CVEs...")
        epss_scores = fetch_epss_enrichment(cve_ids)
        for row in all_rows:
            if row.get("ioc_type") == "cve" and row.get("ioc_value") in epss_scores:
                e = epss_scores[row["ioc_value"]]
                row["post_text"] = f"[EPSS:{e['epss']:.4f} | {e['percentile']*100:.1f}th pct] " + row.get("post_text", "")
                if e["epss"] >= 0.5:
                    row["severity"] = "CRITICAL"
                    row["tags"] = row.get("tags", "") + ";epss-high"
        log.info(f"[POST] EPSS enrichment complete — {len(epss_scores)} CVEs scored")

    ip_iocs = list({r["ioc_value"] for r in all_rows if r.get("ioc_type") == "ip" and r.get("ioc_value")})
    if ip_iocs:
        log.info(f"[POST] GreyNoise enrichment for {len(ip_iocs)} IPs...")
        gn_data = fetch_greynoise_enrichment(ip_iocs)
        for row in all_rows:
            if row.get("ioc_type") == "ip" and row.get("ioc_value") in gn_data:
                gn = gn_data[row["ioc_value"]]
                row["post_text"] = row.get("post_text", "") + f" | [GreyNoise] {gn.get('classification','unknown')}"
                if gn.get("classification") == "malicious":
                    row["severity"] = "CRITICAL"
                    row["tags"] = row.get("tags", "") + ";greynoise-malicious"
                elif gn.get("riot"):
                    row["tags"] = row.get("tags", "") + ";greynoise-riot"
        log.info(f"[POST] GreyNoise enrichment complete — {len(gn_data)} IPs classified")

    if key_available("virustotal_api_key"):
        log.info("[POST] VirusTotal enrichment on this run's real IOCs...")
        enrich_with_virustotal(CONFIG["virustotal_api_key"], all_rows)

    log.info("[POST] Running threat correlation and Shodan InternetDB enrichment...")
    all_rows = correlate_and_enrich(all_rows)

    # Self-dedup within this run: threat_id is a deterministic hash of each
    # module's own key fields, so if an upstream feed lists the same item
    # twice (seen live: RansomWatch's posts.json had one victim duplicated),
    # both copies get generated in the same run and neither is caught by
    # deduplicate_rows() below, which only compares against PREVIOUS runs.
    _seen_this_run: set = set()
    _before = len(all_rows)
    deduped_this_run = []
    for row in all_rows:
        tid = row.get("threat_id", "")
        if tid and tid in _seen_this_run:
            continue
        if tid:
            _seen_this_run.add(tid)
        deduped_this_run.append(row)
    if _before != len(deduped_this_run):
        log.info(f"[POST] Self-dedup: removed {_before - len(deduped_this_run)} exact-duplicate rows within this run")
    all_rows = deduped_this_run

    log.info("[POST] Deduplicating against previous runs (TTL: 30 days)...")
    new_rows, dup_count = deduplicate_rows(all_rows, seen_threats)
    save_seen_threats(seen_threats)
    save_module_health(module_health)
    log.info(f"[POST] {dup_count} duplicates suppressed | {len(new_rows)} new threats this run")

    if CONFIG.get("master_csv"):
        log.info("[POST] Merging new findings into master CSV...")
        append_to_master(new_rows, CONFIG["master_csv"])
        if CONFIG.get("dashboard_html"):
            export_dashboard_snapshot(CONFIG["master_csv"], CONFIG["dashboard_html"])

    with open(Path(CONFIG["output_csv"]), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for row in all_rows:
            w.writerow({col: row.get(col, "") for col in CSV_COLUMNS})

    if CONFIG.get("stix_export", True):
        log.info("[POST] Exporting STIX 2.1 bundle...")
        export_stix_bundle(all_rows, ts)
    if CONFIG.get("weekly_delta_report", True):
        log.info("[POST] Generating weekly delta report...")
        generate_weekly_delta(all_rows, ts)
    generate_task_scheduler_xml(__file__, ts)
    save_quota(run_quota)
    send_discord_alert(new_rows, ts)
    send_whatsapp_alert(new_rows, ts)

    flagged = [m for m, h in module_health.items() if h.get("consecutive_zeros", 0) >= _ZERO_RUN_ALERT_THRESHOLD]
    if flagged:
        log.warning(f"[HEALTH] Modules with repeated zero results: {', '.join(flagged)}")

    log.info("=" * 60)
    log.info(f"Collection complete. Total rows: {len(all_rows)} | New: {len(new_rows)} | Dupes suppressed: {dup_count}")
    log.info(f"Output CSV  : {CONFIG['output_csv']}")
    log.info(f"Dedup file  : {CONFIG.get('dedup_file','seen_threats_v2.json')} ({len(seen_threats)} threats tracked)")
    log.info("=" * 60)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Military Cyber OSINT Tool v2")
    parser.add_argument("--clean", nargs=2, metavar=("INPUT_CSV", "OUTPUT_CSV"),
                         help="Re-filter an existing CSV (e.g. an old merged file) instead of running a live collection")
    args = parser.parse_args()

    if args.clean:
        clean_existing_csv(args.clean[0], args.clean[1])
    else:
        run_collection()

