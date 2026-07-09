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
from urllib.parse import quote

import requests

FILTER_VERSION = "2.1"
# Bumped from 2.0 (see chat) — a live audit found 1,146 of 1,627
# seen_threats_v2.json entries (70%) were "orphaned": marked seen so
# deduplicate_rows() would never re-offer them, but absent from
# military_osint_master.csv entirely (across nearly every module —
# crt.sh, urlscan, ThreatFox, Celestrak, RSS, LeakIX, ransomware.live,
# GrayhatWarfare, OTX, OpenSky, MalwareBazaar, NVD, correlation, CISA,
# DNS, Netlas, Feodo, Tor, URLhaus). Root cause: master CSV was rebuilt/
# filtered during this session's India+neighbours narrowing work, but
# the separate dedup store was never correspondingly cleared, and
# neither self-healing mechanism this store already has (30-day TTL;
# version-stamp invalidation on filter-logic changes) had kicked in yet
# — the entries are only ~1-2 days old, and FILTER_VERSION was never
# bumped despite this session's substantial filter-logic changes
# (LeakIX severity, 8-module category fix, CVE fail-open fix, vendor
# term narrowing, etc.), each of which was exactly the scenario this
# version stamp exists to force a re-evaluation for. Bumping it here
# invalidates the entire stale store at once; append_to_master()'s own
# independent check against the CURRENT master CSV (by threat_id AND
# ioc_value+category_code) still protects against real duplicates, so
# this only lets the 1,146 orphaned entries' live equivalents back in,
# not anything already correctly recorded."


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
    "vulners_api_key":         "",  # not required by NVD; kept for future use.
                                    # Confirmed live-tested (see chat): the
                                    # API is currently gated behind a
                                    # Cloudflare JS bot-challenge for plain
                                    # HTTP clients (403 "Just a moment...",
                                    # same with/without a browser User-
                                    # Agent) — not usable via simple requests
                                    # right now regardless of key validity.
    "onyphe_api_key":          "",
    # Netlas.io — genuinely free "Community" tier (50 req/day, forever free,
    # no card required — sign up at app.netlas.io, key on the profile page).
    # Added as an independent alternative to Shodan/Censys/ZoomEye (all
    # three are currently blocked on the account/credit side — see chat),
    # so this gives a live, working path to the same class of exposed-
    # asset data even while those three stay broken.
    "netlas_api_key":          "",
    # Tavily Search API — genuinely free "forever free" tier, 1,000 credits/
    # month, no card required. Sign up at https://app.tavily.com — the key
    # is on the dashboard immediately after signup (starts with "tvly-").
    # Used for dork-style queries (see fetch_tavily_search) that reach
    # surface web content (pastebins, doc-sharing sites, forum posts) our
    # infrastructure-focused sources (Shodan/Censys/LeakIX) don't index.
    # Chosen after Google's Custom Search JSON API (the original build)
    # turned out to be closed to new signups — see chat and
    # fetch_tavily_search's docstring.
    "tavily_api_key":          "",

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
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    "hudson_rock_domains": [
        # India — all domains verified live (see chat) before adding
        "indianarmy.nic.in", "indiannavy.gov.in", "indianairforce.nic.in",
        "mod.gov.in", "drdo.gov.in",
        # Indian defence PSUs
        "hal-india.co.in", "bel-india.in", "bdl-india.com",
        "mazagondock.in", "grse.in", "bemlindia.in",
        # Pakistan — verified live: pakistanarmy.gov.pk, paknavy.gov.pk,
        # paf.gov.pk, mod.gov.pk, ispr.gov.pk, hit.com.pk
        "pakistanarmy.gov.pk", "paknavy.gov.pk", "paf.gov.pk",
        "mod.gov.pk", "ispr.gov.pk", "hit.com.pk", "modp.gov.pk",
        # China — verified live: mod.gov.cn, norinco.cn, spacechina.com,
        # avic.com, cetc.com.cn
        "mod.gov.cn", "norinco.cn", "spacechina.com", "avic.com", "cetc.com.cn",
        # India's neighbours — all domains verified live before adding
        # (Bhutan skipped: its only candidate domain, rba.bt, is dead)
        "mod.gov.bd", "afd.gov.bd", "ispr.gov.bd",
        "mod.gov.np", "nepalarmy.mil.np",
        "defence.lk", "army.lk", "navy.lk", "airforce.lk",
        "mod.gov.mm", "cincds.gov.mm",
        # Bangladesh state-owned defence-industrial entities (domains
        # confirmed live via web search)
        "bof.gov.bd", "khulnashipyard.gov.bd", "cddl.gov.bd", "dewbn.gov.bd",
        # Broad military-run commercial conglomerates — deliberately only
        # added here (infostealer-log lookup, keyed to compromised employee
        # credentials at that specific domain) and NOT to the crt.sh/urlscan/
        # ZoomEye domain-suffix lists above, since those would auto-pass ANY
        # subdomain as a military-domain match and these two run large
        # ordinary-commercial operations (fertiliser, banking, food) too.
        "fauji.org.pk", "mecwebsite.com",
        # Nuclear facilities/agencies (T5 gap — see chat)
        "barc.gov.in", "npcil.nic.in", "paec.gov.pk", "cnnc.com.cn", "baec.gov.bd",
        # Border Security Force (T7 border-surveillance gap — see chat)
        "bsf.gov.in",
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
    # rybar/intel_slava_z/osintua removed — explicitly Russia-Ukraine conflict
    # channels, out of scope now that this tool is narrowed to India +
    # neighbouring countries only. CyberSecAlert/RALee85/militaryreview kept:
    # general/global OSINT commentary, not tied to one excluded country.
    "telegram_channels": [
        "CyberSecAlert", "RALee85", "militaryreview",
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
    # Section II of sir's framework — dark web marketplace/forum sources.
    # Purely additive: no existing T1-T8 row's category_code changes, so
    # this doesn't affect anything already in the master CSV (see chat).
    "S1": "Dark Web Marketplaces & Forums",
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

# Narrowed to India + neighbouring countries only (per explicit instruction).
# Previously also covered US/UK/Germany/Canada/Australia/Israel/France/Japan/
# South Korea/Taiwan/Ukraine/NATO — those domain suffixes were removed here.
MIL_DOMAIN_SUFFIXES = (
    # India — specific hostnames only, never bare ".gov.in"/".nic.in": both are
    # shared by thousands of unrelated Indian government sites (state govts,
    # municipal bodies, tax dept...) and would reproduce the exact ".gov"
    # over-broad-match bug already found and fixed in RansomWatch.
    ".indianarmy.nic.in", ".indiannavy.gov.in", ".indianairforce.nic.in",
    ".mod.gov.in", ".drdo.gov.in",
    # Nuclear facilities/agencies — T5 "Nuclear Facility Cyber Threats" /
    # "Nuclear Research Data Leakage" had zero domain coverage before
    # (domains confirmed live via web search; see chat).
    ".barc.gov.in", ".npcil.nic.in",
    # Border Security Force — T7 "Border Surveillance System Compromise" gap
    # (guards the India-Pakistan and India-Bangladesh borders specifically;
    # runs the BOLD-QIT/CIBMS electronic border-surveillance systems).
    ".bsf.gov.in",
    # Pakistan — all verified live (403-WAF-blocked but real, or confirmed via
    # multiple independent sources when directly unreachable from this network).
    ".pakistanarmy.gov.pk", ".paknavy.gov.pk", ".paf.gov.pk",
    ".mod.gov.pk", ".ispr.gov.pk", ".modp.gov.pk", ".paec.gov.pk",
    # China — verified live (eng.mod.gov.cn, en.norinco.cn, spacechina.com,
    # avic.com, cetc.com.cn all confirmed reachable).
    ".mod.gov.cn", ".norinco.cn", ".spacechina.com", ".avic.com", ".cetc.com.cn",
    ".cnnc.com.cn",
    # Bangladesh — verified live (mod.gov.bd, afd.gov.bd, ispr.gov.bd all
    # confirmed reachable with real content; army.mil.bd is unreachable from
    # this network despite being cited as official, so left out).
    ".mod.gov.bd", ".afd.gov.bd", ".ispr.gov.bd",
    # Bangladesh state-owned defence-industrial entities — domains confirmed
    # live via web search (bof.gov.bd, khulnashipyard.gov.bd, cddl.gov.bd,
    # dewbn.gov.bd all resolve to the actual official sites).
    ".bof.gov.bd", ".khulnashipyard.gov.bd", ".cddl.gov.bd", ".dewbn.gov.bd",
    ".baec.gov.bd",
    # Nepal — verified live (mod.gov.np confirmed reachable; nepalarmy.mil.np
    # is WAF-blocked but real, same pattern as Pakistan's domains above).
    ".mod.gov.np", ".nepalarmy.mil.np",
    # Sri Lanka — verified live (defence.lk, army.lk via www prefix, navy.lk,
    # airforce.lk all confirmed reachable with real content).
    ".defence.lk", ".army.lk", ".navy.lk", ".airforce.lk",
    # Myanmar — verified live (mod.gov.mm confirmed reachable). cincds.gov.mm
    # added after being surfaced in a user-reviewed LeakIX result — Office
    # of the Commander-in-Chief of Defence Services, Myanmar's top military
    # command authority (currently Min Aung Hlaing's office).
    ".mod.gov.mm", ".cincds.gov.mm",
)

# Narrowed to India + neighbouring countries only (per explicit instruction).
# Previously still had US/NATO-specific bare terms (us army, pentagon, nato
# breach, siprnet, uscybercom, itar...) even after the rest of the tool was
# narrowed in Parts 1-6 — since STRONG_MIL_TERMS feeds relevance_check(),
# used by GHW/Tor/RSS/Telegram/OTX/LeakIX, any of those sources mentioning
# NATO or the Pentagon would still have passed "strong" tier and reintroduced
# exactly the out-of-scope content the Parts 1-6 narrowing was meant to
# remove. Found and fixed in the same accuracy pass as the Shodan/Censys
# fix (see chat).
STRONG_MIL_TERMS = {
    "ministry of defence", "ministry of national defense", "armed forces",
    "military database", "defence contractor", "defense contractor",
    "inter-services intelligence",
}

# Narrowed to India + neighbouring countries only (per explicit instruction).
# Was still 100% foreign (US/European/Israeli) defense contractors —
# Lockheed, Raytheon, Northrop Grumman, BAE Systems, Thales, Elbit, etc —
# despite _TIER2_CONTRACTORS (ransomware.live's own contractor list, a few
# hundred lines below) having already been correctly narrowed to our 7
# countries' actual PSUs/SOEs. This set feeds the SAME relevance_check()
# used broadly across the tool, so it was silently letting foreign-
# contractor content back in wherever it appeared, unlike the ransomware
# module's already-fixed narrow list. _TIER2_CONTRACTORS below now builds
# on top of this one set instead of maintaining its own separate copy, so
# the two can no longer drift apart again.
MIL_CONTRACTORS = {
    # Indian defence PSUs — full names, not 3-4 letter acronyms (hal/bel/
    # bdl/grse) that would be far more collision-prone even with
    # word-boundary matching
    "hindustan aeronautics", "bharat electronics", "bharat dynamics",
    "mazagon dock", "garden reach shipbuilders", "beml limited",
    # Pakistani and Chinese defence contractors/SOEs — full names again,
    # avoiding short ambiguous acronyms (norinco/avic/cetc kept since
    # they're already distinctive enough proper nouns)
    "heavy industries taxila", "pakistan ordnance factories",
    "norinco", "china north industries", "china aerospace science and technology",
    "aviation industry corporation of china", "china electronics technology group",
    "pakistan aeronautical complex", "karachi shipyard",
    "national radio and telecommunication corporation",
    # Pakistani/Myanmar military-run business conglomerates — full names
    # since both run large ordinary-commercial arms too (fertiliser,
    # banking, food), so a bare short acronym would be far too
    # collision-prone here
    "fauji foundation", "army welfare trust", "ministry of defence production",
    "myanmar economic corporation",
    # Bangladesh state-owned defence-industrial entities
    "bangladesh ordnance factory", "khulna shipyard", "chittagong dry dock",
    "chattogram dry dock", "bangladesh machine tools factory",
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
    # South Asia-focused groups researched specifically for this scope
    # (India/Pakistan/China/Bangladesh/Nepal/Sri Lanka/Myanmar), added to
    # widen relevance-check recall. Deliberately using distinctive aliases
    # instead of the groups' own common-word codenames — bare "sidewinder"
    # (a snake/missile), "patchwork", "confucius", and "bitter" would match
    # unrelated text under the word-boundary check and reintroduce exactly
    # the over-broad-match class of bug already fixed once in this engine
    # (see _has_any's docstring above).
    "razor tiger", "sidewinder apt", "operation southnet",
    "bitter apt", "apt-c-08",
    "sloppylemming", "outrider tiger", "fishing elephant",
    "dropping elephant", "donot team", "apt-c-35", "confucius apt",
    # Mustang Panda aliases (already have "mustang panda" above) + malware/
    # tool names tied to these campaigns — distinctive enough to add directly
    "ta416", "red delta", "earth preta", "honeymyte", "camaro dragon",
    "bronze president", "burrowshell", "deskrat", "toneshell",
}

MIL_VENDOR_TERMS = {
    "cisco", "fortinet", "palo alto", "juniper", "f5", "pulse secure",
    "ivanti", "sonicwall", "citrix", "checkpoint",
    "siemens", "rockwell", "allen-bradley", "honeywell", "ge digital",
    "schneider electric", "abb", "emerson", "yokogawa", "beckhoff",
    "inductive automation", "aveva",
    "microsoft", "oracle", "vmware", "solarwinds", "bmc software",
    "openssl", "nginx",
    # Bare "apache" was matching ANY CVE mentioning the Apache Software
    # Foundation (30+ largely unrelated projects) — live example: a
    # CVSS-7.5 ActiveMQ Artemis DoS with no military-specific angle
    # (flagged as noise in chat). Narrowed to the specific sub-projects
    # that are either genuinely common in government/critical-infra
    # backends (Tomcat, Kafka, HTTP Server) or have a track record of
    # severe, broadly-exploited RCEs (Struts/Equifax, Log4j/Log4Shell) —
    # still catches a real Log4Shell-class event, not a routine DoS.
    "apache tomcat", "apache struts", "apache kafka", "apache http server",
    "apache airflow", "apache log4j", "log4j", "apache camel", "apache solr",
    "viasat", "hughes", "iridium", "inmarsat",
}

WEAK_MIL_TERMS = {
    "military", "army", "navy", "air force", "defence", "defense",
    "warfare", "weapon", "drone", "uav", "satellite",
    "intelligence agency", "government", "federal", "national security",
    # Added while closing gaps against sir's OSINT category framework (see
    # chat) — subject-matter terms for T1-T3 subcategories that had no
    # search coverage at all before. Specific enough (2-weak-term minimum
    # still applies) not to reopen the "disa"/"ot" class of over-broad match.
    "biometric", "geolocation", "procurement", "tender",
    "technology transfer", "strategic plan", "joint exercise",
    "supply depot", "communications intercept", "sigint",
    "ground station", "battlefield network", "single sign-on", "saml",
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
# Narrowed to India + neighbouring countries only (per explicit instruction).
_DOMAIN_COUNTRY_SUFFIXES = (
    (".indianarmy.nic.in", "India"), (".indiannavy.gov.in", "India"),
    (".indianairforce.nic.in", "India"), (".mod.gov.in", "India"), (".drdo.gov.in", "India"),
    (".barc.gov.in", "India"), (".npcil.nic.in", "India"), (".bsf.gov.in", "India"),
    (".pakistanarmy.gov.pk", "Pakistan"), (".paknavy.gov.pk", "Pakistan"),
    (".paf.gov.pk", "Pakistan"), (".mod.gov.pk", "Pakistan"), (".ispr.gov.pk", "Pakistan"),
    (".modp.gov.pk", "Pakistan"), (".paec.gov.pk", "Pakistan"),
    (".mod.gov.cn", "China"), (".norinco.cn", "China"), (".spacechina.com", "China"),
    (".avic.com", "China"), (".cetc.com.cn", "China"), (".cnnc.com.cn", "China"),
    (".mod.gov.bd", "Bangladesh"), (".afd.gov.bd", "Bangladesh"), (".ispr.gov.bd", "Bangladesh"),
    (".bof.gov.bd", "Bangladesh"), (".khulnashipyard.gov.bd", "Bangladesh"),
    (".cddl.gov.bd", "Bangladesh"), (".dewbn.gov.bd", "Bangladesh"), (".baec.gov.bd", "Bangladesh"),
    (".mod.gov.np", "Nepal"), (".nepalarmy.mil.np", "Nepal"),
    (".defence.lk", "Sri Lanka"), (".army.lk", "Sri Lanka"),
    (".navy.lk", "Sri Lanka"), (".airforce.lk", "Sri Lanka"),
    (".mod.gov.mm", "Myanmar"), (".cincds.gov.mm", "Myanmar"),
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


def _domain_scan_category(label: str) -> str:
    """The domain-scoped internet-scan modules (crt.sh, urlscan, ZoomEye,
    Onyphe, Shodan, Censys, BinaryEdge, SecurityTrails) share one T3
    (Communication & Network Attacks) default for every row — but a few
    targets added to their shared target lists this session are
    semantically different: nuclear facilities (BARC/NPCIL/PAEC/CNNC/BAEC,
    labelled "... (Nuclear)") are T5 (Critical Infrastructure), and BSF
    (labelled "... (Border Surveillance)") is T7 (Emerging & Autonomous
    System Threats). Every one of those 8 fetch functions was hardcoding
    "T3" regardless of label, silently mislabeling real findings and making
    T5/T7 look empty in the dashboard even though the underlying data
    existed. See chat."""
    low = (label or "").lower()
    if "nuclear" in low:
        return "T5"
    if "border surveillance" in low:
        return "T7"
    return "T3"


# Technology fingerprinting (see chat — a workflow review flagged this as
# missing: raw server banners were captured as free text everywhere but
# never elevated to a structured, filterable field). Ordered so more
# specific signatures (e.g. "citrix") are checked before generic ones
# ("nginx") wouldn't matter here since these are independent categories,
# but kept specific-first as a general habit.
_TECH_SIGNATURES = {
    "nginx": "Nginx", "openresty": "OpenResty", "apache": "Apache",
    "microsoft-iis": "IIS", "iis/": "IIS", "cloudflare": "Cloudflare",
    "big-ip": "F5 BIG-IP", "f5-": "F5 BIG-IP",
    "citrix": "Citrix", "netscaler": "Citrix NetScaler",
    "fortinet": "Fortinet", "fortigate": "Fortinet",
    "palo alto": "Palo Alto", "pan-os": "Palo Alto",
    "cisco asa": "Cisco ASA", "cisco adaptive security": "Cisco ASA",
    "pulse secure": "Pulse Secure", "ivanti": "Ivanti",
    "sonicwall": "SonicWall", "checkpoint": "Check Point",
    "elasticsearch": "Elasticsearch", "kibana": "Kibana", "opensearch": "OpenSearch",
    "mongodb": "MongoDB", "redis": "Redis", "postgres": "PostgreSQL",
    "mysql": "MySQL", "rabbitmq": "RabbitMQ", "jenkins": "Jenkins",
    "gitlab": "GitLab", "grafana": "Grafana", "prometheus": "Prometheus",
    "minio": "MinIO", "phpmyadmin": "phpMyAdmin", "kubernetes": "Kubernetes",
    "docker": "Docker",
}


def _fingerprint_technology(*texts: str) -> list:
    """Checks free-text banners/titles/summaries against known technology
    signatures and returns normalized tag names — used so severity/dashboard
    filtering can act on "this is Elasticsearch" as a real field instead of
    it only existing buried in a raw banner string."""
    combined = " ".join((t or "") for t in texts).lower()
    found = []
    for sig, name in _TECH_SIGNATURES.items():
        if sig in combined and name not in found:
            found.append(name)
    return found


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
# Narrowed to India + neighbouring countries only (per explicit instruction).
_GHW_STRONG_QUERIES = [
    "indianarmy.nic.in", "indiannavy.gov.in", "indianairforce.nic.in",
    "mod.gov.in", "drdo.gov.in", "barc.gov.in", "npcil.nic.in", "bsf.gov.in",
    "pakistanarmy.gov.pk", "paknavy.gov.pk", "paf.gov.pk", "mod.gov.pk", "ispr.gov.pk",
    "modp.gov.pk", "paec.gov.pk",
    "mod.gov.cn", "norinco.cn", "spacechina.com", "avic.com", "cetc.com.cn", "cnnc.com.cn",
    "mod.gov.bd", "afd.gov.bd", "ispr.gov.bd",
    "bof.gov.bd", "khulnashipyard.gov.bd", "cddl.gov.bd", "dewbn.gov.bd", "baec.gov.bd",
    "mod.gov.np", "nepalarmy.mil.np",
    "defence.lk", "army.lk", "navy.lk", "airforce.lk", "mod.gov.mm", "cincds.gov.mm",
]
_GHW_SOFT_QUERIES = []

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


def fetch_github_leaks(token: str, extra_domains: list = None) -> list:
    """T1/T2 — FREE GitHub token. Filename-scoped dork queries for leaked .mil
    credentials/configs. Candidate hits are additionally content-verified: the
    raw file is fetched and scanned for an actual secret-shaped pattern before
    being called CRITICAL. A bare keyword match without a real secret pattern
    (e.g. a dork wordlist mentioning army.mil) is downgraded, not dropped.

    extra_domains: CT-discovered sensitive subdomains pivoted in from
    crt.sh — same pattern as fetch_leakix/fetch_hudson_rock."""
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    queries = [
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
        # India's neighbours (Bangladesh, Nepal, Sri Lanka, Myanmar) — kept to
        # ONE consolidated query to control this module's already-heavy
        # runtime under GitHub's ~10/min code-search rate limit.
        '"@mod.gov.bd" OR "@mod.gov.np" OR "@defence.lk" OR "@mod.gov.mm" OR "@cincds.gov.mm" filename:.env',
        # New confirmed domains: Pakistan MoD Production + Bangladesh
        # state-owned defence-industrial entities — one consolidated query,
        # same rate-limit reasoning as above.
        '"@modp.gov.pk" OR "@bof.gov.bd" OR "@khulnashipyard.gov.bd" OR "@cddl.gov.bd" filename:.env',
        # T1 "Defence Authentication System Compromise" gap — SSO/SAML/LDAP
        # config leaks are a real leaked-file pattern (unlike most of the
        # other framework gap subcategories, which are subject matter, not
        # file patterns, so they belong in the Tor dark-web queries instead).
        'filename:config.json "mod.gov.in" OR "mod.gov.pk" OR "mod.gov.cn" sso OR saml OR ldap OR mfa',
    ]
    if extra_domains:
        pivot_terms = " OR ".join(f'"@{d}"' for d in extra_domains[:8])
        queries.append(f'{pivot_terms} filename:.env')
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


def fetch_hudson_rock(extra_domains: list = None) -> list:
    """T1 — FREE. Infostealer-compromised .mil accounts via Hudson Rock Cavalier.

    extra_domains: CT-discovered sensitive subdomains pivoted in from
    crt.sh (see fetch_leakix's docstring for the same pattern) — an
    infostealer infection on e.g. vpn.mod.gov.in wouldn't be caught by
    only checking the root mod.gov.in domain."""
    rows = []
    domains = list(CONFIG.get("hudson_rock_domains") or ["mod.gov.in", "mod.gov.pk", "mod.gov.cn"])
    domains.extend((extra_domains or [])[:10])
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
                        # domain_to_country(domain), not the infected
                        # machine's own reported location — an employee of an
                        # Indian-domain org could get infected while abroad;
                        # for consistency with how "location" is used
                        # everywhere else (which target country this is
                        # about), the owning domain's country wins when known.
                        "location":      domain_to_country(domain) if domain_to_country(domain) != "Unknown"
                                          else (record.get("country") or "Unknown"),
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
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    targets = [("@indianarmy.nic.in", "Indian Army"), ("@mod.gov.in", "Indian Ministry of Defence"),
               ("@mod.gov.pk", "Pakistan Ministry of Defence"), ("@mod.gov.cn", "China Ministry of National Defense"),
               ("@mod.gov.bd", "Bangladesh Ministry of Defence"), ("@mod.gov.np", "Nepal Ministry of Defence"),
               ("@defence.lk", "Sri Lanka Ministry of Defence"), ("@mod.gov.mm", "Myanmar Ministry of Defence"),
               ("@cincds.gov.mm", "Myanmar Commander-in-Chief of Defence Services")]
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


def fetch_tavily_search(api_key: str) -> list:
    """T1/T2/T3 — FREE, 1,000 credits/month, at api.tavily.com. Needs a free
    Tavily API key (no credit card) — see the CONFIG comment for
    tavily_api_key.

    Replaces an earlier Google Custom Search JSON API build for the same
    purpose (see chat): live-checked Google's own docs and found "The
    Custom Search JSON API is closed to new customers" — existing users
    only, no new signups possible, so that version was dead on arrival
    for anyone without prior access. Tavily was verified as a genuine,
    currently-open alternative (real "forever free" tier, no card, still
    open as of this check) but works differently — it's semantic/AI-
    agent search, not a raw index with site:/filetype:/intitle: operator
    support the way Google was, so the query set below is a best-effort
    natural-language translation of the original dork angles, not a
    literal 1:1 port. Two angles translate cleanly onto Tavily's real
    include_domains parameter (a proper structured filter, arguably more
    reliable than a site: text operator ever was): paste-site and doc-
    sharing-site leak mentions. The filetype:/intitle:"index of" angles
    (exposed config files, open directories) have no equivalent
    structured parameter on Tavily, so those are just natural-language
    queries with no guarantee semantic search surfaces the same kind of
    hit a literal file-type index would have — kept because they cost
    nothing extra to try, not because precision here is confirmed.

    Also functions as a real replacement for fetch_paste_leaks (psbdmp —
    confirmed dead, see that function's docstring): this is the only
    active source in the tool that can reach pastebin/doc-sharing-site
    content at all, since Shodan/Censys/LeakIX all find exposed SERVICES,
    not documents. Kept to 16 queries at search_depth="basic" (1 credit
    each = 16/run) to stay far under the monthly budget even at a daily
    collection cadence."""
    rows = []
    if not api_key:
        return rows
    QUERIES = [
        ("Indian Ministry of Defence DRDO Army BSF leaked data breach credentials",
         ["pastebin.com"], "T1", "India Paste Leak Mention"),
        ("Pakistan military mod.gov.pk army navy air force leaked data breach credentials",
         ["pastebin.com"], "T1", "Pakistan Paste Leak Mention"),
        ("China PLA military mod.gov.cn CNNC leaked data breach credentials",
         ["pastebin.com"], "T1", "China Paste Leak Mention"),
        ("Bangladesh Nepal Sri Lanka Myanmar military ministry of defence leaked data breach",
         ["pastebin.com"], "T1", "Neighbouring Countries Paste Leak Mention"),
        ("DRDO BSF Indian Army leaked credentials database dump",
         ["trello.com", "justpaste.it"], "T1", "India Alternate Paste-Site Leak Mention"),
        ("Pakistan army mod.gov.pk leaked credentials database dump",
         ["trello.com", "justpaste.it"], "T1", "Pakistan Alternate Paste-Site Leak Mention"),
        ("exposed .env or .sql database dump mod.gov.in drdo.gov.in bsf.gov.in leaked",
         None, "T3", "India Exposed Config/Database File"),
        ("exposed .env or .sql database dump mod.gov.pk mod.gov.cn mod.gov.bd mod.gov.np defence.lk mod.gov.mm leaked",
         None, "T3", "Neighbouring Countries Exposed Config/Database File"),
        ("index of directory listing mod.gov.in drdo.gov.in indianarmy.nic.in bsf.gov.in exposed files",
         None, "T3", "India Open Directory Listing"),
        ("index of directory listing mod.gov.pk mod.gov.cn mod.gov.bd mod.gov.np defence.lk mod.gov.mm exposed files",
         None, "T3", "Neighbouring Countries Open Directory Listing"),
        ("Ministry of Defence India confidential classified document",
         ["scribd.com", "docs.google.com"], "T2", "India Leaked Document Mention"),
        ("Ministry of Defence Pakistan confidential classified document",
         ["scribd.com", "docs.google.com"], "T2", "Pakistan Leaked Document Mention"),
        ("top secret classified India government defence document leaked pdf",
         None, "T2", "India Classified Document Mention"),
        ("top secret classified Pakistan government defence document leaked pdf",
         None, "T2", "Pakistan Classified Document Mention"),
        ("personnel employee database DRDO BSF Indian Army leaked spreadsheet",
         None, "T1", "India Personnel/Employee Data Exposure"),
        ("personnel employee database Pakistan China Bangladesh military leaked spreadsheet",
         None, "T1", "Neighbouring Countries Personnel/Employee Data Exposure"),
    ]
    _EXPOSED_FILE_RE = re.compile(r'\.(sql|env|bak|xls|xlsx|pdf)(\?|$)', re.IGNORECASE)
    _LABEL_COUNTRY = {"india": "India", "pakistan": "Pakistan", "china": "China"}

    def _tavily_location(label: str, text: str) -> str:
        # domain_to_country() needs a bare hostname ending in the suffix —
        # useless here (link is a full pastebin/scribd URL with a random
        # path, and text is free-text search-result content, not a
        # hostname) — see chat. Each query already targets one specific
        # country (except the "Neighbouring Countries" ones, which cover
        # 4-6 at once), so derive location from the query's own label
        # first — reliable, no parsing needed — and only fall back to
        # scanning the actual result text for the ambiguous ones.
        low = label.lower()
        for kw, country in _LABEL_COUNTRY.items():
            if kw in low:
                return country
        text_low = text.lower()
        for cc, hints in _COUNTRY_NAME_HINTS.items():
            if any(h in text_low for h in hints):
                return _RANSOMWARE_LIVE_TARGET_COUNTRIES.get(cc, cc)
        return "Unknown"

    seen_urls: set = set()
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}",
               "User-Agent": "MilOSINT/2.0"}
    for query, include_domains, cat, label in QUERIES:
        try:
            payload = {"query": query, "search_depth": "basic", "max_results": 10}
            if include_domains:
                payload["include_domains"] = include_domains
            resp = requests.post("https://api.tavily.com/search", json=payload,
                                  headers=headers, timeout=20)
            if resp.status_code == 432:
                log.warning("Tavily: monthly credit quota exhausted — stopping remaining queries")
                break
            resp.raise_for_status()
            for item in resp.json().get("results", []):
                link = item.get("url", "")
                if not link or link in seen_urls:
                    continue
                title = item.get("title", "")
                snippet = item.get("content", "")
                text = f"{title} {snippet}"
                passes, tier, reason = relevance_check(text, min_weak=1)
                if not passes:
                    continue
                if tier == "weak":
                    # min_weak=1 is a low bar for Tavily's broad semantic
                    # search across the open web — a live run found real
                    # false positives this way: a US Indiana COVID-tracing-
                    # database story (matched on generic breach/leak
                    # language) and a generic breach-search-tool listing
                    # (unrelated companies). Same fix as the Telegram/
                    # deepdarkCTI module (see chat) — require a target-
                    # country anchor for anything below "strong" tier.
                    # Uses _has_any() (word-boundary-safe), NOT a naive
                    # substring check — a naive check on this exact text
                    # would have matched "india" inside "Indiana", the very
                    # false positive this is meant to catch.
                    text_low = text.lower()
                    has_country = any(_has_any(text_low, hints) for hints in _COUNTRY_NAME_HINTS.values())
                    if not has_country:
                        continue
                seen_urls.add(link)
                is_exposed_file = bool(_EXPOSED_FILE_RE.search(link))
                sev = "CRITICAL" if is_exposed_file else ("HIGH" if tier == "strong" else "MEDIUM")
                rows.append({
                    "threat_id":     f"{cat}-TVLY-{short_id(link)}",
                    "threat_name":   f"Tavily Search — {label}",
                    "category_code": cat, "category_name": CATEGORY_NAMES[cat],
                    "source_layer":  "Surface Web", "source": "Tavily Search API",
                    "post_text":     f"Query: {query} | Title: {title[:150]} | Snippet: {snippet[:250]}",
                    "post_url":      link,
                    "timestamp":     now_utc(), "location": _tavily_location(label, text),
                    "severity":      sev, "confidence": "MEDIUM",
                    "ioc_type":      "url", "ioc_value": link[:300],
                    "tags":          f"tavily-search;{reason};{label.lower().replace(' ','-')}"
                                     + (";exposed-file" if is_exposed_file else ""),
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"Tavily search [{label}]: {e}")
    log.info(f"Tavily search: {len(rows)} military-relevant results found")
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
                        # domain_to_country(q) — q is the search keyword,
                        # one of our known domain strings (e.g. "bsf.gov.in"),
                        # so this resolves correctly for the common case
                        # instead of the previous unconditional "Cloud"
                        # placeholder (a real BSF recruitment-portal file
                        # showed up mislabeled as country "Cloud" in a live
                        # run — see chat). Falls back to "Cloud" since a
                        # bucket genuinely has no inherent country when the
                        # keyword isn't a recognized domain.
                        "timestamp":     str(fdate),
                        "location":      domain_to_country(q) if domain_to_country(q) != "Unknown" else "Cloud",
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


# A live check of this session's own LeakIX data found generic HTTP
# redirect/200-OK banners (with no other signal) sitting in the master CSV
# at the same severity as genuine exposures — this is the "ignore normal
# banners" distinction from a shared OSINT workflow guide (cross-checked
# against real data before using, see chat).
_GENERIC_BANNER_RE = re.compile(r'^\s*HTTP/1\.[01]\s+(200|301|302|307|400)\b', re.IGNORECASE)

# Same noise class, different shape: Microsoft Skype for Business/Lync's
# "Autodiscover" service (lyncdiscover.<domain>) is a standard, publicly-
# reachable-by-design endpoint every org that ever deployed it has — its
# root JSON response is just a list of its own sub-endpoint links (self/
# user/xframe), no credentials or internal data. A user-flagged example
# showed this sitting at MEDIUM despite carrying zero actual exposure.
_AUTODISCOVER_RE = re.compile(r'autodiscoverservice\.svc|lyncdiscover|"xframe"\s*:\s*\{', re.IGNORECASE)


def fetch_leakix(api_key: str, extra_domains: list = None) -> list:
    """T2/T3 — FREE signup at leakix.net. Domain-gated: every query is filtered
    to a specific military host, so results only include that domain's assets.

    extra_domains: CT-discovered sensitive subdomains (vpn./admin./git./
    jira./kibana./etc.) pivoted in from crt.sh's own results this run —
    a workflow from a shared OSINT guide (cross-checked, see chat): use
    Certificate Transparency to discover interesting hostnames, then check
    each one specifically in LeakIX rather than only checking the ~30
    hardcoded root domains below. Same query/accept logic as the named
    targets — only the query domain and its own subdomains can match.

    Query syntax rewritten after live A/B testing (see chat) found the old
    plain `host:X` queries returned ZERO results for exact government
    domains (mod.gov.in, drdo.gov.in, mod.gov.pk all came back empty),
    despite the sites being real and live. Empirically, `ssl.certificate.
    domain:"X"` (LeakIX's YQL cert-domain field, same idea as crt.sh's
    Certificate Transparency search) reliably returned hits where `host:`
    returned none — e.g. mod.gov.pk: 0 results via host:, 3 results via
    ssl.certificate.domain:. Confirmed against LeakIX's own docs
    (docs.leakix.net/docs/query/{syntax,fields}) that `+` prefixes a
    required term and ssl.certificate.domain is a real indexed field.

    Also added one broader per-country query per country
    (+geoip.country_iso_code:CC +ssl.certificate.domain:"<gov TLD>") to
    catch military-relevant hosts outside the ~30 specifically-named
    targets below — this is intentionally a wide net at the SEARCH step,
    but its results are NOT trusted directly: each hit's returned host is
    still required to pass has_mil_domain() before becoming a row, so
    widening the search doesn't widen what gets kept."""
    rows = []
    _seen_services: set = set()
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    LEAKIX_TARGETS = [
        ("indianarmy.nic.in", "Indian Army", "T2"), ("indiannavy.gov.in", "Indian Navy", "T2"),
        ("indianairforce.nic.in", "Indian Air Force", "T2"),
        ("mod.gov.in", "Indian Ministry of Defence", "T2"), ("drdo.gov.in", "DRDO", "T3"),
        ("barc.gov.in", "BARC (Nuclear)", "T5"), ("npcil.nic.in", "NPCIL (Nuclear)", "T5"),
        ("bsf.gov.in", "BSF (Border Surveillance)", "T7"),
        ("pakistanarmy.gov.pk", "Pakistan Army", "T2"), ("paknavy.gov.pk", "Pakistan Navy", "T2"),
        ("paf.gov.pk", "Pakistan Air Force", "T2"), ("mod.gov.pk", "Pakistan Ministry of Defence", "T2"),
        ("modp.gov.pk", "Pakistan Ministry of Defence Production", "T2"),
        ("paec.gov.pk", "PAEC (Nuclear)", "T5"),
        ("mod.gov.cn", "China Ministry of National Defense", "T2"),
        ("cnnc.com.cn", "CNNC (Nuclear)", "T5"),
        ("mod.gov.bd", "Bangladesh Ministry of Defence", "T2"),
        ("afd.gov.bd", "Bangladesh Armed Forces Division", "T2"),
        ("ispr.gov.bd", "Bangladesh ISPR", "T3"),
        ("bof.gov.bd", "Bangladesh Ordnance Factory", "T3"),
        ("khulnashipyard.gov.bd", "Bangladesh Khulna Shipyard", "T3"),
        ("cddl.gov.bd", "Bangladesh Chittagong Dry Dock", "T3"),
        ("baec.gov.bd", "BAEC (Nuclear)", "T5"),
        ("mod.gov.np", "Nepal Ministry of Defence", "T2"),
        ("nepalarmy.mil.np", "Nepal Army", "T2"),
        ("defence.lk", "Sri Lanka Ministry of Defence", "T2"),
        ("army.lk", "Sri Lanka Army", "T2"), ("navy.lk", "Sri Lanka Navy", "T2"),
        ("airforce.lk", "Sri Lanka Air Force", "T2"),
        ("mod.gov.mm", "Myanmar Ministry of Defence", "T2"),
        ("cincds.gov.mm", "Myanmar Commander-in-Chief of Defence Services", "T2"),
    ]
    # Broad, country-scoped nets — deliberately loose at the query level
    # (bare ".gov.xx" TLD, not a specific org) because every hit is still
    # gated by has_mil_domain() below before being kept.
    LEAKIX_BROAD_TARGETS = [
        ('+geoip.country_iso_code:IN +ssl.certificate.domain:"gov.in"', "IN"),
        ('+geoip.country_iso_code:PK +ssl.certificate.domain:"gov.pk"', "PK"),
        ('+geoip.country_iso_code:CN +ssl.certificate.domain:"gov.cn"', "CN"),
        ('+geoip.country_iso_code:BD +ssl.certificate.domain:"gov.bd"', "BD"),
        ('+geoip.country_iso_code:NP +ssl.certificate.domain:"gov.np"', "NP"),
    ]
    headers = {"api-key": api_key, "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}

    def _leakix_search(query: str):
        for scope in ("leak", "service"):
            url = f"https://leakix.net/search?scope={scope}&q={requests.utils.quote(query)}"
            try:
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 401:
                    return
                if resp.status_code == 429:
                    time.sleep(5)
                    continue
                resp.raise_for_status()
                if not resp.text.strip():
                    continue  # LeakIX returns an empty 200 body (not "[]") for zero results — not an error
                items = resp.json() or []
                if not isinstance(items, list):
                    continue
                for item in items[:4]:
                    yield scope, item
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"LeakIX [{scope}] {query}: {inner_e}")

    def _build_row(scope, item, label, cat, expected_domain=""):
        plugin = item.get("plugin") or ""
        summary = item.get("summary") or ""
        host = item.get("host") or ""
        ip = item.get("ip") or ""
        port = item.get("port") or ""
        # domain_to_country(), not LeakIX's own geoip.country_name — live test
        # found Pakistani/Bangladeshi government hosts geolocating to France/
        # US (CDN/cloud hosting), which would mislabel the org's actual
        # country. Same reasoning already applied via domain_to_country() in
        # crt.sh/urlscan elsewhere in this file — do it here too for
        # consistency, falling back to geoip only if the domain isn't one of
        # our recognized suffixes (e.g. the broad-net queries).
        country = domain_to_country(host)
        if country == "Unknown":
            country = (item.get("geoip") or {}).get("country_name") or "Unknown"
        severity_raw = (item.get("severity") or "medium").upper()
        sev = severity_raw if severity_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
        cat_name = CATEGORY_NAMES.get(cat, CATEGORY_NAMES["T2"])

        # Named targets: require the returned host to actually BE the
        # expected domain (or a subdomain of it) — not just contain it as a
        # substring. A live run found "modp.gov.pk-mail.org" (a completely
        # unrelated domain) passing a bare `in` check because "modp.gov.pk"
        # happens to be a text prefix of it. Proper suffix/equality check
        # instead, same fix class as has_mil_domain()'s own bare-domain
        # handling elsewhere in this file.
        # Broad country nets (expected_domain=""): require has_mil_domain()
        # instead — this is the strict filter that keeps the wide net clean.
        if expected_domain:
            host_lower = host.lower()
            if not (host_lower == expected_domain or host_lower.endswith("." + expected_domain)):
                return None
        elif not has_mil_domain(host):
            return None
        svc_key = f"{host}:{port}:{plugin}:{scope}"
        if svc_key in _seen_services:
            return None
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
        # Additional data-exposure-prone technologies (see chat — cross-
        # checked against a shared OSINT workflow guide, but verified
        # empirically first: LeakIX's own `plugin` field came back empty in
        # live testing, so this checks summary/plugin text directly instead
        # of trusting a plugin-name query filter that couldn't be confirmed).
        if any(k in summary_lower or k in plugin_lower for k in ("mongodb", "redis", "postgres", "rabbitmq")):
            finding_tags.append("database-exposed")
        if any(k in summary_lower or k in plugin_lower for k in ("minio", "s3", "nas", "synology", "qnap")):
            finding_tags.append("storage-exposed")
        if "gitlab" in summary_lower or "gitlab" in plugin_lower:
            finding_tags.append("gitlab-exposed")
        if "phpmyadmin" in summary_lower or "phpmyadmin" in plugin_lower:
            finding_tags.append("phpmyadmin-exposed")
        if any(k in summary_lower for k in (".sql", ".bak", ".tar.gz", ".zip", "backup")):
            finding_tags.append("backup-file-exposed")

        # A live check of this session's own data found LeakIX results are
        # overwhelmingly generic exposed-service banners (HTTP headers,
        # server strings) rather than actual data exposure — 2 of 3 rows in
        # the master CSV were "service" scope with no real leak content.
        # These finding_tags are the signal that distinguishes "a database/
        # git repo/backup file is actually sitting open" from "a web server
        # responded on a port" — bumping severity here means that
        # distinction actually affects the output instead of being a
        # decorative tag nobody acts on.
        _HIGH_VALUE_TAGS = {"git-exposure", "env-file-exposed", "database-exposed",
                             "storage-exposed", "gitlab-exposed", "phpmyadmin-exposed",
                             "backup-file-exposed", "directory-listing"}
        if any(t in _HIGH_VALUE_TAGS for t in finding_tags):
            sev = "CRITICAL"
        elif not cve_ids and (_GENERIC_BANNER_RE.match(summary) or _AUTODISCOVER_RE.search(summary)):
            # The other side of the same fix: a live check found both
            # non-high-value rows in the master CSV were exactly this —
            # a plain "301 Moved Permanently" redirect and a plain "200 OK"
            # homepage load with standard server headers, nothing else.
            # That's confirmation a site is reachable, not a security
            # exposure, so it shouldn't carry the same severity as one.
            sev = "LOW"

        tech = _fingerprint_technology(summary, plugin)
        return {
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
                               + (";cve-tagged" if cve_ids else "")
                               + (f";tech:{',' .join(tech)}" if tech else "")),
        }

    try:
        for domain, label, cat in LEAKIX_TARGETS:
            q = f'+ssl.certificate.domain:"{domain}"'
            for scope, item in _leakix_search(q):
                row = _build_row(scope, item, label, cat, expected_domain=domain)
                if row:
                    rows.append(row)

        for q, cc in LEAKIX_BROAD_TARGETS:
            for scope, item in _leakix_search(q):
                row = _build_row(scope, item, f"{cc} Government (broad net)", "T3", expected_domain="")
                if row:
                    rows.append(row)

        pivot_count = 0
        for pivot_domain in (extra_domains or [])[:15]:
            pivot_domain = pivot_domain.lower().lstrip("*").lstrip(".")
            if not pivot_domain:
                continue
            q = f'+ssl.certificate.domain:"{pivot_domain}"'
            for scope, item in _leakix_search(q):
                row = _build_row(scope, item, f"CT-Discovered: {pivot_domain}", "T2", expected_domain=pivot_domain)
                if row:
                    rows.append(row)
            pivot_count += 1
        if pivot_count:
            log.info(f"LeakIX: checked {pivot_count} CT-discovered subdomains from crt.sh as additional pivots")
    except Exception as e:
        log.error(f"LeakIX error: {e}")
    log.info(f"LeakIX: {len(rows)} exposed services/leaks found")
    return rows


# Narrowed to India + neighbouring countries only (per explicit instruction).
_TIER1_MIL_DOMAINS = (".indianarmy.nic.in", ".indiannavy.gov.in", ".indianairforce.nic.in",
                       ".mod.gov.in", ".drdo.gov.in", ".barc.gov.in", ".npcil.nic.in", ".bsf.gov.in",
                       ".pakistanarmy.gov.pk", ".paknavy.gov.pk", ".paf.gov.pk",
                       ".mod.gov.pk", ".ispr.gov.pk", ".modp.gov.pk", ".paec.gov.pk",
                       ".mod.gov.cn", ".norinco.cn", ".spacechina.com", ".avic.com", ".cetc.com.cn",
                       ".cnnc.com.cn",
                       ".mod.gov.bd", ".afd.gov.bd", ".ispr.gov.bd",
                       ".bof.gov.bd", ".khulnashipyard.gov.bd", ".cddl.gov.bd", ".dewbn.gov.bd",
                       ".baec.gov.bd",
                       ".mod.gov.np", ".nepalarmy.mil.np",
                       ".defence.lk", ".army.lk", ".navy.lk", ".airforce.lk",
                       ".mod.gov.mm", ".cincds.gov.mm")
_TIER3_GENERIC_GOV_MARKER = ".gov"
# Narrowed to India + neighbouring countries only (per explicit instruction) —
# removed all foreign (US/UK/Germany/Israel/France/etc) contractor names.
# Builds on the module-level MIL_CONTRACTORS set instead of maintaining a
# separate copy (previously duplicated the same ~25 entries here, which is
# exactly how the two sets drifted apart before — MIL_CONTRACTORS still had
# foreign contractors while this list had already been correctly narrowed;
# see chat). Plus a few ransomware-context-specific generic phrases that
# don't belong in the general relevance engine's contractor set.
_TIER2_CONTRACTORS = list(MIL_CONTRACTORS) + [
    "defense intelligence", "naval air", "army corps",
]


_RANSOMWARE_LIVE_TARGET_COUNTRIES = {
    "IN": "India", "PK": "Pakistan", "CN": "China", "BD": "Bangladesh",
    "NP": "Nepal", "LK": "Sri Lanka", "MM": "Myanmar",
}


def _ransomware_live_get(url: str, timeout: int = 25, max_attempts: int = 3):
    """GET with retry on transient connection/DNS failures only (not on HTTP
    error codes). osint_tool_v2.log showed api.ransomware.live's DNS failing
    to resolve from this network on roughly half of past runs
    ("NameResolutionError... getaddrinfo failed") while succeeding on the
    others and while a direct live check confirmed the API itself is healthy
    — a transient local/network hiccup, not a real outage, so a short retry
    is enough."""
    last_exc = None
    for attempt in range(max_attempts):
        try:
            resp = requests.get(url, headers={"User-Agent": "MilOSINT/2.0"}, timeout=timeout)
            resp.raise_for_status()
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < max_attempts - 1:
                time.sleep(8 * (attempt + 1))
    raise last_exc


def _ransomware_live_enrich(victim_name: str, domain: str) -> dict:
    """Looks up one victim on /v2/searchvictims/{term} to answer "how do I
    verify this CSV row" (see chat): the bulk /v2/recentvictims and
    /v2/countryvictims/{cc} feeds this module otherwise runs on only
    return a raw .onion post_url (needs Tor, and dark-web leak-site posts
    routinely go offline/get seized). searchvictims returns a richer
    per-victim record with a clearnet ransomware.live permalink
    ("https://www.ransomware.live/id/...") and a screenshot hosted on
    their own CDN — both viewable in a normal browser, no Tor required.
    Live-tested at ~1s/call with no rate-limit hit across 5 rapid calls,
    unlike countryvictims' confirmed ~1/min limit, so this is affordable
    to call once per already-filtered (military/defence-relevant) row
    rather than for all ~470+ raw victims per country.

    Matches defensively: searchvictims does a substring/fuzzy search, so
    a generic term can return several unrelated victims. Only returns
    enrichment when a result's own domain or victim name matches ours —
    otherwise returns {} rather than risk attaching the wrong screenshot/
    permalink to this row."""
    term = (domain or victim_name or "").strip()
    if not term:
        return {}
    try:
        # A live full-run found this endpoint DOES rate-limit under
        # sustained back-to-back calls (429s appeared once several
        # countries' worth of kept rows queued up enrichment calls in
        # quick succession) — not visible in an earlier small isolated
        # test (5 calls, no 429s), so this only showed up at real
        # per-country-loop scale. One retry after a short pause is cheap
        # insurance; a second 429 just means no enrichment for this row
        # (falls back to the raw post_url — not fatal, see caller).
        resp = requests.get(f"https://api.ransomware.live/v2/searchvictims/{quote(term, safe='')}",
                             headers={"User-Agent": "MilOSINT/2.0"}, timeout=15)
        if resp.status_code == 429:
            time.sleep(5)
            resp = requests.get(f"https://api.ransomware.live/v2/searchvictims/{quote(term, safe='')}",
                                 headers={"User-Agent": "MilOSINT/2.0"}, timeout=15)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        results = resp.json()
        if not isinstance(results, list):
            return {}
        target_domain = (domain or "").lower()
        target_name = (victim_name or "").lower()
        for entry in results:
            e_domain = (entry.get("domain") or "").lower()
            e_victim = (entry.get("victim") or "").lower()
            if (target_domain and e_domain == target_domain) or \
               (target_name and e_victim == target_name):
                out = {}
                if entry.get("url"):
                    out["clearnet_url"] = entry["url"]
                if entry.get("screenshot"):
                    out["screenshot"] = entry["screenshot"]
                infostealer = entry.get("infostealer")
                if isinstance(infostealer, dict) and infostealer.get("users"):
                    stats = infostealer.get("infostealer_stats") or {}
                    top = sorted(stats.items(), key=lambda kv: kv[1], reverse=True)[:3]
                    breakdown = ", ".join(f"{k} ({v})" for k, v in top)
                    out["infostealer_summary"] = (f"{infostealer['users']} compromised users"
                                                   + (f" via {breakdown}" if breakdown else ""))
                return out
        return {}
    except Exception as enrich_e:
        log.warning(f"ransomware.live enrich [{term}]: {enrich_e}")
        return {}


_TIER1_MIL_DOMAIN_FRAGMENTS = tuple(d.lstrip(".") for d in _TIER1_MIL_DOMAINS)

_COUNTRY_TLD_HINTS = {
    "IN": (".in",), "PK": (".pk",), "CN": (".cn",), "BD": (".bd",),
    "NP": (".np",), "LK": (".lk",), "MM": (".mm",),
}

# Adjective/alternate forms too — a plain "china" check misses "Chinese
# Police" (live-tested: it does, "chinese" doesn't contain "china" as a
# substring since the 4th letter differs). Myanmar's old name "Burma" is
# still in common use for its police/government bodies.
_COUNTRY_NAME_HINTS = {
    "IN": ("india", "indian"), "PK": ("pakistan", "pakistani"),
    "CN": ("china", "chinese"), "BD": ("bangladesh", "bangladeshi"),
    "NP": ("nepal", "nepali", "nepalese"), "LK": ("sri lanka", "sri lankan"),
    "MM": ("myanmar", "burma", "burmese"),
}


def _ransomware_live_tiers(victim_name: str, domain: str, activity: str, group: str, country_hint_cc: str = ""):
    """Shared tier classification for one ransomware.live post — used by both
    the global recent-victims feed and the per-country feed below. tier1 now
    also runs the post title through STRONG_MIL_TERMS/APT_GROUPS (not just
    the domain-suffix list), since some genuinely military listings (e.g. an
    "Access to Indian Ministry of Defence and Military Secret (DRDO)
    documents" post) carry no machine-parseable domain field at all — only
    descriptive text naming the ministry directly.

    country_hint_cc: pass the target country code when calling this for the
    per-country feed. A live test found ransomware.live's own per-country
    tagging isn't fully reliable — a Washington-state tribal government and
    an Indiana non-profit both came back mistagged as country=IN. Since
    tier1/tier2 are already domain/name-specific (safe regardless), only
    tier3's generic ".gov"/Public-Sector fallback needs this extra check:
    require the domain to end in the target country's TLD, or the country's
    own name to appear in the text, before trusting a tier3 match."""
    title = (victim_name + " " + domain).lower()
    tier1_mil = (
        # Uses the domain suffix WITHOUT its leading dot so a bare root
        # domain (e.g. victim "drdo.gov.in" with no subdomain) still
        # matches — the leading-dot version only matched subdomains like
        # "portal.drdo.gov.in", silently missing the bare-domain case (the
        # exact bug already found and fixed once for has_mil_domain()).
        any(d in title for d in _TIER1_MIL_DOMAIN_FRAGMENTS)
        or _has_any(title, STRONG_MIL_TERMS)
        or _has_any(title, APT_GROUPS)
    )
    # word-boundary: "mitre"/"parsons"/"leonardo" are also a woodworking
    # tool, a common surname, and a common first name respectively
    tier2_contractor = _has_any(title, _TIER2_CONTRACTORS)
    tier3_generic_gov = (not tier1_mil) and (not tier2_contractor) and (
        _TIER3_GENERIC_GOV_MARKER in title or (activity or "").lower() in ("government", "public sector")
    )
    if tier3_generic_gov and country_hint_cc:
        tlds = _COUNTRY_TLD_HINTS.get(country_hint_cc, ())
        name_hints = _COUNTRY_NAME_HINTS.get(country_hint_cc, ())
        # Check victim_name itself as a candidate domain too, not just the
        # separate `domain`/website field — live-tested: ransomware.live
        # sometimes puts the actual domain-looking string only in the post
        # title (e.g. "keralapolice.gov.in" as the victim name, with an
        # empty website field), so domain-field-only checking silently
        # dropped a real Kerala Police hit.
        candidate_domains = (domain, victim_name.strip().lower())
        domain_matches_country = any(cand.endswith(t) for cand in candidate_domains if cand for t in tlds)
        name_mentions_country = any(h in title for h in name_hints)
        if not (domain_matches_country or name_mentions_country):
            tier3_generic_gov = False
    return tier1_mil, tier2_contractor, tier3_generic_gov


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
    non-military, instead of being conflated with real military/defence hits.

    Extended with a second data path: the "recentvictims" feed only covers a
    short recent WORLDWIDE window, so India/Pakistan/etc-specific hits rarely
    surface there at all — a live check found 473 total India victims on
    file via /v2/countryvictims/IN, including a real "Access to Indian
    Ministry of Defence and Military Secret (DRDO) documents" Babuk2 listing
    that the recent-only version of this function would never have seen.
    Added direct per-country calls (/v2/countryvictims/{cc}) for all 7 target
    countries to close that gap. That endpoint rate-limits to ~1 request/
    minute (confirmed live), so this module now deliberately takes several
    extra minutes per run.

    Also fixed a real noise bug found while building this: tier3 (generic
    .gov / Government-sector) had NO country check at all on the global feed
    — a ransomware victim tagged "Government" in, say, France or the US
    would have been silently readmitted as "MEDIUM Government (non-military)",
    exactly the kind of leftover foreign-country data that had to be
    manually filtered out of the master CSV earlier this session. Tier3 on
    the global feed now also requires the victim's country to be one of the
    7 target countries (the per-country feed is inherently already scoped
    correctly by construction, so it doesn't need this extra check).

    Verification: the site's own homepage/browse view only surfaces recent
    activity (the "shows just the recent 100" issue raised in chat), but
    this module was never sourced from that view — /v2/countryvictims/{cc}
    is a full historical per-country feed (live-confirmed: 474 India
    victims on file, not ~100). To manually spot-check any CSV row, use
    _make_row's enriched post_url instead of eyeballing the site's front
    page: it's a clearnet ransomware.live permalink (via
    /v2/searchvictims/{term} — see _ransomware_live_enrich), openable in
    any browser with no Tor needed, and includes an actual screenshot of
    the leak-site post when ransomware.live has one on file."""
    rows = []
    seen_ids: set = set()
    _HIGH_PRIORITY_GROUPS = {
        "lockbit", "alphv", "blackcat", "clop", "cl0p", "revil", "darkside",
        "conti", "hive", "blackbasta", "akira", "play", "royal", "bianlian",
        "scattered spider", "ragnarlocker", "cuba", "lazarus", "volt typhoon",
        "salt typhoon", "silk typhoon", "vice society", "lorenz", "snatch",
        "rhysida", "medusa", "qilin", "wallstreet", "hunters international",
    }

    def _make_row(sector, victim_name, group, display_group, raw_ts, url, country, sev, conf, tier_label, tag, domain=""):
        tid = f"T2-RW-{short_id(victim_name + group)}"
        if tid in seen_ids:
            return None
        seen_ids.add(tid)
        # Enrich only kept (already tier-filtered) rows — see
        # _ransomware_live_enrich docstring for why this is affordable
        # per-row here but wasn't for the full ~470+/country raw feed.
        enrich = _ransomware_live_enrich(victim_name, domain)
        post_text = (f"Ransomware Group: {display_group} | Victim: {victim_name} | "
                     f"Tier: {tier_label} | Sector: {sector} | "
                     f"Country: {country} | Discovered: {raw_ts}")
        tags = f"ransomware;dark-web;leak-site;{tag};{group.replace(' ','-')}"
        if enrich.get("screenshot"):
            post_text += f" | Screenshot: {enrich['screenshot']}"
            tags += ";has-screenshot"
        if enrich.get("infostealer_summary"):
            post_text += f" | Infostealer exposure: {enrich['infostealer_summary']}"
            tags += ";infostealer-exposure"
        # Prefer the clearnet ransomware.live permalink as the primary
        # verifiable link (viewable in any browser) over the raw .onion
        # leak-site post (needs Tor, and routinely goes offline/seized) —
        # the original post_url is kept in post_text either way.
        verify_url = enrich.get("clearnet_url") or url or "https://www.ransomware.live/"
        if enrich.get("clearnet_url") and url:
            post_text += f" | Original leak-site post: {url}"
        return {
            "threat_id":     tid,
            "threat_name":   f"Ransomware Victim — {display_group}",
            "category_code": "T2", "category_name": CATEGORY_NAMES["T2"],
            "source_layer":  "Dark Web", "source": "ransomware.live (ransomware leak sites)",
            "post_text":     post_text,
            "post_url":      verify_url,
            "timestamp":     str(raw_ts), "location": country or "Unknown",
            "severity":      sev, "confidence": conf,
            "ioc_type":      "url", "ioc_value": url or f"darkweb://{group.replace(' ','-')}/{short_id(victim_name)}",
            "tags":          tags,
        }

    def _sev_for(tier1_mil, tier2_contractor):
        if tier1_mil:
            return "CRITICAL", "HIGH", "Military/Defence", "gov-military"
        if tier2_contractor:
            return "HIGH", "MEDIUM", "Defence Contractor", "contractor"
        return "MEDIUM", "MEDIUM", "Government (non-military)", "government-sector"

    # ── Path 1: global recent-victims feed (fast, narrow time window) ──
    try:
        resp = _ransomware_live_get("https://api.ransomware.live/v2/recentvictims")
        posts = resp.json()
        if isinstance(posts, list):
            for post in posts:
                victim_name = post.get("victim") or ""
                domain      = (post.get("domain") or "").lower()
                group       = (post.get("group") or "Unknown").lower()
                display_group = post.get("group") or "Unknown"
                activity    = post.get("activity") or ""
                country     = post.get("country") or ""
                raw_ts      = post.get("discovered") or post.get("attackdate") or now_utc()

                if not any(g in group for g in _HIGH_PRIORITY_GROUPS):
                    continue
                tier1_mil, tier2_contractor, tier3_generic_gov = _ransomware_live_tiers(
                    victim_name, domain, activity, group)
                if tier3_generic_gov and country.upper() not in _RANSOMWARE_LIVE_TARGET_COUNTRIES:
                    tier3_generic_gov = False
                if not (tier1_mil or tier2_contractor or tier3_generic_gov):
                    continue
                sev, conf, tier_label, tag = _sev_for(tier1_mil, tier2_contractor)
                row = _make_row(activity, victim_name, group, display_group, raw_ts,
                                 post.get("url"), country, sev, conf, tier_label, tag, domain=domain)
                if row:
                    rows.append(row)
    except Exception as e:
        log.error(f"ransomware.live (recent feed) error: {e}")

    # ── Path 2: per-country feed, one country at a time (rate-limited ~1/min) ──
    for cc, country_name in _RANSOMWARE_LIVE_TARGET_COUNTRIES.items():
        try:
            time.sleep(65)  # respect the ~1 request/minute rate limit (confirmed live)
            resp = _ransomware_live_get(f"https://api.ransomware.live/v2/countryvictims/{cc}", timeout=30)
            posts = resp.json()
            if not isinstance(posts, list):
                continue
            kept_for_country = 0
            for post in posts:
                if kept_for_country >= 15:
                    break
                victim_name = post.get("victim") or post.get("post_title") or ""
                domain      = (post.get("domain") or post.get("website") or "").lower()
                group       = (post.get("group") or post.get("group_name") or "Unknown").lower()
                display_group = post.get("group") or post.get("group_name") or "Unknown"
                activity    = post.get("activity") or ""
                raw_ts      = post.get("discovered") or post.get("published") or post.get("attackdate") or now_utc()
                url         = post.get("url") or post.get("post_url") or ""

                # No _HIGH_PRIORITY_GROUPS gate here on purpose: this feed is
                # requested per-country, so tier1/tier2/tier3 (domain /
                # contractor / gov-sector) IS the noise gate — requiring a
                # "famous gang" on top of that would drop real military hits
                # from smaller or regional ransomware groups. country_hint_cc
                # is passed so tier3 double-checks the country tag itself
                # (ransomware.live's own per-country tagging isn't fully
                # reliable — see _ransomware_live_tiers docstring).
                tier1_mil, tier2_contractor, tier3_generic_gov = _ransomware_live_tiers(
                    victim_name, domain, activity, group, country_hint_cc=cc)
                if not (tier1_mil or tier2_contractor or tier3_generic_gov):
                    continue
                sev, conf, tier_label, tag = _sev_for(tier1_mil, tier2_contractor)
                row = _make_row(activity, victim_name, group, display_group, raw_ts,
                                 url, country_name, sev, conf, tier_label, tag, domain=domain)
                if row:
                    rows.append(row)
                    kept_for_country += 1
        except Exception as e:
            log.warning(f"ransomware.live (country feed {cc}) error: {e}")

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

    # Narrowed to India + neighbouring countries only (per explicit instruction)
    # — the queries below replace the original US/NATO-focused set.
    QUERIES = [
        # These 6 "seed" queries were previously bare generic phrases
        # (literally "pakistan military leak" etc.) — the exact pattern
        # flagged as producing noisy/generic matches. Rewritten with the
        # same level of qualifying detail (branch/data-type/asset)
        # already used in the 37 category-gap queries below, so ranking
        # is driven by multiple specific terms instead of 2-3 generic ones.
        ("indian army soldier login credential database exposed", "T1", "Indian Army Credential Database Exposure"),
        ("pakistan army isi military personnel data leak", "T2", "Pakistan Military Personnel Data Leak"),
        ("china pla unit network breach compromise data", "T2", "China PLA Network Breach Mention"),
        ("south asia military cyber espionage nation state actor", "T6", "South Asia Nation-State Cyber Espionage Mention"),
        ("indian defence contractor employee database exposed leak", "T2", "Indian Defense Contractor Data"),
        ("bangladesh nepal sri lanka myanmar military network exploit vulnerability", "T7", "Neighbouring Countries Exploit Mention"),
        # Named-APT-campaign searches — these groups are actively (2025-2026)
        # targeting exactly this region (researched specifically for this
        # scope; see chat), so dark-web chatter naming them is high-signal.
        ("sidewinder razor tiger south asia government breach", "T6", "SideWinder/Razor Tiger Campaign Mention"),
        ("bitter apt pakistan kashmir data leak", "T2", "Bitter APT Pakistan Leak Mention"),
        ("mustang panda myanmar military breach", "T6", "Mustang Panda Myanmar Breach Mention"),
        ("donot team india government data leak", "T2", "DoNot Team India Leak Mention"),
        # Closing gaps against sir's OSINT category framework (see chat) —
        # these subcategories had zero search coverage before. Dark web is
        # the right channel for them (leaked procurement/strategic/supply
        # documents get discussed/sold on underground forums, not found in
        # public GitHub repos), and results still go through the same
        # relevance_check() gate as every other Torch query above.
        ("indian military biometric fingerprint database leak", "T1", "Biometric Data Leak Mention"),
        ("soldier geolocation tracking data leak south asia", "T1", "Geolocation Exposure Mention"),
        ("military procurement tender leak india pakistan", "T2", "Procurement Data Leak Mention"),
        ("defence technology transfer arms deal leak", "T2", "Technology Transfer Leak Mention"),
        ("military strategic plan document leak south asia", "T2", "Strategic Planning Document Leak Mention"),
        ("joint military exercise operations leak india", "T2", "Joint Operations Leak Mention"),
        ("military supply depot ammunition leak south asia", "T2", "Supply Depot Leak Mention"),
        ("military communications intercept sigint leak", "T3", "Comms Interception Mention"),
        ("military secure messaging app compromise south asia", "T3", "Messaging Platform Compromise Mention"),
        ("satellite ground station hack compromise india", "T3", "Satellite Ground Station Compromise Mention"),
        ("battlefield tactical network disruption south asia", "T3", "Battlefield Network Disruption Mention"),
        # T4/T5 framework gaps — same reasoning as above: incident-report
        # based coverage via dark-web/underground chatter, since a real-time
        # GPS-spoofing detector was already tried and reverted this session
        # as a confirmed false positive (see fetch_gps_ew_data docstring).
        ("gps spoofing jamming attack india pakistan border", "T4", "GPS Spoofing/Jamming Incident Mention"),
        ("radar system hack air defence compromise south asia", "T4", "Radar/Air Defence Targeting Mention"),
        ("electronic warfare attack military sensor network", "T4", "EW/Sensor Network Attack Mention"),
        ("defence manufacturing plant cyber breach south asia", "T5", "Defence Manufacturing Breach Mention"),
        ("military logistics fuel supply chain attack india", "T5", "Logistics/Fuel Supply Chain Attack Mention"),
        ("military transportation network battlefield management breach", "T5", "Transportation/BMS Attack Mention"),
        ("nuclear facility cyber attack india pakistan china", "T5", "Nuclear Facility Cyber Threat Mention"),
        ("nuclear research data leak south asia", "T5", "Nuclear Research Data Leak Mention"),
        # T6 gaps
        ("ddos attack defence sector south asia", "T6", "Defence Sector DDoS Attack Mention"),
        ("surveillance spyware pegasus military south asia", "T6", "Surveillance Malware Activity Mention"),
        ("ai-enabled cyberattack military south asia", "T6", "AI-Enabled Cyber Attack Mention"),
        ("cyber sabotage military infrastructure south asia", "T6", "Cyber Sabotage Operation Mention"),
        # T7 gaps — the framework's real T7 subcategories had zero coverage
        # before this (the tool's existing T7 code is unrelated generic
        # vendor-CVE monitoring — see chat). Border Surveillance System
        # Compromise flagged as the highest-priority one for India
        # specifically (LoC/LAC), also given a real domain target (BSF)
        # above, unlike the other 4 which have no identifiable single
        # domain to target and rely on this dark-web search instead.
        ("defence supply chain compromise hardware implant south asia", "T7", "Supply Chain Compromise Mention"),
        ("military drone uav hijack spoofing south asia", "T7", "Drone/UAV Compromise Mention"),
        ("weapon system vulnerability exploit india pakistan china", "T7", "Weapon System Vulnerability Mention"),
        ("autonomous weapon system ai military threat", "T7", "Autonomous Weapon System Threat Mention"),
        ("border surveillance system compromise loc lac india", "T7", "Border Surveillance System Compromise Mention"),
        # T8 gaps. Social Media Influence Operations (the framework's other
        # T8 gap) is deliberately NOT added here — it needs platform access
        # (X/Twitter API is paid, Facebook/YouTube similarly restricted),
        # not a dark-web search; flagging as a real, unsolved-for-free gap
        # rather than faking coverage.
        ("deepfake synthetic media military south asia", "T8", "Deepfake/Synthetic Identity Attack Mention"),
        ("cyber psyop psychological operation military south asia", "T8", "Cyber PSYOP Mention"),
        ("false flag cyber operation military attribution", "T8", "False Flag Cyber Operation Mention"),
        # S1 — Section II of the framework (dark web marketplaces/forums).
        # New category, doesn't retag anything existing (see chat).
        ("military zero-day exploit for sale dark web", "S1", "Defence Zero-Day Exploit Listing"),
        ("military pay salary fraud scam underground market", "S1", "Military Financial Fraud Underground Market Mention"),
    ]
    TORCH_URL = "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega"
    seen_urls: set = set()

    # Parallelized (was fully sequential — 43 queries x (Tor round-trip +
    # a 3.5s artificial delay) made this the slowest module in the tool,
    # 10-20+ minutes on some runs). Researched free/faster external
    # alternatives first (see chat): DarkSearch.io's public API is
    # discontinued, IntelligenceX's free tier has NO API access at all
    # (Search API needs the EUR2,500/yr "Researcher" tier), and Apify's
    # Tor-search actors are metered against a small $5/mo credit that a
    # single 43-query run would mostly burn through — none of them are a
    # real free replacement. A bounded thread pool over the SAME local Tor
    # SOCKS5 proxy is the actual free speedup available: Tor can serve
    # several concurrent streams over one proxy, so this cuts wall-clock
    # time roughly by the worker count without needing any new external
    # service. Kept deliberately modest (4 workers) rather than higher,
    # since a local Tor daemon can get circuit-congested under heavy
    # concurrency.
    import concurrent.futures
    import threading
    session = requests.Session()
    seen_lock = threading.Lock()

    def _run_query(args):
        q, cat, label = args
        local_rows = []
        try:
            # -wiki -wikipedia: live-verified against Torch's Omega/Xapian
            # backend (see chat) — every current result was "The Hidden
            # Wiki" (an onion index/directory site, not real leak/breach
            # content). Xapian supports server-side -term exclusion;
            # tested "pakistan military leak -wiki" and got 0 Hidden Wiki
            # hits vs 100% before, with genuinely different alternative
            # .onion links returned. q itself (used for tagging/threat_id)
            # stays clean — only the actual request param gets the filter.
            #
            # DEFAULTOP=or: Omega's search form defaults to DEFAULTOP=and
            # (confirmed by inspecting the actual HTML — the "Matching all
            # words" radio button ships pre-checked). That means every one
            # of our 5-9-word queries was silently requiring EVERY term to
            # appear in the same document — live-tested and found this
            # collapses several queries (including pre-existing ones, not
            # just ones added this round) to "No documents match your
            # query" outright, and explains why Hidden Wiki dominated the
            # results that DID come through: broad encyclopedia-style
            # index pages are the only documents comprehensive enough to
            # contain every query term at once, so strict AND-mode was
            # structurally biased toward exactly that noise. Switching to
            # OR-mode (probabilistic ranking on any term) restored real
            # results (e.g. "sidewinder razor tiger south asia government
            # breach -wiki -wikipedia" went from 0 matches to ~20,000
            # ranked matches, still 0 Hidden Wiki hits) and relies on the
            # existing relevance_check(min_weak=2) gate below — same as
            # every other keyword-search module — to do the actual
            # precision filtering instead of Torch's own AND matching.
            search_q = f"{q} -wiki -wikipedia"
            resp = session.get(TORCH_URL, params={"P": search_q, "DEFAULTOP": "or"}, proxies=proxies,
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
                                timeout=50)
            resp.raise_for_status()
            # A verification pass found a single U+FFFD replacement
            # character in a scraped snippet ("Director General<?>: Rizwan")
            # — Torch's proxied Tor Hidden Wiki pages don't reliably send a
            # correct charset header, so `requests` was falling back to its
            # ISO-8859-1 default instead of the page's real encoding.
            # apparent_encoding sniffs the actual bytes instead of trusting
            # the (often absent/wrong) header — same class of fix as the
            # PDF font/mojibake issue found earlier this session, just at
            # the scraping layer instead of the rendering layer.
            if resp.encoding is None or resp.encoding.lower() in ("iso-8859-1", "ascii"):
                resp.encoding = resp.apparent_encoding
            kept = 0
            for link, raw_title, raw_snippet in _TORCH_RESULT_RE.findall(resp.text):
                if kept >= 4:
                    break
                with seen_lock:
                    if link in seen_urls:
                        continue
                title = re.sub(r'<[^>]+>', '', raw_title).strip()
                snippet = re.sub(r'<[^>]+>', '', raw_snippet).strip()
                # Defense-in-depth on top of the server-side -wiki/-wikipedia
                # exclusion above — catches it client-side too in case a
                # Torch mirror/cache doesn't fully honor the query-time
                # exclusion. These are onion index/directory pages, not
                # leak or breach content, regardless of which term matched.
                title_low = title.lower()
                if "hidden wiki" in title_low or "wikipedia" in title_low:
                    continue
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
                with seen_lock:
                    if link in seen_urls:
                        continue  # another worker beat us to this link
                    seen_urls.add(link)
                kept += 1
                local_rows.append({
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
        except Exception as inner_e:
            log.warning(f"Tor/Torch [{q}]: {inner_e}")
        return local_rows

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for local_rows in pool.map(_run_query, QUERIES):
            rows.extend(local_rows)
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

def fetch_shodan_military(api_key: str, extra_domains: list = None) -> list:
    """T3 — PAID $69/mo at shodan.io. Exposed military network infrastructure.

    Queries were still US Army/US Navy/UK MoD/generic .mil/DoD — completely
    unscoped from before this session's India+neighbours narrowing (Parts
    1-6). This module is PAID and its API key IS actually configured, so it
    was live and actively pulling non-target-country data into the master
    CSV on every run. Rewritten to hostname:-scope on our actual confirmed
    domains, same pattern as every other module.

    extra_domains: CT-discovered sensitive subdomains pivoted in from
    crt.sh this run — same workflow as the LeakIX pivot (see chat), now
    extended to every actively-working scan module, not just LeakIX."""
    rows = []
    queries = [
        ('hostname:"mod.gov.in"', "Indian MoD exposed infrastructure"),
        ('hostname:"drdo.gov.in"', "DRDO exposed infrastructure"),
        ('hostname:"indianarmy.nic.in"', "Indian Army exposed infrastructure"),
        ('hostname:"barc.gov.in"', "BARC (Nuclear) exposed infrastructure"),
        ('hostname:"bsf.gov.in"', "BSF (Border Surveillance) exposed infrastructure"),
        ('hostname:"mod.gov.pk"', "Pakistan MoD exposed infrastructure"),
        ('hostname:"mod.gov.cn"', "China MoD exposed infrastructure"),
        ('hostname:"mod.gov.bd"', "Bangladesh MoD exposed infrastructure"),
        ('hostname:"mod.gov.np"', "Nepal MoD exposed infrastructure"),
        ('hostname:"defence.lk"', "Sri Lanka MoD exposed infrastructure"),
        ('hostname:"mod.gov.mm"', "Myanmar MoD exposed infrastructure"),
        ('hostname:"cincds.gov.mm"', "Myanmar CINCDS exposed infrastructure"),
    ]
    for pivot_domain in (extra_domains or [])[:15]:
        queries.append((f'hostname:"{pivot_domain}"', f"CT-Discovered: {pivot_domain}"))
    for q, label in queries:
        # Extract the target domain from the hostname:"X" query so location
        # can be resolved via domain_to_country() — Shodan's own IP
        # geolocation reflects where the server is physically hosted
        # (often a foreign CDN/cloud region), not the org's actual country;
        # same fix already applied to LeakIX this session (see chat).
        target_domain = q.split('"')[1] if '"' in q else ""
        try:
            resp = requests.get("https://api.shodan.io/shodan/host/search",
                                 params={"key": api_key, "query": q, "limit": 10}, timeout=15)
            resp.raise_for_status()
            for m in resp.json().get("matches", []):
                ip = m.get("ip_str", "")
                loc = domain_to_country(target_domain)
                if loc == "Unknown":
                    loc = m.get("location", {}).get("country_name", "Unknown")
                tech = _fingerprint_technology(str(m.get("data", "")), str(m.get("product", "")))
                rows.append({
                    "threat_id":     f"T3-SHD-{short_id(ip + str(m.get('port','')))}",
                    "threat_name":   label,
                    "category_code": _domain_scan_category(label),
                    "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                    "source_layer":  "Deep Web", "source": "Shodan",
                    "post_text":     f"Org: {m.get('org','')} | Port: {m.get('port','')} | Banner: {str(m.get('data',''))[:300]}",
                    "post_url":      f"https://www.shodan.io/host/{ip}",
                    "timestamp":     m.get("timestamp", now_utc()),
                    "location":      loc,
                    "severity":      "HIGH", "confidence": "HIGH",
                    "ioc_type":      "ip", "ioc_value": ip,
                    "tags":          "network;exposed;shodan" + (f";tech:{','.join(tech)}" if tech else ""),
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"Shodan error [{q}]: {e}")
    log.info(f"Shodan: {len(rows)} exposed military assets found")
    return rows


def fetch_dns_records(hostnames: list) -> list:
    """T3 — FREE, no key. DNS record enrichment (A/AAAA/MX/NS/TXT) via
    Cloudflare's DNS-over-HTTPS JSON API, plus passive DNS history + ASN/
    organization data via OTX (reuses the existing otx_api_key — no new
    signup needed). Closes two gaps flagged in a workflow review (see
    chat): this tool discovered hostnames from certificates but never
    resolved them, and never captured ASN/organization data for
    correlating infrastructure across sources. Both APIs live-verified
    before adding (real MX/NS/TXT records for avic.com; real passive DNS +
    ASN data for the same domain via OTX)."""
    rows = []
    otx_key = CONFIG.get("otx_api_key", "")
    _RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]
    for hostname in hostnames[:20]:
        try:
            dns_findings = []
            for rtype in _RECORD_TYPES:
                try:
                    resp = requests.get("https://cloudflare-dns.com/dns-query",
                                         params={"name": hostname, "type": rtype},
                                         headers={"Accept": "application/dns-json", "User-Agent": "MilOSINT/2.0"},
                                         timeout=10)
                    resp.raise_for_status()
                    answers = resp.json().get("Answer") or []
                    values = [a.get("data", "").strip('"') for a in answers if a.get("data")]
                    if values:
                        dns_findings.append(f"{rtype}={','.join(values[:5])}")
                except Exception:
                    pass
                time.sleep(0.3)

            passive_dns_findings = []
            asn_seen = set()
            if otx_key:
                try:
                    # 30s not 15s — a live test found OTX's passive_dns endpoint
                    # is noticeably slower than its pulse-search endpoint used
                    # elsewhere in this tool, and 15s timed out on every domain.
                    presp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/passive_dns",
                                          headers={"X-OTX-API-KEY": otx_key, "User-Agent": "MilOSINT/2.0"}, timeout=30)
                    if presp.status_code == 200:
                        for rec in (presp.json().get("passive_dns") or [])[:10]:
                            addr = rec.get("address", "")
                            asn = rec.get("asn", "")
                            if asn:
                                asn_seen.add(asn)
                            if addr:
                                passive_dns_findings.append(f"{addr} ({rec.get('record_type','')}, first seen {rec.get('first','')[:10]})")
                except Exception as e:
                    log.warning(f"OTX passive DNS [{hostname}]: {e}")

            if not dns_findings and not passive_dns_findings:
                continue

            rows.append({
                "threat_id":     f"T3-DNS-{short_id(hostname)}",
                "threat_name":   f"DNS/Passive-DNS Enrichment — {hostname}",
                "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
                "source_layer":  "Surface Web", "source": "Cloudflare DoH + OTX Passive DNS",
                "post_text":     (f"Host: {hostname} | Live DNS: {'; '.join(dns_findings) or 'none resolved'} | "
                                  f"Passive DNS history: {'; '.join(passive_dns_findings[:5]) or 'none on file'} | "
                                  f"ASN/Org: {'; '.join(sorted(asn_seen)) or 'unknown'}"),
                "post_url":      f"https://otx.alienvault.com/indicator/hostname/{hostname}",
                "timestamp":     now_utc(), "location": domain_to_country(hostname),
                "severity":      "MEDIUM", "confidence": "HIGH",
                "ioc_type":      "domain", "ioc_value": hostname,
                "tags":          f"dns;passive-dns;infrastructure-mapping;{';'.join(sorted(asn_seen)).replace(' ','-') if asn_seen else ''}".rstrip(";"),
            })
        except Exception as e:
            log.warning(f"DNS enrichment [{hostname}]: {e}")
    log.info(f"DNS/Passive-DNS enrichment: {len(rows)} hostnames enriched")
    return rows


def fetch_securitytrails(api_key: str) -> list:
    """T3 — PAID $50/mo at securitytrails.com. Military subdomain/DNS intel.

    Domain list was still army.mil/navy.mil/NATO/UK/Germany/Australia/
    Canada/Israel/France/Japan/S.Korea/Taiwan/Ukraine — left over from
    before this session's India+neighbours narrowing (Parts 1-6). Currently
    inactive (no API key configured) so no live-data risk, but fixed for
    consistency/correctness (see chat)."""
    rows = []
    domains = ["mod.gov.in", "drdo.gov.in", "barc.gov.in", "npcil.nic.in", "bsf.gov.in",
               "mod.gov.pk", "modp.gov.pk", "paec.gov.pk",
               "mod.gov.cn", "cnnc.com.cn",
               "mod.gov.bd", "baec.gov.bd", "mod.gov.np", "defence.lk", "mod.gov.mm", "cincds.gov.mm"]
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
                    "category_code": _domain_scan_category(label),
                    "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
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


def fetch_censys(api_id: str, api_secret: str = "", extra_domains: list = None) -> list:
    """T3 — FREE 250 queries/mo at censys.io. Military ASN internet scan.

    Queries were still US Army/US Navy/US Air Force/NATO — completely
    unscoped from before this session's India+neighbours narrowing (Parts
    1-6), and this module's API key IS actually configured, so it was live.
    Rewritten to dns.names:-scope on our actual confirmed domains (Censys
    v2 hosts-search field for DNS/SAN hostnames), same pattern as every
    other module — 250 free queries/mo is tight, so kept to one query per
    country's primary MoD domain rather than every domain we track.

    extra_domains: CT-discovered subdomains pivoted in from crt.sh (see
    chat) — capped much lower than other modules (3, not 15) specifically
    because of the tight 250/mo quota noted above."""
    rows = []
    if api_id.startswith("censys_"):
        creds = base64.b64encode(f"{api_id}:".encode()).decode()
    else:
        creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json", "User-Agent": "MilOSINT/2.0"}
    queries = [
        ('dns.names: "mod.gov.in"', "Indian MoD"),
        ('dns.names: "drdo.gov.in"', "DRDO"),
        ('dns.names: "mod.gov.pk"', "Pakistan MoD"),
        ('dns.names: "mod.gov.cn"', "China MoD"),
        ('dns.names: "mod.gov.bd"', "Bangladesh MoD"),
        ('dns.names: "mod.gov.np"', "Nepal MoD"),
        ('dns.names: "defence.lk"', "Sri Lanka MoD"),
        ('dns.names: "mod.gov.mm"', "Myanmar MoD"),
        ('dns.names: "cincds.gov.mm"', "Myanmar CINCDS"),
    ]
    for pivot_domain in (extra_domains or [])[:3]:
        queries.append((f'dns.names: "{pivot_domain}"', f"CT-Discovered: {pivot_domain}"))
    try:
        for query, label in queries:
            # Same domain-based location fix as Shodan/LeakIX this session
            # (see chat) — Censys's location.country is IP geolocation
            # (hosting region), not the org's actual country.
            target_domain = query.split('"')[1] if '"' in query else ""
            resp = requests.post("https://search.censys.io/api/v2/hosts/search", headers=headers,
                                  json={"q": query, "per_page": 10,
                                        "fields": ["ip", "services.port", "services.service_name",
                                                   "location.country", "autonomous_system.organization"]},
                                  timeout=20)
            resp.raise_for_status()
            for hit in resp.json().get("result", {}).get("hits") or []:
                ip = hit.get("ip") or ""
                services = hit.get("services") or []
                asys = hit.get("autonomous_system") or {}
                org = asys.get("organization") or label
                asn = asys.get("asn") or ""
                svc_str = ", ".join(f"{s.get('service_name','?')}:{s.get('port','?')}" for s in services[:5])
                loc = domain_to_country(target_domain)
                if loc == "Unknown":
                    loc = (hit.get("location") or {}).get("country") or "Unknown"
                tech = _fingerprint_technology(svc_str)
                rows.append({
                    "threat_id":     f"T3-CNS-{short_id(ip)}",
                    "threat_name":   f"Exposed Military Network Asset — {org}",
                    "category_code": _domain_scan_category(label),
                    "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                    "source_layer":  "Deep Web", "source": "Censys",
                    "post_text":     f"IP: {ip} | Org: {org} | ASN: AS{asn} | Services: {svc_str} | Query: {label}",
                    "post_url":      f"https://search.censys.io/hosts/{ip}",
                    "timestamp":     now_utc(), "location": loc,
                    "severity":      "HIGH", "confidence": "HIGH",
                    "ioc_type":      "ip", "ioc_value": ip,
                    "tags":          (f"exposed-asset;network;censys;military-infra;{label.lower().replace(' ','-')}"
                                      + (f";asn:AS{asn}" if asn else "")
                                      + (f";tech:{','.join(tech)}" if tech else "")),
                })
            time.sleep(CONFIG["request_delay_sec"])
    except Exception as e:
        log.error(f"Censys error: {e}")
    log.info(f"Censys: {len(rows)} exposed military network assets found")
    return rows


def fetch_netlas(api_key: str, extra_domains: list = None) -> list:
    """T3 — FREE "Community" tier at netlas.io (50 requests/day, forever
    free, no card required — sign up at app.netlas.io, key on the profile
    page). Added as an independent internet-scan source after Shodan (403),
    Censys (401), and ZoomEye (credits_insufficient) were all found blocked
    on the account/credit side this session — Netlas gives a live, working
    path to the same class of exposed-asset data. Live-tested reachable
    (see chat): api.netlas.io responds 200 even unauthenticated, real
    results need a free key.

    extra_domains: CT-discovered subdomains pivoted in from crt.sh, capped
    at 8 (not 15) given the 12 hardcoded targets already use a good chunk
    of the 50/day quota."""
    rows = []
    targets = [
        ("mod.gov.in", "Indian MoD"), ("drdo.gov.in", "DRDO"),
        ("barc.gov.in", "BARC (Nuclear)"), ("npcil.nic.in", "NPCIL (Nuclear)"),
        ("bsf.gov.in", "BSF (Border Surveillance)"),
        ("mod.gov.pk", "Pakistan MoD"), ("mod.gov.cn", "China MoD"),
        ("mod.gov.bd", "Bangladesh MoD"), ("mod.gov.np", "Nepal MoD"),
        ("defence.lk", "Sri Lanka MoD"), ("mod.gov.mm", "Myanmar MoD"),
        ("cincds.gov.mm", "Myanmar CINCDS"),
    ]
    for pivot_domain in (extra_domains or [])[:8]:
        targets.append((pivot_domain, f"CT-Discovered: {pivot_domain}"))
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json", "User-Agent": "MilOSINT/2.0"}
    try:
        for domain, label in targets:
            try:
                # No `fields` param — an earlier version guessed at Netlas's
                # field-name syntax ("data.http.title") and got a 400 Bad
                # Request even with a fake key (i.e. the malformed param was
                # rejected before auth was even checked). Requesting the
                # default full response and parsing defensively avoids
                # depending on unverified field-path syntax; confirm exact
                # field names once a real key is added (see chat).
                resp = requests.get("https://app.netlas.io/api/responses/",
                                     params={"q": f"host:{domain}"},
                                     headers=headers, timeout=20)
                if resp.status_code in (401, 403, 429):
                    log.warning(f"Netlas: {resp.status_code} — check netlas_api_key / daily quota")
                    break
                if resp.status_code == 400:
                    log.warning(f"Netlas [{domain}]: 400 Bad Request — query syntax may need "
                                f"adjusting once a real key confirms the response shape")
                    continue
                resp.raise_for_status()
                for item in (resp.json().get("items") or [])[:5]:
                    data = item.get("data") or {}
                    ip = data.get("ip") or item.get("ip") or ""
                    port = data.get("port") or item.get("port") or ""
                    title = (((data.get("http") or {}).get("title"))
                             or ((data.get("http") or {}).get("body_title")) or "")[:150]
                    tech = _fingerprint_technology(title)
                    rows.append({
                        "threat_id":     f"T3-NTL-{short_id(str(ip) + str(port) + domain)}",
                        "threat_name":   f"Netlas Exposed Asset — {label}",
                        "category_code": _domain_scan_category(label),
                        "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                        "source_layer":  "Deep Web", "source": "Netlas.io",
                        "post_text":     f"IP: {ip}:{port} | Domain: {domain} | Title: {title}",
                        "post_url":      f"https://app.netlas.io/host/{ip}" if ip else "https://app.netlas.io/",
                        "timestamp":     now_utc(), "location": domain_to_country(domain),
                        "severity":      "HIGH", "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": str(ip),
                        "tags":          (f"netlas;internet-scan;exposed-asset;{label.lower().replace(' ','-')}"
                                          + (f";tech:{','.join(tech)}" if tech else "")),
                    })
                time.sleep(CONFIG["request_delay_sec"])
            except Exception as inner_e:
                log.warning(f"Netlas [{domain}]: {inner_e}")
    except Exception as e:
        log.error(f"Netlas error: {e}")
    log.info(f"Netlas: {len(rows)} exposed military assets found")
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
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    targets = [
        # India
        ("%.indianarmy.nic.in", "Indian Army Subdomains"),
        ("%.indiannavy.gov.in", "Indian Navy Subdomains"),
        ("%.indianairforce.nic.in", "Indian Air Force Subdomains"),
        ("%.mod.gov.in", "Indian MoD Subdomains"),
        ("%.drdo.gov.in", "DRDO Subdomains"),
        ("%.barc.gov.in", "BARC (Nuclear) Subdomains"), ("%.npcil.nic.in", "NPCIL (Nuclear) Subdomains"),
        ("%.bsf.gov.in", "BSF (Border Surveillance) Subdomains"),
        # Pakistan / China
        ("%.pakistanarmy.gov.pk", "Pakistan Army Subdomains"),
        ("%.mod.gov.pk", "Pakistan MoD Subdomains"),
        ("%.modp.gov.pk", "Pakistan MoD Production Subdomains"),
        ("%.paec.gov.pk", "PAEC (Nuclear) Subdomains"),
        ("%.mod.gov.cn", "China MoD Subdomains"),
        ("%.avic.com", "AVIC Subdomains"),
        ("%.cnnc.com.cn", "CNNC (Nuclear) Subdomains"),
        # India's other neighbours — all live-verified before adding.
        ("%.mod.gov.bd", "Bangladesh MoD Subdomains"),
        ("%.afd.gov.bd", "Bangladesh Armed Forces Division Subdomains"),
        ("%.ispr.gov.bd", "Bangladesh ISPR Subdomains"),
        ("%.bof.gov.bd", "Bangladesh Ordnance Factory Subdomains"),
        ("%.khulnashipyard.gov.bd", "Bangladesh Khulna Shipyard Subdomains"),
        ("%.cddl.gov.bd", "Bangladesh Chittagong Dry Dock Subdomains"),
        ("%.baec.gov.bd", "BAEC (Nuclear) Subdomains"),
        ("%.dewbn.gov.bd", "Bangladesh Dockyard & Engineering Works Subdomains"),
        ("%.mod.gov.np", "Nepal MoD Subdomains"),
        ("%.nepalarmy.mil.np", "Nepal Army Subdomains"),
        ("%.defence.lk", "Sri Lanka MoD Subdomains"),
        ("%.army.lk", "Sri Lanka Army Subdomains"),
        ("%.navy.lk", "Sri Lanka Navy Subdomains"),
        ("%.airforce.lk", "Sri Lanka Air Force Subdomains"),
        ("%.mod.gov.mm", "Myanmar MoD Subdomains"),
        ("%.cincds.gov.mm", "Myanmar CINCDS Subdomains"),
    ]

    def _crtsh_fetch(q: str):
        """Returns a list on success (possibly empty — 404 genuinely means no
        certs), or None on failure (exhausted all retries) — the caller needs
        to tell these apart to run a consecutive-failure circuit breaker
        (see chat: a live check found crt.sh's backend itself intermittently
        throwing 502s and full 40s read-timeouts across MOST domains in a
        given run, not any single domain — grinding through all ~29 targets
        with 3 full retries each could cost 30-60+ minutes for almost no
        data on a bad crt.sh day)."""
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
                    return None
                r.raise_for_status()
                if "json" not in r.headers.get("Content-Type", ""):
                    if attempt < 2:
                        time.sleep(6)
                        continue
                    return None
                return r.json() or []
            except (requests.exceptions.Timeout, requests.exceptions.JSONDecodeError):
                if attempt < 2:
                    time.sleep(5)
                    continue
                return None
            except Exception as exc:
                log.warning(f"crt.sh error for {q!r}: {type(exc).__name__}: {exc}")
                return None
        return None

    _SENSITIVE_PREFIXES = {
        "vpn", "remote", "portal", "gateway", "citrix", "rdweb", "gitlab", "github",
        "git", "confluence", "jira", "wiki", "kibana", "jenkins", "sonarqube", "nexus",
        "artifactory", "admin", "internal", "intranet", "mgmt", "management", "mail",
        "webmail", "owa", "exchange", "smtp", "api", "dev", "staging", "test", "qa",
        "uat", "sso", "idp", "ldap", "auth", "login", "ftp", "sftp", "backup",
        "archive", "camera", "cctv", "scada", "ics", "plc",
    }
    _today = datetime.now(timezone.utc).date()

    # Hard wall-clock budget, not a failure-rate/consecutiveness heuristic —
    # two live tests showed crt.sh's failures don't cluster predictably
    # (alternate with successes) and a 60%-failure-rate breaker never
    # tripped even though the module still took 18-25+ minutes both times.
    # Whatever the exact failure PATTERN is, what actually matters is
    # bounding this module's runtime, so cap it directly: once the budget
    # is spent, stop attempting new domains and keep whatever was already
    # collected (crt.sh is one of ~25 modules in a full run — it shouldn't
    # be able to eat the majority of the run's total time on a bad day).
    _crtsh_deadline = time.time() + 480  # 8 minutes
    attempted = 0
    failed = 0
    for domain, label in targets:
        if time.time() > _crtsh_deadline:
            log.warning(f"crt.sh: 8-minute time budget exhausted after {attempted} domains "
                        f"({failed} failed) — stopping early, skipping {label!r} and all "
                        f"remaining targets this run")
            break
        try:
            attempted += 1
            certs = _crtsh_fetch(domain)
            if certs is None:
                failed += 1
                continue
            if not certs:
                continue
            # Explicitly sort newest-first before taking the top 200 — a
            # live check found crt.sh's own return order is only roughly
            # date-ordered (not strictly), e.g. DRDO's results had a 2026
            # entry, then 2024, then back to 2026. For a domain with more
            # than 200 total certs on file, trusting crt.sh's raw order
            # risked silently dropping some of the actual most-recent
            # certificates in favour of older ones. See chat.
            certs = sorted(certs, key=lambda c: c.get("not_before") or "", reverse=True)
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
                    "category_code": _domain_scan_category(label),
                    "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
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


def fetch_zoomeye(api_key: str, extra_domains: list = None) -> list:
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
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    TARGETS = [
        ('hostname:"indianarmy.nic.in"', "Indian Army", "IN"),
        ('hostname:"mod.gov.in"', "Indian MoD", "IN"),
        ('hostname:"drdo.gov.in"', "DRDO", "IN"),
        ('hostname:"pakistanarmy.gov.pk"', "Pakistan Army", "PK"),
        ('hostname:"mod.gov.pk"', "Pakistan MoD", "PK"),
        ('hostname:"modp.gov.pk"', "Pakistan MoD Production", "PK"),
        ('hostname:"mod.gov.cn"', "China MoD", "CN"),
        ('hostname:"mod.gov.bd"', "Bangladesh MoD", "BD"),
        ('hostname:"bof.gov.bd"', "Bangladesh Ordnance Factory", "BD"),
        ('hostname:"khulnashipyard.gov.bd"', "Bangladesh Khulna Shipyard", "BD"),
        ('hostname:"mod.gov.np"', "Nepal MoD", "NP"),
        ('hostname:"defence.lk"', "Sri Lanka MoD", "LK"),
        ('hostname:"mod.gov.mm"', "Myanmar MoD", "MM"),
        ('hostname:"cincds.gov.mm"', "Myanmar CINCDS", "MM"),
    ]
    for pivot_domain in (extra_domains or [])[:15]:
        TARGETS.append((f'hostname:"{pivot_domain}"', f"CT-Discovered: {pivot_domain}", domain_to_country(pivot_domain)))
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
                    tech = _fingerprint_technology(str(m.get("product", "")), str(m.get("title", "")))
                    rows.append({
                        "threat_id":     f"T3-ZY-{short_id(ip + str(port))}",
                        "threat_name":   f"ZoomEye Exposed Asset — {label}",
                        "category_code": _domain_scan_category(label),
                        "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                        "source_layer":  "Deep Web", "source": "ZoomEye (Knownsec)",
                        "post_text":     (f"IP: {ip}:{port} | Hostname: {m.get('hostname') or m.get('domain') or ''} | "
                                          f"Product: {m.get('product','')} | Title: {str(m.get('title',''))[:200]} | Target: {label}"),
                        "post_url":      f"https://www.zoomeye.ai/searchResult?q={requests.utils.quote(query)}",
                        "timestamp":     str(m.get("update_time") or m.get("timestamp") or now_utc()), "location": country,
                        "severity":      "HIGH", "confidence": "HIGH",
                        "ioc_type":      "ip", "ioc_value": ip,
                        "tags":          (f"zoomeye;internet-scan;exposed-asset;{label.lower().replace(' ','-')}"
                                          + (f";tech:{','.join(tech)}" if tech else "")),
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
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    TARGETS = [
        ("mod.gov.in", "Indian Ministry of Defence"), ("drdo.gov.in", "DRDO"),
        ("mod.gov.pk", "Pakistan Ministry of Defence"), ("mod.gov.cn", "China Ministry of National Defense"),
        ("modp.gov.pk", "Pakistan Ministry of Defence Production"),
        ("mod.gov.bd", "Bangladesh Ministry of Defence"),
        ("bof.gov.bd", "Bangladesh Ordnance Factory"), ("khulnashipyard.gov.bd", "Bangladesh Khulna Shipyard"),
        ("mod.gov.np", "Nepal Ministry of Defence"),
        ("defence.lk", "Sri Lanka Ministry of Defence"), ("mod.gov.mm", "Myanmar Ministry of Defence"),
        ("cincds.gov.mm", "Myanmar Commander-in-Chief of Defence Services"),
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
                        "category_code": _domain_scan_category(label),
                        "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                        "source_layer":  "Deep Web", "source": "Onyphe (internet scanner)",
                        "post_text":     f"IP: {ip}:{r.get('port','')} | Domain: {domain} | Product: {r.get('product','')} | CVEs: {vuln[:3]}",
                        "post_url":      f"https://www.onyphe.io/asset/{ip}",
                        "timestamp":     str(r.get("@timestamp") or now_utc()),
                        # domain_to_country(domain) not raw geoip — same
                        # hosting-location-vs-org-country fix as
                        # LeakIX/Shodan/Censys this session (see chat);
                        # `domain` is already the known target, no parsing needed.
                        "location":      domain_to_country(domain) if domain_to_country(domain) != "Unknown"
                                          else ((r.get("location") or {}).get("country_name") or "Unknown"),
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
    """T3 — PAID $50/mo at binaryedge.io. Alternative internet scanner.

    Targets were still army.mil/navy.mil/NATO/UK/Germany — left over from
    before this session's India+neighbours narrowing (Parts 1-6). Currently
    inactive (no API key configured) so no live-data risk, but fixed for
    consistency/correctness (see chat)."""
    rows = []
    TARGETS = [
        ("domain:mod.gov.in", "Indian MoD Exposed Services"), ("domain:drdo.gov.in", "DRDO Exposed Services"),
        ("domain:mod.gov.pk", "Pakistan MoD Exposed Services"), ("domain:mod.gov.cn", "China MoD Exposed Services"),
        ("domain:mod.gov.bd", "Bangladesh MoD Exposed Services"), ("domain:mod.gov.np", "Nepal MoD Exposed Services"),
        ("domain:defence.lk", "Sri Lanka MoD Exposed Services"), ("domain:mod.gov.mm", "Myanmar MoD Exposed Services"),
        ("domain:cincds.gov.mm", "Myanmar CINCDS Exposed Services"),
    ]
    headers = {"X-Key": api_key, "User-Agent": "MilOSINT/2.0", "Accept": "application/json"}
    try:
        for query, label in TARGETS:
            target_domain = query.split("domain:", 1)[1].strip() if "domain:" in query else ""
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
                    # domain_to_country() not raw geoip — same fix as
                    # LeakIX/Shodan/Censys/Onyphe this session (see chat).
                    loc = domain_to_country(target_domain)
                    if loc == "Unknown":
                        loc = origin.get("country") or "Unknown"
                    rows.append({
                        "threat_id":     f"T3-BE-{short_id(ip + str(target.get('port','')) + label)}",
                        "threat_name":   f"BinaryEdge — {label}",
                        "category_code": _domain_scan_category(label),
                        "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                        "source_layer":  "Deep Web", "source": "BinaryEdge (internet scanner)",
                        "post_text":     f"IP: {ip}:{target.get('port','')} | {label} | Country: {origin.get('country','Unknown')}",
                        "post_url":      f"https://app.binaryedge.io/services/query?ip={ip}",
                        "timestamp":     str(origin.get("ts") or now_utc()), "location": loc,
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


def fetch_urlscan(api_key: str = "", extra_domains: list = None) -> list:
    """T3 — FREE 1000 searches/day at urlscan.io. Live scans of military domains
    — catches exposed admin panels and phishing pages mimicking military sites.

    extra_domains: CT-discovered subdomains pivoted in from crt.sh (see
    chat) — 1000/day is generous, so capped the same as LeakIX (15).

    Rebuilt the per-row extraction after a live schema check (see chat):
    the public /search/ endpoint is genuinely sparse (no page.ip/server/
    asn/verdicts fields for an anonymous caller — verified against 3 real
    scans, all missing), and the richer /result/{uuid}/ endpoint 403s with
    "You're not logged in!" even for public scans without an API key. So
    this pulls everything that IS free: domainAgeDays/apexDomainAgeDays
    (flags newly-registered look-alike domains and freshly-added
    subdomains — a real phishing-clone signal that was previously
    discarded), the screenshot URL (the guide's "document evidence with
    screenshots" step — nothing else in this tool captures screenshots),
    and request-footprint stats. If api_key is ever set, it additionally
    fetches the detail endpoint for the highest-value hits to pull
    technology signatures via the shared fingerprinter — that path is
    best-effort/schema-unverified (no key was available to test it live)
    and fails silently if the shape doesn't match."""
    # Narrowed to India + neighbouring countries only (per explicit instruction).
    rows = []
    queries = [
        ("page.domain:indianarmy.nic.in", "Indian Army"), ("page.domain:indiannavy.gov.in", "Indian Navy"),
        ("page.domain:mod.gov.in", "Indian MoD"), ("page.domain:drdo.gov.in", "DRDO"),
        ("page.domain:barc.gov.in", "BARC (Nuclear)"), ("page.domain:npcil.nic.in", "NPCIL (Nuclear)"),
        ("page.domain:bsf.gov.in", "BSF (Border Surveillance)"),
        ("page.domain:pakistanarmy.gov.pk", "Pakistan Army"), ("page.domain:mod.gov.pk", "Pakistan MoD"),
        ("page.domain:modp.gov.pk", "Pakistan MoD Production"),
        ("page.domain:paec.gov.pk", "PAEC (Nuclear)"),
        ("page.domain:mod.gov.cn", "China MoD"), ("page.domain:cnnc.com.cn", "CNNC (Nuclear)"),
        ("page.domain:mod.gov.bd", "Bangladesh MoD"), ("page.domain:afd.gov.bd", "Bangladesh Armed Forces Division"),
        ("page.domain:bof.gov.bd", "Bangladesh Ordnance Factory"),
        ("page.domain:khulnashipyard.gov.bd", "Bangladesh Khulna Shipyard"),
        ("page.domain:cddl.gov.bd", "Bangladesh Chittagong Dry Dock"),
        ("page.domain:baec.gov.bd", "BAEC (Nuclear)"),
        ("page.domain:mod.gov.np", "Nepal MoD"), ("page.domain:nepalarmy.mil.np", "Nepal Army"),
        ("page.domain:defence.lk", "Sri Lanka MoD"), ("page.domain:army.lk", "Sri Lanka Army"),
        ("page.domain:mod.gov.mm", "Myanmar MoD"),
        ("page.domain:cincds.gov.mm", "Myanmar CINCDS"),
    ]
    for pivot_domain in (extra_domains or [])[:15]:
        queries.append((f"page.domain:{pivot_domain}", f"CT-Discovered: {pivot_domain}"))
    headers = {"API-Key": api_key} if api_key else {}
    headers["User-Agent"] = "MilOSINT/2.0"
    _SENSITIVE_PATH_PATTERNS = {
        "admin", "login", "portal", "vpn", "api", "kibana", "jenkins", "gitlab",
        "confluence", "jira", "sonarqube", "swagger", "phpmyadmin", "shell", "upload", "config",
    }
    seen_urls: set = set()
    detail_calls = 0
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

                # Domain-age anomaly check — a freely-available field the
                # old code discarded entirely. A young apex domain matching
                # a government/military name pattern is a strong
                # phishing-clone signal; a young subdomain under a much
                # older, legitimate apex just means recently-stood-up
                # infrastructure (informational, not inherently malicious).
                domain_age = page.get("domainAgeDays")
                apex_age = page.get("apexDomainAgeDays")
                is_new_domain = isinstance(apex_age, int) and apex_age < 30
                is_new_subdomain = (isinstance(domain_age, int) and isinstance(apex_age, int)
                                     and domain_age < 90 and (apex_age - domain_age) > 180)

                uuid = r.get("_id", "")
                screenshot = f"https://urlscan.io/screenshots/{uuid}.png" if uuid else ""
                stats = r.get("stats", {})

                sev = "MEDIUM" if is_error else "LOW"
                if is_sensitive:
                    sev = "HIGH"
                if is_new_domain:
                    sev = "CRITICAL"
                tags = f"urlscan;web-exposure;{label.lower().replace(' ', '-')}"
                if is_sensitive:
                    tags += ";sensitive-path"
                if is_error:
                    tags += f";http-{status}"
                if is_new_domain:
                    tags += ";newly-registered-domain;possible-phishing-clone"
                if is_new_subdomain:
                    tags += ";newly-added-subdomain"

                tech_tags = ""
                # Best-effort enrichment — only fires if a free urlscan.io
                # API key is later added to .env; unverified against a
                # live key (none available this session), fails silently.
                if api_key and (is_sensitive or is_new_domain) and detail_calls < 5:
                    detail_calls += 1
                    try:
                        d = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/",
                                          headers=headers, timeout=15)
                        if d.ok:
                            dj = d.json()
                            server_hdr = ""
                            for h in dj.get("data", {}).get("requests", []):
                                resp_headers = (h.get("response", {}).get("response", {}).get("headers", {}) or {})
                                server_hdr = resp_headers.get("Server", resp_headers.get("server", ""))
                                if server_hdr:
                                    break
                            if server_hdr:
                                fp = _fingerprint_technology(server_hdr)
                                if fp:
                                    tech_tags = ";" + ";".join(f"tech:{t}" for t in fp)
                    except Exception as detail_e:
                        log.warning(f"URLScan detail [{uuid}]: {detail_e}")
                tags += tech_tags

                post_text = f"Domain: {page.get('domain','')} | URL: {url[:200]} | Status: {status}"
                if isinstance(domain_age, int):
                    post_text += f" | Domain age: {domain_age}d"
                if stats:
                    post_text += f" | Requests: {stats.get('requests','?')}, IPs: {stats.get('uniqIPs','?')}, Countries: {stats.get('uniqCountries','?')}"
                if screenshot:
                    post_text += f" | Screenshot: {screenshot}"

                rows.append({
                    "threat_id":     f"T3-US-{short_id(url)}",
                    "threat_name":   f"URLScan — {label} Web Exposure" + (" (Possible Phishing Clone)" if is_new_domain else ""),
                    "category_code": _domain_scan_category(label),
                    "category_name": CATEGORY_NAMES[_domain_scan_category(label)],
                    "source_layer":  "Surface Web", "source": "URLScan.io",
                    "post_text":     post_text[:500],
                    "post_url":      f"https://urlscan.io/result/{uuid}/",
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
    # Narrowed to India + neighbouring countries only (per explicit
    # instruction) — Eastern Europe/Middle East/Baltic/Black Sea/Taiwan
    # Strait/Korean Peninsula regions removed. These were a leftover this
    # session's earlier narrowing pass (Parts 1-6) missed entirely — they
    # were still being actively monitored and their "GPS/EW Region
    # Monitored" rows were showing up on the dashboard threat map outside
    # our target countries. Replaced the single broad South Asia box with
    # 4 more specific ones so all 7 target countries get real coverage
    # instead of Bangladesh/Nepal/Sri Lanka/Myanmar being an afterthought
    # inside one huge India/Pakistan/China-centered box.
    regions = [
        # India-Pakistan border (Punjab/Rajasthan/Kashmir/Sindh) + the
        # India-China LAC (Ladakh, Arunachal Pradesh) — both have documented
        # GPS jamming/spoofing incidents.
        {"name": "India-Pakistan-China Border (Kashmir/Ladakh/LAC)", "bbox": (24.0, 69.0, 36.0, 97.0)},
        # Bangladesh + Northeast India border corridor.
        {"name": "Bangladesh & Northeast India Border", "bbox": (20.0, 88.0, 27.0, 93.0)},
        # Myanmar — full territory (the old broad box's lon range stopped at
        # 97, missing roughly a third of Myanmar's actual territory further east).
        {"name": "Myanmar", "bbox": (9.0, 92.0, 28.5, 101.2)},
        # Sri Lanka + southern India (Tamil Nadu/Kerala) + Palk Strait —
        # relevant given repeated Indian security concerns over Chinese
        # research/survey vessel port calls in Sri Lanka.
        {"name": "Sri Lanka & Southern India (Palk Strait)", "bbox": (5.5, 74.0, 14.0, 82.0)},
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
    # "US Military Satellites" ({"US"}) and "Russian Military Satellites"
    # ({"CIS","RU","USSR"}) categories removed — left over from before this
    # session's India+neighbours narrowing (Parts 1-6), a live run just
    # surfaced an actual "US Military Satellites" row (NORAD 69792) that
    # slipped through. GPS/GLONASS/Cosmos kept: those are global navigation
    # constellations and ASAT-debris risks relevant to GPS spoofing/jamming
    # context for every country including our 7, not foreign-military-
    # specific categories the way the two removed ones were.
    FILTERS = [
        ("GPS Constellation", None, ["GPS"], "LOW"),
        ("GLONASS (Russian NavSat)", None, ["GLONASS"], "MEDIUM"),
        ("Cosmos Series (ASAT Risk)", None, ["COSMOS"], "HIGH"),
        ("Chinese Military Satellites", {"PRC"}, None, "HIGH"),
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
                # Track WHY this matched — a global-constellation match
                # (GPS/GLONASS/Cosmos, name_kw) needs a different location
                # than a country-specific match (owner_set). See below.
                matched.append((obj, bool(name_kw)))

            for obj, is_global_constellation in matched[-20:]:
                norad_id = (obj.get("NORAD_CAT_ID") or "").strip()
                name = (obj.get("OBJECT_NAME") or "").strip()
                owner = (obj.get("OWNER") or "Unknown").strip()
                obj_type = (obj.get("OBJECT_TYPE") or "").strip()
                launch = (obj.get("LAUNCH_DATE") or now_utc()).strip()
                is_debris = "DEB" in obj_type.upper() or "DEB" in name.upper()
                sev = "CRITICAL" if (is_debris and base_sev == "HIGH") else base_sev

                # GPS/GLONASS/Cosmos are global-infrastructure risks (relevant
                # to every country including ours, regardless of which
                # country happens to own the specific satellite sampled) —
                # tagging one "Orbit — United States" made it look like a
                # US-specific finding and put non-target countries back on
                # the dashboard map. Only the two owner-gated buckets
                # (Chinese/Indian Military Satellites) get a real country.
                loc = "Global" if is_global_constellation else f"Orbit — {_SATCAT_OWNER_NAME.get(owner.upper(), owner)}"

                # Recently-launched + orbital inclination check (see chat) —
                # inclination between ~8 deg and 100 deg means the ground
                # track's latitude coverage INCLUDES India's ~8-37 deg N
                # band (necessary, not sufficient — doesn't confirm a
                # specific overflight without full SGP4 propagation, which
                # this tool doesn't do). Flagged as "may overfly", never as
                # confirmed targeting — no public OSINT source can establish
                # sensor-pointing intent from TLE data alone.
                extra_tags = ""
                if owner.upper() == "PRC" and not is_debris:
                    try:
                        incl = float((obj.get("INCLINATION") or "").strip())
                        launch_dt = datetime.fromisoformat(launch) if launch and launch != now_utc() else None
                        days_old = (datetime.now(timezone.utc) - launch_dt.replace(tzinfo=timezone.utc)).days if launch_dt else 9999
                        if 8.0 <= incl <= 100.0 and days_old <= 120:
                            extra_tags = ";recently-launched;may-overfly-india-latitude-band"
                    except (ValueError, TypeError):
                        pass

                rows.append({
                    "threat_id":     f"T4-CTK-{short_id(norad_id + name)}",
                    "threat_name":   f"Satellite Intelligence — {label}" + (" (Recent Launch)" if extra_tags else ""),
                    "category_code": "T4", "category_name": CATEGORY_NAMES["T4"],
                    "source_layer":  "Deep Web", "source": "Celestrak SATCAT (US Space Command)",
                    "post_text":     (f"Object: {name} | NORAD: {norad_id} | Owner: {owner} | Type: {obj_type} | "
                                      f"Status: {(obj.get('OPS_STATUS_CODE') or '+').strip()} | "
                                      f"Apogee: {(obj.get('APOGEE') or '').strip()}km | "
                                      f"Perigee: {(obj.get('PERIGEE') or '').strip()}km | "
                                      f"Inclination: {(obj.get('INCLINATION') or '').strip()}° | "
                                      f"Launch: {launch} | Category: {label}"
                                      + (" | Recently launched, orbital inclination allows overflight of India's "
                                         "latitude band (not confirmed targeting — no sensor-pointing data available)"
                                         if extra_tags else "")),
                    "post_url":      f"https://celestrak.org/satcat/search.php?CATNR={norad_id}",
                    "timestamp":     launch, "location": loc,
                    "severity":      "HIGH" if extra_tags and sev not in ("CRITICAL",) else sev,
                    "confidence":    "HIGH",
                    "ioc_type":      "satellite", "ioc_value": f"NORAD-{norad_id}",
                    "tags":          f"satellite;space;{owner.lower()};{obj_type.lower().replace(' ','-')};celestrak{extra_tags}",
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
                # "United States" was wrong — conflates "CISA (a US agency)
                # publishes this catalog" with "this vulnerability is a
                # US-specific threat". A SCADA/critical-infra CVE is a risk
                # wherever the affected vendor's products are deployed,
                # including our 7 target countries — same class of bug as
                # the hosting-location-vs-org-country issue fixed elsewhere
                # this session, just for a data SOURCE's origin instead of
                # a server's hosting location. Found via a live dashboard
                # data audit (see chat) — 15 CISA rows were plotting on the
                # threat map as United States.
                "timestamp":     v.get("dateAdded", now_utc()) + "T00:00:00Z", "location": "Global",
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
                # min_weak=2 (was 1) — OTX pulses aren't country-scoped by
                # query (searched by generic tags like "military"/"apt"), so
                # a single incidental weak-term match let global noise
                # through (e.g. an unrelated pulse mentioning "satellite"
                # once). Matches the min_weak=2 standard used everywhere
                # else in this tool (RSS, Tor). Strong-tier matches (the
                # APT_GROUPS names researched for this region) bypass this
                # threshold entirely, so real regional APT activity still
                # gets through at CRITICAL/HIGH regardless.
                passes, tier, reason = relevance_check(combined, weak_terms=WEAK_MIL_TERMS, min_weak=2)
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
                # item.get("country") is the C2 SERVER's hosting country
                # (IP geolocation) — not who the botnet targets. Commodity
                # malware C2 (Emotet/QakBot/etc, unlike APT-specific
                # infrastructure) gets hosted wherever is cheap/resistant to
                # takedown, unrelated to victim geography — same hosting-
                # location-vs-relevance bug fixed elsewhere this session.
                # Found via a live dashboard data audit (see chat): US/GB/JP
                # were plotting on the threat map from this field.
                "timestamp":     item.get("first_seen") or now_utc(), "location": "Global",
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
    """T7 — FREE, no key. CIRCL CVE API, last 50 advisories, filtered to
    CVSS >= 9.0 AND a military-supply-chain vendor match. Cross-references
    CISA KEV.

    Rewritten after a live schema check (see chat) found CIRCL has migrated
    /api/last/50 entirely to CSAF 2.0 (Common Security Advisory Framework)
    — confirmed 50/50 real entries in a live pull, 0 in the old flat
    {id, summary, cvss} shape this code used to expect. Each item is now a
    full vendor advisory (document.title/tracking, product_tree, etc.) that
    can BUNDLE several CVEs in a vulnerabilities[] array, each with its own
    cve id, notes[] (description), and scores[] (per-product CVSS blocks) —
    not a 1:1 "one item = one CVE" list anymore.

    Under the old parsing, every field lookup (item.get("id")/("summary")/
    ("cvss")) silently returned nothing against the new shape, which combined
    with a real pre-existing bug — `if score_f is not None and score_f < 9.0`
    only rejects a LOW score, so a CVE whose score extraction failed
    entirely (score_f=None) bypassed the >=9.0 gate rather than being
    excluded by it — to let anything with a vendor-term-matching
    description through regardless of actual severity. That's exactly how
    a CVSS-7.5 (High, not Critical) Apache ActiveMQ Artemis DoS got flagged
    as "Critical CVE — Military Supply Chain" (raised in chat): the module
    was fail-open on missing CVSS data instead of fail-closed. Fixed here:
    unresolvable severity is now treated as NOT meeting the bar, not as
    meeting it by default."""
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
        resp = requests.get("https://cve.circl.lu/api/last/50", timeout=45, headers={"User-Agent": "MilOSINT/2.0"})
        resp.raise_for_status()
        advisories = resp.json() or []
        if not isinstance(advisories, list):
            return rows
        seen_cves: set = set()
        for item in advisories:
            if not isinstance(item, dict):
                continue
            doc = item.get("document") or {}
            advisory_title = doc.get("title", "")
            for vuln in (item.get("vulnerabilities") or []):
                if not isinstance(vuln, dict):
                    continue
                cve_id = vuln.get("cve") or ""
                if not cve_id or cve_id in seen_cves:
                    continue

                notes = vuln.get("notes") or []
                desc = next((n.get("text", "") for n in notes if n.get("category") == "description"), "")
                if not desc:
                    desc = next((n.get("text", "") for n in notes if n.get("category") == "summary"), "")
                desc = desc or vuln.get("title", "") or advisory_title

                # A CVE can carry several CVSS blocks (one per affected
                # product/config) — take the highest baseScore found.
                score_f = None
                for s in (vuln.get("scores") or []):
                    if not isinstance(s, dict):
                        continue
                    cvss_block = s.get("cvss_v4") or s.get("cvss_v3") or s.get("cvss_v2")
                    if isinstance(cvss_block, dict) and cvss_block.get("baseScore") is not None:
                        try:
                            bs = float(cvss_block["baseScore"])
                        except (TypeError, ValueError):
                            continue
                        if score_f is None or bs > score_f:
                            score_f = bs

                # Fail-closed: unknown severity does NOT meet a >=9.0 bar.
                if score_f is None or score_f < 9.0:
                    continue

                desc_lower = desc.lower()
                if not _has_any(desc_lower, MIL_VENDOR_TERMS):
                    continue

                seen_cves.add(cve_id)
                in_kev = cve_id in _kev_cves
                severity = "CRITICAL" if (in_kev or score_f >= 9.5) else "HIGH"
                rows.append({
                    "threat_id":     f"T7-CIRCL-{short_id(cve_id)}",
                    "threat_name":   f"Critical CVE — Military Supply Chain{'  ★KEV' if in_kev else ''}",
                    "category_code": "T7", "category_name": CATEGORY_NAMES["T7"],
                    "source_layer":  "Deep Web", "source": "CIRCL CVE API",
                    "post_text":     (f"{cve_id} | CVSS {score_f} | Advisory: {advisory_title[:100]}"
                                      f"{' | IN CISA KEV (actively exploited)' if in_kev else ''} | {desc[:300]}"),
                    "post_url":      f"https://cve.circl.lu/cve/{cve_id}",
                    "timestamp":     str(vuln.get("release_date") or vuln.get("discovery_date") or now_utc()),
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
        # Army/Navy/Air Force Times removed — explicitly US-service-branch
        # outlets (not general/global), out of scope now that this tool is
        # narrowed to India + neighbouring countries only.
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
        # Militarnyi (Ukraine), Opex360 (France), and Asia-Pacific Defence
        # Reporter (Australia) removed — explicitly single-country outlets for
        # non-neighbour countries, out of scope now that this tool is narrowed
        # to India + neighbouring countries only.
        # Data-breach/cybercrime-specific outlets — researched specifically
        # for India/South Asia coverage (see chat), each live-tested (real
        # RSS content-type, real recent article titles, not a redirect/bot-
        # block page — DataBreaches.net and databreachtoday.in were also
        # tried and rejected: the former is gated behind a Cloudflare bot
        # challenge, the latter's every guessed feed URL 404s). General
        # cybercrime outlets, not defence-specific, so min_weak=2 like
        # BleepingComputer/CyberScoop/Hacker News above.
        ("https://thecyberexpress.com/feed", "The Cyber Express", 2),
        ("https://hackread.com/feed/", "Hackread", 2),
        ("https://therecord.media/feed", "The Record", 2),
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


_DEEPDARKCTI_TELEGRAM_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/telegram_threat_actors.md"
_DEEPDARKCTI_RELEVANT_TYPES = ("leak", "breach", "combo", "infostealer", "forum",
                                "ransomware", "database", "stealer", "dump")
_DEEPDARKCTI_COUNTRY_KW = ("india", "pakistan", "kashmir", "bangladesh", "nepal",
                            "lanka", "myanmar", "china", "pla", "hindustan", "bharat")


def _fetch_deepdarkcti_leak_channels(cap: int = 40) -> list:
    """Live-fetches deepfire/deepdarkCTI's community-maintained Telegram
    threat-actor list (see chat — researched as the answer to "how do we
    get S1 marketplace data") instead of hardcoding channel names. That
    list churns constantly — a live pull found 464 already OFFLINE and
    134 EXPIRED out of 965 total entries — so a static copy would go
    stale almost immediately, the same trap RansomWatch's archived repo
    already caught out earlier this session.

    Filters to entries that are actually usable by this tool's free,
    unauthenticated t.me/s/{channel} scraper: status ONLINE/VALID (skips
    OFFLINE/EXPIRED/PRIVATE), and a plain public t.me/{username} link —
    the majority of the list (live-checked: 171 of ~1019 rows) are
    t.me/+{invite-code} private-invite links, which are a fundamentally
    different, unscrapable format (need to actually join via the Telegram
    app/API, not a public HTTP GET).

    Then narrows to channels actually relevant here: either the
    "type of attacks" column mentions leak/breach/combo/infostealer/forum/
    ransomware-type activity (this is what makes them S1 marketplace-
    adjacent instead of generic hacktivist/DDoS chatter), or the channel's
    own name references one of our 7 target countries. This is a much
    broader net than a country-name match alone would give (most
    channel names don't literally name a country), relying on the
    existing relevance_check() gate in the caller to do the actual
    per-post military/target-country filtering — same division of labour
    as Torch (broad uncurated source, narrow content filter)."""
    try:
        resp = requests.get(_DEEPDARKCTI_TELEGRAM_URL, timeout=20,
                             headers={"User-Agent": "MilOSINT/2.0"})
        resp.raise_for_status()
    except Exception as e:
        log.warning(f"deepdarkCTI Telegram list fetch failed: {e} — using static channel list only")
        return []

    channels = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line.startswith("|") or "---" in line or "Telegram|Status" in line:
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) < 3:
            continue
        url, status = parts[0], parts[1]
        name = parts[2] if len(parts) > 2 else ""
        attack_type = parts[3] if len(parts) > 3 else ""
        if status not in ("ONLINE", "VALID"):
            continue
        if not url.startswith("https://t.me/") or "/+" in url:
            continue
        type_l, name_l = attack_type.lower(), name.lower()
        if not (any(k in type_l for k in _DEEPDARKCTI_RELEVANT_TYPES)
                or any(k in name_l for k in _DEEPDARKCTI_COUNTRY_KW)):
            continue
        username = url.rsplit("/", 1)[-1]
        if username:
            channels.append(username)

    channels = list(dict.fromkeys(channels))[:cap]
    log.info(f"deepdarkCTI: {len(channels)} candidate leak/breach Telegram channels selected")
    return channels


def fetch_telegram_channels() -> list:
    """T8/S1 — FREE, no key. Public Telegram channel scraper (t.me/s/{channel}).
    Keyword-density scoring (unchanged from v1 — it was already solid): a
    single high-value hit or several context hits are required, and posts
    with zero forwards on non-OSINT channels are treated as background noise.

    Extended with a second channel set from deepdarkCTI (see
    _fetch_deepdarkcti_leak_channels and chat — this was in direct response
    to "how do we get marketplace data in S1", since generic Tor search
    can't reach registration-gated marketplaces/forums but a lot of real
    leak/database-sale activity has moved to public Telegram channels that
    a plain HTTP scrape CAN reach). Those channels get the shared
    relevance_check() engine (military/government/target-country terms)
    instead of the geopolitical-commentary density scorer below, since
    that scorer's vocabulary (missile, sigint, bundeswehr, ...) targets
    war/conflict news, not leak-marketplace listings — a post like
    "fresh dump: govt.pk emails + passwords, DM to buy" would score 0 on
    it despite being exactly the S1 content this is meant to find."""
    rows = []
    channels = CONFIG.get("telegram_channels") or []
    leak_channels = _fetch_deepdarkcti_leak_channels()
    leak_channel_set = set(c.lower() for c in leak_channels)
    all_channels = list(dict.fromkeys(channels + leak_channels))
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
    for channel in all_channels:
        is_leak_channel = channel.lower() in leak_channel_set
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

                if is_leak_channel:
                    # Leak/breach/marketplace-type channels: the shared
                    # military/target-country relevance engine is the right
                    # gate here, not the geopolitical-commentary word list
                    # below — see fetch_telegram_channels docstring.
                    passes, tier, reason = relevance_check(clean_text, min_weak=2)
                    if not passes:
                        continue
                    if tier == "weak":
                        # Live-tested and found a real false positive here:
                        # a US government-surveillance/privacy news repost
                        # on a ransomware channel matched purely on generic
                        # "government"+"federal" weak terms, with zero
                        # connection to any of our 7 target countries. These
                        # channels post about all kinds of unrelated global
                        # topics (unlike the defense-specific RSS outlets
                        # elsewhere, where an incidental weak-term hit is
                        # much more likely to be genuinely relevant), so
                        # weak-tier alone isn't enough evidence here — also
                        # require a target-country name/adjective. Strong-
                        # tier (military domain/contractor/APT name) is
                        # specific enough to trust without this extra check.
                        has_country = any(kw in text_lower for kws in _COUNTRY_NAME_HINTS.values() for kw in kws)
                        if not has_country:
                            continue
                    density_score = 9 if tier == "strong" else 5
                    label = f"[{reason}"
                else:
                    high_hits = sum(1 for k in _HIGH_VALUE_KW if k in text_lower)
                    context_hits = sum(1 for k in _CONTEXT_KW if k in text_lower)
                    density_score = (high_hits * 3) + context_hits
                    if density_score < 3:
                        continue
                    label = f"[Score:{density_score}"

                fwd_match = re.search(r'(\d[\d,]*)\s*(?:forward|view|repost)', block, re.IGNORECASE)
                fwd_count = int(fwd_match.group(1).replace(",", "")) if fwd_match else 0
                osint_channels = {"osintdefender", "militaryosint", "csis_canada", "intelslava"}
                if not is_leak_channel and fwd_count == 0 and channel.lower() not in osint_channels and density_score < 6:
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
                cat = "S1" if is_leak_channel else "T8"
                rows.append({
                    "threat_id":     f"{cat}-TG-{short_id(msg_url)}",
                    "threat_name":   f"Telegram {'Leak/Marketplace' if is_leak_channel else 'Intelligence'} — @{channel}",
                    "category_code": cat, "category_name": CATEGORY_NAMES[cat],
                    "source_layer":  "Deep Web", "source": f"Telegram @{channel}",
                    "post_text":     f"{label} Fwd:{fwd_count}] {clean_text}",
                    "post_url":      msg_url,
                    "timestamp":     dt_match.group(1) if dt_match else now_utc(),
                    "location":      "Global", "severity": sev,
                    "confidence":    "MEDIUM" if fwd_count >= 20 else "LOW",
                    # Same channel-level-IOC issue as RSS (see fetch_defence_news_rss) —
                    # a per-channel ioc_value caps each channel at 1 row in the
                    # master file forever. Use the actual per-message URL.
                    "ioc_type":      "url", "ioc_value": msg_url,
                    "tags":          (f"telegram;dark-web-marketplace;leak-channel;{channel};deepdarkcti"
                                       if is_leak_channel else
                                       f"telegram;info-ops;{channel};density-{density_score}"),
                })
            time.sleep(CONFIG["request_delay_sec"])
        except Exception as e:
            log.error(f"Telegram error [{channel}]: {e}")
    log.info(f"Telegram: {len(rows)} relevant posts found across {len(all_channels)} channels "
             f"({len(channels)} static + {len(leak_channels)} deepdarkCTI leak-type)")
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


_HOSTNAME_IN_TEXT_RE = re.compile(r'(?:Host|Domain|Hostname)[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')


def correlate_infrastructure(rows: list) -> list:
    """Post-processing correlation pass — the final, most-valuable gap
    flagged in a workflow review (see chat): every finding was an
    independent, disconnected row; nothing ever cross-referenced an IP or
    domain seen by multiple sources, and nothing built a consolidated
    per-organization view the way the guide's final "Correlate" step
    describes (cert -> hostnames -> DNS -> subdomains -> passive service
    discovery -> tech fingerprinting -> infrastructure map). Runs once per
    collection, over just this run's own rows (not the whole historical
    master CSV) — two effects:

    1. Any IP or domain independently confirmed by 2+ different sources
       this run gets tagged "corroborated-multi-source" — a real
       confidence signal no single-source row can carry on its own.
    2. One new summary row per root domain (matched against
       MIL_DOMAIN_SUFFIXES) consolidating every hostname/IP/ASN/
       technology discovered for that organization across every source
       into a single readable map, instead of leaving the reader to
       manually cross-reference dozens of separate rows."""
    ip_sources: dict = {}
    domain_sources: dict = {}
    for r in rows:
        src = r.get("source", "")
        itype = r.get("ioc_type")
        iv = r.get("ioc_value", "")
        if not iv:
            continue
        if itype == "ip":
            ip_sources.setdefault(iv, set()).add(src)
        elif itype == "domain":
            domain_sources.setdefault(iv, set()).add(src)

    for r in rows:
        itype = r.get("ioc_type")
        iv = r.get("ioc_value", "")
        srcs = (ip_sources.get(iv) if itype == "ip" else domain_sources.get(iv)) or set()
        if len(srcs) >= 2:
            existing = r.get("tags") or ""
            if "corroborated-multi-source" not in existing:
                r["tags"] = (existing + ";corroborated-multi-source").lstrip(";")
            r["confidence"] = "HIGH"

    org_map: dict = {}
    for r in rows:
        hostnames = []
        if r.get("ioc_type") == "domain" and r.get("ioc_value"):
            hostnames.append(r["ioc_value"])
        hostnames += _HOSTNAME_IN_TEXT_RE.findall(r.get("post_text", ""))
        for host in hostnames:
            host = host.lower().rstrip(".")
            root = next((s.lstrip(".") for s in MIL_DOMAIN_SUFFIXES
                         if host == s.lstrip(".") or host.endswith("." + s.lstrip("."))), None)
            if not root:
                continue
            entry = org_map.setdefault(root, {"hostnames": set(), "ips": set(), "sources": set(),
                                               "asns": set(), "tech": set(), "country": "Unknown"})
            entry["hostnames"].add(host)
            if r.get("source"):
                entry["sources"].add(r["source"])
            if r.get("location") and r["location"] != "Unknown":
                entry["country"] = r["location"]
            if r.get("ioc_type") == "ip" and r.get("ioc_value"):
                entry["ips"].add(r["ioc_value"])
            for tag in (r.get("tags") or "").split(";"):
                if tag.startswith("asn:"):
                    entry["asns"].add(tag[4:])
                elif tag.startswith("tech:"):
                    entry["tech"].update(t for t in tag[5:].split(",") if t)

    summary_rows = []
    for root, data in org_map.items():
        if not data["sources"]:
            continue
        summary_rows.append({
            "threat_id":     f"T3-MAP-{short_id(root)}",
            "threat_name":   f"Infrastructure Map — {root}",
            "category_code": "T3", "category_name": CATEGORY_NAMES["T3"],
            "source_layer":  "Surface Web", "source": "Correlation (multi-source)",
            "post_text":     (f"Organization: {root} | Hostnames discovered: {len(data['hostnames'])} "
                              f"({', '.join(sorted(data['hostnames'])[:10])}) | "
                              f"IPs: {', '.join(sorted(data['ips'])[:10]) or 'none this run'} | "
                              f"ASN: {', '.join(sorted(data['asns'])) or 'unknown'} | "
                              f"Technologies seen: {', '.join(sorted(data['tech'])) or 'none identified'} | "
                              f"Confirmed by: {', '.join(sorted(s for s in data['sources'] if s))}"),
            "post_url":      "", "timestamp": now_utc(), "location": data["country"],
            "severity":      "MEDIUM", "confidence": "HIGH",
            "ioc_type":      "domain", "ioc_value": root,
            "tags":          f"infrastructure-map;correlation;{root}",
        })
    if summary_rows:
        log.info(f"[POST] Correlation: built {len(summary_rows)} infrastructure maps "
                 f"({sum(1 for r in rows if 'corroborated-multi-source' in (r.get('tags') or ''))} rows corroborated by 2+ sources)")
    return rows + summary_rows


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
    log.info(f"  [T1/T2/T3] Tavily Search (dork-style)  : {status('tavily_api_key')}")
    log.info(f"  [T2] GrayhatWarfare (exposed buckets)  : {status('grayhatwarfare_api_key')}")
    log.info(f"  [T2] IntelligenceX (dark web docs)     : {status('intelx_api_key')}")
    log.info(f"  [T2] LeakIX (exposed services/leaks)   : {status('leakix_api_key')}")
    log.info(f"  [T3] Shodan (network scan)             : {status('shodan_api_key')}")
    log.info(f"  [T3] SecurityTrails (DNS intel)        : {status('securitytrails_api_key')}")
    censys_ready = key_available("censys_api_id") and (
        CONFIG.get("censys_api_id", "").startswith("censys_") or key_available("censys_api_secret"))
    log.info(f"  [T3] Censys (internet scan)            : {'ACTIVE' if censys_ready else 'SKIPPED — set censys_api_id(+secret)'}")
    log.info(f"  [T3] ZoomEye (internet scan)           : {status('zoomeye_api_key')}")
    log.info(f"  [T3] Netlas.io (internet scan)         : {status('netlas_api_key')}")
    log.info(f"  [T3] Onyphe (internet scan)             : {status('onyphe_api_key')}")
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
    if key_available("tavily_api_key"):
        run("[T1/T2/T3] Running dork-style Tavily search queries...", fetch_tavily_search,
            CONFIG["tavily_api_key"])
    # GitHub leaks moved below crt.sh (see [T3]) — it now takes crt.sh's
    # CT-discovered sensitive subdomains as extra pivot targets, same
    # reasoning as LeakIX/Hudson Rock, so it has to run after crt.sh.

    # ── T2 ──
    if key_available("grayhatwarfare_api_key"):
        run("[T2] Searching exposed cloud buckets via GrayhatWarfare...", fetch_grayhatwarfare, CONFIG["grayhatwarfare_api_key"])
    if key_available("intelx_api_key"):
        run("[T2] Fetching document/paste leaks from IntelligenceX...", fetch_intelx_pastes, CONFIG["intelx_api_key"], ".mil")
        run("[T2] Fetching document/paste leaks from IntelligenceX (classified)...", fetch_intelx_pastes,
            CONFIG["intelx_api_key"], "classified defence")
    # LeakIX moved below crt.sh (see [T3]) — it now takes crt.sh's
    # CT-discovered sensitive subdomains as additional pivot targets, so it
    # has to run after crt.sh instead of before it.

    # ── T3 ──
    # crt.sh moved to the FRONT of T3 (was after Shodan/Censys) — its
    # discovered sensitive subdomains now pivot into every actively-working
    # scan module below, not just LeakIX. Workflow cross-checked against a
    # shared OSINT guide, verified live before building (see chat).
    crtsh_rows = run("[T3] Querying crt.sh certificate transparency for military domains...", fetch_crtsh)
    _ct_pivot_domains = list(dict.fromkeys(
        r["ioc_value"] for r in crtsh_rows
        if r.get("ioc_value") and "sensitive-subdomain" in (r.get("tags") or "")
    ))
    if key_available("shodan_api_key"):
        run("[T3] Scanning exposed military infrastructure via Shodan...", fetch_shodan_military,
            CONFIG["shodan_api_key"], _ct_pivot_domains)
    if key_available("securitytrails_api_key"):
        run("[T3] Fetching military DNS intelligence via SecurityTrails...", fetch_securitytrails, CONFIG["securitytrails_api_key"])
    if censys_ready:
        run("[T3] Scanning exposed military network assets via Censys...", fetch_censys,
            CONFIG["censys_api_id"], CONFIG.get("censys_api_secret", ""), _ct_pivot_domains)
    if key_available("leakix_api_key"):
        run("[T2/T3] Searching exposed services and data leaks via LeakIX...", fetch_leakix,
            CONFIG["leakix_api_key"], _ct_pivot_domains)
    if key_available("github_token"):
        run("[T1/T2] Dorking GitHub for leaked military credentials/configs...", fetch_github_leaks,
            CONFIG["github_token"], _ct_pivot_domains)
    run("[T1] Querying Hudson Rock Cavalier for infostealer-compromised .mil accounts...", fetch_hudson_rock,
        _ct_pivot_domains)
    if key_available("zoomeye_api_key"):
        run("[T3] Scanning military infrastructure via ZoomEye...", fetch_zoomeye,
            CONFIG["zoomeye_api_key"], _ct_pivot_domains)
    if key_available("netlas_api_key"):
        run("[T3] Scanning exposed military infrastructure via Netlas.io...", fetch_netlas,
            CONFIG["netlas_api_key"], _ct_pivot_domains)
    if key_available("onyphe_api_key"):
        run("[T3] Scanning military infrastructure via Onyphe...", fetch_onyphe, CONFIG["onyphe_api_key"])
    if key_available("criminal_ip_api_key"):
        run("[T3/T6] Fetching malicious IPs via Criminal IP...", fetch_criminalip, CONFIG["criminal_ip_api_key"])
    if key_available("binaryedge_api_key"):
        run("[T3] Scanning military exposed services via BinaryEdge...", fetch_binaryedge, CONFIG["binaryedge_api_key"])
    urlscan_rows = run("[T3] Scanning military domain web exposures via URLScan.io...", fetch_urlscan,
                        CONFIG.get("urlscan_api_key", ""), _ct_pivot_domains)
    _health_warn = update_module_health(module_health, "URLScan", len(urlscan_rows))
    if _health_warn:
        log.warning(_health_warn)
    # DNS/passive-DNS/ASN enrichment (see chat) — pivot domains first
    # (freshly discovered, highest value), backfilled with our own root
    # domains up to the function's internal 20-hostname cap.
    _dns_targets = list(dict.fromkeys(_ct_pivot_domains + [s.lstrip(".") for s in MIL_DOMAIN_SUFFIXES]))
    run("[T3] Resolving DNS/passive-DNS/ASN data for discovered hostnames...", fetch_dns_records, _dns_targets)

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
    # Hudson Rock moved up to run right after crt.sh (see [T3]) so it can
    # take crt.sh's CT-discovered subdomains as extra pivot targets too.
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

    log.info("[POST] Correlating infrastructure across sources (IP/domain cross-referencing + org map)...")
    all_rows = correlate_infrastructure(all_rows)

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

