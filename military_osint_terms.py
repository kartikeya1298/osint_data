"""
Hardcoded term lists, domain suffixes, contractor/APT/vendor names, technology
fingerprint signatures, and other curated reference data used by the relevance
engine and per-source modules in military_osint_tool_v2.py.

Extracted verbatim (values and rationale comments unchanged) from that file so
this data can be reviewed/tuned as its own unit, separate from collection and
correlation logic. Every name here is imported back into military_osint_tool_v2
and used exactly as before -- this file has no behaviour of its own.
"""
import re


# ────────────────────────────────────────────────────────────────────────────
# Category taxonomy
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Military domain suffixes (relevance engine "domain" tier)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Strong military terms (relevance engine "strong" tier)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Named defence contractors (relevance engine "strong" tier)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# APT / threat-actor group aliases (relevance engine "strong" tier)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Network/OT/enterprise vendor terms (relevance engine "strong" tier)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Weak military terms (relevance engine "weak" tier, needs 2+ hits)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Negative terms (hard-reject unless a domain match overrides)
# ────────────────────────────────────────────────────────────────────────────
NEGATIVE_TERMS = {
    "icon", "medal", "clipart", "clip art", "wallpaper", "meme", "logo",
    "favicon", "thumbnail", "wordpress theme", "google dork", "dork list",
    "ghdb", "google hacking database", "wordlist", "word list",
    "cheatsheet", "cheat sheet", "awesome-", "bug bounty", "bugbounty",
    "pentest", "hack the box", "tryhackme", "ctf writeup", "writeup",
    "how to hack",
}


# ────────────────────────────────────────────────────────────────────────────
# Domain -> country mapping (dashboard location field)
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Technology fingerprint signatures
# ────────────────────────────────────────────────────────────────────────────
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
    # Webmin/MiniServ -- added after a live Shodan review (see chat) found
    # a Sri Lanka MoD host with port 10000 open running MiniServ and it
    # fingerprinted as nothing at all: Webmin has real unauthenticated-RCE
    # history (CVE-2019-15107) so an admin panel on the open internet is
    # exactly the "named product, real CVE track record" case this dict
    # exists for, same reasoning as the Zimbra entry above.
    "miniserv": "Webmin", "webmin": "Webmin",
    "elasticsearch": "Elasticsearch", "kibana": "Kibana", "opensearch": "OpenSearch",
    "mongodb": "MongoDB", "redis": "Redis", "postgres": "PostgreSQL",
    "mysql": "MySQL", "rabbitmq": "RabbitMQ", "jenkins": "Jenkins",
    "gitlab": "GitLab", "grafana": "Grafana", "prometheus": "Prometheus",
    "minio": "MinIO", "phpmyadmin": "phpMyAdmin", "kubernetes": "Kubernetes",
    "docker": "Docker",
    # Mail/collaboration platforms -- added after a live cert-intel review
    # (see chat) found a Bangladeshi defense-facility's webmail portal
    # (mail.cddl.gov.bd, Zimbra, build 2023-09-21 -- ~3 years stale against
    # real 2023/2024 Zimbra CVEs) went completely unflagged: this dict
    # covered infrastructure/devops tooling and network appliances, but
    # nothing in the webmail/groupware space at all, so there was no way
    # for a finding like this to ever get picked up regardless of how
    # interesting it was.
    "zimbra": "Zimbra", "outlook web app": "Exchange/OWA", "owa/": "Exchange/OWA",
    "exchange server": "Exchange/OWA", "roundcube": "Roundcube",
    "confluence": "Confluence", "atlassian": "Confluence/Jira",
    "sharepoint": "SharePoint", "vmware vcenter": "vCenter", "vsphere": "vCenter",
    "wp-content": "WordPress", "wordpress": "WordPress",
    "drupal": "Drupal", "joomla": "Joomla",
}


# ────────────────────────────────────────────────────────────────────────────
# High-value tech (severity-floor escalation list)
# ────────────────────────────────────────────────────────────────────────────
# Products worth escalating severity for on their own, independent of the
# per-module file-exposure/directory-listing checks -- these are all named
# enterprise targets with real, recurring, serious CVE histories (account
# takeover, RCE, auth bypass), where knowing the EXACT product+version is
# itself an actionable lead regardless of whether anything else is also
# exposed. Deliberately excludes generic infrastructure (nginx, Apache,
# MySQL, Redis, Elasticsearch, ...) -- "we found what web server this is"
# isn't a signal the way "we found a 3-year-stale Zimbra build" is.
_HIGH_VALUE_TECH = {
    "Zimbra", "Exchange/OWA", "Confluence", "Confluence/Jira", "SharePoint",
    "vCenter", "Citrix", "F5 BIG-IP", "Fortinet", "Palo Alto", "Cisco ASA",
    "Pulse Secure", "Ivanti", "SonicWall", "Check Point", "Webmin",
}


# ────────────────────────────────────────────────────────────────────────────
# GitHub secret-content detection patterns
# ────────────────────────────────────────────────────────────────────────────
# ── GitHub secret-content verification (used by fetch_github_leaks) ────────
_SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["\']?[A-Za-z0-9+/_\-\.]{10,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(r'-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'),
]


# ────────────────────────────────────────────────────────────────────────────
# Dork/GHDB filename markers
# ────────────────────────────────────────────────────────────────────────────
_DORK_FILE_PATTERNS = {"dork", "ghdb", "wordlist", "payload-list", "cheatsheet", "cheat-sheet"}


# ────────────────────────────────────────────────────────────────────────────
# Noise repo name patterns (GitHub relevance filter)
# ────────────────────────────────────────────────────────────────────────────
_NOISE_REPO_PATTERNS = {
    "awesome-", "osint-", "-dork", "ghdb", "-pentest",
    "hacking-", "security-hardening", "cheatsheet", "wordlist",
    "bugbounty", "-recon", "exploit-db", "payload-", "ctf-",
    "pagodo", "googledork", "shodan-dork", "censys-",
    "hack-the-box", "tryhackme", "writeup",
}


# ────────────────────────────────────────────────────────────────────────────
# Doc file extensions/names (GitHub relevance filter)
# ────────────────────────────────────────────────────────────────────────────
_DOC_EXTS = {".md", ".rst", ".txt", ".adoc", ".wiki"}
_DOC_NAMES = {"readme", "changelog", "contributing", "license", "authors",
              "history", "notice", "todo", "faq", "news"}


# ────────────────────────────────────────────────────────────────────────────
# GrayhatWarfare tiered bucket-search queries
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# GrayhatWarfare skip extensions (non-sensitive media/code)
# ────────────────────────────────────────────────────────────────────────────
_GHW_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".svg",
    ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".mp3", ".wav",
    ".aac", ".ogg", ".ico", ".cur", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".map",
}


# ────────────────────────────────────────────────────────────────────────────
# GrayhatWarfare sensitive extensions (exposure-worthy)
# ────────────────────────────────────────────────────────────────────────────
_GHW_SENSITIVE_EXTS = {
    ".env", ".sql", ".db", ".bak", ".config", ".conf", ".key", ".pem",
    ".csv", ".xlsx", ".xls", ".docx", ".doc", ".pdf", ".json", ".zip",
    ".7z", ".rar", ".ini", ".yaml", ".yml", ".tf", ".kubeconfig",
    ".sqlite", ".mdb", ".ppk",
}


# ────────────────────────────────────────────────────────────────────────────
# GrayhatWarfare negative filename terms
# ────────────────────────────────────────────────────────────────────────────
_GHW_NEG_FILENAME_TERMS = {
    "icon", "medal", "clipart", "wallpaper", "meme", "logo",
    "thumbnail", "favicon", "banner", "badge",
    # Found live (see chat): a "webcrawler.fra1.digitaloceanspaces.com"
    # bucket matched every avic.com STRONG query, but it's a generic
    # third-party web-scraping/monitoring service's own cache of AVIC's
    # already-PUBLIC website and investor-relations pages -- not AVIC's
    # own infrastructure, and not an exposure of anything confidential.
    # "webcrawler"/"crawler_results" catch that bucket's own naming
    # convention specifically; "investor_reports"/"investor_relations"
    # catch the broader pattern (any company's public disclosures re-
    # hosted by a monitoring tool) since public-by-definition documents
    # aren't a leak regardless of which bucket happens to store them.
    "webcrawler", "crawler_results", "investor_reports", "investor_relations",
    # Found live (see chat): apparel/retail e-commerce listings sharing a
    # bucket naming scheme ("...-navy-pajamas-for-him-for-her-lk-...")
    # that happened to word-match a STRONG query's literal country-code
    # suffix (".lk") in an unrelated context. These terms don't
    # legitimately co-occur with a military/defence file.
    "pajamas", "sleep-set", "sleepset", "outfits", "allover-print",
}


# ────────────────────────────────────────────────────────────────────────────
# Ransomware.live tier-1 domains / tier-2 contractors
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Ransomware.live target-country codes
# ────────────────────────────────────────────────────────────────────────────
_RANSOMWARE_LIVE_TARGET_COUNTRIES = {
    "IN": "India", "PK": "Pakistan", "CN": "China", "BD": "Bangladesh",
    "NP": "Nepal", "LK": "Sri Lanka", "MM": "Myanmar",
}


# ────────────────────────────────────────────────────────────────────────────
# Tier-1 domain fragments + country TLD/name hint tables
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Shodan port->service map + ccTLD second-level labels
# ────────────────────────────────────────────────────────────────────────────
# Port -> human-readable service, so `tags` says what's actually open
# (mail server, admin panel, DNS...) instead of leaving the reader to dig
# a bare port number out of post_text. Added in the same noise-review pass
# as the checks below (see chat).
_SHODAN_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "smtp-submission", 993: "imaps", 995: "pop3s",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 9200: "elasticsearch", 10000: "webmin-panel",
    27017: "mongodb",
}

# ccTLD second-level labels seen across our actual target list (gov.in,
# gov.pk, gov.bd, gov.np, gov.mm, gov.cn, ...) -- not a full public-suffix-
# list implementation, just enough that _registrable_base("mail.afd.gov.bd")
# returns "afd.gov.bd" (the organisation) rather than "gov.bd" (which would
# then "confirm" against ANY Bangladeshi government host) or "bd" (which
# would confirm against anything in the country).
_CCTLD_SECOND_LEVEL = {"gov", "mil", "ac", "co", "net", "org", "edu"}


# ────────────────────────────────────────────────────────────────────────────
# CelesTrak commercial-satellite exclude list + owner-code map
# ────────────────────────────────────────────────────────────────────────────
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


# ────────────────────────────────────────────────────────────────────────────
# Malware/adversary indicator tags + adversary TLDs/URL targets
# ────────────────────────────────────────────────────────────────────────────
_MIL_MALWARE_TAGS = {
    "cobalt strike", "cobaltstrike", "metasploit", "emotet", "qakbot", "qbot",
    "bazarloader", "bazar", "icedid", "apt", "nation-state", "wiper",
    "industroyer", "triton", "trisis", "lazarus", "turla", "sandworm",
    "apt28", "apt29", "shadowpad", "plugx",
}
_ADVERSARY_TLDS = {".ru", ".cn", ".kp", ".ir", ".by"}
_MIL_URL_TARGETS = {".mil", ".gov", "dod.", "army.", "navy.", "pentagon", "nato"}


# ────────────────────────────────────────────────────────────────────────────
# deepdarkCTI channel relevance filter (types + country keywords)
# ────────────────────────────────────────────────────────────────────────────
_DEEPDARKCTI_RELEVANT_TYPES = ("leak", "breach", "combo", "infostealer", "forum",
                                "ransomware", "database", "stealer", "dump")
_DEEPDARKCTI_COUNTRY_KW = ("india", "pakistan", "kashmir", "bangladesh", "nepal",
                            "lanka", "myanmar", "china", "pla", "hindustan", "bharat")


