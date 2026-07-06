# Military Cyber Threat OSINT — Source Map
> Mapped to the Military Cyber Threat OSINT Category Framework (T1–T8, S1)
> Sources are organised into three layers: **Surface Web**, **Deep Web**, and **Dark Web (via aggregators only)**

---

## Source Layer Definitions

| Layer | What it means | Access method |
|---|---|---|
| **Surface Web** | Indexed, publicly accessible | Direct URL / API |
| **Deep Web** | Not indexed by search engines but publicly accessible | Direct URL, login, or API key |
| **Dark Web** | .onion / underground platforms | **Never directly — only via commercial CTI aggregator APIs** |

---

## T1 — Personnel & Identity Threats
*Military personnel data, credentials, biometrics, geolocation*

### Surface Web
- **HaveIBeenPwned** (haveibeenpwned.com/API v3) — credential breach lookup
- **LinkedIn** — military personnel OSINT, unit identification via profiles
- **Twitter/X API** — soldiers posting geolocation, unit info
- **GitHub** — accidental pushes of .mil credentials, config files
- **Pastebin / Ghostbin / Rentry.co** — credential dump pastes
- **Telegram public channels** — credential sharing, data dumps
- **Google Dorks** — `site:*.mil filetype:xls`, `intext:"soldier" filetype:csv`

### Deep Web
- **DeHashed** (dehashed.com) — breach database search, API available
- **IntelligenceX** (intelx.io) — breach data, dark web archives, .mil email search
- **Snusbase** — credential/identity leak database API
- **LeakCheck.net** — aggregated breach data API
- **Melissa Data / Spokeo API** — identity resolution for OSINT correlation
- **Shodan** — exposed military cloud/SSO endpoints (`org:"US Army"`, `org:"Ministry of Defence"`)

### Dark Web (via aggregators)
- **Recorded Future Identity Intelligence** — monitors dark web for .mil credential leaks
- **Flashpoint** — underground forum posts selling military personnel data
- **Intel 471** — criminal marketplace monitoring for military identity data
- **DarkOwl Vision** — dark web full-text search for `.mil`, military unit names
- **Cybersixgill** — real-time dark web collection on credential markets

---

## T2 — Data & Document Leakage
*Classified docs, defence DB leaks, vendor breaches, R&D, procurement data*

### Surface Web
- **WikiLeaks** (wikileaks.org) — historical classified document archive
- **DDoSecrets** (ddosecrets.com) — leaked government/military datasets
- **DocumentCloud** (documentcloud.org) — FOIA'd defence documents
- **MuckRock** (muckrock.com) — FOIA request tracker, released documents
- **GitHub** — leaked source code, config files from defence contractors
  - Search: `org:DoD`, `filename:.env "mil"`, `path:secret military`
- **Pastebin** / **ControlC** / **Ghostbin** — document fragment dumps
- **Archive.org Wayback Machine** — cached versions of removed defence pages

### Deep Web
- **FOIA.gov** — US federal FOIA release library
- **DTIC** (dtic.mil) — Defense Technical Information Center, unclassified R&D reports
- **SAM.gov** — US procurement contracts, vendor information, contract awards
- **USASpending.gov API** — defence spending, vendor names, contract details
- **FPDS-NG** (fpds.gov) — Federal Procurement Data System, full contract history
- **SEC EDGAR** — defence contractor financial filings, subsidiary disclosures
- **IntelligenceX** — indexes paste sites, dark web dumps, and document leaks
- **Pipl / BeenVerified** — vendor identity resolution
- **Google Patents / USPTO** — defence R&D patent filings
- **IEEE Xplore / DTIC** — military technology research papers

### Dark Web (via aggregators)
- **Recorded Future** — classified document leak alerts on dark web
- **Flashpoint** — tracks defence vendor breach announcements on forums
- **DarkOwl** — indexes breach dump sites, mirrors, and paste mirrors
- **Cybersixgill** — early warning on procurement/R&D data being sold

---

## T3 — Communication & Network Attacks
*Secure comms interception, military VPN, PKI, satellite ground stations*

### Surface Web
- **CISA Advisories** (cisa.gov/news-events/cybersecurity-advisories) — official alerts on military network compromises
- **NVD / NIST CVE** (nvd.nist.gov) — vulnerabilities in military communication products
- **MITRE ATT&CK** (attack.mitre.org) — TTP mapping for comms attacks
- **Shodan** (shodan.io) — exposed military VPN endpoints, satellite modems
  - Queries: `org:"US Army"`, `product:"Cisco AnyConnect"`, `port:1194 country:US`
- **Censys** (censys.io) — TLS certificate search for `.mil` domains
- **BinaryEdge** — internet scan data, exposed defence endpoints
- **GreyNoise** — mass scanner/attacker IP intelligence

### Deep Web
- **Shodan Facets API** — programmatic scan of military ASNs
- **Censys Search API** — certificate transparency for `.mil`
- **FOFA.info** — Chinese internet scan platform, useful for adversary infra hunting
- **ZoomEye** — Knownsec internet scan, strong coverage of satellite/ICS exposed systems
- **RiskIQ / Microsoft Defender TI** — passive DNS, military domain infrastructure
- **SecurityTrails** — DNS history, subdomain enumeration for `.mil` domains
- **Shodan InternetDB** — fast IP reputation lookup

### Dark Web (via aggregators)
- **Flashpoint** — forum discussions on military VPN exploits
- **Intel 471** — actor intelligence on comms interception tools
- **Recorded Future** — dark web chatter on PKI/certificate theft

---

## T4 — Navigation, Positioning & Electronic Warfare
*GPS spoofing, jamming, radar/satellite attacks, EW activity*

### Surface Web
- **GPSJam.org** — real-time GPS jamming/spoofing heatmap (crowd-sourced ADS-B data)
- **C4ADS GPS Spoofing Tracker** (c4ads.org) — documented spoofing incidents
- **ADSBExchange** (adsbexchange.com) — unfiltered ADS-B flight tracking; detect spoofing anomalies
- **MarineTraffic / VesselFinder** — AIS vessel tracking; detect GPS manipulation at sea
- **OpenStreetMap + Wikimapia** — ground truth comparison for location anomalies
- **EW News / Jane's** — open source electronic warfare reporting
- **Defense One / Breaking Defense** — GPS/EW incident reporting

### Deep Web
- **FAA NOTAM database** (notams.aim.faa.gov) — GPS test/interference notices
- **ITU Radiocommunication** (itu.int) — satellite frequency filings, interference reports
- **FCC ULS database** — licensed transmitter geolocation (useful for EW triangulation)
- **Satnogs Network** (satnogs.org) — open satellite observation network
- **Space-Track.org** (space-track.org) — US Space Command satellite catalog, TLE data
- **Celestrak** (celestrak.org) — orbital elements for satellite tracking
- **NOAA GOES Viewer** — satellite signal monitoring

### Dark Web (via aggregators)
- **Recorded Future** — dark web references to GPS/EW tool sales
- **Flashpoint** — underground market listings for EW equipment/exploits

---

## T5 — Critical Infrastructure Attacks
*Defence SCADA/ICS, manufacturing, logistics, C2, nuclear facilities*

### Surface Web
- **CISA ICS-CERT Advisories** (cisa.gov/ics) — official ICS/SCADA vulnerability alerts
- **NVD CVE** — CVEs tagged `CWE` for ICS products (Siemens, Rockwell, Schneider)
- **MITRE ATT&CK for ICS** (attack.mitre.org/matrices/ics) — TTP framework for OT attacks
- **Dragos Year in Review** (dragos.com) — annual ICS threat report
- **Claroty Research Blog** — ICS vulnerability research
- **SCADAfence Blog** — OT security incidents
- **ICS-CERT RSS Feed** — real-time ICS advisories

### Deep Web
- **Shodan ICS Filters** — `tag:ics`, `product:Modbus`, `product:DNP3`, `country:XX`
- **ZoomEye ICS** — Chinese ICS internet scan, adversary infrastructure
- **FOFA** — `protocol=modbus` `protocol=s7` for exposed PLCs
- **NIST SP 800-82** database references — ICS security control mapping
- **NRC.gov ADAMS** — US Nuclear Regulatory Commission public document system
- **DoE OSTI** (osti.gov) — Department of Energy scientific/nuclear research

### Dark Web (via aggregators)
- **Recorded Future** — dark web C2 infrastructure sales, ICS exploit listings
- **Flashpoint** — ransomware group announcements targeting defence manufacturers
- **Cybersixgill** — early-warning on ICS/SCADA exploit availability

---

## T6 — Malware & Advanced Cyber Attacks
*Ransomware, DDoS, APTs, nation-state ops, cyber espionage, zero-days*

### Surface Web
- **MalwareBazaar** (bazaar.abuse.ch) — malware sample database, API
- **URLhaus** (urlhaus.abuse.ch) — malicious URL feed
- **VirusTotal** (virustotal.com) — file/URL/domain/IP reputation, API
- **ANY.RUN** (any.run) — interactive malware sandbox
- **Hybrid Analysis** (hybrid-analysis.com) — automated malware sandbox
- **Triage / Hatching** (tria.ge) — advanced malware sandbox
- **OTX AlienVault** (otx.alienvault.com) — open threat exchange, IOC feeds
- **MISP Project** (misp-project.org) — threat intelligence sharing platform
- **Malpedia** (malpedia.caad.fkie.fraunhofer.de) — malware family encyclopedia
- **APT Groups & Operations** (apt.threattracking.com) — APT group tracker
- **CISA Known Exploited Vulnerabilities** (cisa.gov/known-exploited-vulnerabilities-catalog)

### Deep Web
- **Recorded Future Malware Intelligence** — APT actor tracking API
- **Mandiant Threat Intelligence** (mandiant.com/advantage) — APT attribution reports
- **CrowdStrike Adversary Intelligence** — nation-state actor profiles
- **Secureworks CTU** — Counter Threat Unit APT research
- **Group-IB Threat Intelligence** — Eastern European/Russian APT focus
- **ESET Threat Intelligence** — APT campaign tracking
- **MITRE CTI GitHub** (github.com/mitre/cti) — STIX/TAXII format ATT&CK data
- **Phishtank** — defence-targeted phishing domains

### Dark Web (via aggregators)
- **Flashpoint** — ransomware group communications, victim announcements
- **Intel 471** — cybercriminal actor intelligence, forum monitoring
- **Recorded Future** — zero-day exploit listings, APT C2 infrastructure
- **DarkOwl** — ransomware leak sites, data dump monitoring
- **Cybersixgill** — real-time dark web collection on APT tool sales

---

## T7 — Emerging & Autonomous System Threats
*Supply chain, drone/UAV, weapon systems, autonomous platforms*

### Surface Web
- **GitHub** — drone firmware vulnerabilities, UAV exploit PoCs
  - Search: `DJI exploit`, `UAV firmware vulnerability`, `supply chain backdoor`
- **DEF CON / Black Hat talks** — drone/autonomous system security research
- **CVE for embedded systems** — NVD filtered by vendor (DJI, Autel, Parrot)
- **RAND Corporation** (rand.org) — autonomous weapons policy/threat research
- **CNAS** (cnas.org) — Center for New American Security, autonomous systems
- **Bellingcat** (bellingcat.com) — open source drone/weapon system tracking
- **Oryx Blog** — visual confirmation of military equipment losses (Ukraine/conflicts)

### Deep Web
- **DTIC** — US military autonomous systems R&D reports
- **DARPA Broad Agency Announcements** (darpa.mil/work-with-us/opportunities)
- **DoD SBIR/STTR database** (sbir.defense.gov) — defence startup contracts, tech areas
- **IEEE Xplore** — autonomous weapon systems academic research
- **USPTO / EPO Patent Search** — adversary nation drone/autonomous tech patents
- **Import Genius / Panjiva** — supply chain shipment data, component origins

### Dark Web (via aggregators)
- **Recorded Future** — supply chain compromise discussions, component fraud
- **Flashpoint** — underground markets for drone components/exploits

---

## T8 — Information Operations & Influence Threats
*Deepfakes, PSYOP, disinformation, social media influence, hack-and-leak*

### Surface Web
- **Twitter/X API v2** — narrative tracking, bot detection, coordinated inauthentic behaviour
- **DFRLab** (digitalresearchlab.org) — Atlantic Council influence op investigations
- **Stanford Internet Observatory** (cyber.fsi.stanford.edu/io) — disinformation research
- **EU DisinfoLab** (disinfo.eu) — EU-focused influence operation tracking
- **EUvsDisinfo** (euvsdisinfo.eu) — pro-Kremlin disinformation database
- **GDI** (disinformationindex.org) — Global Disinformation Index
- **Botometer** (botometer.osome.iu.edu) — Twitter account bot scoring API
- **CrowdTangle** (Meta) — public Facebook/Instagram content monitoring
- **TikTok Research API** — video/account data for influence op detection
- **Facebook Ad Library** (facebook.com/ads/library) — political/influence ad tracking

### Deep Web
- **RAND Disinformation Database** (rand.org/research/projects/truth-decay.html)
- **MediaCloud** (mediacloud.org) — news media analysis platform, API
- **GDELT Project** (gdeltproject.org) — global news event database, API
- **NewsAPI** — aggregated news monitoring for defence disinformation events
- **Wayback Machine CDX API** — detect removed disinformation content
- **Social Links Pro** — social media OSINT API (Telegram, VK, Twitter)
- **Maltego Transforms** — entity graph analysis for influence networks

### Dark Web (via aggregators)
- **Flashpoint** — PSYOP campaign planning forums, hack-and-leak staging
- **Recorded Future** — tracking disinformation infrastructure, state actor campaigns
- **DarkOwl** — monitoring for deepfake tools, synthetic media services

---

## S1 — Dark Web Marketplaces & Forums (Monitoring Layer)
*Defence data sales, stolen credentials, zero-day listings, military fraud*

> **Important:** This section covers **passive monitoring** of dark web activity through commercial CTI platforms. Direct access to illegal marketplaces is not part of a legitimate OSINT tool.

### Commercial CTI Aggregators (Primary)
| Platform | Focus | API |
|---|---|---|
| **Recorded Future** | Broadest dark web coverage, structured intelligence | Yes (REST) |
| **Flashpoint** | Criminal forum expertise, ransomware groups | Yes (REST) |
| **Intel 471** | Underground actor intelligence, credential markets | Yes (REST) |
| **DarkOwl Vision** | Dark web full-text search, data breach detection | Yes (REST) |
| **Cybersixgill** | Real-time dark web stream, early warning | Yes (REST) |
| **Kela Cyber** | Focused on cybercriminal underground | Yes |
| **Mandiant Advantage** | APT + dark web, government-grade | Yes |

### Paste & Leak Site Monitoring (Semi-Surface)
- **IntelligenceX** (intelx.io) — indexes dark web pastes, breach mirrors, Tor sites
- **Dehashed API** — breach data aggregator
- **LeakIX** — internet scan + exposed data detection
- **GrayhatWarfare** (grayhatwarfare.com) — exposed cloud bucket / file detection

### Telegram Intelligence
- **TGStat** (tgstat.com) — Telegram channel analytics
- **Telemetr.io** — channel/group search and monitoring
- **KNIME + Telegram API** — bulk channel scraping pipeline
- **Combot** — group analytics

### Forum & Market Monitoring (via aggregators only)
Platforms monitored by the above CTI vendors:
- XSS.is, Exploit.in — Russian-language vulnerability/exploit forums
- BreachForums mirrors — credential and data dump listings
- Ramp, RAMP2 — ransomware affiliate programme discussions
- Russian Market — credential stealer log marketplace
- Genesis Market (legacy) — compromised device/session marketplace

---

## Recommended API Stack for Tool Build

```
LAYER 1 — Real-time alerts
  ├── CISA API (free)
  ├── NVD CVE API (free)
  ├── OTX AlienVault API (free)
  └── HaveIBeenPwned API (paid tier for bulk)

LAYER 2 — Deep scanning
  ├── Shodan API (paid)
  ├── Censys API (paid)
  ├── IntelligenceX API (paid)
  └── SecurityTrails API (paid)

LAYER 3 — Dark web monitoring
  ├── Recorded Future API (enterprise)
  ├── Flashpoint API (enterprise)
  └── DarkOwl API (enterprise)

LAYER 4 — Specialised
  ├── VirusTotal API — malware (free + paid)
  ├── GDELT API — disinformation (free)
  ├── GPSJam data — EW/GPS (free)
  └── Space-Track.org — satellite (free, registration required)
```

---

*Next step: Define the tool architecture — query routing, alert logic, and output schema per category.*
