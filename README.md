# Military Cyber Threat OSINT Collection Tool

Automated OSINT (open-source intelligence) collection tool that gathers
military- and defence-related cyber threat intelligence from ~40 free and
paid data sources -- certificate transparency logs, exposed cloud storage
buckets, dark web search, ransomware leak-site monitoring, satellite
tracking, CVE/vulnerability feeds, Telegram channels, and defence news --
across 13+ countries. Every result passes through a shared relevance-filtering
engine before being kept, so results are scoped to actual military/government/
defence-contractor domains and named APT/contractor entities, not generic
keyword matches.

A browsable dashboard and an optional desktop GUI app are included.

## What's in this repo

| File | Purpose |
|---|---|
| `military_osint_tool_v2.py` | The collection tool itself |
| `military_osint_master.csv` | The compiled, deduplicated dataset (2,400+ findings) |
| `osint_dashboard.html` | Standalone dashboard -- the dataset is embedded in the file, opens directly in any browser |
| `osint_gui_app.py` / `control_panel.html` | Desktop app wrapper (view results + trigger new collections) |
| `Launch_OSINT_GUI.bat` | Windows shortcut to launch the desktop app |
| `merge_osint_csv.py` | Standalone utility to merge older CSV exports (the main tool now does this automatically) |
| `whatsapp_bot.py` | Optional two-way WhatsApp interface (Twilio + ngrok) for triggering runs remotely |
| `Military_OSINT_Source_Map.md` | Reference notes on data sources |
| `.env.example` | Template for API keys -- copy to `.env` and fill in your own |
| `requirements.txt` | Python dependencies |
| `generate_summary_report.py` | Generates the PDF summary report from the master CSV |
| `Military_OSINT_Summary_Report.pdf` | Findings summary -- category/severity breakdowns, top sources, notable findings |

## Just want to browse the data?

No setup needed. Open `osint_dashboard.html` in any browser -- the dataset
is embedded directly in the file.

## Running a fresh collection yourself

### 1. Requirements
Python 3.9+. Only two third-party packages are needed (everything else is
standard library):
```bash
pip install -r requirements.txt
```

### 2. Get the code
```bash
git clone https://github.com/kartikeya1298/osint_data.git
cd osint_data
```

### 3. Add your own API keys
All keys were stripped out before this repo went public. Copy `.env.example`
to a new file named `.env` in the same folder, then paste in keys for
whichever sources you want active:
```bash
cp .env.example .env
```
Every key is optional -- leaving one blank just skips that module at
runtime. Free signups exist for most of them (GitHub, LeakIX, GrayHatWarfare,
ZoomEye, OTX AlienVault, VirusTotal, abuse.ch/ThreatFox).

### 4. Run a collection
```bash
python military_osint_tool_v2.py
```
New findings are deduplicated against everything collected before and merged
into `military_osint_master.csv`. The dashboard refreshes automatically after
every run.

### 5. View the results
- Open `osint_dashboard.html` directly in a browser, **or**
- Run `python osint_gui_app.py` for the desktop app, which can also trigger a
  collection run on demand from its control panel.

### 6. Optional: dark web search
The Torch dark-web search module needs a local Tor SOCKS5 proxy running on
port 9050 (Tor Browser or a standalone Tor daemon). Without it, that one
module is skipped and everything else still runs normally.

### 7. Re-filter an existing CSV
```bash
python military_osint_tool_v2.py --clean input.csv output.csv
```
Re-applies the current relevance rules to an older export without
re-collecting from scratch -- useful after a filtering bug fix.

## Notes

- This tool only queries free/public APIs and licensed data sources. No
  unauthorized access, exploitation, or scanning of non-public systems is
  performed.
- `seen_threats_v2.json`, `weekly_snapshot_v2.json`, `module_health_v2.json`,
  and `api_quota_v2.json` are operational state files the tool uses for
  deduplication and health tracking across runs -- don't delete them if you
  want continuity with the existing dataset.
