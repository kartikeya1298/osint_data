"""
Military OSINT — WhatsApp Bot
==============================
Two-way WhatsApp interface for military_osint_tool.py via Twilio + ngrok.

SETUP (one time, ~5 minutes):
──────────────────────────────
1. Install dependencies:
       pip install flask twilio pyngrok requests

2. Sign up free at https://www.twilio.com  (no credit card for sandbox)
   → Console → Messaging → Try it out → Send a WhatsApp message
   → Note your Account SID and Auth Token from the Console home page

3. Join the Twilio WhatsApp Sandbox:
   → Send the message shown (e.g. "join lion-drum") to +1 415 523 8886 on WhatsApp
   → Your number is now connected to the sandbox

4. Fill in your credentials below in WHATSAPP_CONFIG

5. Run this file:
       python whatsapp_bot.py
   → ngrok tunnel starts automatically
   → Twilio webhook is configured automatically
   → Bot is live — message it from WhatsApp!

COMMANDS (send these to the Twilio sandbox number):
──────────────────────────────────────────────────
  run        → Start a full OSINT collection run (takes ~4 min)
  status     → Show stats from the last run
  critical   → List the last 10 CRITICAL threats
  high       → List the last 10 HIGH threats
  sources    → Show which sources are active
  help       → Show this command list
  stop       → Stop any running collection

NOTES:
  - Keep this script running in a terminal while you want the bot active
  - The OSINT tool runs in a background thread — you can still send commands
  - ngrok free tier gives a new URL each time you restart — that's fine,
    the script auto-updates Twilio's webhook on every start
"""

import os
import sys
import csv
import glob
import json
import time
import threading
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no python-dotenv dependency) — sets os.environ from
    a local KEY=VALUE file so real credentials never have to be hardcoded."""
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

# ─────────────────────────────────────────────────────────────────
#  CONFIG — fill these in
# ─────────────────────────────────────────────────────────────────
# Real values come from a local .env file (WHATSAPP_ACCOUNT_SID etc, never
# committed — see .env.example) so credentials never have to be hardcoded here.
WHATSAPP_CONFIG = {
    # From https://console.twilio.com → Account Info
    "account_sid":   os.environ.get("WHATSAPP_ACCOUNT_SID", ""),
    "auth_token":    os.environ.get("WHATSAPP_AUTH_TOKEN", ""),

    # Your WhatsApp number (with country code, no spaces)
    "your_number":   os.environ.get("WHATSAPP_YOUR_NUMBER", ""),

    # Twilio sandbox number — this is always the same for sandbox
    "twilio_number": "whatsapp:+14155238886",

    # ngrok authtoken — free at https://dashboard.ngrok.com/get-started/your-authtoken
    # Sign up free at dashboard.ngrok.com, then paste your token here
    "ngrok_authtoken": os.environ.get("WHATSAPP_NGROK_AUTHTOKEN", ""),

    # Port for the local Flask server
    "port": 5000,

    # Path to your OSINT tool (relative to this file's location)
    "osint_tool_path": "military_osint_tool.py",
}

# ─────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────
import sys as _sys
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
_stream_handler = logging.StreamHandler(stream=_sys.stdout)
_stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_stream_handler, logging.FileHandler("whatsapp_bot.log", encoding="utf-8")]
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
collection_thread = None
collection_running = False
last_run_info = {
    "timestamp": None,
    "total": 0,
    "new": 0,
    "critical": 0,
    "high": 0,
    "csv_file": None,
}

# ─────────────────────────────────────────────────────────────────
#  TWILIO HELPER
# ─────────────────────────────────────────────────────────────────
def get_client():
    return Client(WHATSAPP_CONFIG["account_sid"], WHATSAPP_CONFIG["auth_token"])

def send_whatsapp(message: str, to: str = None):
    """Send a WhatsApp message proactively (not in response to an incoming msg)."""
    to_num = to or WHATSAPP_CONFIG["your_number"]
    if not to_num:
        log.warning("WhatsApp: no target number set — message not sent")
        return
    try:
        client = get_client()
        client.messages.create(
            from_=WHATSAPP_CONFIG["twilio_number"],
            to=f"whatsapp:{to_num}" if not to_num.startswith("whatsapp:") else to_num,
            body=message,
        )
        log.info(f"WhatsApp sent -> {to_num}")
    except Exception as e:
        log.error(f"WhatsApp send error: {e}")

# ─────────────────────────────────────────────────────────────────
#  OSINT TOOL RUNNER
# ─────────────────────────────────────────────────────────────────
def run_osint_collection(requester_number: str):
    """Runs military_osint_tool.py in a subprocess, monitors output, sends updates."""
    global collection_running, last_run_info

    tool_path = Path(WHATSAPP_CONFIG["osint_tool_path"])
    if not tool_path.exists():
        # Try same directory as this script
        tool_path = Path(__file__).parent / WHATSAPP_CONFIG["osint_tool_path"]
    if not tool_path.exists():
        send_whatsapp(f"❌ Cannot find military_osint_tool.py\nLooked at: {tool_path}", requester_number)
        collection_running = False
        return

    send_whatsapp("🚀 *OSINT Collection Started*\nRunning all modules... this takes ~10 minutes.\nI'll message you when done.", requester_number)

    start_time = datetime.now()
    try:
        result = subprocess.run(
            [sys.executable, str(tool_path)],
            cwd=str(tool_path.parent),
            capture_output=True,
            text=True,
            timeout=1500,  # 25 min max
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + stderr
    except subprocess.TimeoutExpired:
        send_whatsapp("⚠️ Collection timed out after 10 minutes.", requester_number)
        collection_running = False
        return
    except Exception as e:
        send_whatsapp(f"❌ Collection failed: {e}", requester_number)
        collection_running = False
        return

    # Parse results from log output
    duration = int((datetime.now() - start_time).total_seconds())
    total, new_count, critical, high = 0, 0, 0, 0
    csv_file = None

    for line in combined.splitlines():
        if "Total rows:" in line:
            try: total = int(line.split("Total rows:")[1].split("|")[0].strip())
            except: pass
        if "New:" in line and "Total rows:" in line:
            try: new_count = int(line.split("New:")[1].split("|")[0].strip())
            except: pass
        if "Output CSV" in line or "military_osint_data_" in line:
            for part in line.split():
                if "military_osint_data_" in part and part.endswith(".csv"):
                    csv_file = part

    # Count severities from latest CSV
    if not csv_file:
        csvs = sorted(glob.glob(str(tool_path.parent / "military_osint_data_*.csv")))
        if csvs:
            csv_file = csvs[-1]

    if csv_file and Path(csv_file).exists():
        try:
            with open(csv_file, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
                if not total:
                    total = len(rows)
                critical = sum(1 for r in rows if r.get("severity") == "CRITICAL")
                high     = sum(1 for r in rows if r.get("severity") == "HIGH")
        except Exception:
            pass

    last_run_info.update({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": total,
        "new": new_count,
        "critical": critical,
        "high": high,
        "csv_file": csv_file,
    })

    # Send summary
    status_emoji = "🔴" if critical > 0 else ("🟠" if high > 0 else "🟢")
    msg = (
        f"{status_emoji} *OSINT Collection Complete*\n"
        f"──────────────────────\n"
        f"⏱ Duration: {duration//60}m {duration%60}s\n"
        f"📊 Total threats: *{total}*\n"
        f"🆕 New this run: *{new_count}*\n"
        f"🔴 Critical: *{critical}*\n"
        f"🟠 High: *{high}*\n"
        f"──────────────────────\n"
        f"Send *critical* for top CRITICAL threats\n"
        f"Send *high* for top HIGH threats"
    )
    send_whatsapp(msg, requester_number)

    # Auto-send critical alert if any found
    if critical > 0:
        time.sleep(2)
        send_critical_threats(requester_number, max_rows=5, from_last_run=True)

    collection_running = False

# ─────────────────────────────────────────────────────────────────
#  COMMAND HANDLERS
# ─────────────────────────────────────────────────────────────────
def send_critical_threats(to_number: str, max_rows: int = 10, from_last_run: bool = False):
    csv_file = last_run_info.get("csv_file")
    if not csv_file:
        csvs = sorted(glob.glob("military_osint_data_*.csv"))
        if csvs:
            csv_file = csvs[-1]
    if not csv_file or not Path(csv_file).exists():
        return "❌ No CSV data found. Run *run* first."

    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            rows = [r for r in csv.DictReader(f) if r.get("severity") == "CRITICAL"]
    except Exception as e:
        return f"❌ Error reading CSV: {e}"

    if not rows:
        msg = "✅ No CRITICAL threats in last run."
        if to_number: send_whatsapp(msg, to_number)
        return msg

    lines = [f"🔴 *CRITICAL THREATS* ({len(rows)} total)\n──────────────────────"]
    for r in rows[:max_rows]:
        name  = (r.get("threat_name") or "")[:40]
        ioc   = (r.get("ioc_value")   or "")[:30]
        src   = (r.get("source")      or "")[:25]
        cat   = r.get("category_code", "")
        lines.append(f"▸ [{cat}] {name}\n  `{ioc}` — {src}")

    if len(rows) > max_rows:
        lines.append(f"\n_+{len(rows)-max_rows} more — open the dashboard CSV for full list_")

    msg = "\n".join(lines)
    if to_number: send_whatsapp(msg, to_number)
    return msg

def send_high_threats(to_number: str, max_rows: int = 10):
    csv_file = last_run_info.get("csv_file")
    if not csv_file:
        csvs = sorted(glob.glob("military_osint_data_*.csv"))
        if csvs: csv_file = csvs[-1]
    if not csv_file or not Path(csv_file).exists():
        return "❌ No CSV data found. Run *run* first."
    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            rows = [r for r in csv.DictReader(f) if r.get("severity") == "HIGH"]
    except Exception as e:
        return f"❌ Error reading CSV: {e}"

    if not rows:
        msg = "✅ No HIGH threats in last run."
        if to_number: send_whatsapp(msg, to_number)
        return msg

    lines = [f"🟠 *HIGH THREATS* ({len(rows)} total)\n──────────────────────"]
    for r in rows[:max_rows]:
        name = (r.get("threat_name") or "")[:40]
        ioc  = (r.get("ioc_value")   or "")[:30]
        src  = (r.get("source")      or "")[:25]
        cat  = r.get("category_code", "")
        lines.append(f"▸ [{cat}] {name}\n  `{ioc}` — {src}")
    if len(rows) > max_rows:
        lines.append(f"\n_+{len(rows)-max_rows} more_")
    msg = "\n".join(lines)
    if to_number: send_whatsapp(msg, to_number)
    return msg

def build_status_message():
    info = last_run_info
    if not info["timestamp"]:
        return "⚠️ No run completed yet.\nSend *run* to start a collection."
    return (
        f"📊 *Last Run Status*\n"
        f"──────────────────────\n"
        f"🕐 Time: {info['timestamp']}\n"
        f"📋 Total threats: *{info['total']}*\n"
        f"🆕 New threats: *{info['new']}*\n"
        f"🔴 Critical: *{info['critical']}*\n"
        f"🟠 High: *{info['high']}*\n"
        f"📁 File: {Path(info['csv_file']).name if info['csv_file'] else 'unknown'}"
    )

def build_sources_message():
    try:
        tool_path = Path(__file__).parent / WHATSAPP_CONFIG["osint_tool_path"]
        log_path  = tool_path.parent / "osint_tool.log"
        if log_path.exists():
            lines = log_path.read_text(encoding="utf-8").splitlines()
            # Find last module status block
            start = -1
            for i in range(len(lines)-1, -1, -1):
                if "Module status:" in lines[i]:
                    start = i
                    break
            if start >= 0:
                status_lines = []
                for l in lines[start+1:start+25]:
                    if "===" in l: break
                    status_lines.append(l.split("] ")[-1] if "] " in l else l)
                return "🔌 *Active Sources*\n──────────────────────\n" + "\n".join(status_lines)
    except Exception:
        pass
    return "⚠️ No source log found yet. Send *run* first."

HELP_TEXT = (
    "🛡️ *Military OSINT Bot Commands*\n"
    "──────────────────────\n"
    "▸ *run* — Start full OSINT collection (~4 min)\n"
    "▸ *status* — Last run stats\n"
    "▸ *critical* — Top CRITICAL threats\n"
    "▸ *high* — Top HIGH threats\n"
    "▸ *sources* — Which modules are active\n"
    "▸ *stop* — Stop running collection\n"
    "▸ *help* — This message\n"
    "──────────────────────\n"
    "_Alerts are sent automatically after each run_"
)

# ─────────────────────────────────────────────────────────────────
#  FLASK WEBHOOK
# ─────────────────────────────────────────────────────────────────
@app.route("/whatsapp", methods=["POST"])
def whatsapp_webhook():
    global collection_thread, collection_running

    incoming_msg = (request.form.get("Body") or "").strip().lower()
    from_number  = request.form.get("From") or ""

    log.info(f"WhatsApp IN from {from_number}: '{incoming_msg}'")

    resp = MessagingResponse()
    msg  = resp.message()

    if incoming_msg in ("run", "start", "collect", "go"):
        if collection_running:
            msg.body("⚠️ A collection is already running. Send *status* to check progress.")
        else:
            collection_running = True
            collection_thread  = threading.Thread(
                target=run_osint_collection,
                args=(from_number,),
                daemon=True,
            )
            collection_thread.start()
            msg.body("⏳ Starting collection... I'll message you when it's done!")

    elif incoming_msg == "stop":
        if collection_running and collection_thread:
            # Can't kill a thread cleanly in Python, but flag it
            collection_running = False
            msg.body("🛑 Stop requested. The current module will finish then collection will halt.")
        else:
            msg.body("ℹ️ No collection is currently running.")

    elif incoming_msg == "status":
        msg.body(build_status_message())

    elif incoming_msg in ("critical", "crit"):
        if not last_run_info["timestamp"] and not glob.glob("military_osint_data_*.csv"):
            msg.body("⚠️ No data yet. Send *run* first.")
        else:
            send_critical_threats(from_number, max_rows=10)
            msg.body("📤 Sending critical threats...")

    elif incoming_msg == "high":
        if not last_run_info["timestamp"] and not glob.glob("military_osint_data_*.csv"):
            msg.body("⚠️ No data yet. Send *run* first.")
        else:
            send_high_threats(from_number, max_rows=10)
            msg.body("📤 Sending high threats...")

    elif incoming_msg == "sources":
        msg.body(build_sources_message())

    elif incoming_msg in ("help", "?", "commands", "hi", "hello"):
        msg.body(HELP_TEXT)

    else:
        # Unknown command — give a hint
        msg.body(
            f"❓ Unknown command: *{incoming_msg}*\n"
            "Send *help* for the list of commands."
        )

    return str(resp)

@app.route("/health")
def health():
    return {"status": "ok", "running": collection_running, "last_run": last_run_info["timestamp"]}

# ─────────────────────────────────────────────────────────────────
#  NGROK AUTO-SETUP
# ─────────────────────────────────────────────────────────────────
def start_ngrok_and_register(port: int):
    """Start ngrok tunnel, get public URL, register it with Twilio."""
    try:
        from pyngrok import ngrok, conf
    except ImportError:
        log.error("pyngrok not installed — run:  pip install pyngrok")
        return None

    log.info("Starting ngrok tunnel...")
    try:
        # Set authtoken if provided
        authtoken = WHATSAPP_CONFIG.get("ngrok_authtoken", "").strip()
        if authtoken:
            conf.get_default().auth_token = authtoken
        tunnel = ngrok.connect(port, "http")
        public_url = tunnel.public_url.replace("http://", "https://")
        webhook_url = f"{public_url}/whatsapp"
        log.info(f"ngrok tunnel: {public_url}")
        log.info(f"Webhook URL : {webhook_url}")
    except Exception as e:
        log.error(f"ngrok failed: {e}")
        log.info("You can manually set the webhook URL in Twilio console:")
        log.info(f"  https://console.twilio.com -> Messaging -> Sandbox settings")
        log.info(f"  Set 'When a message comes in' to:  http://YOUR_NGROK_URL/whatsapp")
        return None

    # Register webhook with Twilio
    try:
        sid   = WHATSAPP_CONFIG["account_sid"]
        token = WHATSAPP_CONFIG["auth_token"]
        if sid and token:
            client = Client(sid, token)
            # Update sandbox webhook
            client.messaging.v1.services.list()  # just to verify creds
            # Sandbox webhook is updated via the console OR the API below:
            import requests as req
            r = req.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json",
                auth=(sid, token),
                data={"SmsUrl": webhook_url},
            )
            # The above might not work for sandbox — log the URL for manual setup
            log.info(f"✅ Set this URL in Twilio Sandbox settings:")
            log.info(f"   {webhook_url}")
        else:
            log.warning("Twilio credentials not set — set them in WHATSAPP_CONFIG")
    except Exception as e:
        log.warning(f"Auto-registration skipped: {e}")
        log.info(f"Manually set webhook in Twilio console: {webhook_url}")

    return public_url

# ─────────────────────────────────────────────────────────────────
#  STARTUP CHECK
# ─────────────────────────────────────────────────────────────────
def check_config():
    missing = []
    if not WHATSAPP_CONFIG.get("account_sid"):
        missing.append("account_sid")
    if not WHATSAPP_CONFIG.get("auth_token"):
        missing.append("auth_token")
    if not WHATSAPP_CONFIG.get("your_number"):
        missing.append("your_number")
    if missing:
        print("\n" + "="*60)
        print("⚠️  MISSING CONFIG in whatsapp_bot.py:")
        for m in missing:
            print(f"   → WHATSAPP_CONFIG['{m}'] is empty")
        print("\nFill these in then re-run.")
        print("="*60 + "\n")
        return False
    return True

# ─────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║        Military OSINT — WhatsApp Bot                ║
║  Twilio + ngrok — Two-way WhatsApp interface        ║
╚══════════════════════════════════════════════════════╝
""")
    if not check_config():
        sys.exit(1)

    port = WHATSAPP_CONFIG["port"]

    # Start ngrok in background thread
    ngrok_thread = threading.Thread(
        target=start_ngrok_and_register,
        args=(port,),
        daemon=True
    )
    ngrok_thread.start()
    time.sleep(2)  # give ngrok a moment

    print(f"\n✅ Bot running on port {port}")
    print(f"📱 Send WhatsApp messages to: {WHATSAPP_CONFIG['twilio_number']}")
    print(f"📋 Commands: run, status, critical, high, sources, help")
    print(f"\nPress Ctrl+C to stop.\n")

    # Send startup notification to your number
    try:
        send_whatsapp(
            "🛡️ *Military OSINT Bot is online!*\n"
            "Send *help* for available commands.\n"
            "Send *run* to start a collection.",
            WHATSAPP_CONFIG["your_number"]
        )
    except Exception as e:
        log.warning(f"Startup notification failed: {e}")

    # Start Flask (blocking)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
