#!/usr/bin/env python3
import concurrent.futures
import logging
import os
import re
import socket
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

# ------------------------------------------------------------
# Load Secrets from .env
# ------------------------------------------------------------
load_dotenv()

FONNTE_TOKEN = os.getenv("FONNTE_TOKEN")
FONNTE_TARGETS = os.getenv("FONNTE_TARGETS", "").split(",")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
MONITORED_USERS = [
    u.strip() for u in os.getenv("MONITORED_USERS", "angel").split(",") if u.strip()
]

# ------------------------------------------------------------
# Basic Config
# ------------------------------------------------------------
HOST = socket.gethostname()
LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
POLL_INTERVAL = 1.0

FAIL_WINDOW_SEC = 300  # Time window for counting brute force attempts
FAIL_THRESHOLD = 3  # Trigger alert when >= this many fails in window
DEDUP_TTL = 60  # Prevent repeating duplicate alerts within N seconds
ALERT_SESSION_OPEN = False  # Usually too noisy → keep off

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ------------------------------------------------------------
# Regexes to identify SSH events
# ------------------------------------------------------------
RE_SUCCESS = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

RE_FAIL = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

RE_SESSION = re.compile(r"session opened for user\s+(?P<user>\S+)", re.IGNORECASE)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def send_whatsapp(message: str):
    if not FONNTE_TOKEN or not FONNTE_TARGETS:
        logging.warning("Fonnte not configured, skipping send.")
        return

    for target in FONNTE_TARGETS:
        try:
            requests.post(
                "https://api.fonnte.com/send",
                headers={"Authorization": FONNTE_TOKEN},
                data={"target": target, "message": message},
                timeout=10,
            )
            logging.info("Sent alert to %s", target)
        except requests.RequestException as e:
            logging.warning("Fonnte send error: %s", e)


def gemini_analysis(text: str, timeout: float = 10.0):
    """Ask Gemini for short risk evaluation."""
    if not GEMINI_API_KEY:
        logging.debug("Gemini API key not configured")
        return "-"

    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)

        prompt = (
            "Berikan analisis singkat terhadap kejadian keamanan berikut.\n"
            "Format:\n"
            "*Tingkat Risiko:* <Low|Medium|High>\n"
            "*Alasan:* <1-3 kalimat>\n\n"
            f"Peristiwa: {text}"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(model.generate_content, prompt)
            resp = future.result(timeout=timeout)
            result = (resp.text or "-").strip()
            logging.debug("Gemini analysis success")
            return result
    except concurrent.futures.TimeoutError:
        logging.warning("Gemini analysis timeout after %ss", timeout)
        return "-"
    except Exception as e:
        logging.warning("Gemini analysis failed: %s - %s", type(e).__name__, str(e))
        return "-"


def format_message(event: dict, analysis: str) -> str:
    msg_type = event["type"]
    user = event.get("user", "-")
    ip = event.get("ip", "-")
    ts = event["ts"]

    if msg_type == "success":
        header = "SSH LOGIN SUCCESS"
    elif msg_type == "fail":
        header = "SSH LOGIN FAILED"
    elif msg_type == "session":
        header = "SESSION OPENED"
    else:
        header = f"SSH EVENT: {msg_type}"

    body = f"""*{header}*

Username: {user}
IP: {ip}
Time: {ts}

---ANALISIS OLEH GEMINI LLM---
{analysis}"""

    return body


def parse_line(line: str):
    now = utc_timestamp()

    if m := RE_SUCCESS.search(line):
        return {
            "type": "success",
            "user": m.group("user"),
            "ip": m.group("ip"),
            "raw": line,
            "ts": now,
        }

    if m := RE_FAIL.search(line):
        return {
            "type": "fail",
            "user": m.group("user"),
            "ip": m.group("ip"),
            "raw": line,
            "ts": now,
        }

    if ALERT_SESSION_OPEN and (m := RE_SESSION.search(line)):
        return {"type": "session", "user": m.group("user"), "raw": line, "ts": now}

    return None


# ------------------------------------------------------------
# Tail Log (with journald fallback)
# ------------------------------------------------------------
def iter_logs():
    files = [p for p in LOG_PATHS if os.path.exists(p)]

    if files:
        for p in files:
            logging.info("Reading log from %s", p)
        gens = [tail_file(p) for p in files]
    else:
        logging.info("Using journald fallback")
        gens = [journald_stream()]

    while True:
        for gen in gens:
            line = next(gen, None)
            yield line


def tail_file(path):
    pos = 0
    initialized = False

    while True:
        try:
            with open(path, "r", errors="ignore") as f:
                if not initialized:
                    f.seek(0, os.SEEK_END)
                    pos = f.tell()
                    initialized = True
                else:
                    f.seek(pos)

                chunk = f.read()
                if chunk:
                    pos = f.tell()
                    for line in chunk.splitlines():
                        yield line

        except FileNotFoundError:
            pass

        time.sleep(POLL_INTERVAL)
        yield None


def journald_stream():
    try:
        proc = subprocess.Popen(
            ["journalctl", "-f", "-o", "cat", "-u", "ssh", "-u", "sshd"],
            stdout=subprocess.PIPE,
            text=True,
        )
        while True:
            line = proc.stdout.readline().strip()
            yield line if line else None
    except:
        while True:
            time.sleep(POLL_INTERVAL)
            yield None


# ------------------------------------------------------------
# Main Monitor Loop
# ------------------------------------------------------------
def main():
    logging.info("Starting SSH monitor on %s", HOST)

    fail_records = defaultdict(deque)
    last_sent = {}

    for line in iter_logs():
        if not line:
            continue

        event = parse_line(line)
        if not event:
            continue

        # Filter: only monitor specific usernames (ignore bots)
        if MONITORED_USERS and event.get("user") not in MONITORED_USERS:
            continue

        key = (event["type"], event.get("user"), event.get("ip"))
        now = time.time()

        # DEDUP
        if key in last_sent and now - last_sent[key] < DEDUP_TTL:
            logging.debug(
                "[%s] [%s] Skipped (dedup)",
                event.get("ip", "-"),
                event.get("user", "-"),
            )
            continue

        # Track fail attempts
        if event["type"] == "fail":
            q = fail_records[event["ip"]]
            q.append(now)

            while q and (now - q[0]) > FAIL_WINDOW_SEC:
                q.popleft()

            if len(q) >= FAIL_THRESHOLD:
                # Brute force detected - send alert
                logging.warning(
                    "[%s] [%s] BRUTE FORCE DETECTED - %d attempts in %ds",
                    event["ip"],
                    event["user"],
                    len(q),
                    FAIL_WINDOW_SEC,
                )
                summary = (
                    f"{len(q)} gagal login dari {event['ip']} dalam {FAIL_WINDOW_SEC}s"
                )
            else:
                # Single failed login - skip alert
                logging.info(
                    "[%s] [%s] Failed login attempt (%d/%d)",
                    event["ip"],
                    event["user"],
                    len(q),
                    FAIL_THRESHOLD,
                )
                continue

        else:
            if event["type"] == "success":
                logging.info(
                    "[%s] [%s] Successful SSH login", event["ip"], event["user"]
                )
            elif event["type"] == "session":
                logging.info("[%s] [%s] Session opened", event["ip"], event["user"])
            summary = f"{event['type']} {event.get('user')} {event.get('ip', '-')}"

        # AI Evaluation
        analysis = gemini_analysis(summary)

        # Send Alert
        send_whatsapp(format_message(event, analysis))

        last_sent[key] = now


if __name__ == "__main__":
    main()
