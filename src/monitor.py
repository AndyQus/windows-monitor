import psutil
import time
import json
import os
from datetime import datetime
from winotify import Notification

# ================== CONFIG ==================

BASELINE_FILE = "src/baseline.json"
WHITELIST_FILE = "src/whitelist.json"
LOG_FILE = "src/alerts.log"

CHECK_INTERVAL = 5          # Sekunden
# BASELINE_DURATION = 60 * 60 * 24  # 24 Stunden (für Tests z. B. 300)
BASELINE_DURATION = 300  # 5 Minuten


SUSPICIOUS_DLL_KEYWORDS = [
    "avicap",
    "mf.dll",
    "ksproxy",
    "camera",
    "microphone"
]

# ---------- Ensure log file exists ----------

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        pass


# ============================================


# ---------- Utils ----------

def now():
    return datetime.now().isoformat(timespec="seconds")

def notify(title, msg):
    Notification(
        app_id="Windows Monitor",
        title=title,
        msg=msg,
        duration="short"
    ).show()

def log(event):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(event)

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------- Init ----------

baseline = load_json(BASELINE_FILE, {
    "started": None,
    "processes": [],
    "network": []
})

whitelist = load_json(WHITELIST_FILE, {
    "processes": [],
    "ips": []
})

if not baseline["started"]:
    baseline["started"] = time.time()
    save_json(BASELINE_FILE, baseline)

learning = (time.time() - baseline["started"]) < BASELINE_DURATION

if learning:
    notify("Monitor", "Baseline-Lernphase aktiv")
else:
    notify("Monitor", "Überwachung aktiv")

known_pids = set()
known_connections = set()


# ---------- Monitoring ----------

def inspect_dlls(proc):
    try:
        for m in proc.memory_maps():
            path = m.path.lower()
            for kw in SUSPICIOUS_DLL_KEYWORDS:
                if kw in path:
                    event = {
                        "time": now(),
                        "type": "media_access",
                        "process": proc.name(),
                        "pid": proc.pid,
                        "dll": m.path
                    }
                    log(event)
                    notify("🎥 Medienzugriff", proc.name())
                    return
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


def check_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.pid in known_pids:
                continue
            known_pids.add(proc.pid)

            name = proc.name()

            if learning:
                if name not in baseline["processes"]:
                    baseline["processes"].append(name)
                    save_json(BASELINE_FILE, baseline)
                continue

            if name in whitelist["processes"]:
                continue

            if name not in baseline["processes"]:
                event = {
                    "time": now(),
                    "type": "new_process",
                    "process": name,
                    "pid": proc.pid
                }
                log(event)
                notify("⚠ Neuer Prozess", name)
                inspect_dlls(proc)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def check_network():
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue

        key = (conn.pid, conn.raddr.ip)
        if key in known_connections:
            continue
        known_connections.add(key)

        try:
            proc = psutil.Process(conn.pid)
            ip = conn.raddr.ip

            if learning:
                if ip not in baseline["network"]:
                    baseline["network"].append(ip)
                    save_json(BASELINE_FILE, baseline)
                continue

            if ip in whitelist["ips"]:
                continue

            if ip not in baseline["network"]:
                event = {
                    "time": now(),
                    "type": "new_connection",
                    "process": proc.name(),
                    "pid": proc.pid,
                    "remote": f"{ip}:{conn.raddr.port}"
                }
                log(event)
                notify("🌐 Neue Verbindung", f"{proc.name()} → {ip}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


# ---------- Main Loop ----------

print("Monitor läuft – STRG+C beendet")

try:
    while True:
        check_processes()
        check_network()
        time.sleep(CHECK_INTERVAL)

except KeyboardInterrupt:
    notify("Monitor", "Überwachung beendet")
    print("Monitor sauber beendet")
