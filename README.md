@'
# Windows Monitor (Mini-EDR)

Ein leichtgewichtiger, transparenter **Endpoint-Monitor für Windows 10/11**, geschrieben in Python.  
Das Tool läuft im Hintergrund und erkennt **neue Prozesse**, **neue ausgehende Netzwerkverbindungen** sowie **potenziellen Kamera-/Mikrofonzugriff** anhand geladener DLLs.

Ziel ist **Sichtbarkeit**, nicht Magie:  
Das Skript macht verdächtige Aktivitäten sichtbar und meldet sie aktiv – ähnlich wie ein stark vereinfachtes EDR (Endpoint Detection & Response).

---

## 🎯 Ziele des Projekts

- Laufende **Überwachung im Hintergrund**
- Keine Blackbox, **vollständig auditierbar**
- Keine Cloud, **keine Datenabflüsse**
- Funktioniert auf **Windows 11**
- Fokus auf:
  - neue Prozesse
  - neue Netzwerkziele
  - Medienzugriffe (Kamera/Mikrofon, indirekt)

---

## 🧠 Funktionsprinzip

### 1. Baseline-Lernphase
- Dauer: konfigurierbar (z. B. 5 Minuten oder 24 Stunden)
- Erfasst:
  - laufende Prozesse
  - beobachtete Ziel-IPs
- Keine Alerts, nur Lernen

### 2. Überwachungsphase
Nach Ablauf der Baseline:

- Neuer Prozess → Alert
- Neue Ziel-IP → Alert
- Kamera-/Media-DLLs → Sofort-Alert
- Whitelist filtert bekannte Aktivitäten

---

## 🔍 Überwachung im Detail

### Prozesse
- Jeder neu gestartete Prozess wird erkannt
- Vergleich mit Baseline + Whitelist

### Netzwerk
- Überwachung ausgehender Verbindungen
- Neue IP-Ziele werden gemeldet

### Kamera / Mikrofon (indirekt)
Erkennung über typische Media-DLLs:
- avicap32.dll
- mf.dll
- ksproxy.ax

---

## 📁 Projektstruktur

windows-monitor/
 ├─ src/
 │   ├─ monitor.py
 │   ├─ baseline.json
 │   ├─ whitelist.json
 │   └─ alerts.log
 ├─ .venv/
 └─ README.md

---

## ⚙️ Konfiguration

Wichtige Parameter in `monitor.py`:

CHECK_INTERVAL – Prüfintervall  
BASELINE_DURATION – Dauer der Lernphase

---

## ▶️ Start
Python als Administrator starten:
```
python src/monitor.py
```

## ▶️ Log
```
Get-Content src/alerts.log -Wait
```
---

## ⚠️ Grenzen

- Keine Kernel-Überwachung
- Keine Rootkit-Erkennung
- Reiner User-Mode

---

## 🚀 Mögliche Erweiterungen

- SHA-256-Hashing unbekannter Prozesse
- Windows-Dienst
- Log-Rotation
- Regel-Engine
- Web-Dashboard

---

## 🧠 Philosophie

Sichtbarkeit statt blinder Sicherheit.

---

## 📜 Lizenz

Open Source, frei nutzbar.
'@ | Out-File README.md -Encoding utf8
