<p align="center">
  <img src="pic.png" alt="CyberOps Banner" width="100%">
</p>

# CYBEROPS — Real Cyber Investigation System

A lightweight cyber security toolkit built with Python and Flask to simulate real-world incident investigation workflows.

---

## 🚀 What This Project Does

CYBEROPS combines multiple cyber security tasks into one system:

* Analyze authentication logs
* Scan network ports
* Capture live packets
* Check malicious IPs

All through a simple web interface.

---

## 🧠 Features

| Module                 | Description                                           |
| ---------------------- | ----------------------------------------------------- |
| 🔐 Auth Log Analyzer   | Detects failed/success logins from Windows Event Logs |
| 🌐 Port Scanner        | Scans open ports using real socket connections        |
| 📡 Packet Capture      | Captures live packets using Scapy                     |
| 🧠 Threat Intelligence | Checks IPs via AbuseIPDB + local blacklist            |

---

## 🏗️ Project Structure

```
cybercrime_real/
├── app.py              # Flask app (routes + UI)
├── log_scanner.py      # Log analysis + port scanning
├── packet_capture.py   # Packet sniffing (Scapy)
├── threat_intel.py     # IP reputation checks
├── requirements.txt
```

---

## ⚙️ Setup Instructions

### 1. Install Npcap (Required for packet capture)

https://npcap.com/#download
✔ Enable **WinPcap API-compatible mode**

---

### 2. Install dependencies

Run as Administrator:

```
pip install -r requirements.txt
```

---

### 3. (Optional) AbuseIPDB API Key

https://www.abuseipdb.com/register

Set environment variable:

```
set ABUSEIPDB_KEY=your_key_here
```

---

### 4. Run the app

```
python app.py
```

Open:

```
http://127.0.0.1:5000
```

---

## 🧪 How to Use

1. Open dashboard
2. Choose module:

   * Auth Log → view login attempts
   * Port Scan → scan target IP
   * Packets → capture live traffic
   * Threat Intel → check IP reputation

---

## ⚠️ Notes

* Requires **Administrator privileges**
* Packet capture only works with Npcap installed
* Designed for **educational and lab use only**

---

## 🎯 Tech Stack

* Python
* Flask
* Scapy
* PyWin32
* Socket Programming

---

## 💀 Reality

This is a **learning-focused cyber security project**, not a full enterprise tool.

---

## 📌 Future Improvements

* Multi-threaded fast port scanning
* Better service detection
* Linux support
* UI enhancements

---

## 👤 Author

Gaurav Kumar
GitHub: https://github.com/ohnogaurav
