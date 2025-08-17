# 🍯 Honeypot Alert System

A comprehensive intrusion detection and alerting system designed to detect, log, and notify about unauthorized access attempts using honeypot technology.

---

## 📦 Overview

The **Honeypot Alert System** is a Python-based security tool that simulates vulnerable services on various network ports to attract and monitor potential attackers. When an intrusion attempt is detected, it logs the event and sends real-time alerts via multiple channels.

This system is ideal for:
- Monitoring network threats
- Gathering threat intelligence
- Enhancing network security posture
- Educational purposes in cybersecurity

---

## 🔧 Key Features

### 🕵️‍♂️ Intrusion Detection
- Simulates real services (SSH, FTP, HTTP, etc.) on open ports
- Listens on both **TCP** and **UDP** protocols
- Captures connection metadata and transmitted data

### 🚨 Multi-Channel Alerts
- **Email alerts** with HTML formatting
- **Webhook integration** (Slack, Discord, SIEM, etc.)
- **Console logging** with severity levels
- Detailed intrusion information

### 🗃️ Data Logging & Storage
- SQLite database for persistent storage
- Logs include:
  - Timestamp
  - Source IP and port
  - Target port and protocol
  - Transmitted data
  - Threat level
  - Geographic information (via IP geolocation)

### 🧠 Threat Intelligence
- Automatic **threat level analysis** (LOW/MEDIUM/HIGH)
- Pattern matching for suspicious payloads
- Detection of common attack vectors:
  - SQL injection attempts
  - XSS patterns
  - Credential scanning
  - System file access
- IP geolocation using public APIs

---

## 🛠️ Installation

### Prerequisites
- Python 3.6+
- Standard libraries: `socket`, `threading`, `logging`, `sqlite3`, `json`, `smtplib`, `requests`

### Install Dependencies
```bash
pip install requests
```

> ✅ No other external packages required.

---

## ⚙️ Configuration

A configuration file (`honeypot_config.json`) manages all settings. If not present, a default one is created.

### Sample Configuration
```json
{
    "ports": [22, 23, 21, 80, 443, 25, 135, 445, 3389],
    "protocols": ["TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP"],
    "email": {
        "enabled": true,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "from_email": "honeypot@yourcompany.com",
        "to_email": "security@yourcompany.com",
        "username": "your_email@gmail.com",
        "password": "your_app_password"
    },
    "webhook": {
        "enabled": true,
        "url": "https://your-webhook-url.com/alerts"
    }
}
```

### Create Sample Config
```bash
python honeypot.py --create-config
```
> Creates `sample_config.json` – customize and rename to `honeypot_config.json`.

---

## 🚀 Usage

### Start the Honeypot System
```bash
python honeypot.py
```

Or with custom config:
```bash
python honeypot.py --config /path/to/custom_config.json
```

### Stop the System
Press `Ctrl+C` to gracefully shut down all services.

---

## 🌐 Supported Services & Ports

The system can simulate services on any port. Common defaults include:

| Port | Service | Risk Level |
|------|--------|------------|
| 21   | FTP    | High |
| 22   | SSH    | High |
| 23   | Telnet | High |
| 25   | SMTP   | Medium |
| 53   | DNS    | Medium |
| 80   | HTTP   | High |
| 135  | RPC    | High |
| 443  | HTTPS  | High |
| 445  | SMB    | High |
| 3389 | RDP    | High |

> All services return **fake banners** to appear legitimate.

---

## 📊 Sample Alert Output

### Console Log
```
2023-12-05 14:23:18,456 - WARNING - 🚨 INTRUSION DETECTED 🚨
Time: 2023-12-05T14:23:18.456
Source IP: 45.34.12.99
Target Port: 22
Protocol: TCP
Threat Level: HIGH
Data: SSH-2.0-libssh...
==================================================
```


### Webhook Payload
```json
{
  "alert_type": "honeypot_intrusion",
  "timestamp": "2023-12-05T14:23:18.456",
  "source_ip": "45.34.12.99",
  "threat_level": "HIGH",
  "details": {
    "source_port": 54321,
    "target_port": 22,
    "protocol": "TCP",
    "data": "SSH-2.0-libssh...",
    "geographic_info": "Moscow, Russia (ISP: Example Telecom)"
  }
}
```

---

## 🗃️ Database Schema

All intrusion attempts are stored in `honeypot.db`:

```sql
CREATE TABLE intrusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER,
    target_port INTEGER,
    protocol TEXT,
    data TEXT,
    threat_level TEXT,
    geographic_info TEXT
);
```

### Query Examples
```sql
-- View all high-risk attempts
SELECT * FROM intrusions WHERE threat_level = 'HIGH';

-- Count attempts by IP
SELECT source_ip, COUNT(*) FROM intrusions GROUP BY source_ip ORDER BY COUNT(*) DESC;

-- Recent HTTP attempts
SELECT * FROM intrusions WHERE target_port = 80 ORDER BY timestamp DESC LIMIT 10;
```

---

## 🧠 Threat Analysis

The system uses multiple heuristics to determine threat levels:

| Factor | Weight |
|-------|--------|
| Suspicious keywords (SQLi, XSS, etc.) | +2 |
| High-risk port | +1 |
| Large payload size (>1KB) | +1 |

**Threat Levels:**
- **HIGH**: Score ≥ 4
- **MEDIUM**: Score ≥ 2
- **LOW**: Score < 2

---

## 🌍 Geolocation

Uses [ip-api.com](http://ip-api.com) to resolve attacker location:
- City
- Country
- ISP (Internet Service Provider)

> ✅ No API key required for basic usage.

---

## 🛡️ Security & Best Practices

### For Production Use:
- Run on a **dedicated machine** or VM
- Use **firewall rules** to limit exposure
- Enable alerts only on necessary channels
- Rotate email credentials regularly
- Monitor logs for false positives

### Email Security
- Use **App Passwords** instead of regular passwords (e.g., Gmail)
- Never commit credentials to version control
- Consider using a dedicated email account

---

## 📁 File Structure
```
honeypot/
├── honeypot.py               # Main application
├── honeypot_config.json      # Configuration file
├── honeypot.db               # SQLite database
├── honeypot_alerts.log       # Log file
└── sample_config.json        # Template (generated)
```

---

## 🧩 Extensibility

The modular design allows easy enhancements:
- Add new alert channels (SMS, Telegram, etc.)
- Integrate with SIEM systems
- Implement machine learning for anomaly detection
- Add service-specific response logic
- Support for IPv6

---

## 📚 Educational Use

Perfect for:
- Cybersecurity labs
- Ethical hacking courses
- Network security demonstrations
- Threat intelligence research

Students can:
- Learn about attacker behavior
- Analyze real-world attack patterns
- Understand intrusion detection
- Practice incident response

---

## 📄 License

This project is open-source and available for educational and non-commercial use.

> ⚠️ **Important**: Use only on networks you have explicit permission to monitor. Unauthorized monitoring may violate privacy laws.

---

## 🧑‍💻 Author

**Lokesh Acharya**  
Cybersecurity Student

---

## 🐛 Troubleshooting

| Issue | Solution |
|------|----------|
| `Permission denied` on port | Run with `sudo` or use ports > 1024 |
| Email not sending | Check SMTP settings and app password |
| Webhook timeout | Verify URL and network connectivity |
| No alerts | Ensure config file is properly formatted |
| High CPU usage | Reduce number of monitored ports |

---

## 🚀 Future Enhancements

- 📈 Web dashboard for real-time monitoring
- 📊 Attack pattern visualization
- 🔁 Auto-blocking of malicious IPs (via firewall)
- 🤖 AI-based anomaly detection
- 📱 Mobile push notifications
- 🔄 Integration with threat intelligence feeds

---

> 🍯 **"The best defense is a good deception."**  
> Deploy honeypots to turn attackers into informants.
