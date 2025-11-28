# 🦅 CyberHawk - AI-Powered Intrusion Detection and Prevention System

<div align="center">

![CyberHawk Logo](assets/img/logo.png)

**Comprehensive Cybersecurity Platform with Real-Time Threat Detection**

[![PHP](https://img.shields.io/badge/PHP-8.x-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](LICENSE)

</div>

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Technologies](#technologies)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Contributors](#contributors)
- [Supervisor](#supervisor)
- [License](#license)

---

## 🎯 About

**CyberHawk** is an advanced, AI-powered **Intrusion Detection and Prevention System (IDPS)** developed as a Final Year Project at COMSATS University Islamabad, Wah Campus. The system integrates:

- **Network Intrusion Detection System (IDS)** - Real-time network traffic monitoring and anomaly detection
- **Malware Analysis Engine** - Multi-source threat intelligence integration (VirusTotal, MalwareBazaar, ThreatFox)
- **Ransomware Detection & Prevention** - Behavioral analysis and auto-quarantine capabilities
- **Web-Based Dashboard** - Comprehensive visualization and management interface

### 🎓 Academic Information

- **Project Title**: CyberHawk: AI-Powered Intrusion Detection and Prevention System with Ransomware & Malware Analysis
- **Institution**: COMSATS University Islamabad, Wah Campus
- **Department**: Computer Sciences
- **Session**: 2022-2026
- **Degree**: Bachelor of Science in Computer Science / Software Engineering

---

## ✨ Features

### 🔍 Network Intrusion Detection System (IDS)

- **Real-time packet capture** using Scapy
- **Machine Learning-based anomaly detection**
  - Deep Neural Network (TensorFlow)
  - 49-feature extraction per network flow
  - Attack detection: DoS/DDoS, Port Scanning, Brute Force, Infiltration, XSS, SQL Injection
- **Live traffic visualization** with interactive charts
- **Automated alert generation** with severity classification
- **JSON-based logging** for forensic analysis

### 🦠 Malware Analysis System

- **Multi-engine scanning** integration:
  - VirusTotal API (70+ antivirus engines)
  - MalwareBazaar (abuse.ch) - Known malware hash lookup
  - ThreatFox IOC API - Indicators of compromise
- **Static analysis capabilities**:
  - File hash calculation (MD5, SHA1, SHA256)
  - Entropy analysis for packed/encrypted files
  - Suspicious string extraction
  - PE header analysis
- **Behavioral analysis** (planned):
  - API call monitoring
  - Registry modification tracking
  - Network connection analysis
- **Comprehensive threat reports** with:
  - Detection rate from multiple engines
  - Malware family classification
  - Risk scoring and recommendations

### 🔒 Ransomware Detection & Prevention

- **Real-time file system monitoring** using Watchdog
- **Entropy-based detection** (Shannon entropy > 7.5 bits/byte)
- **Suspicious extension detection** (.locky, .enc, .encrypted, etc.)
- **Ransom note detection** (common ransomware text patterns)
- **Automated quarantine system**
- **Backup restoration capabilities**
- **Activity logging** for incident response

### 📊 Web Dashboard

- **Responsive Bootstrap 5 UI**
- **Real-time metrics and charts**:
  - Protocol distribution (TCP, UDP, ICMP)
  - Top source IPs
  - Recent attacks timeline
  - Port scan activity radar chart
- **Live traffic logs** with search and filtering
- **Alert management system**
- **Comprehensive reporting**:
  - Executive summary
  - Detailed threat analysis
  - Network statistics
  - Export to PDF/HTML

### 👤 User Management

- **Secure authentication** with bcrypt password hashing
- **Session management**
- **Role-based access control** (Admin, User)
- **Profile management**
- **Email verification system**
- **Notification system** for security events

---

## 🏗️ System Architecture

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Browser                            │
│                     (Dashboard Interface)                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP/HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Web Server (Apache)                         │
│  ┌──────────────────┐  ┌──────────────────┐                     │
│  │   PHP Backend    │  │   API Layer      │                     │
│  │   (MVC Pattern)  │  │   (REST APIs)    │                     │
│  └────────┬─────────┘  └────────┬─────────┘                     │
└───────────┼────────────────────┼──────────────────────────────┘
            │                     │
            │                     ▼
            │          ┌─────────────────────┐
            │          │   Python Engines    │
            │          │  ┌──────────────┐   │
            │          │  │ IDS Module   │   │
            │          │  ├──────────────┤   │
            │          │  │ Malware      │   │
            │          │  │ Scanner      │   │
            │          │  ├──────────────┤   │
            │          │  │ Ransomware   │   │
            │          │  │ Monitor      │   │
            │          │  └──────────────┘   │
            │          └─────────┬───────────┘
            │                    │
            ▼                    ▼
┌──────────────────┐  ┌─────────────────────┐
│   MySQL Database │  │  External APIs      │
│  ┌────────────┐  │  │  • VirusTotal       │
│  │ Users      │  │  │  • MalwareBazaar    │
│  │ Logs       │  │  │  • ThreatFox        │
│  │ Reports    │  │  └─────────────────────┘
│  │ Settings   │  │
│  └────────────┘  │
└──────────────────┘
```

### Machine Learning Pipeline

```
Network Traffic → Packet Capture → Flow Aggregation → Feature Extraction (49 features)
                     (Scapy)         (5-tuple key)      (duration, packets, bytes, flags, etc.)
                                                                    ↓
Alert Generation ← Classification ← Prediction ← Deep Neural Network
  (JSON logs)      (Attack type)    (Confidence)   (TensorFlow/Keras)
```

---

## 🛠️ Technologies

### Backend
- **PHP 8.x** - Server-side logic, routing, session management
- **FastRoute** - High-performance routing library
- **MySQL/MariaDB** - Relational database management
- **Composer** - Dependency management

### Frontend
- **HTML5/CSS3** - Markup and styling
- **Bootstrap 5** - Responsive UI framework
- **JavaScript (ES6+)** - Interactive features
- **jQuery & AJAX** - Asynchronous data updates
- **Chart.js** - Data visualization

### Python Security Engines
- **Scapy** - Packet manipulation and capture
- **TensorFlow/Keras** - Machine learning models
- **Scikit-learn** - ML utilities and preprocessing
- **Watchdog** - File system event monitoring
- **Requests** - HTTP library for API calls
- **NumPy/Pandas** - Data processing

### External APIs
- **VirusTotal API v3** - Multi-engine malware scanning
- **MalwareBazaar API** - Malware hash database
- **ThreatFox API** - IOC intelligence

### Development Tools
- **XAMPP** - Local development environment
- **VS Code** - Code editor
- **Git/GitHub** - Version control
- **Postman** - API testing

---

## 📥 Installation

### Prerequisites

- **Operating System**: Windows 10/11 or Linux (Ubuntu 20.04+)
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk Space**: At least 10GB free
- **Python**: 3.9 or higher
- **PHP**: 8.0 or higher
- **MySQL**: 8.0 or higher
- **XAMPP** (recommended) or Apache + PHP + MySQL separately

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cyberhawk.git
cd cyberhawk

# 2. Install PHP dependencies
composer install

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your database credentials and API keys

# 5. Import database
mysql -u root -p cyberhawk < database/schema.sql

# 6. Configure Apache
# Set document root to: /path/to/cyberhawk/
# Ensure .htaccess is enabled

# 7. Start the application
# - Start XAMPP (Apache + MySQL)
# - Access: http://localhost/cyberhawk/
```

For detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md).

---

## 🚀 Usage

### Starting the System

1. **Login** to the dashboard using your credentials
2. **Dashboard** - View real-time metrics and system status

### Network Intrusion Detection

1. Navigate to **Dashboard**
2. Click **"Start Monitoring"**
3. Select your network interface
4. View live traffic logs and alerts in real-time
5. Click **"Stop Monitoring"** when done

### Malware Analysis

1. Navigate to **Malware Analysis**
2. Click **"Upload Sample"** or drag-and-drop a file
3. Click **"Start Scan"**
4. View comprehensive analysis report with:
   - Detection results from multiple engines
   - File hashes and entropy
   - Threat classification
   - Recommendations

### Ransomware Protection

1. Navigate to **Ransomware Detection**
2. Click **"Start Monitoring"**
3. Select folders to protect
4. The system will:
   - Monitor file changes in real-time
   - Detect high-entropy files
   - Alert on suspicious extensions
   - Auto-quarantine critical threats

### Generating Reports

1. Navigate to **Reporting**
2. Select report type:
   - Executive Summary
   - Detailed Threat Report
   - Network Statistics
3. Choose date range
4. Select export format (HTML/PDF)
5. Click **"Generate Report"**

---

## 📂 Project Structure

```
cyberhawk/
├── app/
│   ├── core/
│   │   ├── functions.php          # Core helper functions
│   │   └── views.php               # View rendering functions
│   ├── database/
│   │   ├── config.php              # Database configuration
│   │   └── index.php               # Database utilities
│   ├── helpers/
│   │   ├── email.php               # Email notification functions
│   │   └── notifications.php      # In-app notifications
│   └── views/
│       ├── pages/                  # Page views
│       │   ├── dashboard.php
│       │   ├── malware.php
│       │   ├── ransomware.php
│       │   ├── reporting.php
│       │   ├── settings.php
│       │   └── profile.php
│       └── common/                 # Shared components
│           ├── header.php
│           └── sidebar.php
├── assets/
│   ├── css/                        # Stylesheets
│   ├── js/                         # JavaScript files
│   └── img/                        # Images and icons
├── database/
│   ├── schema.sql                  # Complete database schema
│   └── create_system_settings_table.sql
├── python/
│   ├── malware/
│   │   ├── malware_analyzer.py    # Malware analysis engine
│   │   ├── malware_scanner.py     # File scanning module
│   │   └── malware_training.py    # ML model training
│   ├── ranswomware/
│   │   ├── ransomware_monitor.py  # Real-time file monitoring
│   │   ├── ransomware_scanner.py  # Ransomware detection
│   │   └── ransomware_training.py # ML model training
│   ├── traffic_capture/
│   │   └── traffic_sniffer.py     # Network packet capture
│   └── training/
│       ├── train_model.py          # IDS model training
│       ├── predict_realtime.py    # Real-time prediction
│       └── ransomware_training.py # Ransomware ML training
├── routes/
│   └── routes.php                  # Application routing
├── vendor/                         # Composer dependencies
├── .env.example                    # Environment configuration template
├── .htaccess                       # Apache configuration
├── composer.json                   # PHP dependencies
├── requirements.txt                # Python dependencies
├── README.md                       # This file
└── INSTALLATION.md                 # Installation guide
```

---

## 📚 API Documentation

### Authentication Required

All protected endpoints require a valid session. Include session cookie in requests.

### IDS Endpoints

#### Start Network Monitoring
```http
POST /cyberhawk/start-logs
Content-Type: application/json

Response:
{
  "status": "success",
  "message": "IDS monitoring started",
  "interface": "eth0"
}
```

#### Get Intrusion Chart Data
```http
GET /cyberhawk/get-intrusion-chart-data

Response:
{
  "protocol_distribution": {...},
  "top_source_ips": [...],
  "recent_attacks": [...],
  "port_scan_activity": {...}
}
```

### Malware Endpoints

#### Upload Sample
```http
POST /cyberhawk/upload-malware-sample
Content-Type: multipart/form-data

Parameters:
- file: Binary file data

Response:
{
  "status": "success",
  "file_id": "abc123",
  "filename": "sample.exe"
}
```

#### Start Malware Scan
```http
POST /cyberhawk/start-malware-scan
Content-Type: application/json

Body:
{
  "file_id": "abc123"
}

Response:
{
  "status": "success",
  "scan_id": "scan_xyz",
  "message": "Scan initiated"
}
```

### Ransomware Endpoints

#### Start Ransomware Monitoring
```http
POST /cyberhawk/start-ransomware-monitor
Content-Type: application/json

Body:
{
  "paths": ["/path/to/monitor"]
}

Response:
{
  "status": "success",
  "monitoring": true,
  "paths": [...]
}
```

For complete API documentation, see the routes configuration in `routes/routes.php`.

---

## 🧪 Testing

### Unit Tests

Test cases cover core functionalities:
- User authentication and session management
- IDS packet capture and analysis
- Malware file scanning
- Ransomware detection algorithms
- API integrations

### Test Results

All 7 critical test cases passed:
- ✅ TC-1: User Login with Valid Credentials
- ✅ TC-2: Start IDS Monitoring
- ✅ TC-3: Malware File Upload & Scan
- ✅ TC-4: Ransomware Detection - High Entropy File
- ✅ TC-5: API Integration - VirusTotal
- ✅ TC-6: View Reports
- ✅ TC-7: Logout Function

For detailed test documentation, see Chapter 5 (Quality Assurance) in the project report.

---

## 📸 Screenshots

### Dashboard - Real-Time Monitoring
![Dashboard](docs/screenshots/dashboard.png)

### Malware Analysis Interface
![Malware Analysis](docs/screenshots/malware.png)

### Ransomware Detection
![Ransomware](docs/screenshots/ransomware.png)

### Security Reporting
![Reporting](docs/screenshots/reporting.png)

---

## 🔐 Security Considerations

- **Authentication**: Bcrypt password hashing with salt
- **Session Management**: Secure session handling with timeout
- **SQL Injection Prevention**: Prepared statements with MySQLi
- **XSS Protection**: Input sanitization and output escaping
- **CSRF Protection**: Token-based request validation
- **File Upload Security**: Type validation and size restrictions
- **API Key Management**: Environment variable storage

---

## 🚧 Known Limitations & Future Work

### Current Limitations

1. **Azure SSO** - Routes defined but implementation pending
2. **Behavioral Analysis** - Sandbox environment requires enhancement
3. **Scale** - Optimized for small to medium networks (< 1000 Mbps)

### Future Enhancements

- ✨ **Advanced ML Models** - GAN-based anomaly detection, LSTM for sequential patterns
- 🌐 **Cloud Deployment** - AWS/Azure integration for scalability
- 🔄 **Real-time Updates** - WebSocket implementation for live updates
- 📱 **Mobile Application** - iOS/Android monitoring apps
- 🧠 **Behavioral Sandboxing** - Automated malware execution analysis
- 🔗 **SIEM Integration** - Splunk, ELK stack compatibility
- 🤖 **Automated Response** - AI-driven threat mitigation

---

## 👥 Contributors

### Development Team

| Name | Registration | Role | Responsibilities |
|------|--------------|------|------------------|
| **M Ahmed** | CIIT/SP22-BSE-055/WAH | Backend Developer | PHP Backend, Python Engines, Security Integrations, Documentation |
| **Hassan Javed** | CIIT/SP22-BSE-057/WAH | Frontend Developer | UI/UX Design, Dashboard, Charts, Testing |

---

## 👨‍🏫 Supervisor

**Dr. Kashif Ayyub**
Assistant Professor
Department of Computer Science
COMSATS University Islamabad, Wah Campus

---

## 📄 License

This project is developed for academic purposes as part of the Final Year Project requirement for the Bachelor's degree in Computer Science / Software Engineering at COMSATS University Islamabad, Wah Campus (2022-2026).

**Academic Use Only** - Not for commercial distribution.

---

## 📞 Contact

For questions or collaboration:

- **Email**: [project email]
- **University**: COMSATS University Islamabad, Wah Campus
- **Department**: Computer Sciences

---

## 🙏 Acknowledgments

We express our sincere gratitude to:

- **Dr. Kashif Ayyub** - Our supervisor, for continuous guidance and support
- **COMSATS University** - For providing resources and infrastructure
- **Our families** - For unwavering support throughout this journey
- **Open-source community** - For the excellent tools and libraries

---

## 📖 Documentation

- [Installation Guide](INSTALLATION.md)
- [User Manual](initial%20report.pdf#page=48) - Chapter 6 of Project Report
- [System Design](initial%20report.pdf#page=30) - Chapter 3 of Project Report
- [API Documentation](#api-documentation)

---

## 📊 Project Statistics

- **Lines of Code**: ~15,000+
- **Languages**: PHP, Python, JavaScript, SQL
- **Modules**: 6 major security modules
- **API Integrations**: 3 external threat intelligence sources
- **Development Time**: March 2025 - December 2025 (9 months)
- **Test Coverage**: 7 critical test cases (100% pass rate)

---

<div align="center">

**Built with ❤️ by M Ahmed and Hassan Javed**

**COMSATS University Islamabad, Wah Campus**

**Session 2022-2026**

</div>
