# 🛠️ CyberHawk Installation Guide

Complete installation and setup instructions for the CyberHawk IDPS system.

---

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
  - [Method 1: XAMPP Installation (Recommended)](#method-1-xampp-installation-recommended)
  - [Method 2: Manual Installation](#method-2-manual-installation)
- [Post-Installation Configuration](#post-installation-configuration)
- [Training Machine Learning Models](#training-machine-learning-models)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## 💻 System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|--------------|
| **Operating System** | Windows 10/11 (64-bit) or Linux (Ubuntu 20.04+) |
| **Processor** | Intel Core i5 or AMD Ryzen 5 (Quad-core, 2.0 GHz+) |
| **RAM** | 8 GB |
| **Storage** | 10 GB free disk space |
| **Network** | Active network adapter with administrator access |
| **Internet** | Required for API-based malware scanning |

### Recommended Requirements

| Component | Specification |
|-----------|--------------|
| **Operating System** | Windows 11 (64-bit) or Ubuntu 22.04 LTS |
| **Processor** | Intel Core i7 or AMD Ryzen 7 (Hexa-core, 3.0 GHz+) |
| **RAM** | 16 GB or more |
| **Storage** | 20 GB+ SSD |
| **Network** | Gigabit Ethernet or fast Wi-Fi |
| **GPU** | NVIDIA GPU with CUDA support (optional, for ML acceleration) |

---

## 📦 Prerequisites

Before installing CyberHawk, ensure you have the following software installed:

### 1. PHP (Version 8.0 or higher)

**Windows:**
```bash
# Download and install PHP from:
https://windows.php.net/download/

# Or use XAMPP (recommended - includes PHP, Apache, MySQL)
https://www.apachefriends.org/download.html
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install php8.1 php8.1-cli php8.1-common php8.1-mysql php8.1-mbstring php8.1-xml php8.1-curl
php -v  # Verify installation
```

### 2. MySQL/MariaDB (Version 8.0 or higher)

**Windows:**
```bash
# Included with XAMPP
# Or download from: https://dev.mysql.com/downloads/mysql/
```

**Linux:**
```bash
sudo apt install mysql-server mysql-client
sudo mysql_secure_installation  # Secure your installation
sudo systemctl start mysql
sudo systemctl enable mysql
mysql --version  # Verify
```

### 3. Python (Version 3.9 or higher)

**Windows:**
```bash
# Download from: https://www.python.org/downloads/
# ✅ Check "Add Python to PATH" during installation
python --version  # Verify
pip --version
```

**Linux:**
```bash
sudo apt install python3.9 python3.9-venv python3-pip
python3 --version
pip3 --version
```

### 4. Composer (PHP Dependency Manager)

**Windows & Linux:**
```bash
# Download from: https://getcomposer.org/download/
# Or install globally:
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php
php -r "unlink('composer-setup.php');"
sudo mv composer.phar /usr/local/bin/composer  # Linux only
composer --version  # Verify
```

### 5. Git (Version Control)

**Windows:**
```bash
# Download from: https://git-scm.com/download/win
```

**Linux:**
```bash
sudo apt install git
git --version
```

### 6. Network Packet Capture Tools

**Windows:**
- Download and install **Npcap**: https://npcap.com/
- ✅ Enable "WinPcap API-compatible Mode" during installation

**Linux:**
```bash
sudo apt install libpcap-dev tcpdump
```

---

## 📥 Installation Methods

### Method 1: XAMPP Installation (Recommended)

This method is easiest for beginners and works on both Windows and Linux.

#### Step 1: Install XAMPP

**Windows:**
1. Download XAMPP from: https://www.apachefriends.org/download.html
2. Run the installer
3. Select components:
   - ✅ Apache
   - ✅ MySQL
   - ✅ PHP
   - ✅ phpMyAdmin
4. Install to: `C:\xampp\`
5. Start XAMPP Control Panel
6. Start Apache and MySQL services

**Linux:**
```bash
wget https://sourceforge.net/projects/xampp/files/XAMPP%20Linux/8.1.6/xampp-linux-x64-8.1.6-0-installer.run
chmod +x xampp-linux-x64-8.1.6-0-installer.run
sudo ./xampp-linux-x64-8.1.6-0-installer.run
sudo /opt/lampp/lampp start
```

#### Step 2: Clone CyberHawk Repository

```bash
# Navigate to htdocs folder
cd C:\xampp\htdocs          # Windows
cd /opt/lampp/htdocs        # Linux

# Clone the repository
git clone https://github.com/yourusername/cyberhawk.git
cd cyberhawk
```

#### Step 3: Install PHP Dependencies

```bash
composer install
```

If you don't have Composer, download it from: https://getcomposer.org/

#### Step 4: Install Python Dependencies

**Windows:**
```bash
# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Linux:**
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt
```

#### Step 5: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
notepad .env        # Windows
nano .env           # Linux
```

**Important settings to configure:**
```ini
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=cyberhawk
DB_USERNAME=root
DB_PASSWORD=             # Leave empty for XAMPP default
APP_URL=http://localhost/cyberhawk/
APP_DIR=C:/xampp/htdocs/cyberhawk/    # Update to your path
MDIR=/cyberhawk/
```

#### Step 6: Create Database

```bash
# Access MySQL
mysql -u root -p

# Or use phpMyAdmin at: http://localhost/phpmyadmin
```

**Execute these commands:**
```sql
CREATE DATABASE cyberhawk CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
exit;
```

**Import schema:**
```bash
mysql -u root -p cyberhawk < database/schema.sql
```

**Verify:**
```bash
mysql -u root -p cyberhawk -e "SHOW TABLES;"
```

You should see tables like: `users`, `ids_alerts`, `malware_samples`, etc.

#### Step 7: Configure Apache

**Edit Apache configuration (httpd.conf):**

**Windows:** `C:\xampp\apache\conf\httpd.conf`
**Linux:** `/opt/lampp/etc/httpd.conf`

Find and ensure these lines are uncommented:
```apache
LoadModule rewrite_module modules/mod_rewrite.so
```

**Create/Edit .htaccess in project root:**
```apache
RewriteEngine On
RewriteBase /cyberhawk/

# Redirect to index.php if file/directory doesn't exist
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]
```

**Restart Apache:**
```bash
# Windows: Use XAMPP Control Panel
# Linux:
sudo /opt/lampp/lampp restart
```

#### Step 8: Set Permissions (Linux only)

```bash
# Set ownership
sudo chown -R www-data:www-data /opt/lampp/htdocs/cyberhawk

# Set permissions
sudo chmod -R 755 /opt/lampp/htdocs/cyberhawk
sudo chmod -R 777 /opt/lampp/htdocs/cyberhawk/uploads
sudo chmod -R 777 /opt/lampp/htdocs/cyberhawk/quarantine
sudo chmod -R 777 /opt/lampp/htdocs/cyberhawk/logs
```

#### Step 9: Configure API Keys

Edit your `.env` file and add:

```ini
# Get free API key from: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
```

#### Step 10: Access the Application

1. Open your browser
2. Navigate to: **http://localhost/cyberhawk/**
3. You should see the login page

**Default admin credentials:**
- Email: `admin@cyberhawk.com`
- Password: `Admin@123`

**⚠️ IMPORTANT: Change the password immediately after first login!**

---

### Method 2: Manual Installation

For advanced users who want full control.

#### Prerequisites

- Apache 2.4+
- PHP 8.0+
- MySQL 8.0+
- Python 3.9+

#### Installation Steps

```bash
# 1. Clone repository
git clone https://github.com/yourusername/cyberhawk.git
cd cyberhawk

# 2. Install PHP dependencies
composer install

# 3. Install Python dependencies
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
nano .env  # Edit configuration

# 5. Create database
mysql -u root -p
CREATE DATABASE cyberhawk CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
exit;

# 6. Import schema
mysql -u root -p cyberhawk < database/schema.sql

# 7. Configure web server (see Apache configuration section)

# 8. Set permissions (Linux)
sudo chown -R www-data:www-data /var/www/html/cyberhawk
sudo chmod -R 755 /var/www/html/cyberhawk
```

---

## ⚙️ Post-Installation Configuration

### 1. Verify Installation

Navigate to: **http://localhost/cyberhawk/dashboard**

You should see:
- ✅ Dashboard loads without errors
- ✅ No PHP errors displayed
- ✅ Database connection successful

### 2. Configure System Settings

**Login → Settings → System Settings**

- Configure monitored paths for ransomware detection
- Set up email notifications (optional)
- Configure alert thresholds

### 3. Configure API Keys

**Login → Settings → Security Settings**

Add your API keys:
- VirusTotal API Key
- AbuseIPDB API Key (optional)

### 4. Test Python Engines

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Test network capture (requires admin/root)
sudo python3 python/traffic_capture/traffic_sniffer.py

# Test malware scanner
python3 python/malware/malware_scanner.py --help

# Test ransomware monitor
python3 python/ranswomware/ransomware_monitor.py --help
```

### 5. Create Additional Users

**Login as admin → Settings → User Management**

- Create accounts for security analysts
- Assign appropriate roles

---

## 🤖 Training Machine Learning Models

CyberHawk includes pre-trained models, but you can retrain them with your own data.

### Prerequisites

- Training dataset (e.g., CICIDS2017, NSL-KDD)
- At least 8 GB RAM
- GPU recommended for faster training

### Training IDS Model

```bash
# Activate virtual environment
source venv/bin/activate

# Navigate to training directory
cd python/training

# Download training dataset
# Example: CICIDS2017 from Canadian Institute for Cybersecurity
wget https://www.unb.ca/cic/datasets/ids-2017.html

# Place CSV files in: python/training/datasets/

# Train the model
python3 train_model.py --dataset datasets/CICIDS2017 --epochs 50 --batch-size 32

# Model will be saved to: python/training/models/ids_model.h5
```

### Training Malware Detection Model

```bash
cd python/malware
python3 malware_training.py --dataset datasets/malware_samples --epochs 30
```

### Training Ransomware Detection Model

```bash
cd python/ranswomware
python3 ransomware_training.py --dataset datasets/ransomware_samples --epochs 25
```

### Model Configuration

Update `.env` with new model paths:
```ini
IDS_MODEL_PATH=python/training/models/ids_model.h5
MALWARE_MODEL_PATH=python/malware/models/malware_model.h5
RANSOMWARE_MODEL_PATH=python/ranswomware/models/ransomware_model.h5
```

---

## 🔧 Troubleshooting

### Issue: "Permission Denied" when capturing packets

**Solution:**
```bash
# Linux: Run Python scripts with sudo
sudo python3 python/traffic_capture/traffic_sniffer.py

# Or add your user to pcap group
sudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo chgrp pcap /usr/bin/tcpdump
sudo chmod 750 /usr/bin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
```

### Issue: "Database connection failed"

**Check:**
1. MySQL service is running:
   ```bash
   sudo systemctl status mysql  # Linux
   # Or check XAMPP Control Panel
   ```

2. Correct credentials in `.env`:
   ```ini
   DB_HOST=localhost
   DB_USERNAME=root
   DB_PASSWORD=
   DB_DATABASE=cyberhawk
   ```

3. Database exists:
   ```bash
   mysql -u root -p -e "SHOW DATABASES;"
   ```

### Issue: "Composer command not found"

**Solution:**
```bash
# Download Composer
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php
sudo mv composer.phar /usr/local/bin/composer
```

### Issue: Python module import errors

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Issue: "ModuleNotFoundError: No module named 'tensorflow'"

**Solution:**
```bash
# Install TensorFlow
pip install tensorflow==2.13.0

# For GPU support (NVIDIA only)
pip install tensorflow-gpu==2.13.0
```

### Issue: VirusTotal API rate limit exceeded

**Solution:**
- Free API key has 4 requests/minute limit
- Implement request throttling
- Consider upgrading to premium API

### Issue: Apache doesn't start

**Check port conflicts:**
```bash
# Windows
netstat -ano | findstr :80
netstat -ano | findstr :443

# Linux
sudo netstat -tulpn | grep :80
sudo netstat -tulpn | grep :443
```

**Common conflicts:**
- Skype using port 80
- IIS using port 80
- Other web servers

**Solution:** Stop conflicting service or change Apache port.

---

## 🔍 Verification Checklist

After installation, verify:

- [ ] Dashboard loads at `http://localhost/cyberhawk/`
- [ ] Login works with admin credentials
- [ ] Database connection successful
- [ ] IDS monitoring starts without errors
- [ ] Malware upload and scan works
- [ ] Ransomware monitoring activates
- [ ] Reports generate correctly
- [ ] Notifications appear
- [ ] No PHP/Python errors in logs

---

## 🗑️ Uninstallation

### Complete Removal

```bash
# 1. Stop services
# XAMPP Control Panel → Stop All (Windows)
sudo /opt/lampp/lampp stop  # Linux

# 2. Drop database
mysql -u root -p -e "DROP DATABASE cyberhawk;"

# 3. Remove application files
rm -rf /path/to/cyberhawk

# 4. Remove virtual environment
rm -rf venv/

# 5. (Optional) Uninstall XAMPP
# Windows: Use Control Panel
sudo /opt/lampp/uninstall  # Linux
```

---

## 📞 Getting Help

If you encounter issues:

1. **Check Logs:**
   - Apache error log: `xampp/apache/logs/error.log`
   - PHP error log: `xampp/php/logs/php_error_log`
   - Application log: `cyberhawk/logs/app.log`

2. **Documentation:**
   - [README.md](README.md)
   - [Project Report](initial%20report.pdf)

3. **Contact:**
   - Email: [your-email]
   - GitHub Issues: [repository URL]

---

## 🎓 Academic Support

This software is part of an academic Final Year Project at:

**COMSATS University Islamabad, Wah Campus**
Department of Computer Sciences
Session: 2022-2026

**Supervisor:** Dr. Kashif Ayyub
**Developers:** M Ahmed, Hassan Javed

---

<div align="center">

**Happy Securing! 🔐**

</div>
