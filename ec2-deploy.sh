#!/bin/bash
# ============================================================================
# CyberHawk EC2 Deployment Script
# ============================================================================
# Run this script on your fresh Ubuntu EC2 instance
# Usage: curl -sSL https://raw.githubusercontent.com/100-1824/cyberhawk/master/ec2-deploy.sh | bash
# Or: ./ec2-deploy.sh
# ============================================================================

set -e

echo "=============================================="
echo "🦅 CyberHawk EC2 Deployment"
echo "=============================================="

# Update system
echo ""
echo "[1/6] Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker
echo ""
echo "[2/6] Installing Docker..."
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Install Docker Compose
echo ""
echo "[3/6] Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add current user to docker group
echo ""
echo "[4/6] Configuring Docker permissions..."
sudo usermod -aG docker $USER

# Create application directory
echo ""
echo "[5/6] Setting up application directory..."
sudo mkdir -p /opt/cyberhawk
cd /opt/cyberhawk

# Create docker-compose.yml
echo ""
echo "[6/6] Creating Docker Compose configuration..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  app:
    image: ahmedsahni/cyberhawk-app:latest
    container_name: cyberhawk-app
    ports:
      - "80:80"
    environment:
      - DB_HOST=mysql
      - DB_USER=${DB_USER:-cyberhawk}
      - DB_PASSWORD=${DB_PASSWORD:-cyberhawk_secure_2024}
      - DB_NAME=${DB_NAME:-cyberhawk}
      - APP_DIR=/var/www/html/
    volumes:
      - app_data:/var/www/html/assets/data
      - app_uploads:/var/www/html/assets/uploads
    depends_on:
      mysql:
        condition: service_healthy
    networks:
      - cyberhawk-network
    restart: unless-stopped

  python:
    image: ahmedsahni/cyberhawk-python:latest
    container_name: cyberhawk-python
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - PYTHON_DATA_DIR=/var/www/html/assets/data
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY:-}
    volumes:
      - app_data:/var/www/html/assets/data
    restart: unless-stopped

  mysql:
    image: mysql:8.0
    container_name: cyberhawk-mysql
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-root_secure_2024}
      - MYSQL_DATABASE=${DB_NAME:-cyberhawk}
      - MYSQL_USER=${DB_USER:-cyberhawk}
      - MYSQL_PASSWORD=${DB_PASSWORD:-cyberhawk_secure_2024}
    volumes:
      - mysql_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - cyberhawk-network
    restart: unless-stopped

  phpmyadmin:
    image: phpmyadmin:latest
    container_name: cyberhawk-phpmyadmin
    environment:
      - PMA_HOST=mysql
      - PMA_USER=root
      - PMA_PASSWORD=${MYSQL_ROOT_PASSWORD:-root_secure_2024}
    ports:
      - "8080:80"
    depends_on:
      mysql:
        condition: service_healthy
    networks:
      - cyberhawk-network
    restart: unless-stopped

volumes:
  app_data:
  app_uploads:
  mysql_data:

networks:
  cyberhawk-network:
    driver: bridge
EOF

# Create .env file
cat > .env << 'EOF'
# CyberHawk Production Environment
DB_HOST=mysql
DB_USER=cyberhawk
DB_PASSWORD=cyberhawk_secure_2024
DB_NAME=cyberhawk
MYSQL_ROOT_PASSWORD=root_secure_2024
VIRUSTOTAL_API_KEY=
EOF

echo ""
echo "=============================================="
echo "✅ EC2 Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "1. Log out and log back in (for docker group)"
echo "   Or run: newgrp docker"
echo ""
echo "2. Start the application:"
echo "   cd /opt/cyberhawk"
echo "   docker-compose up -d"
echo ""
echo "3. Access the application:"
echo "   http://<your-ec2-public-ip>/cyberhawk/"
echo "   phpMyAdmin: http://<your-ec2-public-ip>:8080"
echo ""
echo "4. Default login:"
echo "   Email: admin@gmail.com"
echo "   Password: admin@123"
echo ""
echo "=============================================="
echo ""
echo "⚠️  Security Reminders:"
echo "  - Update .env with strong passwords"
echo "  - Configure EC2 Security Group (allow ports 80, 8080)"
echo "  - Set up HTTPS with Let's Encrypt for production"
echo "=============================================="
