#!/bin/bash
# ============================================================================
# CyberHawk Docker Build and Push Script
# ============================================================================
# Usage: ./deploy.sh [dockerhub_username] [version_tag]
# Example: ./deploy.sh ahmedsahni v1.0.0
# ============================================================================

set -e

# Configuration
DOCKERHUB_USER="${1:-ahmedsahni}"
VERSION="${2:-latest}"
APP_NAME="cyberhawk"

echo "=============================================="
echo "🦅 CyberHawk Docker Deployment"
echo "=============================================="
echo "DockerHub User: $DOCKERHUB_USER"
echo "Version: $VERSION"
echo "=============================================="

# Login to DockerHub
echo ""
echo "[1/5] Logging into DockerHub..."
docker login

# Build PHP/Apache image
echo ""
echo "[2/5] Building PHP/Apache application image..."
docker build -t $DOCKERHUB_USER/$APP_NAME-app:$VERSION -f Dockerfile .
docker tag $DOCKERHUB_USER/$APP_NAME-app:$VERSION $DOCKERHUB_USER/$APP_NAME-app:latest

# Build Python services image
echo ""
echo "[3/5] Building Python services image..."
docker build -t $DOCKERHUB_USER/$APP_NAME-python:$VERSION -f Dockerfile.python .
docker tag $DOCKERHUB_USER/$APP_NAME-python:$VERSION $DOCKERHUB_USER/$APP_NAME-python:latest

# Push images to DockerHub
echo ""
echo "[4/5] Pushing images to DockerHub..."
docker push $DOCKERHUB_USER/$APP_NAME-app:$VERSION
docker push $DOCKERHUB_USER/$APP_NAME-app:latest
docker push $DOCKERHUB_USER/$APP_NAME-python:$VERSION
docker push $DOCKERHUB_USER/$APP_NAME-python:latest

# Create production docker-compose
echo ""
echo "[5/5] Creating production docker-compose file..."
cat > docker-compose.prod.yml << EOF
version: '3.8'

services:
  app:
    image: $DOCKERHUB_USER/$APP_NAME-app:$VERSION
    container_name: cyberhawk-app
    ports:
      - "80:80"
    environment:
      - DB_HOST=mysql
      - DB_USER=\${DB_USER:-cyberhawk}
      - DB_PASSWORD=\${DB_PASSWORD:-cyberhawk_secure_2024}
      - DB_NAME=\${DB_NAME:-cyberhawk}
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
    image: $DOCKERHUB_USER/$APP_NAME-python:$VERSION
    container_name: cyberhawk-python
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - PYTHON_DATA_DIR=/var/www/html/assets/data
      - VIRUSTOTAL_API_KEY=\${VIRUSTOTAL_API_KEY:-}
    volumes:
      - app_data:/var/www/html/assets/data
    restart: unless-stopped

  mysql:
    image: mysql:8.0
    container_name: cyberhawk-mysql
    environment:
      - MYSQL_ROOT_PASSWORD=\${MYSQL_ROOT_PASSWORD:-root_secure_2024}
      - MYSQL_DATABASE=\${DB_NAME:-cyberhawk}
      - MYSQL_USER=\${DB_USER:-cyberhawk}
      - MYSQL_PASSWORD=\${DB_PASSWORD:-cyberhawk_secure_2024}
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

volumes:
  app_data:
  app_uploads:
  mysql_data:

networks:
  cyberhawk-network:
    driver: bridge
EOF

echo ""
echo "=============================================="
echo "✅ Deployment Complete!"
echo "=============================================="
echo ""
echo "Images pushed to DockerHub:"
echo "  - $DOCKERHUB_USER/$APP_NAME-app:$VERSION"
echo "  - $DOCKERHUB_USER/$APP_NAME-python:$VERSION"
echo ""
echo "Production docker-compose file created:"
echo "  - docker-compose.prod.yml"
echo ""
echo "To deploy on EC2, copy docker-compose.prod.yml"
echo "and run: docker-compose -f docker-compose.prod.yml up -d"
echo "=============================================="
