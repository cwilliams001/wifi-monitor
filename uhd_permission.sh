#!/bin/bash
# Run this script to fix UHD permissions issues

# Fix permissions for the UHD images directory
sudo chmod -R 755 /usr/share/uhd/images

# Create the environment variable for the current user
echo 'export UHD_IMAGES_DIR=/usr/share/uhd/images' >> ~/.bashrc
export UHD_IMAGES_DIR=/usr/share/uhd/images

# Create a systemd environment file for the service
sudo mkdir -p /etc/systemd/system/wifi-monitor.service.d
sudo bash -c 'cat > /etc/systemd/system/wifi-monitor.service.d/environment.conf << EOF
[Service]
Environment="UHD_IMAGES_DIR=/usr/share/uhd/images"
EOF'

# Reload systemd
sudo systemctl daemon-reload

echo "UHD environment variables and permissions have been set."
echo "Please restart the WiFi Monitor service if it's running."
