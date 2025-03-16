#!/bin/bash
# WiFi Attack Monitoring System - Setup Script
# This script installs necessary dependencies for the WiFi monitoring system

# Exit on error
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect Architecture
detect_architecture() {
    ARCH=$(uname -m)
    print_message "Detected architecture: $ARCH"
    
    if [[ "$ARCH" == "x86_64" ]]; then
        print_message "Installing for x64 architecture"
        IS_X64=true
    elif [[ "$ARCH" == "aarch64" || "$ARCH" == "armv7l" ]]; then
        print_message "Installing for ARM architecture"
        IS_X64=false
    else
        print_warning "Unsupported architecture: $ARCH. Will attempt to install anyway."
        IS_X64=false
    fi
}

# Detect distribution
detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        print_message "Detected distribution: $DISTRO"
    else
        DISTRO="unknown"
        print_warning "Could not detect distribution. Assuming Debian-based."
    fi
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        print_message "Please run with: sudo $0"
        exit 1
    fi
}

# Install common dependencies
install_common_deps() {
    print_message "Installing common system dependencies..."
    
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
        apt-get update
        apt-get install -y \
            python3 \
            python3-pip \
            python3-dev \
            git \
            iw \
            aircrack-ng \
            wireless-tools \
            build-essential \
            libssl-dev \
            libfftw3-dev \
            pkg-config
        
    elif [[ "$DISTRO" == "fedora" || "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
        dnf install -y \
            python3 \
            python3-pip \
            python3-devel \
            git \
            iw \
            aircrack-ng \
            wireless-tools \
            gcc \
            gcc-c++ \
            openssl-devel \
            fftw-devel \
            pkgconfig
            
    elif [[ "$DISTRO" == "arch" || "$DISTRO" == "manjaro" ]]; then
        pacman -Sy --noconfirm \
            python \
            python-pip \
            git \
            iw \
            aircrack-ng \
            wireless_tools \
            base-devel \
            openssl \
            fftw \
            pkg-config
    else
        print_warning "Unsupported distribution. Please install dependencies manually."
        print_message "Required packages: python3, python3-pip, iw, aircrack-ng, wireless-tools"
        print_message "And for SDR: libssl-dev, libfftw3-dev, pkg-config"
        return 1
    fi
    
    print_success "System dependencies installed"
    return 0
}

# Install Python dependencies
install_python_deps() {
    print_message "Installing Python dependencies using apt packages..."
    
    # Use apt packages instead of pip
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
        apt-get install -y \
            python3-scapy \
            python3-yaml \
            python3-requests \
            python3-numpy \
            python3-flask \
            python3-werkzeug \
            python3-soapysdr
        
        # Check if all packages were installed successfully
        if [ $? -ne 0 ]; then
            print_warning "Some Python packages could not be installed via apt."
            print_message "You may need to install missing packages manually."
            print_message "Options include:"
            print_message "1. Use pipx: sudo apt install pipx; pipx install <package>"
            print_message "2. Use --break-system-packages (not recommended): pip install --break-system-packages <package>"
            print_message "3. Use --user (for non-root installs): pip install --user <package>"
        fi
    elif [[ "$DISTRO" == "fedora" || "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
        dnf install -y \
            python3-scapy \
            python3-pyyaml \
            python3-requests \
            python3-numpy \
            python3-flask \
            python3-werkzeug
        
        # Try pip for SoapySDR on these distros
        python3 -m pip install soapysdr --user
        
    elif [[ "$DISTRO" == "arch" || "$DISTRO" == "manjaro" ]]; then
        pacman -Sy --noconfirm \
            python-scapy \
            python-yaml \
            python-requests \
            python-numpy \
            python-flask \
            python-werkzeug
        
        # Try pip for SoapySDR on arch
        python3 -m pip install soapysdr --user
    else
        print_warning "Unsupported distribution for Python packages."
        print_message "Installing with pip as a fallback (may not work on all systems)..."
        
        # Try user installation
        python3 -m pip install --user \
            scapy \
            pyyaml \
            requests \
            numpy \
            flask \
            werkzeug \
            'https://github.com/pothosware/python-soapysdr/archive/master.zip'
    fi
    
    # Install SoapySDR Python bindings - this is different depending on the distro
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
        apt-get install -y python3-soapysdr
    else
        # Try pip for other distros, but with --user
        python3 -m pip install --user 'https://github.com/pothosware/python-soapysdr/archive/master.zip' || true
        
        # If pip failed, give instructions for manual installation
        if ! python3 -c "import SoapySDR" &> /dev/null; then
            print_warning "SoapySDR Python bindings installation failed."
            print_message "You may need to install them manually for your distribution."
            print_message "Try: sudo apt-get install python3-soapysdr"
            print_message "     or visit: https://github.com/pothosware/python-soapysdr"
        fi
    fi
        
    print_success "Python dependencies installed"
}

# Install SDR dependencies
install_sdr_deps() {
    print_message "Do you want to install SDR support? [y/N]"
    read -r install_sdr
    
    if [[ "$install_sdr" =~ ^[Yy]$ ]]; then
        print_message "Which SDR device will you use?"
        echo "1) HackRF"
        echo "2) Ettus B205 Mini (USRP)"
        echo "3) Both"
        echo "4) None (Skip SDR installation)"
        read -r device_choice
        
        case $device_choice in
            1)
                install_hackrf
                ;;
            2)
                install_uhd
                ;;
            3)
                install_hackrf
                install_uhd
                ;;
            4)
                print_message "Skipping SDR installation"
                return 0
                ;;
            *)
                print_warning "Invalid choice. Skipping SDR installation."
                return 0
                ;;
        esac
        
        print_success "SDR dependencies installed"
    else
        print_message "Skipping SDR installation"
    fi
}

# Install HackRF support
install_hackrf() {
    print_message "Installing HackRF dependencies..."
    
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
        apt-get install -y \
            hackrf \
            libhackrf-dev \
            soapysdr-module-hackrf
            
    elif [[ "$DISTRO" == "fedora" || "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
        dnf install -y \
            hackrf \
            hackrf-devel \
            soapysdr-hackrf
            
    elif [[ "$DISTRO" == "arch" || "$DISTRO" == "manjaro" ]]; then
        pacman -Sy --noconfirm \
            hackrf \
            soapysdr-hackrf
    else
        print_warning "Unsupported distribution for HackRF packages."
        print_message "Please install HackRF manually from https://github.com/greatscottgadgets/hackrf"
        return 1
    fi
    
    # Test HackRF detection
    if command -v hackrf_info &> /dev/null; then
        print_message "Testing HackRF detection..."
        if hackrf_info; then
            print_success "HackRF detected successfully"
        else
            print_warning "HackRF not detected. Please check your device connection."
        fi
    else
        print_warning "HackRF utilities not found in PATH. Installation may have failed."
    fi
    
    print_success "HackRF dependencies installed"
}

# Install UHD (USRP) support
install_uhd() {
    print_message "Installing Ettus USRP dependencies..."
    
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
        apt-get install -y \
            libuhd-dev \
            uhd-host \
            python3-uhd \
            soapysdr-module-uhd
            
    elif [[ "$DISTRO" == "fedora" || "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
        dnf install -y \
            uhd-devel \
            uhd \
            soapysdr-uhd
            
    elif [[ "$DISTRO" == "arch" || "$DISTRO" == "manjaro" ]]; then
        pacman -Sy --noconfirm \
            uhd \
            soapysdr-uhd
    else
        print_warning "Unsupported distribution for UHD packages."
        print_message "Please install UHD manually from https://github.com/EttusResearch/uhd"
        return 1
    fi
    
    # Download USRP FPGA images
    print_message "Downloading USRP images (this may take a while)..."
    sudo uhd_images_downloader
    
    # Fix permissions for UHD images directory
    if [ -d "/usr/share/uhd/images" ]; then
        sudo chmod -R 755 /usr/share/uhd/images
    fi
    
    # Set up environment variable
    echo 'export UHD_IMAGES_DIR=/usr/share/uhd/images' >> ~/.bashrc
    export UHD_IMAGES_DIR=/usr/share/uhd/images
    
    # Test USRP detection
    if command -v uhd_find_devices &> /dev/null; then
        print_message "Testing USRP detection..."
        if uhd_find_devices; then
            print_success "USRP device detected successfully"
        else
            print_warning "USRP not detected. Please check your device connection."
            print_message "You can retry detection later with: sudo uhd_find_devices"
        fi
    else
        print_warning "UHD utilities not found in PATH. Installation may have failed."
    fi
    
    print_success "USRP dependencies installed"
}

# Create service file
create_service() {
    print_message "Do you want to install the program as a system service? [y/N]"
    read -r install_service
    
    if [[ "$install_service" =~ ^[Yy]$ ]]; then
        print_message "Creating systemd service..."
        
        # Get the full path to the script directory
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
        
        # Create service file
        cat > /etc/systemd/system/wifi-monitor.service << EOF
[Unit]
Description=WiFi Attack Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/wifi_monitor.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        
        # Reload systemd
        systemctl daemon-reload
        
        print_message "Do you want to enable and start the service now? [y/N]"
        read -r start_service
        
        if [[ "$start_service" =~ ^[Yy]$ ]]; then
            systemctl enable wifi-monitor.service
            systemctl start wifi-monitor.service
            print_success "Service started and enabled"
        else
            print_message "You can start the service later with: sudo systemctl start wifi-monitor.service"
        fi
        
        print_success "Service installation complete"
    else
        print_message "Skipping service installation"
    fi
}

# Configure the system
configure_system() {
    print_message "Setting up the WiFi Attack Monitoring System..."
    
    # Create log directory with proper permissions
    mkdir -p /var/log/wifi-monitor
    chmod 755 /var/log/wifi-monitor
    
    # Create config directory if it doesn't exist
    mkdir -p /etc/wifi-monitor
    
    # Create Web UI directories
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
    mkdir -p "${SCRIPT_DIR}/templates"
    mkdir -p "${SCRIPT_DIR}/static/css"
    
    # Check if Web UI port is accessible
    print_message "Checking if Web UI port (8080) is available..."
    if command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":8080 "; then
            print_warning "Port 8080 appears to be in use. You may need to change the Web UI port in the configuration."
        else
            print_message "Port 8080 is available for the Web UI."
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":8080 "; then
            print_warning "Port 8080 appears to be in use. You may need to change the Web UI port in the configuration."
        else
            print_message "Port 8080 is available for the Web UI."
        fi
    fi
    
    # Copy default config if it doesn't exist
    if [ ! -f /etc/wifi-monitor/config.yaml ]; then
        if [ -f ./config.yaml ]; then
            cp ./config.yaml /etc/wifi-monitor/config.yaml
            print_message "Default configuration copied to /etc/wifi-monitor/config.yaml"
            print_message "Please edit this file to match your network configuration."
        else
            print_warning "Default config.yaml not found in current directory."
            print_message "Please create a configuration file at /etc/wifi-monitor/config.yaml"
        fi
    else
        print_message "Configuration file already exists at /etc/wifi-monitor/config.yaml"
    fi
    
    print_success "System configuration complete"
}

# Configure firewall for Web UI access
configure_firewall() {
    print_message "Do you want to configure the firewall to allow Web UI access? [y/N]"
    read -r configure_fw
    
    if [[ "$configure_fw" =~ ^[Yy]$ ]]; then
        # Check which firewall is in use
        if command -v ufw &> /dev/null; then
            print_message "Configuring UFW firewall..."
            
            # Check if UFW is active
            if sudo ufw status | grep -q "Status: active"; then
                sudo ufw allow 8080/tcp
                print_success "UFW rule added for port 8080"
            else
                print_warning "UFW is installed but not active. No rules added."
                print_message "You can enable UFW with: sudo ufw enable"
            fi
            
        elif command -v firewall-cmd &> /dev/null; then
            print_message "Configuring firewalld..."
            
            # Check if firewalld is running
            if sudo systemctl is-active --quiet firewalld; then
                sudo firewall-cmd --permanent --add-port=8080/tcp
                sudo firewall-cmd --reload
                print_success "Firewalld rule added for port 8080"
            else
                print_warning "Firewalld is installed but not active. No rules added."
                print_message "You can enable firewalld with: sudo systemctl start firewalld"
            fi
            
        elif command -v iptables &> /dev/null; then
            print_message "Configuring iptables..."
            
            # Add rule for port 8080
            sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
            
            # Check if iptables-persistent is available to save rules
            if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "raspbian" ]]; then
                if ! dpkg -l | grep -q iptables-persistent; then
                    print_message "Installing iptables-persistent to save rules..."
                    sudo apt-get install -y iptables-persistent
                fi
                
                sudo iptables-save > /etc/iptables/rules.v4
                print_success "Iptables rule added and saved for port 8080"
            else
                print_warning "Iptables rule added but may not persist after reboot."
                print_message "Consider installing a tool to save iptables rules."
            fi
            
        else
            print_warning "No supported firewall detected. You may need to manually configure firewall rules."
            print_message "Ensure port 8080 is open for Web UI access."
        fi
    else
        print_message "Skipping firewall configuration"
        print_message "Ensure port 8080 is open if you want to access the Web UI from other devices."
    fi
}

# Main installation flow
main() {
    print_message "WiFi Attack Monitoring System - Setup Script"
    print_message "============================================="
    
    # Check if running as root
    check_root
    
    # Detect system information
    detect_architecture
    detect_distribution
    
    # Install dependencies
    install_common_deps
    install_python_deps
    install_sdr_deps
    
    # Configure the system
    configure_system
    
    # Create service
    create_service
    
    # Configure firewall if needed
    configure_firewall
    
    print_success "WiFi Attack Monitoring System installation complete"
    print_message "Please check the documentation for next steps."
}

# Run main function
main
