# WiFi Attack Monitoring System

A comprehensive system for detecting WiFi jamming and deauthentication attacks using a Raspberry Pi or x64-based mini PC with a dedicated WiFi adapter and optional SDR hardware.

## Features

- **Deauthentication Attack Detection**: Monitors WiFi traffic to detect abnormal patterns of deauthentication frames that may indicate an attack
- **RF Jamming Detection**: Uses Software Defined Radio (SDR) to scan wireless spectrum for potential jamming signals
- **Cross-Platform Support**: Works on both ARM-based SBCs (like Raspberry Pi) and x64-based mini PCs
- **Minimal Storage Impact**: Logs are created only when anomalous events are detected
- **Real-time Alerting**: Sends alerts to a web server and/or Home Assistant for immediate notification
- **Built-in Web UI**: Includes a web-based dashboard to monitor system status and view attack events
- **NAS Integration**: Optional offloading of logs to network storage for long-term retention

## Hardware Requirements

- **Computing Platform**:
  - Raspberry Pi 3/4/5 with Raspberry Pi OS, or
  - x64-based mini PC or server running Linux
  
- **WiFi Hardware**:
  - Panda Wireless PAU0B AC600 (or similar adapter supporting monitor mode)
  
- **SDR Hardware (Optional)**:
  - HackRF One, or
  - Ettus Research B205 Mini (USRP B205)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/wifi-monitor
   cd wifi-monitor
   ```

2. Run the setup script:
   ```bash
   sudo ./setup.sh
   ```
   
   The setup script will:
   - Install system dependencies based on your platform
   - Install required Python packages
   - Configure SDR support if requested
   - Create a systemd service for automatic startup
   - Set up configuration directories

3. Edit the configuration file:
   ```bash
   sudo nano /etc/wifi-monitor/config.yaml
   ```
   
   Adjust settings according to your network and hardware.

## Configuration Options

The system is highly configurable through the `config.yaml` file. Key configuration sections include:

### General Settings
```yaml
general:
  debug_mode: false
  log_directory: "/var/log/wifi-monitor"
  nas_offload:
    enabled: false
    path: "/mnt/nas/wifi-monitor"
    schedule: "daily"
```

### Deauth Detection Settings
```yaml
deauth_detection:
  enabled: true
  interface: "wlan1"
  channel: 0
  threshold:
    count: 10
    window: 30
  whitelist:
    - "00:11:22:33:44:55"
  channel_hop_interval: 5
```

### Jamming Detection Settings
```yaml
jamming_detection:
  enabled: true
  sdr_device: "hackrf"
  scan_bands:
    - name: "2.4GHz"
      start_freq: 2400000000
      end_freq: 2500000000
      step: 5000000
```

### Alert Settings
```yaml
alerts:
  web_server:
    enabled: true
    url: "http://192.168.1.100:5000/api/alerts"
  home_assistant:
    enabled: true
    webhook_url: "http://192.168.1.100:8123/api/webhook/wifi_attack_alert"
```

### Web UI Settings
```yaml
web_ui:
  enabled: true
  host: "0.0.0.0"           # Listen on all interfaces
  port: 8080                # Web UI port
  auth_enabled: true        # Enable basic authentication
  password: "admin"         # Default password (change this!)
  debug: false              # Enable debug mode
```

## Usage

The system can be run manually or as a service:

### Running Manually

```bash
sudo python3 wifi_monitor.py
```

Command-line options:
- `-c, --config`: Path to configuration file (default: config.yaml)
- `-d, --debug`: Enable debug logging
- `-t, --test`: Run in test mode with simulated attacks

### Running as a Service

If you installed the systemd service:

```bash
# Start the service
sudo systemctl start wifi-monitor

# View logs
sudo journalctl -u wifi-monitor -f

# Enable automatic startup
sudo systemctl enable wifi-monitor
```

## Preparing WiFi Adapter

To use the system, you need to set your WiFi adapter to monitor mode:

```bash
# Check interface name
ip a

# Set monitor mode
sudo airmon-ng start wlan1  # Replace wlan1 with your interface name
```

Alternatively, the system can attempt to set monitor mode automatically if it has sufficient permissions.

## Web UI Dashboard

The system includes a built-in web interface that provides:

- System status and uptime information
- Module status (running/stopped/error)
- Real-time attack event display
- Access to log files
- Configuration viewer

### Accessing the Web UI

1. Ensure web_ui.enabled is set to true in your configuration
2. Access the dashboard at: `http://[device-ip]:8080`
3. Default login (if auth_enabled is true):
   - Username: `admin`
   - Password: `admin` (change this in the configuration file)

### Security Considerations

- Change the default password in the configuration file
- Consider using a reverse proxy (like Nginx) with HTTPS for secure remote access
- Restrict access to the Web UI by setting `host` to a specific interface IP instead of `0.0.0.0`

## Integrating with Home Assistant

To receive notifications in Home Assistant:

1. Create a webhook automation in Home Assistant:

```yaml
automation:
  - alias: "WiFi Attack Alert"
    trigger:
      platform: webhook
      webhook_id: wifi_attack_alert
    action:
      - service: notify.mobile_app
        data:
          title: "WiFi Security Alert!"
          message: "{{trigger.json.event_type}} detected at {{trigger.json.timestamp}}"
```

2. Update the webhook URL in the configuration file with your Home Assistant instance address.

## Log Files

Attack events are logged to:
- `/var/log/wifi-monitor/attack_events.json` - JSON file containing attack details
- `/var/log/wifi-monitor/wifi_monitor_YYYYMMDD.log` - Daily log file with system messages

## Testing

To test the system without actual attacks:

```bash
sudo python3 wifi_monitor.py --test
```

This will simulate periodic deauthentication attacks and jamming events to verify your notification system.

## Troubleshooting

### Common Issues

- **WiFi Adapter Not Found**: Ensure your adapter is properly connected and recognized by the system.
- **Monitor Mode Failed**: Some adapters require specific drivers. Try setting monitor mode manually.
- **SDR Not Detected**: Check USB connections and drivers for your specific SDR device.
- **Alert Delivery Failed**: Verify network connectivity and correct URLs in the configuration.

### Debug Mode

Enable debug mode for more detailed logging:

```bash
sudo python3 wifi_monitor.py --debug
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [SoapySDR](https://github.com/pothosware/SoapySDR) for SDR support
- [Home Assistant](https://www.home-assistant.io/) for notification integration