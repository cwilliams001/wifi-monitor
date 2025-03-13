#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility functions for the WiFi Attack Monitoring System.
"""

import os
import sys
import logging
import platform
import subprocess
import importlib
from pathlib import Path
from datetime import datetime

def setup_logging(log_dir, debug=False):
    """
    Configure logging for the application.
    
    Args:
        log_dir: Directory to store log files
        debug: Enable debug logging if True
    """
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up log file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d")
    log_file = os.path.join(log_dir, f"wifi_monitor_{timestamp}.log")
    
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Root logger configuration
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Log system information
    logging.info(f"WiFi Attack Monitoring System starting")
    logging.info(f"System: {platform.system()} {platform.release()}")
    logging.info(f"Architecture: {platform.machine()}")
    logging.info(f"Python: {platform.python_version()}")
    logging.info(f"Log level: {'DEBUG' if debug else 'INFO'}")
    
    return log_file

def check_dependencies(sdr_enabled=True, sdr_device=None):
    """
    Check if required dependencies are available.
    
    Args:
        sdr_enabled: Whether SDR functionality is enabled
        sdr_device: Type of SDR device ('hackrf' or 'b205')
        
    Returns:
        bool: True if all required dependencies are available
    """
    missing = []
    
    # Check Python dependencies
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    
    # Check system tools
    required_tools = ['iw', 'iwconfig']
    
    if sdr_enabled:
        if sdr_device == 'hackrf':
            required_tools.append('hackrf_info')
        elif sdr_device == 'b205':
            required_tools.append('uhd_find_devices')
    
    for tool in required_tools:
        try:
            subprocess.run(
                ['which', tool],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
        except subprocess.CalledProcessError:
            missing.append(tool)
    
    # Log results
    if missing:
        logging.error(f"Missing dependencies: {', '.join(missing)}")
        return False
    else:
        logging.debug("All required dependencies found")
        return True

def ensure_directory(directory):
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory: Path to the directory
        
    Returns:
        bool: True if directory exists/was created, False on error
    """
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Failed to create directory {directory}: {e}")
        return False

def check_monitor_mode(interface):
    """
    Check if a wireless interface is in monitor mode.
    
    Args:
        interface: Name of the wireless interface
        
    Returns:
        bool: True if the interface is in monitor mode
    """
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
        
        if result.returncode != 0:
            logging.error(f"Interface {interface} not found")
            return False
            
        output = result.stdout.decode('utf-8', errors='ignore')
        return 'Mode:Monitor' in output
    except Exception as e:
        logging.error(f"Error checking monitor mode: {e}")
        return False

def set_monitor_mode(interface):
    """
    Attempt to set an interface to monitor mode.
    
    Args:
        interface: Name of the wireless interface
        
    Returns:
        bool: True if monitor mode was enabled successfully
    """
    try:
        # Check if already in monitor mode
        if check_monitor_mode(interface):
            logging.debug(f"Interface {interface} already in monitor mode")
            return True
            
        # Try using airmon-ng
        try:
            logging.info(f"Setting {interface} to monitor mode using airmon-ng")
            subprocess.run(
                ['airmon-ng', 'start', interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
        except subprocess.CalledProcessError:
            # Fallback to using iw
            logging.info(f"Setting {interface} to monitor mode using iw")
            
            # First, bring interface down
            subprocess.run(
                ['ip', 'link', 'set', interface, 'down'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            
            # Set monitor mode
            subprocess.run(
                ['iw', 'dev', interface, 'set', 'type', 'monitor'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            
            # Bring interface back up
            subprocess.run(
                ['ip', 'link', 'set', interface, 'up'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
        
        # Verify monitor mode was enabled
        return check_monitor_mode(interface)
    except Exception as e:
        logging.error(f"Failed to set monitor mode: {e}")
        return False

def is_root():
    """
    Check if the script is running with root privileges.
    
    Returns:
        bool: True if running as root
    """
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def human_readable_size(size, decimal_places=2):
    """
    Convert bytes to a human-readable format.
    
    Args:
        size: Size in bytes
        decimal_places: Number of decimal places to display
        
    Returns:
        str: Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PB':
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

def get_device_info():
    """
    Get system and device information.
    
    Returns:
        dict: Dictionary of system information
    """
    info = {
        'system': platform.system(),
        'release': platform.release(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'hostname': platform.node()
    }
    
    # Get CPU info
    try:
        if platform.system() == 'Linux':
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        info['cpu'] = line.split(':', 1)[1].strip()
                        break
    except Exception:
        info['cpu'] = 'Unknown'
    
    # Get memory info
    try:
        if platform.system() == 'Linux':
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal'):
                        mem_kb = int(line.split()[1])
                        info['memory'] = human_readable_size(mem_kb * 1024)
                        break
    except Exception:
        info['memory'] = 'Unknown'
    
    return info
