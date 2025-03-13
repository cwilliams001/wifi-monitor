#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WiFi Attack Monitoring System

This program detects WiFi deauthentication attacks and jamming attempts
using a monitor-mode WiFi adapter and optional Software Defined Radio.
"""

import os
import sys
import time
import signal
import logging
import yaml
import argparse
from pathlib import Path
from threading import Event

# Import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from modules.alert_manager import AlertManager
from modules.utils import setup_logging, ensure_directory, get_device_info

# Global shutdown event
shutdown_event = Event()

def signal_handler(signum, frame):
    """Handle termination signals gracefully"""
    logging.info("Received termination signal, shutting down...")
    shutdown_event.set()

def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        sys.exit(1)

def main():
    """Main entry point for the WiFi attack monitoring system"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='WiFi Attack Monitoring System')
    parser.add_argument('-c', '--config', default='config.yaml', help='Path to configuration file')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-t', '--test', action='store_true', help='Run in test mode (simulated attacks)')
    parser.add_argument('--ignore-deps', action='store_true', help='Ignore missing dependencies')
    parser.add_argument('--no-sdr', action='store_true', help='Disable SDR functionality')
    parser.add_argument('--no-deauth', action='store_true', help='Disable deauth detection')
    parser.add_argument('--web-only', action='store_true', help='Run only the web interface')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)
    
    # Override debug setting if specified in command line
    if args.debug:
        config['general']['debug_mode'] = True

    # Setup logging
    log_dir = config['general']['log_directory']
    ensure_directory(log_dir)
    setup_logging(log_dir, debug=config['general']['debug_mode'])
    
    # Disable components based on command line flags
    if args.no_sdr:
        config['jamming_detection']['enabled'] = False
        logging.info("SDR functionality disabled via command line")
    
    if args.no_deauth:
        config['deauth_detection']['enabled'] = False
        logging.info("Deauth detection disabled via command line")
        
    if args.web_only:
        config['deauth_detection']['enabled'] = False
        config['jamming_detection']['enabled'] = False
        logging.info("Running in web-only mode")

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize alert manager for logging and notifications
    alert_manager = AlertManager(config['alerts'], log_dir, config['general']['nas_offload'])
    
    # Initialize active modules based on configuration
    modules = []
    
    # Try to import and initialize modules with better error handling
    
    # Web UI
    web_ui = None
    if 'web_ui' in config and config['web_ui'].get('enabled', False):
        try:
            from modules.web_ui import WebUI, update_module_status, update_system_info
            
            # Get system information for Web UI
            system_info = get_device_info()
            update_system_info(system_info)
            
            logging.info("Initializing Web UI...")
            web_ui_config = config['web_ui']
            web_ui_config['log_directory'] = log_dir
            web_ui_config['config_file'] = args.config
            
            web_ui = WebUI(
                web_ui_config,
                shutdown_event
            )
            modules.append(web_ui)
            update_module_status("WebUI", "Running")
        except ImportError:
            logging.error("Web UI module not found. Continuing without Web UI.")
        except Exception as e:
            logging.error(f"Failed to initialize Web UI: {e}")
    
    # Deauth detector
    if config['deauth_detection']['enabled']:
        try:
            from modules.deauth_detector import DeauthDetector
            
            logging.info("Initializing WiFi deauthentication detector...")
            deauth_detector = DeauthDetector(
                config['deauth_detection'],
                alert_manager,
                shutdown_event,
                test_mode=args.test
            )
            modules.append(deauth_detector)
            if 'update_module_status' in locals():
                update_module_status("DeauthDetector", "Running")
        except ImportError:
            logging.error("Deauth detector module not found. Continuing without deauth detection.")
        except Exception as e:
            import traceback
            logging.error(f"Failed to initialize deauth detector: {e}")
            logging.error(f"Detailed error: {traceback.format_exc()}")
    
    # Spectrum analyzer
    if config['jamming_detection']['enabled'] and not args.no_sdr:
        try:
            from modules.spectrum_analyzer import SpectrumAnalyzer
            
            logging.info("Initializing RF spectrum analyzer...")
            spectrum_analyzer = SpectrumAnalyzer(
                config['jamming_detection'],
                alert_manager,
                shutdown_event,
                test_mode=args.test
            )
            modules.append(spectrum_analyzer)
            if 'update_module_status' in locals():
                update_module_status("SpectrumAnalyzer", "Running")
        except ImportError:
            logging.error("Spectrum analyzer module not found. Continuing without SDR functionality.")
        except Exception as e:
            logging.error(f"Failed to initialize spectrum analyzer: {e}")
    
    # Check if we have any active modules
    if not modules:
        logging.error("No active modules. Exiting.")
        sys.exit(1)
    
    # Start all modules
    for module in modules:
        module.start()
    
    logging.info("WiFi Attack Monitoring System started")
    
    # If Web UI is running, log the access URL
    if web_ui:
        host = config['web_ui'].get('host', '0.0.0.0')
        port = config['web_ui'].get('port', 8080)
        if host == '0.0.0.0':
            logging.info(f"Web UI is accessible at: http://[your-ip-address]:{port}")
        else:
            logging.info(f"Web UI is accessible at: http://{host}:{port}")
    
    # Main loop - we just wait for shutdown signal
    try:
        while not shutdown_event.is_set():
            time.sleep(1)
    except Exception as e:
        logging.error(f"Error in main loop: {e}")
    finally:
        # Shutdown procedure
        logging.info("Shutting down WiFi Attack Monitoring System...")
        for module in modules:
            try:
                module.stop()
            except Exception as e:
                logging.error(f"Error stopping module {module.__class__.__name__}: {e}")
        
        # Final cleanup
        alert_manager.shutdown()
        logging.info("Shutdown complete")

if __name__ == "__main__":
    main()
