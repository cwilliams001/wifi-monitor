#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Alert Manager Module

Handles logging of detection events and sending alerts to configured endpoints.
"""

import os
import json
import time
import logging
import threading
import requests
from datetime import datetime
from pathlib import Path
import subprocess
import shutil
from queue import Queue

# Import will be ignored if web_ui doesn't exist yet during first import
try:
    from modules.web_ui import update_module_status
    WEB_UI_AVAILABLE = True
except ImportError:
    WEB_UI_AVAILABLE = False

class AlertManager:
    """
    Manages alert logging and notification delivery.
    
    Responsibilities:
    - Log detected events to disk
    - Send alerts to configured web server and/or Home Assistant
    - Handle retries and error conditions
    - Offload logs to NAS if configured
    """
    
    def __init__(self, alert_config, log_dir, nas_config):
        """Initialize the alert manager with the provided configuration"""
        self.alert_config = alert_config
        self.log_dir = log_dir
        self.nas_config = nas_config
        
        # Initialize the shutdown flag before starting any threads
        self.shutdown_requested = threading.Event()
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Alert event log file
        self.event_log_path = os.path.join(self.log_dir, "attack_events.json")
        
        # Alert queue for threaded processing
        self.alert_queue = Queue()
        
        # Create threads but don't start them yet
        self.alert_thread = threading.Thread(target=self._process_alert_queue)
        self.alert_thread.daemon = True
        
        # NAS offload thread if enabled
        if nas_config and nas_config.get('enabled', False):
            self.nas_thread = threading.Thread(target=self._offload_logs_loop)
            self.nas_thread.daemon = True
        else:
            self.nas_thread = None
            
        # Now start threads after all initialization is complete
        self.alert_thread.start()
        if self.nas_thread:
            self.nas_thread.start()
        
        logging.info("Alert manager initialized")
    
    def send_alert(self, alert_data):
        """
        Send an alert for a detected attack.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        # Add alert to the queue for async processing
        self.alert_queue.put(alert_data)
        
        # Also log immediately for visibility
        logging.warning(f"ALERT: {alert_data['event_type']} - {alert_data['timestamp']}")
        
        # Directly notify web UI for immediate display (in addition to queue)
        try:
            self._notify_web_ui(alert_data)
            logging.debug(f"Sent alert directly to Web UI: {alert_data['event_type']}")
        except Exception as e:
            logging.debug(f"Failed to send direct alert to Web UI: {e}")
    
    def _notify_web_ui(self, alert_data):
        """
        Notify the Web UI of a new alert.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        if WEB_UI_AVAILABLE:
            try:
                # Send alert to Web UI via local API
                response = requests.post(
                    'http://127.0.0.1:8080/api/alert',
                    json=alert_data,
                    timeout=1
                )
                logging.debug(f"Web UI notification response: {response.status_code}")
                return response.status_code < 400
            except Exception as e:
                # Log errors for debugging
                logging.debug(f"Failed to notify Web UI: {e}")
                return False
        return False
                
    def _log_to_file(self, alert_data):
        """
        Log an alert to the local event log file.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        try:
            # Append to the JSON log file
            with open(self.event_log_path, 'a+') as f:
                # If file is new/empty, start with an opening bracket
                f.seek(0, os.SEEK_END)
                if f.tell() == 0:
                    f.write('[\n')
                else:
                    # Not empty - go back and check for closing bracket
                    f.seek(max(0, f.tell() - 2), os.SEEK_SET)
                    last_chars = f.read(2)
                    # If the last char is ], we need to remove it and add a comma
                    if last_chars.endswith(']'):
                        f.seek(max(0, f.tell() - 1), os.SEEK_SET)
                        f.truncate()
                        f.write(',\n')
                    else:
                        # It's a new entry after an existing one
                        f.write(',\n')
                
                # Write the alert data
                json.dump(alert_data, f, indent=2)
                f.write('\n]')  # Close the JSON array
                
            logging.debug(f"Alert logged to file: {self.event_log_path}")
            
            # Notify Web UI if available
            self._notify_web_ui(alert_data)
            
            return True
        except Exception as e:
            logging.error(f"Error logging alert to file: {e}")
            return False
    
    def _send_to_web_server(self, alert_data):
        """
        Send alert to the configured web server.
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            bool: Whether the alert was successfully sent
        """
        if not self.alert_config['web_server'].get('enabled', False):
            return True  # Silently succeed if disabled
            
        web_config = self.alert_config['web_server']
        url = web_config['url']
        auth_token = web_config.get('auth_token')
        timeout = web_config.get('timeout', 5)
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        max_attempts = self.alert_config['retry'].get('max_attempts', 3)
        delay = self.alert_config['retry'].get('delay', 5)
        
        # Attempt to send alert with retries
        for attempt in range(max_attempts):
            try:
                response = requests.post(
                    url,
                    json=alert_data,
                    headers=headers,
                    timeout=timeout
                )
                
                if response.status_code < 400:  # Any successful status code
                    logging.info(f"Alert sent to web server successfully: {response.status_code}")
                    return True
                else:
                    logging.warning(f"Failed to send alert to web server: HTTP {response.status_code}")
            except requests.RequestException as e:
                logging.warning(f"Error sending alert to web server (attempt {attempt+1}/{max_attempts}): {e}")
            
            # Don't sleep after the last attempt
            if attempt < max_attempts - 1:
                time.sleep(delay)
        
        logging.error(f"Failed to send alert to web server after {max_attempts} attempts")
        return False
    
    def _send_to_home_assistant(self, alert_data):
        """
        Send alert to Home Assistant webhook.
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            bool: Whether the alert was successfully sent
        """
        ha_config = self.alert_config['home_assistant']
        
        # Skip if Home Assistant integration is disabled
        if not ha_config.get('enabled', False):
            return True
            
        # If not using direct webhook, we assume the web server forwards to HA
        if not ha_config.get('direct_webhook', False):
            return True
            
        url = ha_config['webhook_url']
        max_attempts = self.alert_config['retry'].get('max_attempts', 3)
        delay = self.alert_config['retry'].get('delay', 5)
        
        # Format data for HA webhook - simplify for webhook consumption
        webhook_data = {
            'event_type': alert_data['event_type'],
            'timestamp': alert_data['timestamp'],
            'details': json.dumps(alert_data)  # Include full details as a JSON string
        }
        
        # Attempt to send webhook with retries
        for attempt in range(max_attempts):
            try:
                response = requests.post(
                    url,
                    json=webhook_data,
                    timeout=5
                )
                
                if response.status_code < 400:
                    logging.info("Alert sent to Home Assistant webhook successfully")
                    return True
                else:
                    logging.warning(f"Failed to send alert to Home Assistant: HTTP {response.status_code}")
            except requests.RequestException as e:
                logging.warning(f"Error sending alert to Home Assistant (attempt {attempt+1}/{max_attempts}): {e}")
            
            # Don't sleep after the last attempt
            if attempt < max_attempts - 1:
                time.sleep(delay)
        
        logging.error(f"Failed to send alert to Home Assistant after {max_attempts} attempts")
        return False
    
    def _process_alert_queue(self):
        """
        Process alerts from the queue in a background thread.
        This ensures alert sending doesn't block the detection threads.
        """
        # Small delay to ensure proper initialization
        time.sleep(0.1)
        
        while True:
            try:
                # Check for shutdown and empty queue
                if hasattr(self, 'shutdown_requested') and self.shutdown_requested.is_set() and self.alert_queue.empty():
                    break
                    
                # Get an alert from the queue, with timeout to check shutdown flag periodically
                try:
                    alert_data = self.alert_queue.get(timeout=1.0)
                except Exception:
                    # Timeout is expected, just continue the loop
                    continue
                
                # Process this alert
                try:
                    # First log locally - this is most important
                    self._log_to_file(alert_data)
                    
                    # Then try to send to external systems
                    web_server_success = self._send_to_web_server(alert_data)
                    ha_success = self._send_to_home_assistant(alert_data)
                    
                    if not (web_server_success or ha_success):
                        logging.warning("Failed to send alert to any configured destination")
                        
                    # Mark task as done in the queue
                    self.alert_queue.task_done()
                except Exception as e:
                    logging.error(f"Error processing alert: {e}")
            except Exception as e:
                logging.error(f"Error in alert queue processing: {e}")
    
    def _offload_logs_to_nas(self):
        """
        Copy log files to NAS if configured.
        """
        if not self.nas_config or not self.nas_config.get('enabled', False):
            return
            
        nas_path = self.nas_config['path']
        
        # Ensure NAS directory exists
        try:
            os.makedirs(nas_path, exist_ok=True)
        except Exception as e:
            logging.error(f"Failed to create NAS directory {nas_path}: {e}")
            return
            
        # Timestamp for this backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Copy event log file if it exists
        if os.path.exists(self.event_log_path) and os.path.getsize(self.event_log_path) > 0:
            try:
                # Destination filename includes timestamp
                dest_file = os.path.join(
                    nas_path, 
                    f"attack_events_{timestamp}.json"
                )
                
                shutil.copy2(self.event_log_path, dest_file)
                logging.info(f"Logs offloaded to NAS: {dest_file}")
            except Exception as e:
                logging.error(f"Failed to copy logs to NAS: {e}")
    
    def _offload_logs_loop(self):
        """
        Background thread for periodic log offloading to NAS.
        """
        # Determine offload frequency
        schedule = self.nas_config.get('schedule', 'daily').lower()
        
        if schedule == 'realtime':
            interval = 10  # Check every 10 seconds
        elif schedule == 'hourly':
            interval = 3600  # Check every hour
        else:  # daily or any other value
            interval = 86400  # Check every day
            
        logging.info(f"NAS log offload scheduled: {schedule} (every {interval} seconds)")
        
        while not self.shutdown_requested.is_set():
            try:
                # Sleep between offloads, checking shutdown flag periodically
                for _ in range(int(interval / 10)):
                    if self.shutdown_requested.is_set():
                        break
                    time.sleep(10)
                
                if self.shutdown_requested.is_set():
                    break
                    
                # Perform the offload
                self._offload_logs_to_nas()
                
            except Exception as e:
                logging.error(f"Error in NAS offload loop: {e}")
                time.sleep(60)  # Wait a minute and retry
    
    def shutdown(self):
        """Perform clean shutdown of the alert manager"""
        logging.info("Shutting down alert manager...")
        
        # Signal threads to stop
        self.shutdown_requested.set()
        
        # Process any remaining alerts in the queue
        if not self.alert_queue.empty():
            logging.info(f"Processing {self.alert_queue.qsize()} remaining alerts...")
            self.alert_queue.join()
            
        # Final NAS offload before shutdown
        if self.nas_config and self.nas_config.get('enabled', False):
            logging.info("Performing final NAS offload...")
            self._offload_logs_to_nas()
            
        logging.info("Alert manager shutdown complete")