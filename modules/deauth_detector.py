#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Deauthentication Attack Detector Module

Uses Scapy to monitor WiFi traffic for deauthentication frames and
detects potential attacks based on frequency thresholds.
"""

import time
import logging
import threading
from collections import deque
from datetime import datetime
import subprocess
import os
import signal
from threading import Event, Thread

try:
    from scapy.all import sniff, Dot11, Dot11Deauth
except ImportError:
    logging.error("Scapy library not found. Please install with: pip install scapy")
    raise

class DeauthDetector(Thread):
    """
    Monitor WiFi traffic for deauthentication attacks.
    
    Attributes:
        interface: WiFi interface in monitor mode
        threshold_count: Number of deauth frames to trigger an alert
        threshold_window: Time window in seconds for threshold
        channel: WiFi channel to monitor (0 for channel hopping)
        channel_hop_interval: Seconds between channel changes when hopping is enabled
        whitelist: List of MAC addresses to ignore (e.g., legitimate APs)
    """
    
    def __init__(self, config, alert_manager, shutdown_event, test_mode=False):
        """Initialize the deauth detector with the provided configuration"""
        super().__init__()
        self.daemon = True
        self.name = "DeauthDetector"
        
        self.interface = config['interface']
        self.threshold_count = config['threshold']['count']
        self.threshold_window = config['threshold']['window']
        self.channel = config['channel']
        self.channel_hop_interval = config['channel_hop_interval']
        self.whitelist = [mac.lower() for mac in config.get('whitelist', [])]
        
        self.alert_manager = alert_manager
        self.shutdown_event = shutdown_event
        self.test_mode = test_mode
        
        # Queue to store recent deauth frames with timestamps
        self.deauth_history = deque(maxlen=1000)  # Store up to 1000 recent frames
        
        # For channel hopping
        self.channel_hop_process = None
        self.sniffer_running = False
        self.sniffer_thread = None
    
    def _hop_channels(self):
        """
        Hop through WiFi channels on the monitoring interface.
        This runs as a separate process to avoid blocking the main thread.
        """
        try:
            while not self.shutdown_event.is_set():
                for channel in range(1, 14):  # 2.4 GHz channels
                    if self.shutdown_event.is_set():
                        break
                    logging.debug(f"Switching to channel {channel}")
                    try:
                        subprocess.run(
                            ["iw", "dev", self.interface, "set", "channel", str(channel)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=True
                        )
                        time.sleep(self.channel_hop_interval)
                    except subprocess.CalledProcessError as e:
                        logging.error(f"Failed to switch to channel {channel}: {e}")
                        time.sleep(1)  # Avoid rapid retries on failure
                
                # Optionally scan 5 GHz channels if needed
                # This would require additional channel definitions
        except Exception as e:
            logging.error(f"Channel hopping error: {e}")
    
    def _is_deauth_packet(self, packet):
        """Check if a packet is a deauthentication frame"""
        return packet.haslayer(Dot11Deauth)
    
    def _should_ignore(self, packet):
        """Check if a packet should be ignored based on whitelist"""
        if not packet.haslayer(Dot11):
            return True
            
        # Extract MAC addresses
        addr1 = packet.addr1.lower() if packet.addr1 else None  # Destination
        addr2 = packet.addr2.lower() if packet.addr2 else None  # Source
        
        # Ignore if either address is in whitelist
        if addr1 in self.whitelist or addr2 in self.whitelist:
            return True
            
        return False
    
    def _packet_handler(self, packet):
        """Process captured packets and detect deauth attacks"""
        if not self._is_deauth_packet(packet) or self._should_ignore(packet):
            return
            
        # Get source and destination MAC addresses
        src = packet.addr2 if packet.addr2 else "Unknown"
        dst = packet.addr1 if packet.addr1 else "Broadcast"
        reason = packet.reason if hasattr(packet, 'reason') else 0
        
        # Record this deauth frame with current timestamp
        now = time.time()
        self.deauth_history.append((now, src, dst, reason))
        
        # Count recent deauth frames within our time window
        cutoff_time = now - self.threshold_window
        recent_count = sum(1 for frame in self.deauth_history if frame[0] >= cutoff_time)
        
        # Log every packet in debug mode
        logging.debug(f"Deauth: {src} -> {dst}, Reason: {reason}, Recent count: {recent_count}")
        
        # Check if we've exceeded the threshold
        if recent_count >= self.threshold_count:
            # Find unique sources of deauth in the window
            deauth_sources = set(frame[1] for frame in self.deauth_history 
                                if frame[0] >= cutoff_time and frame[1] != "Unknown")
            
            # Find unique targets in the window
            deauth_targets = set(frame[2] for frame in self.deauth_history 
                                if frame[0] >= cutoff_time and frame[2] != "Broadcast")
            
            # Create alert data
            alert_data = {
                "event_type": "deauth_attack",
                "timestamp": datetime.utcnow().isoformat(),
                "count": recent_count,
                "window_seconds": self.threshold_window,
                "sources": list(deauth_sources),
                "targets": list(deauth_targets),
                "channel": self.current_channel if hasattr(self, 'current_channel') else "unknown"
            }
            
            # Send alert and reset history to avoid multiple alerts for same event
            self.alert_manager.send_alert(alert_data)
            self.deauth_history.clear()
            
            # Wait a bit before starting to detect again to avoid alert spam
            time.sleep(5)
    
    def _start_packet_sniffer(self):
        """Start packet sniffing on the interface"""
        try:
            logging.info(f"Starting packet sniffer on interface {self.interface}")
            self.sniffer_running = True
            
            if self.test_mode:
                # In test mode, we'll generate fake deauth packets
                self._run_test_mode()
            else:
                # Production mode - actually sniff packets
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=0,  # Don't store packets in memory
                    stop_filter=lambda _: self.shutdown_event.is_set()
                )
            
            self.sniffer_running = False
            logging.info("Packet sniffer stopped")
        except Exception as e:
            self.sniffer_running = False
            logging.error(f"Sniffer error: {e}")
    
    def _run_test_mode(self):
        """
        Simulate deauth packets in test mode.
        This is useful for testing the detection logic without actual attacks.
        """
        logging.warning("Running in TEST MODE - generating simulated deauth packets")
        
        class FakePacket:
            def __init__(self, src, dst, reason=7):
                self.addr1 = dst
                self.addr2 = src
                self.reason = reason
            
            def haslayer(self, layer_type):
                return layer_type == Dot11Deauth
                
        # Test loop
        try:
            while not self.shutdown_event.is_set():
                # Normal background rate - occasional deauths
                if time.time() % 60 < 58:  # 58 seconds of normal behavior
                    if time.time() % 10 < 1:  # Only occasional packets
                        # Simulate occasional legitimate deauth
                        packet = FakePacket("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
                        self._packet_handler(packet)
                    time.sleep(1)
                else:
                    # Simulate attack for 2 seconds every minute
                    logging.info("Test mode: Simulating deauth attack")
                    attacker = "de:ad:be:ef:00:00"
                    victims = ["aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66", "aa:bb:cc:77:88:99"]
                    
                    # Rapid deauth frames
                    for _ in range(20):
                        if self.shutdown_event.is_set():
                            break
                        for victim in victims:
                            packet = FakePacket(attacker, victim)
                            self._packet_handler(packet)
                        time.sleep(0.1)
        except Exception as e:
            logging.error(f"Test mode error: {e}")
    
    def _setup_interface(self):
        """Ensure the interface is in monitor mode"""
        try:
            # Check if interface exists
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            if result.returncode != 0:
                logging.error(f"Interface {self.interface} not found")
                return False
                
            # Check if monitor mode is active
            result = subprocess.run(
                ["iwconfig", self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            if "Mode:Monitor" not in result.stdout.decode('utf-8', errors='ignore'):
                logging.warning(f"Interface {self.interface} not in monitor mode")
                logging.warning("Please enable monitor mode manually with: sudo airmon-ng start <interface>")
                return False
                
            return True
        except Exception as e:
            logging.error(f"Error checking interface: {e}")
            return False
    
    def run(self):
        """Main thread run method"""
        try:
            # Validate interface is ready
            if not self.test_mode and not self._setup_interface():
                logging.error("Interface setup failed. Exiting deauth detector.")
                logging.error(f"Interface {self.interface} is not in monitor mode.")
                logging.error("Please put your interface in monitor mode manually with:")
                logging.error(f"    sudo ip link set {self.interface} down")
                logging.error(f"    sudo iw dev {self.interface} set type monitor")
                logging.error(f"    sudo ip link set {self.interface} up")
                return
                
            # Set fixed channel if specified, otherwise start channel hopping
            if self.channel > 0 and not self.test_mode:
                logging.info(f"Setting fixed channel {self.channel}")
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(self.channel)],
                    check=True
                )
                self.current_channel = self.channel
            elif not self.test_mode:
                # Start channel hopping in a separate thread
                logging.info("Starting channel hopping")
                channel_hop_thread = threading.Thread(target=self._hop_channels)
                channel_hop_thread.daemon = True
                channel_hop_thread.start()
            
            # Start packet sniffer
            self._start_packet_sniffer()
            
        except Exception as e:
            logging.error(f"Deauth detector error: {e}")
    
    def stop(self):
        """Stop the detector cleanly"""
        logging.info("Stopping deauth detector...")
        # The shutdown event should stop the sniffer and channel hopping
        
        # Wait up to 5 seconds for sniffer to stop
        start_time = time.time()
        while self.sniffer_running and time.time() - start_time < 5:
            time.sleep(0.1)
            
        logging.info("Deauth detector stopped")