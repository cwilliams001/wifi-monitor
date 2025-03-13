#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spectrum Analyzer Module

Uses Software Defined Radio (SDR) to scan RF spectrum for jamming signals
in WiFi frequency bands.
"""

import time
import logging
import threading
import numpy as np
from threading import Thread, Event
from datetime import datetime
import json
import os
from pathlib import Path
import random

# Set UHD_IMAGES_DIR environment variable if not already set
if 'UHD_IMAGES_DIR' not in os.environ:
    os.environ['UHD_IMAGES_DIR'] = '/usr/share/uhd/images'
    logging.info(f"Setting UHD_IMAGES_DIR to {os.environ['UHD_IMAGES_DIR']}")

# Try to import SoapySDR
try:
    import SoapySDR
    from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_CF32
    SOAPYSDR_AVAILABLE = True
except ImportError:
    SOAPYSDR_AVAILABLE = False
    logging.warning("SoapySDR not found. SDR functions will be disabled.")

class SpectrumAnalyzer(Thread):
    """
    Analyze RF spectrum to detect jamming signals using an SDR.
    
    Attributes:
        sdr_device: Type of SDR ('hackrf' or 'b205')
        scan_bands: List of frequency bands to scan
        sample_rate: SDR sample rate
        fft_size: Size of FFT for spectrum analysis
        threshold_relative_db: Power threshold above baseline to trigger alert
        threshold_duration: Duration of threshold crossing to confirm jamming
        calibration_enabled: Whether to calibrate baseline
        calibration_interval: Time between baseline calibrations
    """
    
    def __init__(self, config, alert_manager, shutdown_event, test_mode=False):
        """Initialize the spectrum analyzer with the provided configuration"""
        super().__init__()
        self.daemon = True
        self.name = "SpectrumAnalyzer"
        
        # Store config and dependencies
        self.config = config
        self.alert_manager = alert_manager
        self.shutdown_event = shutdown_event
        self.test_mode = test_mode
        
        # Extract configuration values
        self.sdr_device = config['sdr_device']
        self.scan_bands = config['scan_bands']
        self.sample_rate = config['sample_rate']
        self.fft_size = config['fft_size']
        self.threshold_relative_db = config['threshold']['relative_db']
        self.threshold_duration = config['threshold']['duration']
        self.calibration_enabled = config['calibration']['enabled']
        self.calibration_interval = config['calibration']['interval']
        
        # Initialize state variables
        self.sdr = None
        self.baselines = {}  # Baseline power levels by frequency
        self.jamming_start_times = {}  # Track when jamming started at each frequency
        self.calibration_time = 0  # Time of last calibration
        
        # Create a directory for storing spectrum data
        self.data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "spectrum_data"
        )
        Path(self.data_dir).mkdir(exist_ok=True)
        
        # Load any saved baselines
        self._load_baselines()
        
        # Initialize SDR device
        if not self.test_mode:
            self._init_sdr()
    
    def _init_sdr(self):
        """Initialize the SDR device"""
        if not SOAPYSDR_AVAILABLE:
            logging.error("SoapySDR not available. Cannot initialize SDR.")
            return False
            
        try:
            # List available devices
            devices = SoapySDR.Device.enumerate()
            if not devices:
                logging.error("No SDR devices found")
                return False
                
            # Find a matching device
            device_found = False
            for device_info in devices:
                logging.debug(f"Found SDR: {device_info}")
                
                # Check if this matches our configured device
                if self.sdr_device.lower() == 'hackrf' and 'hackrf' in device_info.get('driver', '').lower():
                    device_found = True
                    break
                elif self.sdr_device.lower() == 'b205' and ('b205' in device_info.get('driver', '').lower() or 'uhd' in device_info.get('driver', '').lower()):
                    device_found = True
                    break
            
            if not device_found:
                logging.error(f"Configured SDR device '{self.sdr_device}' not found")
                return False
                
            # Create device instance
            self.sdr = SoapySDR.Device(device_info)
            
            # Configure SDR settings
            self.sdr.setSampleRate(SOAPY_SDR_RX, 0, self.sample_rate)
            
            # Set reasonable gain based on device type
            if self.sdr_device.lower() == 'hackrf':
                self.sdr.setGain(SOAPY_SDR_RX, 0, 'LNA', 32)  # HackRF LNA gain
                self.sdr.setGain(SOAPY_SDR_RX, 0, 'VGA', 20)  # HackRF VGA gain
            else:
                # For B205 or other devices, set a mid-range gain
                self.sdr.setGain(SOAPY_SDR_RX, 0, 40)  # General gain setting
            
            logging.info(f"SDR initialized: {self.sdr_device}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize SDR: {e}")
            self.sdr = None
            return False
    
    def _save_baselines(self):
        """Save baseline power levels to a file"""
        try:
            baseline_file = os.path.join(self.data_dir, "baselines.json")
            with open(baseline_file, 'w') as f:
                json.dump(self.baselines, f, indent=2)
            logging.debug(f"Saved baseline data to {baseline_file}")
        except Exception as e:
            logging.error(f"Failed to save baseline data: {e}")
    
    def _load_baselines(self):
        """Load baseline power levels from a file"""
        try:
            baseline_file = os.path.join(self.data_dir, "baselines.json")
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    self.baselines = json.load(f)
                logging.info(f"Loaded baseline data from {baseline_file}")
                return True
            else:
                logging.info("No saved baseline data found. Will calibrate during operation.")
                return False
        except Exception as e:
            logging.error(f"Failed to load baseline data: {e}")
            return False
    
    def _scan_frequency(self, freq_hz):
        """
        Scan a specific frequency and return the power level.
        
        Args:
            freq_hz: Frequency to scan in Hz
            
        Returns:
            float: Power level in dBm, or None on error
        """
        if self.test_mode:
            return self._simulate_scan(freq_hz)
            
        if not self.sdr:
            logging.error("SDR not initialized")
            return None
            
        try:
            # Set the SDR to the target frequency
            self.sdr.setFrequency(SOAPY_SDR_RX, 0, freq_hz)
            
            # Create a buffer for samples
            buff = np.zeros(self.fft_size * 2, np.complex64)
            rxStream = self.sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32)
            self.sdr.activateStream(rxStream)
            
            # Read samples
            sr = self.sdr.readStream(rxStream, [buff], len(buff))
            self.sdr.deactivateStream(rxStream)
            self.sdr.closeStream(rxStream)
            
            if sr.ret < 0:
                logging.warning(f"Error reading from SDR: {sr.ret}")
                return None
                
            # Convert to numpy array of complex values
            samples = buff[:sr.ret]
            
            # Calculate power spectral density using FFT
            psd = np.abs(np.fft.fftshift(np.fft.fft(samples)))**2
            
            # Convert to dBm (approximate)
            psd_db = 10 * np.log10(np.mean(psd))
            
            return psd_db
            
        except Exception as e:
            logging.error(f"Error scanning frequency {freq_hz/1e6} MHz: {e}")
            return None
    
    def _simulate_scan(self, freq_hz):
        """
        Simulate SDR scan for test mode.
        
        Args:
            freq_hz: Frequency being simulated
            
        Returns:
            float: Simulated power level in dBm
        """
        # Get or create a baseline for this frequency
        freq_key = f"{int(freq_hz/1e6)}"
        baseline = self.baselines.get(freq_key, -85 - random.uniform(0, 10))
        
        # Check if we should simulate a jamming attack
        # For testing, we'll create a jamming pattern on 2.4 GHz every few minutes
        is_2_4ghz = 2400e6 <= freq_hz <= 2500e6
        current_minute = time.time() // 60
        simulate_jamming = is_2_4ghz and (current_minute % 5 == 0)  # Every 5 minutes
        
        if simulate_jamming:
            # Simulate high power jamming signal
            power = baseline + self.threshold_relative_db + random.uniform(5, 15)
            if freq_key not in self.jamming_start_times:
                logging.debug(f"TEST MODE: Simulating jamming at {freq_key} MHz")
                self.jamming_start_times[freq_key] = time.time()
        else:
            # Normal variation around baseline
            power = baseline + random.uniform(-3, 3)
            if freq_key in self.jamming_start_times:
                del self.jamming_start_times[freq_key]
                
        return power
    
    def _calibrate_baseline(self, force=False):
        """
        Calibrate the baseline power levels for all scan bands.
        
        Args:
            force: Force recalibration even if the interval hasn't elapsed
        """
        current_time = time.time()
        
        # Check if calibration is due
        if not force and self.calibration_time > 0:
            if current_time - self.calibration_time < self.calibration_interval:
                return
                
        logging.info("Calibrating RF baseline power levels...")
        
        # Scan each band and record baseline power
        for band in self.scan_bands:
            start_freq = band['start_freq']
            end_freq = band['end_freq']
            step = band['step']
            
            freq = start_freq
            while freq <= end_freq:
                freq_key = f"{int(freq/1e6)}"
                
                # Take multiple samples and average them
                samples = []
                for _ in range(3):  # Take 3 samples
                    power = self._scan_frequency(freq)
                    if power is not None:
                        samples.append(power)
                    time.sleep(0.1)
                
                # Calculate average if we have samples
                if samples:
                    avg_power = sum(samples) / len(samples)
                    self.baselines[freq_key] = avg_power
                    logging.debug(f"Calibrated {freq_key} MHz: {avg_power:.2f} dBm")
                
                freq += step
                
                # Check for shutdown request
                if self.shutdown_event.is_set():
                    break
            
            if self.shutdown_event.is_set():
                break
        
        # Save calibration data
        self._save_baselines()
        
        # Update calibration timestamp
        self.calibration_time = current_time
        logging.info("Baseline calibration complete")
    
    def _check_for_jamming(self, freq_hz, power):
        """
        Check if a power reading indicates jamming.
        
        Args:
            freq_hz: Frequency in Hz
            power: Measured power in dBm
            
        Returns:
            bool: True if jamming is detected at this frequency
        """
        freq_key = f"{int(freq_hz/1e6)}"
        
        # Get baseline for this frequency
        baseline = self.baselines.get(freq_key)
        
        # If no baseline, return False
        if baseline is None:
            return False
            
        # Check if power exceeds threshold
        if power > baseline + self.threshold_relative_db:
            logging.debug(f"High power at {freq_key} MHz: {power:.2f} dBm (baseline: {baseline:.2f} dBm)")
            
            # Record when we first saw this potential jamming signal
            if freq_key not in self.jamming_start_times:
                self.jamming_start_times[freq_key] = time.time()
                
            # Check if it has persisted long enough to trigger an alert
            jamming_duration = time.time() - self.jamming_start_times[freq_key]
            if jamming_duration >= self.threshold_duration:
                logging.info(f"Jamming detected at {freq_key} MHz: {power:.2f} dBm, {jamming_duration:.1f}s above threshold")
                return True
        else:
            # Reset the timer if power drops below threshold
            if freq_key in self.jamming_start_times:
                del self.jamming_start_times[freq_key]
                
        return False
    
    def _get_band_name(self, freq_hz):
        """
        Get the band name for a frequency.
        
        Args:
            freq_hz: Frequency in Hz
            
        Returns:
            str: Band name (e.g., "2.4GHz", "5GHz")
        """
        for band in self.scan_bands:
            if band['start_freq'] <= freq_hz <= band['end_freq']:
                return band['name']
        return "Unknown"
    
    def _scan_bands(self):
        """Scan all configured frequency bands for jamming signals"""
        # Track frequencies with jamming for this scan cycle
        jamming_freqs = []
        
        # Check for calibration interval
        if self.calibration_enabled and time.time() - self.calibration_time >= self.calibration_interval:
            self._calibrate_baseline()
        
        # Scan each band
        for band in self.scan_bands:
            band_name = band['name']
            start_freq = band['start_freq']
            end_freq = band['end_freq']
            step = band['step']
            
            logging.debug(f"Scanning {band_name} band ({start_freq/1e6}-{end_freq/1e6} MHz)")
            
            # Track jamming in this band
            band_jamming = False
            affected_frequencies = []
            max_power = -float('inf')
            max_freq = 0
            
            # Scan frequencies in this band
            freq = start_freq
            while freq <= end_freq:
                # Check for shutdown
                if self.shutdown_event.is_set():
                    return
                
                # Scan this frequency
                power = self._scan_frequency(freq)
                
                if power is not None:
                    # Track maximum power in this band
                    if power > max_power:
                        max_power = power
                        max_freq = freq
                    
                    # Check for jamming at this frequency
                    if self._check_for_jamming(freq, power):
                        band_jamming = True
                        affected_frequencies.append(int(freq/1e6))
                        jamming_freqs.append(freq)
                
                # Move to next frequency
                freq += step
            
            # If jamming is detected in this band, send an alert
            if band_jamming:
                logging.warning(f"Jamming activity detected in {band_name} band")
                
                # Prepare alert data
                alert_data = {
                    "event_type": "jamming_attack",
                    "timestamp": datetime.utcnow().isoformat(),
                    "band": band_name,
                    "affected_frequencies_mhz": affected_frequencies,
                    "max_power_dbm": max_power,
                    "threshold_dbm": self.baselines.get(f"{int(max_freq/1e6)}", -100) + self.threshold_relative_db,
                    "baseline_dbm": self.baselines.get(f"{int(max_freq/1e6)}", -100)
                }
                
                # Send the alert
                self.alert_manager.send_alert(alert_data)
                
                # Wait to avoid alert spam
                time.sleep(10)
        
        # Return list of frequencies with jamming
        return jamming_freqs
    
    def run(self):
        """Main thread run method"""
        try:
            logging.info("Spectrum analyzer starting")
            
            # Immediate calibration on startup if enabled
            if self.calibration_enabled:
                self._calibrate_baseline(force=True)
            
            # Main monitoring loop
            while not self.shutdown_event.is_set():
                try:
                    # Scan for jamming
                    self._scan_bands()
                    
                    # Brief pause before next scan
                    time.sleep(1)
                except Exception as e:
                    logging.error(f"Error in spectrum scan: {e}")
                    time.sleep(5)  # Wait before retry
            
            logging.info("Spectrum analyzer stopping")
            
        except Exception as e:
            logging.error(f"Spectrum analyzer error: {e}")
        finally:
            # Clean up SDR resources
            self._cleanup_sdr()
    
    def _cleanup_sdr(self):
        """Clean up SDR resources"""
        if self.sdr:
            try:
                del self.sdr
                self.sdr = None
                logging.debug("SDR resources released")
            except Exception as e:
                logging.error(f"Error cleaning up SDR: {e}")
    
    def stop(self):
        """Stop the spectrum analyzer cleanly"""
        logging.info("Stopping spectrum analyzer...")
        self._cleanup_sdr()
        logging.info("Spectrum analyzer stopped")
