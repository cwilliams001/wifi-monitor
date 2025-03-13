#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web UI Module for WiFi Attack Monitoring System

Provides a web-based dashboard to monitor system status,
view detected attacks, and check configuration.
"""

import os
import json
import time
import logging
import threading
import socketserver
from datetime import datetime, timedelta
from pathlib import Path
import yaml
from functools import wraps

from flask import Flask, render_template, jsonify, request, redirect, url_for, Response, abort, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

# Create Flask application
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "../templates"),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "../static"))

# Global state tracking
class SystemState:
    def __init__(self):
        self.modules_status = {}
        self.last_events = []
        self.system_info = {}
        self.start_time = time.time()
        self.spectrum_data = []
        self.attack_history = []
        self.deauth_counts = [0] * 60  # Last 60 10-second intervals of deauth counts
        self.deauth_threshold = 10  # Default threshold, gets updated from config

# Initialize global state
system_state = SystemState()

# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_enabled = app.config.get('AUTH_ENABLED', False)
        
        if not auth_enabled:
            return f(*args, **kwargs)
            
        auth = request.authorization
        if not auth or not check_password_hash(app.config.get('PASSWORD_HASH', ''), auth.password):
            return Response(
                'Authentication required', 401,
                {'WWW-Authenticate': 'Basic realm="WiFi Monitor Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@requires_auth
def index():
    """Main dashboard page"""
    return render_template('index.html', 
                          system_state=system_state,
                          uptime=format_uptime(time.time() - system_state.start_time))

@app.route('/status')
@requires_auth
def status():
    """Return system status as JSON"""
    status_data = {
        "modules": system_state.modules_status,
        "uptime": format_uptime(time.time() - system_state.start_time),
        "system_info": system_state.system_info
    }
    return jsonify(status_data)

@app.route('/events')
@requires_auth
def events():
    """Return recent events as JSON"""
    return jsonify(system_state.last_events)

@app.route('/api/graph/attack_history')
@requires_auth
def attack_history_data():
    """Return attack history data for graphs"""
    # Group by day and event type for the chart
    days = {}
    for event in system_state.attack_history:
        # Convert timestamp to day
        day = datetime.fromtimestamp(event['timestamp']/1000).strftime('%Y-%m-%d')
        event_type = event['event_type']
        
        if day not in days:
            days[day] = {}
            
        if event_type not in days[day]:
            days[day][event_type] = 0
            
        days[day][event_type] += 1
    
    # Convert to format suitable for charts
    result = {
        'labels': [],
        'datasets': []
    }
    
    # Get all unique event types
    event_types = set()
    for day_data in days.values():
        for event_type in day_data:
            event_types.add(event_type)
    
    # Generate colors for each event type
    colors = {
        'deauth_attack': 'rgba(231, 76, 60, 0.8)',  # Red
        'jamming_attack': 'rgba(243, 156, 18, 0.8)'  # Orange
    }
    
    # Sort days
    sorted_days = sorted(days.keys())
    result['labels'] = sorted_days
    
    # Create datasets for each event type
    for event_type in event_types:
        dataset = {
            'label': event_type.replace('_', ' ').title(),
            'data': [days.get(day, {}).get(event_type, 0) for day in sorted_days],
            'backgroundColor': colors.get(event_type, 'rgba(52, 152, 219, 0.8)'),  # Default blue
            'borderColor': colors.get(event_type, 'rgba(52, 152, 219, 1.0)'),
            'borderWidth': 1
        }
        result['datasets'].append(dataset)
    
    return jsonify(result)

@app.route('/api/graph/deauth_frames')
@requires_auth
def deauth_frames_data():
    """Return deauth frames data for real-time graph"""
    # Get deauth count time series
    # This endpoint is used for the real-time deauth frame counter visualization
    
    # Prepare frame data structure - assume last 5 minutes of data
    # with 5-second intervals
    intervals = 60  # 5 minutes in 5-second intervals
    
    # Simulation data if we don't have real deauth data yet
    deauth_counts = system_state.deauth_counts if hasattr(system_state, 'deauth_counts') else []
    
    # If we don't have enough data, pad with zeros
    if len(deauth_counts) < intervals:
        padding = [0] * (intervals - len(deauth_counts))
        deauth_counts = padding + deauth_counts
    elif len(deauth_counts) > intervals:
        deauth_counts = deauth_counts[-intervals:]
    
    # Create timestamps for the data
    now = datetime.now()
    timestamps = []
    for i in range(intervals):
        time_ago = now - timedelta(seconds=(intervals-i-1)*5)
        timestamps.append(time_ago.strftime('%H:%M:%S'))
    
    # Define the threshold from config (usually 10)
    threshold = 10  # Default value, should be read from config
    
    # Create the chart data
    result = {
        'labels': timestamps,
        'datasets': [
            {
                'label': 'Deauth Frames',
                'data': deauth_counts,
                'backgroundColor': 'rgba(52, 152, 219, 0.6)',  # Use blue as default color
                'borderColor': 'rgba(52, 152, 219, 1)',
                'borderWidth': 1,
                'barPercentage': 0.9,
                'categoryPercentage': 0.9,
            },
            {
                'label': 'Threshold',
                'data': [threshold] * intervals,
                'backgroundColor': 'rgba(0, 0, 0, 0)',
                'borderColor': 'rgba(255, 193, 7, 1)',
                'borderWidth': 2,
                'borderDash': [5, 5],  # Dashed line for threshold
                'pointRadius': 0,
                'type': 'line'  # Ensure this is rendered as a line even in bar chart
            }
        ]
    }
    
    return jsonify(result)

@app.route('/api/graph/spectrum')
@requires_auth
def spectrum_data():
    """Return spectrum data for graphs"""
    # Get the most recent spectrum data point
    if not system_state.spectrum_data:
        return jsonify({
            'labels': [],
            'datasets': []
        })
    
    # Get the most recent data
    recent_data = system_state.spectrum_data[-1]
    
    # Format for chart.js
    result = {
        'labels': [],
        'datasets': [{
            'label': 'Current Power (dBm)',
            'data': [],
            'backgroundColor': 'rgba(52, 152, 219, 0.2)',
            'borderColor': 'rgba(52, 152, 219, 1)',
            'borderWidth': 2,
            'pointRadius': 0
        }, {
            'label': 'Baseline (dBm)',
            'data': [],
            'backgroundColor': 'rgba(46, 204, 113, 0.2)',
            'borderColor': 'rgba(46, 204, 113, 1)',
            'borderWidth': 2,
            'pointRadius': 0
        }, {
            'label': 'Threshold (dBm)',
            'data': [],
            'backgroundColor': 'rgba(231, 76, 60, 0.2)',
            'borderColor': 'rgba(231, 76, 60, 1)',
            'borderWidth': 2,
            'pointRadius': 0,
            'fill': 0
        }]
    }
    
    # Process data - this is a placeholder since we don't know the exact format
    # Adjust this based on the actual format of spectrum_data
    if 'frequencies' in recent_data and 'powers' in recent_data and 'baselines' in recent_data:
        result['labels'] = recent_data['frequencies']
        result['datasets'][0]['data'] = recent_data['powers']
        result['datasets'][1]['data'] = recent_data['baselines']
        
        # Calculate threshold from baseline
        threshold_offset = recent_data.get('threshold_db', 15)  # Default to 15dB
        result['datasets'][2]['data'] = [b + threshold_offset for b in recent_data['baselines']]
    
    return jsonify(result)

@app.route('/logs')
@requires_auth
def logs():
    """View system logs"""
    log_dir = app.config.get('LOG_DIRECTORY', '/var/log/wifi-monitor')
    log_files = []
    
    # List available log files
    try:
        for file in os.listdir(log_dir):
            if file.endswith('.log') or file.endswith('.json'):
                file_path = os.path.join(log_dir, file)
                log_files.append({
                    'name': file,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                })
    except Exception as e:
        logging.error(f"Error reading log directory: {e}")
    
    return render_template('logs.html', log_files=log_files)

@app.route('/logs/<path:filename>')
@requires_auth
def download_log(filename):
    """Download a specific log file"""
    log_dir = app.config.get('LOG_DIRECTORY', '/var/log/wifi-monitor')
    
    # Security check - prevent directory traversal
    requested_path = os.path.abspath(os.path.join(log_dir, filename))
    if not requested_path.startswith(os.path.abspath(log_dir)):
        abort(403)  # Forbidden
    
    # Check if file exists
    if not os.path.exists(requested_path):
        abort(404)  # Not found
    
    # Determine content type
    content_type = 'text/plain'
    if filename.endswith('.json'):
        content_type = 'application/json'
    
    return send_from_directory(
        log_dir, 
        filename, 
        mimetype=content_type,
        as_attachment=request.args.get('download', 'false') == 'true'
    )

@app.route('/view_log/<path:filename>')
@requires_auth
def view_log(filename):
    """View a log file in the browser"""
    log_dir = app.config.get('LOG_DIRECTORY', '/var/log/wifi-monitor')
    
    # Security check - prevent directory traversal
    requested_path = os.path.abspath(os.path.join(log_dir, filename))
    if not requested_path.startswith(os.path.abspath(log_dir)):
        abort(403)  # Forbidden
    
    # Check if file exists
    if not os.path.exists(requested_path):
        abort(404)  # Not found
    
    # Read file contents
    try:
        with open(requested_path, 'r') as f:
            contents = f.read()
            
        # Format JSON logs for better readability
        if filename.endswith('.json'):
            try:
                # Load and re-format with indentation
                json_data = json.loads(contents)
                contents = json.dumps(json_data, indent=2)
            except json.JSONDecodeError:
                # If not valid JSON, just display as is
                pass
                
        return render_template('view_log.html', filename=filename, contents=contents)
    except Exception as e:
        return render_template('error.html', error=f"Error reading log file: {e}")

@app.route('/config')
@requires_auth
def config():
    """View current configuration"""
    config_file = app.config.get('CONFIG_FILE', '/etc/wifi-monitor/config.yaml')
    
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
            
        # Convert to JSON for display
        config_json = json.dumps(config_data, indent=2)
        return render_template('config.html', config=config_json)
    except Exception as e:
        return render_template('error.html', error=f"Error reading configuration: {e}")

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """
    API endpoint to receive alerts from the monitoring system
    This is used for internal communication, not external access
    """
    # Check if request is from localhost or local network (192.168.1.x)
    if not (request.remote_addr == '127.0.0.1' or request.remote_addr.startswith('192.168.1.')):
        abort(403)  # Forbidden for non-local access
    
    # Process the alert
    try:
        alert_data = request.json
        if alert_data:
            # Add timestamp if not present
            if 'timestamp' not in alert_data:
                alert_data['timestamp'] = datetime.utcnow().isoformat()
                
            # Log alert for debugging
            logging.info(f"Web UI received alert: {alert_data['event_type']} at {alert_data['timestamp']}")
                
            # Add to recent events
            system_state.last_events.insert(0, alert_data)
            
            # Keep only the most recent events
            MAX_EVENTS = 100
            if len(system_state.last_events) > MAX_EVENTS:
                system_state.last_events = system_state.last_events[:MAX_EVENTS]
            
            # Track attack history for graphs
            event_type = alert_data.get('event_type')
            timestamp = alert_data.get('timestamp')
            
            # Add to attack history for graphing
            if event_type and timestamp:
                # Convert to timestamp for easier graphing
                try:
                    dt = datetime.fromisoformat(timestamp)
                except ValueError:
                    dt = datetime.utcnow()
                    
                unix_time = dt.timestamp() * 1000  # For JavaScript Date
                
                system_state.attack_history.append({
                    'timestamp': unix_time,
                    'event_type': event_type,
                    'data': alert_data
                })
                
                # Keep only last 7 days of history
                cutoff = (datetime.utcnow() - timedelta(days=7)).timestamp() * 1000
                system_state.attack_history = [
                    event for event in system_state.attack_history 
                    if event['timestamp'] > cutoff
                ]
                
                # Log the attack history size
                logging.debug(f"Attack history size: {len(system_state.attack_history)} events")
                
            return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f"Error processing alert: {e}")
        logging.error(f"Alert data: {request.data}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        
    return jsonify({"status": "error"}), 400
    
@app.route('/api/spectrum', methods=['POST'])
def update_spectrum():
    """
    API endpoint to receive spectrum data from the monitoring system
    This is used for displaying spectrum graphs in the UI
    """
    # Check if request is from localhost
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden for non-localhost access
    
    # Process the spectrum data
    try:
        spectrum_data = request.json
        if spectrum_data:
            # Add timestamp if not present
            if 'timestamp' not in spectrum_data:
                spectrum_data['timestamp'] = datetime.utcnow().isoformat()
                
            # Add to spectrum data list
            system_state.spectrum_data.append(spectrum_data)
            
            # Keep only the most recent data points
            MAX_SPECTRUM_POINTS = 1000
            if len(system_state.spectrum_data) > MAX_SPECTRUM_POINTS:
                system_state.spectrum_data = system_state.spectrum_data[-MAX_SPECTRUM_POINTS:]
                
            return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f"Error processing spectrum data: {e}")
        
    return jsonify({"status": "error"}), 400

def format_uptime(seconds):
    """Format uptime in a human-readable format"""
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    
    return " ".join(parts)

def update_module_status(name, status, details=None):
    """Update the status of a module"""
    system_state.modules_status[name] = {
        "status": status,
        "details": details,
        "last_update": datetime.utcnow().isoformat()
    }

def update_system_info(info):
    """Update system information"""
    system_state.system_info = info

class WebUI(threading.Thread):
    """
    Web UI server component that runs in a separate thread.
    """
    
    def __init__(self, config, shutdown_event):
        """Initialize the Web UI with the provided configuration"""
        super().__init__()
        self.daemon = True
        self.name = "WebUI"
        
        self.config = config
        self.shutdown_event = shutdown_event
        
        # Extract web UI configuration
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8080)
        self.debug = config.get('debug', False)
        self.auth_enabled = config.get('auth_enabled', True)
        
        # Configure Flask app
        app.config['AUTH_ENABLED'] = self.auth_enabled
        app.config['LOG_DIRECTORY'] = self.config.get('log_directory', '/var/log/wifi-monitor')
        app.config['CONFIG_FILE'] = self.config.get('config_file', '/etc/wifi-monitor/config.yaml')
        
        # Set up password if auth is enabled
        if self.auth_enabled:
            password = config.get('password', 'admin')
            app.config['PASSWORD_HASH'] = generate_password_hash(password)
        
        # Set up Flask server
        self.server = None
        
        logging.info(f"Web UI initialized on http://{self.host}:{self.port}")
        
        # Add shutdown route only in debug mode
        if self.debug:
            @app.route('/shutdown', methods=['POST'])
            @requires_auth
            def shutdown():
                """Shutdown the server (debug only)"""
                if not self.debug:
                    abort(403)
                self.shutdown_event.set()
                return "Server shutting down..."
    
    def _create_templates_directory(self):
        """Create template directory if it doesn't exist"""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
        os.makedirs(template_dir, exist_ok=True)
        
        # Create template files if they don't exist
        self._create_template_file(template_dir, "index.html", self._get_index_template())
        self._create_template_file(template_dir, "logs.html", self._get_logs_template())
        self._create_template_file(template_dir, "view_log.html", self._get_view_log_template())
        self._create_template_file(template_dir, "config.html", self._get_config_template())
        self._create_template_file(template_dir, "error.html", self._get_error_template())
        self._create_template_file(template_dir, "layout.html", self._get_layout_template())
    
    def _create_static_directory(self):
        """Create static directory for CSS if it doesn't exist"""
        static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
        css_dir = os.path.join(static_dir, "css")
        os.makedirs(css_dir, exist_ok=True)
        
        # Create CSS file
        self._create_template_file(css_dir, "style.css", self._get_css_template())
    
    def _create_template_file(self, directory, filename, content):
        """Create a template file if it doesn't exist"""
        file_path = os.path.join(directory, filename)
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content)
            logging.debug(f"Created template file: {file_path}")
    
    def run(self):
        """Main thread run method"""
        try:
            logging.info("Starting Web UI server")
            
            # Create template directories and files
            self._create_templates_directory()
            self._create_static_directory()
            
            # Create threaded server
            class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
                allow_reuse_address = True
            
            # Use werkzeug server in debug mode, threaded server otherwise
            if self.debug:
                # Run with werkzeug server (auto-reloading)
                app.run(host=self.host, port=self.port, debug=True, use_reloader=False)
            else:
                # Use custom threaded server
                from werkzeug.serving import WSGIRequestHandler
                
                # Create a proper WSGI server
                from werkzeug.serving import make_server
                self.server = make_server(self.host, self.port, app, threaded=True)
                
                # Run in a separate thread to allow for shutdown  
                server_thread = threading.Thread(target=self.server.serve_forever)
                server_thread.daemon = True
                server_thread.start()
                
                # Wait for shutdown event
                while not self.shutdown_event.is_set():
                    time.sleep(1)
                    
                # Shutdown server
                if self.server:
                    self.server.shutdown()
                    
        except Exception as e:
            logging.error(f"Web UI server error: {e}")
    
    def stop(self):
        """Stop the Web UI server cleanly"""
        logging.info("Stopping Web UI server...")
        
        # If using the custom threaded server, shut it down
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
                logging.info("Web UI server stopped")
            except Exception as e:
                logging.error(f"Error stopping Web UI server: {e}")
    
    # Template content
    def _get_layout_template(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Attack Monitor - {% block title %}Dashboard{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <meta http-equiv="refresh" content="30">
    {% block head %}{% endblock %}
</head>
<body>
    <header>
        <h1>WiFi Attack Monitoring System</h1>
        <nav>
            <ul>
                <li><a href="{{ url_for('index') }}">Dashboard</a></li>
                <li><a href="{{ url_for('logs') }}">Logs</a></li>
                <li><a href="{{ url_for('config') }}">Configuration</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        {% block content %}{% endblock %}
    </main>
    
    <footer>
        <p>WiFi Attack Monitoring System</p>
    </footer>
    
    {% block scripts %}{% endblock %}
</body>
</html>
"""
    
    def _get_index_template(self):
        return """{% extends "layout.html" %}

{% block title %}Dashboard{% endblock %}

{% block head %}
<meta http-equiv="refresh" content="10">
{% endblock %}

{% block content %}
<section class="dashboard">
    <div class="card system-info">
        <h2>System Status</h2>
        <div class="info-grid">
            <div class="info-item">
                <span class="info-label">Uptime:</span>
                <span class="info-value">{{ uptime }}</span>
            </div>
            
            {% for key, value in system_state.system_info.items() %}
            <div class="info-item">
                <span class="info-label">{{ key|capitalize }}:</span>
                <span class="info-value">{{ value }}</span>
            </div>
            {% endfor %}
        </div>
    </div>

    <div class="card modules">
        <h2>Module Status</h2>
        <div class="module-grid">
            {% for name, data in system_state.modules_status.items() %}
            <div class="module-item">
                <div class="module-name">{{ name }}</div>
                <div class="module-status status-{{ data.status|lower }}">{{ data.status }}</div>
                {% if data.details %}
                <div class="module-details">{{ data.details }}</div>
                {% endif %}
                <div class="module-updated">Last update: {{ data.last_update }}</div>
            </div>
            {% else %}
            <p>No module status information available.</p>
            {% endfor %}
        </div>
    </div>

    <div class="card recent-events">
        <h2>Recent Events</h2>
        {% if system_state.last_events %}
        <div class="events-list">
            {% for event in system_state.last_events %}
            <div class="event-item event-{{ event.event_type }}">
                <div class="event-header">
                    <span class="event-type">{{ event.event_type|replace('_', ' ')|capitalize }}</span>
                    <span class="event-time">{{ event.timestamp }}</span>
                </div>
                <div class="event-details">
                    <pre>{{ event|tojson(indent=2) }}</pre>
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <p>No attack events detected yet.</p>
        {% endif %}
    </div>
</section>
{% endblock %}

{% block scripts %}
<script>
// Auto-refresh the page every 10 seconds
setTimeout(function() {
    location.reload();
}, 10000);
</script>
{% endblock %}
"""
    
    def _get_logs_template(self):
        return """{% extends "layout.html" %}

{% block title %}Logs{% endblock %}

{% block content %}
<section class="logs">
    <h2>System Logs</h2>
    
    {% if log_files %}
    <div class="log-files">
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for file in log_files %}
                <tr>
                    <td>{{ file.name }}</td>
                    <td>{{ file.size|filesizeformat }}</td>
                    <td>{{ file.modified }}</td>
                    <td class="actions">
                        <a href="{{ url_for('view_log', filename=file.name) }}" class="button">View</a>
                        <a href="{{ url_for('download_log', filename=file.name, download='true') }}" class="button">Download</a>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% else %}
    <p>No log files found.</p>
    {% endif %}
</section>
{% endblock %}
"""
    
    def _get_view_log_template(self):
        return """{% extends "layout.html" %}

{% block title %}View Log - {{ filename }}{% endblock %}

{% block content %}
<section class="view-log">
    <h2>Log File: {{ filename }}</h2>
    
    <div class="log-actions">
        <a href="{{ url_for('logs') }}" class="button">Back to Logs</a>
        <a href="{{ url_for('download_log', filename=filename, download='true') }}" class="button">Download</a>
    </div>
    
    <div class="log-content">
        <pre>{{ contents }}</pre>
    </div>
</section>
{% endblock %}
"""
    
    def _get_config_template(self):
        return """{% extends "layout.html" %}

{% block title %}Configuration{% endblock %}

{% block content %}
<section class="config">
    <h2>System Configuration</h2>
    
    <div class="config-content">
        <pre>{{ config }}</pre>
    </div>
</section>
{% endblock %}
"""
    
    def _get_error_template(self):
        return """{% extends "layout.html" %}

{% block title %}Error{% endblock %}

{% block content %}
<section class="error">
    <h2>Error</h2>
    
    <div class="error-message">
        <p>{{ error }}</p>
    </div>
    
    <a href="{{ url_for('index') }}" class="button">Return to Dashboard</a>
</section>
{% endblock %}
"""
    
    def _get_css_template(self):
        return """/* Global styles */
:root {
    --primary-color: #3498db;
    --secondary-color: #2c3e50;
    --background-color: #f5f5f5;
    --card-bg-color: #ffffff;
    --text-color: #333333;
    --border-color: #dddddd;
    --success-color: #2ecc71;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --info-color: #3498db;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--background-color);
    padding-bottom: 20px;
}

header {
    background-color: var(--secondary-color);
    color: white;
    padding: 1rem;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}

header h1 {
    margin: 0;
    font-size: 1.5rem;
}

nav {
    margin-top: 0.5rem;
}

nav ul {
    list-style: none;
    display: flex;
}

nav li {
    margin-right: 1rem;
}

nav a {
    color: white;
    text-decoration: none;
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    transition: background-color 0.3s;
}

nav a:hover {
    background-color: rgba(255, 255, 255, 0.1);
}

main {
    max-width: 1200px;
    margin: 1rem auto;
    padding: 0 1rem;
}

footer {
    text-align: center;
    padding: 1rem;
    margin-top: 2rem;
    font-size: 0.8rem;
    color: #666;
}

/* Card styles */
.card {
    background-color: var(--card-bg-color);
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}

.card h2 {
    margin-top: 0;
    margin-bottom: 1rem;
    color: var(--secondary-color);
    font-size: 1.2rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.5rem;
}

/* Dashboard styles */
.dashboard {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1.5rem;
}

@media (min-width: 768px) {
    .dashboard {
        grid-template-columns: 1fr 1fr;
    }
    
    .dashboard .recent-events {
        grid-column: span 2;
    }
}

/* System info styles */
.info-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.5rem;
}

.info-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border-color);
}

.info-label {
    font-weight: bold;
}

/* Module styles */
.module-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

.module-item {
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 1rem;
    background-color: #f9f9f9;
}

.module-name {
    font-weight: bold;
    margin-bottom: 0.5rem;
}

.module-status {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-size: 0.8rem;
    color: white;
    margin-bottom: 0.5rem;
}

.status-running {
    background-color: var(--success-color);
}

.status-stopped {
    background-color: var(--danger-color);
}

.status-error {
    background-color: var(--danger-color);
}

.status-warning {
    background-color: var(--warning-color);
}

.module-details {
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
}

.module-updated {
    font-size: 0.8rem;
    color: #666;
}

/* Event styles */
.events-list {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

.event-item {
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background-color: #f9f9f9;
    overflow: hidden;
}

.event-header {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 1rem;
    color: white;
    font-weight: bold;
}

.event-deauth_attack .event-header {
    background-color: var(--danger-color);
}

.event-jamming_attack .event-header {
    background-color: var(--warning-color);
}

.event-details {
    padding: 1rem;
    font-size: 0.9rem;
}

.event-details pre {
    overflow-x: auto;
    background-color: #f5f5f5;
    padding: 0.5rem;
    border-radius: 3px;
}

/* Log styles */
.logs table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}

.logs th, .logs td {
    border: 1px solid var(--border-color);
    padding: 0.5rem;
    text-align: left;
}

.logs th {
    background-color: var(--secondary-color);
    color: white;
}

.logs tr:nth-child(even) {
    background-color: #f5f5f5;
}

.logs .actions {
    display: flex;
    gap: 0.5rem;
}

/* Log view styles */
.view-log .log-actions {
    margin-bottom: 1rem;
    display: flex;
    gap: 0.5rem;
}

.view-log .log-content {
    background-color: #f5f5f5;
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
}

.view-log pre {
    white-space: pre-wrap;
    font-family: monospace;
}

/* Config styles */
.config-content {
    background-color: #f5f5f5;
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
}

.config-content pre {
    white-space: pre-wrap;
    font-family: monospace;
}

/* Button styles */
.button {
    display: inline-block;
    padding: 0.4rem 0.8rem;
    background-color: var(--primary-color);
    color: white;
    text-decoration: none;
    border-radius: 3px;
    border: none;
    cursor: pointer;
    font-size: 0.9rem;
    transition: background-color 0.3s;
}

.button:hover {
    background-color: #2980b9;
}

/* Error page */
.error-message {
    background-color: #fee;
    border: 1px solid #f99;
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
}
"""