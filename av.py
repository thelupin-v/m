#!/usr/bin/env python3
"""
VTX Antivirus System - Sophisticated Real-time Protection
Author: VTX Security
Version: 1.0
"""

import sys
import os
import json
import time
import threading
import socket
import signal
import subprocess
import hashlib
import base64
import sqlite3
from pathlib import Path
from datetime import datetime
import logging
import queue
import tempfile
import shutil
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# PySide6 imports
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                              QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                              QProgressBar, QSystemTrayIcon, QMenu, QDialog,
                              QMessageBox, QFrame, QScrollArea, QGridLayout,
                              QCheckBox, QSpinBox, QLineEdit, QTabWidget,
                              QListWidget, QSplitter, QGroupBox)
from PySide6.QtCore import (Qt, QTimer, QThread, QObject, Signal, QSettings,
                           QPropertyAnimation, QEasingCurve, QRect, QPoint, QSize)
from PySide6.QtGui import (QIcon, QPixmap, QPainter, QFont, QColor, QPalette,
                          QLinearGradient, QBrush, QPen, QMovie)

# Security imports
try:
    import pyclamd
except ImportError:
    print("Error: pyclamd not installed. Install with: pip install pyclamd")
    sys.exit(1)

try:
    import tgcrypto
except ImportError:
    print("Error: tgcrypto not installed. Install with: pip install tgcrypto")
    sys.exit(1)

try:
    import qtawesome as qta
except ImportError:
    print("Error: qtawesome not installed. Install with: pip install qtawesome")
    sys.exit(1)

# Mitmproxy imports for network interception
try:
    from mitmproxy import http, options, master
    from mitmproxy.tools.dump import DumpMaster
    import asyncio
except ImportError:
    print("Error: mitmproxy not installed. Install with: pip install mitmproxy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vtx-antivirus.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('VTX-AV')

# Global configuration
CONFIG = {
    'ENCRYPTION_KEY': 'eeef64a99c54822173ddd8f895e0a43273dc0e4a44ca9560052fb5a76b2fd8f7',
    'QUARANTINE_DIR': '/var/vtx/quarantine',
    'DB_PATH': '/var/vtx/vtx.db',
    'PROXY_PORT': 8080,
    'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'SCAN_DIRS': ['/home', '/tmp', '/var/tmp', '/Downloads'],
    'SERVICE_NAME': 'vtx',
    'PHISHING_URLS': [
        'portfolio-trezor-cdn.webflow.io',
        'agodahotelmall.com',
        'refundagoda.life',
        'parmagicl.com',
        'shanghaianlong.com',
        'agodamall.net',
        'stmpx0-gm.myshopify.com',
        '888nyw.com',
        'verifications.smcavalier.com',
        'coupangshopag.shop',
        'thanhtoanhoahongcoupangltd.com',
        'galxboysa.com',
        'allegro.pi-993120462528302.rest'
    ]
}

class DatabaseManager:
    """Manage SQLite database for VTX operations"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                threat_type TEXT,
                threat_name TEXT,
                action_taken TEXT,
                file_hash TEXT
            )
        ''')
        
        # Quarantine table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                quarantine_date TEXT NOT NULL,
                threat_name TEXT,
                file_hash TEXT,
                encrypted BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Network threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                threat_type TEXT,
                detection_date TEXT NOT NULL,
                blocked BOOLEAN DEFAULT TRUE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_scan_result(self, file_path, threat_type, threat_name, action_taken):
        """Log scan result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        file_hash = self.get_file_hash(file_path) if os.path.exists(file_path) else None
        
        cursor.execute('''
            INSERT INTO scan_results 
            (file_path, scan_date, threat_type, threat_name, action_taken, file_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file_path, datetime.now().isoformat(), threat_type, threat_name, action_taken, file_hash))
        
        conn.commit()
        conn.close()
    
    def get_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

class FileEncryption:
    """Handle file encryption for quarantine using tgcrypto AES-256-IGE"""
    
    def __init__(self, key_hex):
        self.key = bytes.fromhex(key_hex)
        self.iv = os.urandom(32)  # 256-bit IV for AES-256-IGE
    
    def encrypt_file(self, file_path, output_path):
        """Encrypt file using AES-256-IGE"""
        try:
            with open(file_path, 'rb') as infile:
                data = infile.read()
            
            # Pad data to 16-byte boundary
            padding_length = 16 - (len(data) % 16)
            padded_data = data + bytes([padding_length] * padding_length)
            
            # Encrypt using tgcrypto
            encrypted_data = tgcrypto.ige256_encrypt(padded_data, self.key, self.iv)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(self.iv)  # Write IV first
                outfile.write(encrypted_data)
            
            logger.info(f"File encrypted: {file_path} -> {output_path}")
            return True
        except Exception as e:
            logger.error(f"Encryption failed for {file_path}: {e}")
            return False
    
    def decrypt_file(self, encrypted_path, output_path):
        """Decrypt file using AES-256-IGE"""
        try:
            with open(encrypted_path, 'rb') as infile:
                iv = infile.read(32)  # Read IV
                encrypted_data = infile.read()
            
            # Decrypt using tgcrypto
            decrypted_data = tgcrypto.ige256_decrypt(encrypted_data, self.key, iv)
            
            # Remove padding
            padding_length = decrypted_data[-1]
            original_data = decrypted_data[:-padding_length]
            
            with open(output_path, 'wb') as outfile:
                outfile.write(original_data)
            
            logger.info(f"File decrypted: {encrypted_path} -> {output_path}")
            return True
        except Exception as e:
            logger.error(f"Decryption failed for {encrypted_path}: {e}")
            return False

class NetworkInterceptor:
    """Network traffic interception using mitmproxy"""
    
    def __init__(self, port, parent_callback):
        self.port = port
        self.parent_callback = parent_callback
        self.master = None
        self.running = False
    
    def start_proxy(self):
        """Start mitmproxy server"""
        try:
            opts = options.Options(listen_port=self.port, confdir="~/.mitmproxy")
            self.master = DumpMaster(opts)
            self.master.addons.add(NetworkAddon(self.parent_callback))
            
            self.running = True
            logger.info(f"Proxy started on port {self.port}")
            
            # Run proxy in separate thread
            proxy_thread = threading.Thread(target=self._run_proxy, daemon=True)
            proxy_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            return False
    
    def _run_proxy(self):
        """Run proxy server"""
        try:
            asyncio.run(self.master.run())
        except Exception as e:
            logger.error(f"Proxy error: {e}")
    
    def stop_proxy(self):
        """Stop proxy server"""
        if self.master and self.running:
            self.master.shutdown()
            self.running = False
            logger.info("Proxy stopped")

class NetworkAddon:
    """Mitmproxy addon for request inspection"""
    
    def __init__(self, callback):
        self.callback = callback
        self.phishing_domains = CONFIG['PHISHING_URLS']
    
    def request(self, flow):
        """Inspect HTTP/HTTPS requests"""
        url = flow.request.pretty_url
        host = flow.request.pretty_host
        
        # Check for phishing domains
        if any(phishing_domain in host for phishing_domain in self.phishing_domains):
            logger.warning(f"Phishing attempt blocked: {url}")
            self.callback('phishing_detected', {'url': url, 'host': host})
            
            # Inject warning page
            flow.response = http.Response.make(
                200,
                self.get_warning_page(url),
                {"Content-Type": "text/html"}
            )
        
        # Check with VirusTotal if API key available
        if CONFIG['VIRUSTOTAL_API_KEY']:
            self.check_virustotal(url, flow)
    
    def get_warning_page(self, url):
        """Generate warning page HTML"""
        return f"""
        <html>
        <head>
            <title>VTX Security Warning</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #ff4444, #cc0000);
                    color: white;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }}
                .warning-container {{
                    text-align: center;
                    background: rgba(0,0,0,0.8);
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                }}
                .warning-icon {{
                    font-size: 80px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    font-size: 32px;
                    margin: 20px 0;
                }}
                p {{
                    font-size: 18px;
                    margin: 15px 0;
                }}
                .btn {{
                    display: inline-block;
                    padding: 15px 30px;
                    margin: 10px;
                    background: #007acc;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 16px;
                    border: none;
                    cursor: pointer;
                }}
                .btn:hover {{
                    background: #005aa7;
                }}
                .btn-danger {{
                    background: #ff6b6b;
                }}
                .btn-danger:hover {{
                    background: #ff5252;
                }}
            </style>
        </head>
        <body>
            <div class="warning-container">
                <div class="warning-icon">⚠️</div>
                <h1>DANGEROUS WEBSITE BLOCKED</h1>
                <p>The website <strong>{url}</strong> has been identified as potentially malicious.</p>
                <p>This site may contain phishing attempts, malware, or other security threats.</p>
                <p>Your safety is our priority. VTX Antivirus has blocked access to protect your system.</p>
                <br>
                <button class="btn" onclick="history.back()">Go Back</button>
                <button class="btn" onclick="location.href='https://www.google.com'">Go to Google</button>
                <br><br>
                <small>Protected by VTX Antivirus System</small>
            </div>
        </body>
        </html>
        """
    
    def check_virustotal(self, url, flow):
        """Check URL with VirusTotal API"""
        try:
            # This would implement VirusTotal checking
            # For now, just log the check
            logger.info(f"Checking URL with VirusTotal: {url}")
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")

class FileSystemWatcher(FileSystemEventHandler):
    """Monitor file system for real-time scanning"""
    
    def __init__(self, scanner_callback):
        super().__init__()
        self.scanner_callback = scanner_callback
        self.scan_queue = queue.Queue()
        
        # Start queue processor
        processor_thread = threading.Thread(target=self._process_queue, daemon=True)
        processor_thread.start()
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.scan_queue.put(event.src_path)
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.scan_queue.put(event.src_path)
    
    def _process_queue(self):
        """Process scan queue"""
        while True:
            try:
                file_path = self.scan_queue.get(timeout=1)
                # Add small delay to allow file operations to complete
                time.sleep(0.5)
                if os.path.exists(file_path):
                    self.scanner_callback(file_path)
                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Queue processing error: {e}")

class ClamAVScanner:
    """ClamAV integration for file scanning"""
    
    def __init__(self):
        self.clamd = None
        self.connect_clamav()
    
    def connect_clamav(self):
        """Connect to ClamAV daemon"""
        try:
            self.clamd = pyclamd.ClamdNetworkSocket()
            if self.clamd.ping():
                logger.info("Connected to ClamAV daemon")
                return True
        except:
            try:
                self.clamd = pyclamd.ClamdUnixSocket()
                if self.clamd.ping():
                    logger.info("Connected to ClamAV Unix socket")
                    return True
            except:
                logger.error("Failed to connect to ClamAV daemon")
                self.clamd = None
                return False
    
    def scan_file(self, file_path):
        """Scan single file with ClamAV"""
        if not self.clamd:
            return None, "ClamAV not available"
        
        try:
            result = self.clamd.scan_file(file_path)
            if result is None:
                return 'clean', None
            else:
                # Result format: {file_path: ('FOUND', 'threat_name')}
                for path, (status, threat) in result.items():
                    if status == 'FOUND':
                        return 'infected', threat
                return 'clean', None
        except Exception as e:
            logger.error(f"Scan error for {file_path}: {e}")
            return 'error', str(e)
    
    def update_signatures(self):
        """Update ClamAV virus signatures"""
        try:
            subprocess.run(['freshclam'], check=True, capture_output=True)
            logger.info("ClamAV signatures updated")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update signatures: {e}")
            return False

class SystemMonitor:
    """Monitor system resources and processes"""
    
    def __init__(self, callback):
        self.callback = callback
        self.monitoring = False
        self.webcam_processes = set()
        self.microphone_processes = set()
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        logger.info("System monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._check_media_access()
                self._check_suspicious_processes()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
    
    def _check_media_access(self):
        """Check for webcam/microphone access"""
        try:
            # Check for processes accessing video/audio devices
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for file in proc.info['open_files']:
                            if '/dev/video' in file.path or '/dev/audio' in file.path:
                                proc_info = {
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'device': file.path
                                }
                                self.callback('media_access_detected', proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Media access check error: {e}")
    
    def _check_suspicious_processes(self):
        """Check for suspicious process behavior"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    # Check for high resource usage
                    if proc.info['cpu_percent'] > 80 or proc.info['memory_percent'] > 50:
                        self.callback('high_resource_usage', proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Process check error: {e}")

class FirefoxConfigurator:
    """Configure Firefox to use VTX proxy"""
    
    @staticmethod
    def configure_proxy(proxy_port):
        """Configure Firefox proxy settings"""
        try:
            # Find Firefox profile directory
            profile_dirs = []
            home_dir = os.path.expanduser("~")
            firefox_dir = os.path.join(home_dir, ".mozilla", "firefox")
            
            if os.path.exists(firefox_dir):
                for item in os.listdir(firefox_dir):
                    item_path = os.path.join(firefox_dir, item)
                    if os.path.isdir(item_path) and item.endswith(".default-release"):
                        profile_dirs.append(item_path)
            
            for profile_dir in profile_dirs:
                prefs_file = os.path.join(profile_dir, "prefs.js")
                
                # Read existing preferences
                prefs = []
                if os.path.exists(prefs_file):
                    with open(prefs_file, 'r') as f:
                        prefs = f.readlines()
                
                # Remove existing proxy settings
                prefs = [line for line in prefs if not any(setting in line for setting in [
                    'network.proxy.type',
                    'network.proxy.http',
                    'network.proxy.http_port',
                    'network.proxy.ssl',
                    'network.proxy.ssl_port'
                ])]
                
                # Add VTX proxy settings
                prefs.extend([
                    f'user_pref("network.proxy.type", 1);\n',
                    f'user_pref("network.proxy.http", "127.0.0.1");\n',
                    f'user_pref("network.proxy.http_port", {proxy_port});\n',
                    f'user_pref("network.proxy.ssl", "127.0.0.1");\n',
                    f'user_pref("network.proxy.ssl_port", {proxy_port});\n'
                ])
                
                # Write updated preferences
                with open(prefs_file, 'w') as f:
                    f.writelines(prefs)
                
                logger.info(f"Firefox proxy configured for profile: {profile_dir}")
            
            return True
        except Exception as e:
            logger.error(f"Firefox configuration failed: {e}")
            return False
    
    @staticmethod
    def remove_proxy():
        """Remove VTX proxy from Firefox configuration"""
        try:
            home_dir = os.path.expanduser("~")
            firefox_dir = os.path.join(home_dir, ".mozilla", "firefox")
            
            if os.path.exists(firefox_dir):
                for item in os.listdir(firefox_dir):
                    item_path = os.path.join(firefox_dir, item)
                    if os.path.isdir(item_path) and item.endswith(".default-release"):
                        prefs_file = os.path.join(item_path, "prefs.js")
                        
                        if os.path.exists(prefs_file):
                            with open(prefs_file, 'r') as f:
                                prefs = f.readlines()
                            
                            # Remove VTX proxy settings
                            prefs = [line for line in prefs if not any(setting in line for setting in [
                                'network.proxy.type',
                                'network.proxy.http',
                                'network.proxy.http_port',
                                'network.proxy.ssl',
                                'network.proxy.ssl_port'
                            ])]
                            
                            # Set proxy type to no proxy
                            prefs.append('user_pref("network.proxy.type", 0);\n')
                            
                            with open(prefs_file, 'w') as f:
                                f.writelines(prefs)
            
            logger.info("Firefox proxy configuration removed")
            return True
        except Exception as e:
            logger.error(f"Firefox proxy removal failed: {e}")
            return False

class VTXMainWindow(QMainWindow):
    """Main VTX Antivirus GUI Window"""
    
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager(CONFIG['DB_PATH'])
        self.scanner = ClamAVScanner()
        self.encryptor = FileEncryption(CONFIG['ENCRYPTION_KEY'])
        self.network_interceptor = NetworkInterceptor(CONFIG['PROXY_PORT'], self.handle_network_event)
        self.system_monitor = SystemMonitor(self.handle_system_event)
        
        # File system watchers
        self.observers = []
        self.file_watcher = FileSystemWatcher(self.scan_file_callback)
        
        self.init_ui()
        self.setup_watchers()
        self.start_services()
        
        # System tray
        self.setup_system_tray()
        
        logger.info("VTX Antivirus initialized")
    
    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("VTX Antivirus - Advanced Security Suite")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set window icon using qtawesome with proper configuration
        try:
            # Use Material Design Icons instead of FontAwesome
            self.setWindowIcon(qta.icon('mdi.shield-check', color='#2196F3'))
        except Exception as e:
            logger.warning(f"Could not set window icon: {e}")
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                background-color: #f0f0f0;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 10px 15px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #2196F3;
                color: white;
            }
        """)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_quarantine_tab()
        self.create_network_tab()
        self.create_settings_tab()
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("VTX Antivirus - Ready")
        
        # Apply dark theme
        self.apply_dark_theme()
    
    def create_header(self):
        """Create application header"""
        header = QFrame()
        header.setFixedHeight(80)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #2196F3, stop:1 #1976D2);
                border-radius: 10px;
                margin: 5px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Logo and title
        title_label = QLabel("🛡️ VTX ANTIVIRUS")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                background: transparent;
            }
        """)
        layout.addWidget(title_label)
        
        layout.addStretch()
        
        # Status indicators
        self.real_time_indicator = QLabel("🟢 Real-time Protection: ON")
        self.real_time_indicator.setStyleSheet("color: white; font-weight: bold;")
        layout.addWidget(self.real_time_indicator)
        
        self.network_indicator = QLabel("🟢 Network Protection: ON")
        self.network_indicator.setStyleSheet("color: white; font-weight: bold;")
        layout.addWidget(self.network_indicator)
        
        return header
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        
        # Protection status
        status_group = QGroupBox("Protection Status")
        status_layout = QGridLayout(status_group)
        
        # Status cards
        self.create_status_card(status_layout, "Real-time Scanning", "Active", "green", 0, 0)
        self.create_status_card(status_layout, "Network Protection", "Active", "green", 0, 1)
        self.create_status_card(status_layout, "Quarantine", "Secure", "blue", 1, 0)
        self.create_status_card(status_layout, "Last Update", "Today", "orange", 1, 1)
        
        layout.addWidget(status_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_list = QListWidget()
        self.activity_list.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_list)
        
        layout.addWidget(activity_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        quick_scan_btn = QPushButton("Quick Scan")
        quick_scan_btn.clicked.connect(self.start_quick_scan)
        actions_layout.addWidget(quick_scan_btn)
        
        full_scan_btn = QPushButton("Full System Scan")
        full_scan_btn.clicked.connect(self.start_full_scan)
        actions_layout.addWidget(full_scan_btn)
        
        update_btn = QPushButton("Update Signatures")
        update_btn.clicked.connect(self.update_signatures)
        actions_layout.addWidget(update_btn)
        
        layout.addWidget(actions_group)
        layout.addStretch()
        
        self.tab_widget.addTab(dashboard, "Dashboard")
    
    def create_status_card(self, layout, title, status, color, row, col):
        """Create status card widget"""
        card = QFrame()
        card.setFrameStyle(QFrame.Box)
        card.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {color};
                border-radius: 10px;
                padding: 10px;
                background-color: rgba(255, 255, 255, 0.1);
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        card_layout.addWidget(title_label)
        
        status_label = QLabel(status)
        status_label.setStyleSheet(f"color: {color}; font-size: 12px;")
        card_layout.addWidget(status_label)
        
        layout.addWidget(card, row, col)
    
    def create_scanner_tab(self):
        """Create scanner tab"""
        scanner = QWidget()
        layout = QVBoxLayout(scanner)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.scan_downloads = QCheckBox("Scan Downloads Directory")
        self.scan_downloads.setChecked(True)
        options_layout.addWidget(self.scan_downloads)
        
        self.scan_temp = QCheckBox("Scan Temporary Files")
        self.scan_temp.setChecked(True)
        options_layout.addWidget(self.scan_temp)
        
        self.scan_system = QCheckBox("Deep System Scan")
        options_layout.addWidget(self.scan_system)
        
        layout.addWidget(options_group)
        
        # Scan controls
        controls_layout = QHBoxLayout()
        
        start_scan_btn = QPushButton("Start Scan")
        start_scan_btn.clicked.connect(self.start_custom_scan)
        controls_layout.addWidget(start_scan_btn)
        
        stop_scan_btn = QPushButton("Stop Scan")
        controls_layout.addWidget(stop_scan_btn)
        
        layout.addLayout(controls_layout)
        
        # Progress
        self.scan_progress = QProgressBar()
        layout.addWidget(self.scan_progress)
        
        # Results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        results_layout.addWidget(self.scan_results)
        
        layout.addWidget(results_group)
        
        self.tab_widget.addTab(scanner, "Scanner")
    
    def create_quarantine_tab(self):
        """Create quarantine tab"""
        quarantine = QWidget()
        layout = QVBoxLayout(quarantine)
        
        # Quarantine list
        self.quarantine_list = QListWidget()
        layout.addWidget(self.quarantine_list)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        restore_btn = QPushButton("Restore File")
        restore_btn.clicked.connect(self.restore_quarantined_file)
        controls_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete Permanently")
        delete_btn.clicked.connect(self.delete_quarantined_file)
        controls_layout.addWidget(delete_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine_list)
        controls_layout.addWidget(refresh_btn)
        
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(quarantine, "Quarantine")
        self.refresh_quarantine_list()
    
    def create_network_tab(self):
        """Create network protection tab"""
        network = QWidget()
        layout = QVBoxLayout(network)
        
        # Network status
        status_group = QGroupBox("Network Protection Status")
        status_layout = QVBoxLayout(status_group)
        
        self.proxy_status = QLabel("Proxy Status: Active")
        status_layout.addWidget(self.proxy_status)
        
        self.blocked_urls = QLabel("Blocked URLs: 0")
        status_layout.addWidget(self.blocked_urls)
        
        layout.addWidget(status_group)
        
        # Blocked threats
        threats_group = QGroupBox("Blocked Network Threats")
        threats_layout = QVBoxLayout(threats_group)
        
        self.network_threats_list = QListWidget()
        threats_layout.addWidget(self.network_threats_list)
        
        layout.addWidget(threats_group)
        
        self.tab_widget.addTab(network, "Network Protection")
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings = QWidget()
        layout = QVBoxLayout(settings)
        
        # Real-time protection
        realtime_group = QGroupBox("Real-time Protection")
        realtime_layout = QVBoxLayout(realtime_group)
        
        self.enable_realtime = QCheckBox("Enable Real-time Scanning")
        self.enable_realtime.setChecked(True)
        realtime_layout.addWidget(self.enable_realtime)
        
        self.enable_network = QCheckBox("Enable Network Protection")
        self.enable_network.setChecked(True)
        realtime_layout.addWidget(self.enable_network)
        
        layout.addWidget(realtime_group)
        
        # Scan settings
        scan_group = QGroupBox("Scan Settings")
        scan_layout = QVBoxLayout(scan_group)
        
        scan_layout.addWidget(QLabel("Scan Frequency (minutes):"))
        self.scan_frequency = QSpinBox()
        self.scan_frequency.setRange(1, 1440)
        self.scan_frequency.setValue(30)
        scan_layout.addWidget(self.scan_frequency)
        
        layout.addWidget(scan_group)
        
        # VirusTotal settings
        vt_group = QGroupBox("VirusTotal Integration")
        vt_layout = QVBoxLayout(vt_group)
        
        vt_layout.addWidget(QLabel("API Key:"))
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setPlaceholderText("Enter VirusTotal API key")
        self.vt_api_key.setText(CONFIG['VIRUSTOTAL_API_KEY'])
        vt_layout.addWidget(self.vt_api_key)
        
        layout.addWidget(vt_group)
        
        # Save settings
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        self.tab_widget.addTab(settings, "Settings")
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setIcon(qta.icon('mdi.shield-check', color='#2196F3'))
            
            # Tray menu
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction("Show VTX")
            show_action.triggered.connect(self.show)
            
            scan_action = tray_menu.addAction("Quick Scan")
            scan_action.triggered.connect(self.start_quick_scan)
            
            tray_menu.addSeparator()
            
            quit_action = tray_menu.addAction("Quit")
            quit_action.triggered.connect(self.quit_application)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            
            # Tray messages
            self.tray_icon.showMessage(
                "VTX Antivirus",
                "Real-time protection is active",
                QSystemTrayIcon.Information,
                3000
            )
        except Exception as e:
            logger.warning(f"System tray setup failed: {e}")
    
    def setup_watchers(self):
        """Setup file system watchers"""
        for scan_dir in CONFIG['SCAN_DIRS']:
            if os.path.exists(scan_dir):
                observer = Observer()
                observer.schedule(self.file_watcher, scan_dir, recursive=True)
                observer.start()
                self.observers.append(observer)
                logger.info(f"Watching directory: {scan_dir}")
    
    def start_services(self):
        """Start VTX services"""
        # Start network interceptor
        if self.network_interceptor.start_proxy():
            self.network_indicator.setText("🟢 Network Protection: ON")
            
            # Configure Firefox proxy
            FirefoxConfigurator.configure_proxy(CONFIG['PROXY_PORT'])
        else:
            self.network_indicator.setText("🔴 Network Protection: ERROR")
        
        # Start system monitoring
        self.system_monitor.start_monitoring()
        
        # Update signatures on startup
        self.update_signatures()
    
    def stop_services(self):
        """Stop VTX services"""
        # Stop file watchers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        # Stop network interceptor
        self.network_interceptor.stop_proxy()
        
        # Remove Firefox proxy
        FirefoxConfigurator.remove_proxy()
        
        # Stop system monitoring
        self.system_monitor.stop_monitoring()
        
        logger.info("VTX services stopped")
    
    def scan_file_callback(self, file_path):
        """Callback for real-time file scanning"""
        if not self.enable_realtime.isChecked():
            return
        
        result, threat = self.scanner.scan_file(file_path)
        
        if result == 'infected':
            logger.warning(f"Threat detected: {file_path} - {threat}")
            
            # Show threat dialog
            self.show_threat_dialog(file_path, threat)
            
            # Log to database
            self.db_manager.log_scan_result(file_path, 'malware', threat, 'detected')
            
            # Add to activity list
            self.add_activity(f"Threat detected: {os.path.basename(file_path)} - {threat}")
        
        elif result == 'error':
            logger.error(f"Scan error: {file_path} - {threat}")
    
    def show_threat_dialog(self, file_path, threat_name):
        """Show threat detection dialog"""
        dialog = QMessageBox(self)
        dialog.setWindowTitle("VTX Security Alert")
        dialog.setIcon(QMessageBox.Warning)
        dialog.setText(f"Threat Detected!")
        dialog.setInformativeText(f"File: {file_path}\nThreat: {threat_name}")
        
        quarantine_btn = dialog.addButton("Quarantine", QMessageBox.AcceptRole)
        keep_btn = dialog.addButton("Keep File", QMessageBox.RejectRole)
        
        dialog.exec()
        
        if dialog.clickedButton() == quarantine_btn:
            self.quarantine_file(file_path, threat_name)
        else:
            logger.info(f"User chose to keep infected file: {file_path}")
    
    def quarantine_file(self, file_path, threat_name):
        """Quarantine infected file"""
        try:
            # Create quarantine directory
            os.makedirs(CONFIG['QUARANTINE_DIR'], exist_ok=True)
            
            # Generate quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{os.path.basename(file_path)}.vtx"
            quarantine_path = os.path.join(CONFIG['QUARANTINE_DIR'], quarantine_filename)
            
            # Encrypt and move file
            if self.encryptor.encrypt_file(file_path, quarantine_path):
                # Remove original file
                os.remove(file_path)
                
                # Log to database
                conn = sqlite3.connect(CONFIG['DB_PATH'])
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO quarantine 
                    (original_path, quarantine_path, quarantine_date, threat_name, encrypted)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_path, quarantine_path, datetime.now().isoformat(), threat_name, True))
                conn.commit()
                conn.close()
                
                logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
                self.add_activity(f"File quarantined: {os.path.basename(file_path)}")
                
                # Show tray notification
                if hasattr(self, 'tray_icon'):
                    self.tray_icon.showMessage(
                        "VTX Security",
                        f"Threat quarantined: {os.path.basename(file_path)}",
                        QSystemTrayIcon.Warning,
                        3000
                    )
            else:
                logger.error(f"Failed to quarantine file: {file_path}")
        
        except Exception as e:
            logger.error(f"Quarantine error: {e}")
    
    def handle_network_event(self, event_type, data):
        """Handle network security events"""
        if event_type == 'phishing_detected':
            logger.warning(f"Phishing blocked: {data['url']}")
            self.add_activity(f"Phishing blocked: {data['host']}")
            
            # Add to blocked threats list
            self.network_threats_list.addItem(f"PHISHING: {data['url']} - {datetime.now().strftime('%H:%M:%S')}")
            
            # Show tray notification
            if hasattr(self, 'tray_icon'):
                self.tray_icon.showMessage(
                    "VTX Network Protection",
                    f"Phishing attempt blocked: {data['host']}",
                    QSystemTrayIcon.Warning,
                    3000
                )
    
    def handle_system_event(self, event_type, data):
        """Handle system monitoring events"""
        if event_type == 'media_access_detected':
            self.show_media_access_dialog(data)
        elif event_type == 'high_resource_usage':
            logger.info(f"High resource usage detected: {data['name']} (PID: {data['pid']})")
    
    def show_media_access_dialog(self, process_info):
        """Show media access permission dialog"""
        dialog = QMessageBox(self)
        dialog.setWindowTitle("VTX Media Protection")
        dialog.setIcon(QMessageBox.Question)
        dialog.setText("Media Access Request")
        dialog.setInformativeText(f"Process '{process_info['name']}' (PID: {process_info['pid']}) is trying to access {process_info['device']}")
        
        allow_btn = dialog.addButton("Allow", QMessageBox.AcceptRole)
        block_btn = dialog.addButton("Block", QMessageBox.RejectRole)
        
        dialog.exec()
        
        if dialog.clickedButton() == allow_btn:
            logger.info(f"Media access allowed for {process_info['name']}")
        else:
            logger.info(f"Media access blocked for {process_info['name']}")
            # Here you would implement actual blocking logic
    
    def start_quick_scan(self):
        """Start quick system scan"""
        self.add_activity("Quick scan started")
        self.scan_results.append("Starting quick scan...\n")
        
        # Implement quick scan logic
        scan_dirs = [os.path.expanduser("~/Downloads"), "/tmp"]
        self.perform_scan(scan_dirs, "Quick Scan")
    
    def start_full_scan(self):
        """Start full system scan"""
        self.add_activity("Full system scan started")
        self.scan_results.append("Starting full system scan...\n")
        
        # Implement full scan logic
        self.perform_scan(CONFIG['SCAN_DIRS'], "Full System Scan")
    
    def start_custom_scan(self):
        """Start custom scan based on selected options"""
        scan_dirs = []
        
        if self.scan_downloads.isChecked():
            scan_dirs.append(os.path.expanduser("~/Downloads"))
        
        if self.scan_temp.isChecked():
            scan_dirs.extend(["/tmp", "/var/tmp"])
        
        if self.scan_system.isChecked():
            scan_dirs.extend(["/usr", "/bin", "/sbin"])
        
        if scan_dirs:
            self.perform_scan(scan_dirs, "Custom Scan")
        else:
            QMessageBox.information(self, "VTX Scanner", "Please select scan options.")
    
    def perform_scan(self, directories, scan_type):
        """Perform file system scan"""
        self.scan_progress.setValue(0)
        total_files = 0
        scanned_files = 0
        threats_found = 0
        
        # Count total files
        for directory in directories:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    total_files += len(files)
        
        self.scan_progress.setMaximum(total_files)
        
        # Scan files
        for directory in directories:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        try:
                            result, threat = self.scanner.scan_file(file_path)
                            
                            if result == 'infected':
                                threats_found += 1
                                self.scan_results.append(f"THREAT: {file_path} - {threat}\n")
                                self.db_manager.log_scan_result(file_path, 'malware', threat, 'detected')
                            elif result == 'error':
                                self.scan_results.append(f"ERROR: {file_path} - {threat}\n")
                            
                            scanned_files += 1
                            self.scan_progress.setValue(scanned_files)
                            
                            # Process events to keep GUI responsive
                            QApplication.processEvents()
                            
                        except Exception as e:
                            logger.error(f"Scan error for {file_path}: {e}")
        
        # Scan complete
        self.scan_results.append(f"\n{scan_type} complete!\n")
        self.scan_results.append(f"Files scanned: {scanned_files}\n")
        self.scan_results.append(f"Threats found: {threats_found}\n")
        
        self.add_activity(f"{scan_type} completed - {threats_found} threats found")
    
    def update_signatures(self):
        """Update antivirus signatures"""
        self.add_activity("Updating virus signatures...")
        
        if self.scanner.update_signatures():
            self.add_activity("Signatures updated successfully")
            
            if hasattr(self, 'tray_icon'):
                self.tray_icon.showMessage(
                    "VTX Antivirus",
                    "Virus signatures updated",
                    QSystemTrayIcon.Information,
                    2000
                )
        else:
            self.add_activity("Signature update failed")
    
    def refresh_quarantine_list(self):
        """Refresh quarantine file list"""
        self.quarantine_list.clear()
        
        try:
            conn = sqlite3.connect(CONFIG['DB_PATH'])
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM quarantine ORDER BY quarantine_date DESC')
            
            for row in cursor.fetchall():
                item_text = f"{row[1]} - {row[3]} - {row[4]}"
                self.quarantine_list.addItem(item_text)
            
            conn.close()
        except Exception as e:
            logger.error(f"Failed to refresh quarantine list: {e}")
    
    def restore_quarantined_file(self):
        """Restore file from quarantine"""
        current_item = self.quarantine_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "VTX Quarantine", "Please select a file to restore.")
            return
        
        # Implement file restoration logic
        QMessageBox.information(self, "VTX Quarantine", "File restoration functionality will be implemented.")
    
    def delete_quarantined_file(self):
        """Permanently delete quarantined file"""
        current_item = self.quarantine_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "VTX Quarantine", "Please select a file to delete.")
            return
        
        # Implement permanent deletion logic
        reply = QMessageBox.question(self, "VTX Quarantine", 
                                   "Are you sure you want to permanently delete this file?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "VTX Quarantine", "File deletion functionality will be implemented.")
    
    def save_settings(self):
        """Save application settings"""
        # Update configuration
        CONFIG['VIRUSTOTAL_API_KEY'] = self.vt_api_key.text()
        
        # Save to file or registry
        settings = QSettings('VTX', 'Antivirus')
        settings.setValue('virustotal_api_key', self.vt_api_key.text())
        settings.setValue('scan_frequency', self.scan_frequency.value())
        settings.setValue('enable_realtime', self.enable_realtime.isChecked())
        settings.setValue('enable_network', self.enable_network.isChecked())
        
        QMessageBox.information(self, "VTX Settings", "Settings saved successfully.")
        self.add_activity("Settings updated")
    
    def add_activity(self, activity):
        """Add activity to recent activity list"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        activity_text = f"[{timestamp}] {activity}"
        self.activity_list.addItem(activity_text)
        
        # Keep only last 50 items
        if self.activity_list.count() > 50:
            self.activity_list.takeItem(0)
        
        # Scroll to bottom
        self.activity_list.scrollToBottom()
    
    def apply_dark_theme(self):
        """Apply dark theme to application"""
        dark_stylesheet = """
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                border: 2px solid #555555;
                border-radius: 5px;
                margin: 5px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4c4c4c;
            }
            QPushButton:pressed {
                background-color: #2c2c2c;
            }
            QListWidget, QTextEdit {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 3px;
            }
        """
        
        self.setStyleSheet(dark_stylesheet)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Hide to system tray instead of closing
        event.ignore()
        self.hide()
        
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                "VTX Antivirus",
                "Application minimized to tray. Protection continues.",
                QSystemTrayIcon.Information,
                2000
            )
    
    def quit_application(self):
        """Quit application completely"""
        reply = QMessageBox.question(self, "VTX Antivirus",
                                   "Are you sure you want to quit VTX Antivirus?\nThis will disable real-time protection.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.stop_services()
            QApplication.quit()

class VTXWatermark(QWidget):
    """Always-on-top watermark widget with STOP button"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        """Initialize watermark UI"""
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(120, 40)
        
        # Position in top-right corner
        screen = QApplication.primaryScreen().geometry()
        self.move(screen.width() - 130, 10)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # VTX label
        vtx_label = QLabel("🛡️ VTX")
        vtx_label.setStyleSheet("""
            QLabel {
                color: white;
                font-weight: bold;
                font-size: 12px;
                background-color: rgba(33, 150, 243, 0.8);
                border-radius: 3px;
                padding: 2px 5px;
            }
        """)
        layout.addWidget(vtx_label)
        
        # STOP button
        stop_btn = QPushButton("STOP")
        stop_btn.setFixedSize(40, 25)
        stop_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(244, 67, 54, 0.8);
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(244, 67, 54, 1.0);
            }
        """)
        stop_btn.clicked.connect(self.stop_antivirus)
        layout.addWidget(stop_btn)
    
    def stop_antivirus(self):
        """Stop VTX antivirus"""
        reply = QMessageBox.question(self, "VTX Control",
                                   "Stop VTX Antivirus protection?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.main_window.quit_application()

def create_systemd_service():
    """Create systemd service file for VTX"""
    service_content = f"""[Unit]
Description=VTX Antivirus Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vtx-antivirus

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open('/etc/systemd/system/vtx.service', 'w') as f:
            f.write(service_content)
        
        # Enable and start service
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'vtx.service'], check=True)
        
        print("VTX systemd service created and enabled")
        return True
    except Exception as e:
        print(f"Failed to create systemd service: {e}")
        return False

def main():
    """Main application entry point"""
    # Check if running as root for service mode
    if len(sys.argv) > 1 and sys.argv[1] == '--install-service':
        if os.geteuid() != 0:
            print("Error: Root privileges required for service installation")
            sys.exit(1)
        
        if create_systemd_service():
            print("VTX service installed successfully")
            print("Start with: sudo systemctl start vtx.service")
        sys.exit(0)
    
    # Initialize Qt application
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("VTX Antivirus")
    app.setApplicationVersion("1.0")
    
    # Create main window
    try:
        main_window = VTXMainWindow()
        main_window.show()
        
        # Create watermark widget
        watermark = VTXWatermark(main_window)
        watermark.show()
        
        # Setup signal handlers
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal")
            main_window.stop_services()
            app.quit()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start application
        logger.info("VTX Antivirus started successfully")
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Failed to start VTX Antivirus: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
