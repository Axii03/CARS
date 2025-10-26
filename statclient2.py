# ransomware_detection_client_enhanced.py
# UPDATED CLIENT WITH QUARANTINE NOTIFICATION TO SERVER

import os
import socket
import json
import time
import hashlib
import threading
import logging 
import shutil
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pefile
import requests

def wait_for_file_ready(file_path, timeout=5):
    """Wait until the file exists and is non-zero size, or timeout (in seconds)."""
    start = time.time()
    last_size = -1
    while time.time() - start < timeout:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            if size > 0 and size == last_size:
                return True
            last_size = size
        time.sleep(0.5)
    return False

class PEFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion',
            'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA',
            'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections',
            'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 'BitcoinAddresses'
        ]
    
    def extract_features(self, file_path):
        for attempt in range(3):
            try:
                pe = pefile.PE(file_path, fast_load=True)
                features = {}
                # Basic PE header features
                features['Machine'] = pe.FILE_HEADER.Machine
                features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
                features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
                features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
                features['MajorImageVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorImageVersion', 0)
                features['MajorOSVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorOSVersion', 0)
                features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
                features['DllCharacteristics'] = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
                # Directory entries
                directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                features['ExportRVA'] = directories[0].VirtualAddress if len(directories) > 0 else 0
                features['ExportSize'] = directories[0].Size if len(directories) > 0 else 0
                features['IatVRA'] = directories[1].VirtualAddress if len(directories) > 1 else 0
                features['ResourceSize'] = directories[2].Size if len(directories) > 2 else 0
                features['DebugRVA'] = directories[6].VirtualAddress if len(directories) > 6 else 0
                features['DebugSize'] = directories[6].Size if len(directories) > 6 else 0
                features['BitcoinAddresses'] = self.detect_bitcoin_addresses(file_path)
                pe.close()
                return features
            except FileNotFoundError:
                time.sleep(0.5)
            except Exception as e:
                print(f"Feature extraction failed for {file_path}: {e}")
                return None
        print(f"File not found after retries: {file_path}")
        return None
    
    def detect_bitcoin_addresses(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(1024*1024, os.path.getsize(file_path)))
                bitcoin_patterns = [b'1', b'3', b'bc1']
                count = 0
                for pattern in bitcoin_patterns:
                    count += content.count(pattern)
                return min(count, 100)
        except Exception:
            return 0

class SmartFileMonitor(FileSystemEventHandler):
    def __init__(self, client_callback, quarantine_path=None):
        self.client_callback = client_callback
        self.pe_extensions = {'.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.cpl', '.com', '.pif'}
        self.last_scan_times = {}
        self.scan_cooldown = 3
        self.processed_files = {}
        
        # COMPREHENSIVE SYSTEM FILE WHITELIST - ALL Windows/Microsoft/Program paths
        self.system_whitelist_paths = [
            # Windows folders - COMPLETE
            'c:\\windows',  # Entire Windows directory
            
            # Program Files - ALL installed programs
            'c:\\program files',
            'c:\\program files (x86)',
            
            # ProgramData - System data
            'c:\\programdata',
            
            # User AppData (system apps like WindowsApps)
            os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData').lower(),
        ]
        
        # QUARANTINE FOLDER - Skip monitoring files in quarantine
        if quarantine_path:
            self.quarantine_path = quarantine_path.lower()
        else:
            userprofile = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
            self.quarantine_path = os.path.join(userprofile, 'Documents', 'RansomwareQuarantine').lower()
        
        print("Enhanced file monitor initialized with SYSTEM WHITELIST")
        print(f"Monitoring file types: {', '.join(self.pe_extensions)}")
        print(f"Protected system paths: {len(self.system_whitelist_paths)} locations")
        print(f"Quarantine folder excluded: {self.quarantine_path}")
    
    def is_system_file(self, file_path):
        """Check if file is in a protected system location or quarantine folder"""
        try:
            file_path_lower = file_path.lower()
            
            # Check if file is in quarantine folder
            if file_path_lower.startswith(self.quarantine_path):
                return True
            
            # Check system whitelist
            for protected_path in self.system_whitelist_paths:
                if file_path_lower.startswith(protected_path):
                    return True
            return False
        except Exception:
            return False
    
    def is_pe_file(self, file_path):
        try:
            _, ext = os.path.splitext(file_path.lower())
            if ext not in self.pe_extensions:
                return False
            
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(2)
                    return header == b'MZ'
            except (PermissionError, OSError, IOError):
                return True
                
        except Exception:
            return False
    
    def determine_file_source(self, file_path):
        path_lower = file_path.lower()
        
        if 'downloads' in path_lower:
            return 'DOWNLOADS'
        elif 'desktop' in path_lower:
            return 'DESKTOP'
        elif 'documents' in path_lower:
            return 'DOCUMENTS'
        elif 'temp' in path_lower or 'tmp' in path_lower:
            return 'TEMP'
        elif 'appdata' in path_lower:
            return 'APPDATA'
        elif 'public' in path_lower:
            return 'PUBLIC'
        elif 'programdata' in path_lower:
            return 'PROGRAMDATA'
        elif 'roaming' in path_lower:
            return 'ROAMING'
        elif 'local' in path_lower:
            return 'LOCAL'
        elif any(drive in path_lower for drive in ['d:', 'e:', 'f:', 'g:', 'h:']):
            return 'USB_DRIVE'
        else:
            return 'OTHER'
    
    def should_scan_file(self, file_path):
        current_time = time.time()
        if file_path in self.last_scan_times:
            if current_time - self.last_scan_times[file_path] < self.scan_cooldown:
                return False
        
        file_signature = f"{file_path}_{current_time}"
        if file_signature in self.processed_files:
            return False
        
        return True
    
    def on_created(self, event):
        if not event.is_directory:
            self.process_file_event(event.src_path, "CREATED")
    
    def on_moved(self, event):
        if not event.is_directory:
            self.process_file_event(event.dest_path, "MOVED_OR_COPIED")
    
    def on_modified(self, event):
        if not event.is_directory:
            try:
                if os.path.exists(event.src_path):
                    file_age = time.time() - os.path.getctime(event.src_path)
                    if file_age <= 10:
                        self.process_file_event(event.src_path, "MODIFIED_NEW")
            except Exception:
                pass
    
    def process_file_event(self, file_path, event_type):
        try:
            # CHECK SYSTEM WHITELIST FIRST
            if self.is_system_file(file_path):
                # Silently skip system files - don't print anything
                return
            
            if not self.is_pe_file(file_path):
                return
            
            if not self.should_scan_file(file_path):
                return
            
            self.last_scan_times[file_path] = time.time()
            file_signature = f"{file_path}_{time.time()}"
            self.processed_files[file_signature] = time.time()
            
            file_source = self.determine_file_source(file_path)
            
            file_name = os.path.basename(file_path)
            print(f"\nPE FILE DETECTED!")
            print(f"   Event: {event_type}")
            print(f"   File: {file_name}")
            print(f"   Source: {file_source}")
            print(f"   Time: {time.strftime('%H:%M:%S')}")
            
            if self.client_callback:
                thread = threading.Thread(
                    target=self.client_callback,
                    args=(file_path, event_type, file_source)
                )
                thread.daemon = True
                thread.start()
                
        except Exception as e:
            print(f"Error processing file event: {e}")

class AccessibleLocationFinder:
    def __init__(self):
        self.accessible_paths = []
        self.discover_accessible_locations()
    
    def is_path_accessible(self, path):
        try:
            if os.path.exists(path) and os.path.isdir(path):
                os.listdir(path)
                return True
        except (PermissionError, OSError):
            return False
        return False
    
    def discover_accessible_locations(self):
        """Discover all accessible locations for monitoring - EXPANDED"""
        print("\nDiscovering accessible locations for monitoring...")
        
        # Get user profile directory
        userprofile = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
        
        # SAFE MONITORING LOCATIONS - User folders only (no system/temp folders)
        potential_locations = [
            # User-specific locations (SAFE to monitor)
            os.path.join(userprofile, 'Downloads'),
            os.path.join(userprofile, 'Desktop'),
            os.path.join(userprofile, 'Documents'),
            os.path.join(userprofile, 'Pictures'),
            os.path.join(userprofile, 'Videos'),
            os.path.join(userprofile, 'Music'),
            
            # Public folders (SAFE to monitor)
            'C:\\Users\\Public',
            'C:\\Users\\Public\\Desktop',
            'C:\\Users\\Public\\Documents',
            'C:\\Users\\Public\\Downloads',
            
            # USB/External drives (SAFE to monitor)
            'D:\\',
            'E:\\',
            'F:\\',
            'G:\\',
            'H:\\',
            'I:\\',
            'J:\\',
        ]
        
        # Check each location
        for location in potential_locations:
            if self.is_path_accessible(location):
                self.accessible_paths.append(location)
                print(f"   ✓ Accessible: {location}")
            else:
                print(f"   ✗ Not accessible: {location}")
        
        print(f"\nTotal accessible locations: {len(self.accessible_paths)}")
    
    def get_monitoring_locations(self):
        return self.accessible_paths

class QuarantineManager:
    """Manages quarantining of detected ransomware files"""
    def __init__(self, quarantine_base_path=None):
        if quarantine_base_path is None:
            # Create quarantine folder in user's Documents
            userprofile = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
            self.quarantine_path = os.path.join(userprofile, 'Documents', 'RansomwareQuarantine')
        else:
            self.quarantine_path = quarantine_base_path
        
        # Create quarantine directory if it doesn't exist
        try:
            os.makedirs(self.quarantine_path, exist_ok=True)
            print(f"Quarantine folder: {self.quarantine_path}")
        except Exception as e:
            print(f"Warning: Could not create quarantine folder: {e}")
            self.quarantine_path = None
    
    def quarantine_file(self, file_path, file_info):
        """Move a file to quarantine folder"""
        if self.quarantine_path is None:
            return False, "Quarantine folder not available"
        
        try:
            # Create timestamp-based subfolder
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_name = os.path.basename(file_path)
            
            # Create unique quarantine filename
            quarantine_filename = f"{timestamp}_{file_name}"
            quarantine_filepath = os.path.join(self.quarantine_path, quarantine_filename)
            
            # Create info file with detection details
            info_filepath = quarantine_filepath + ".info.txt"
            info_content = f"""QUARANTINED FILE INFORMATION
{'='*50}
Original Path: {file_path}
File Name: {file_name}
Quarantine Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
File Size: {file_info.get('file_size', 'Unknown')} bytes
Detection Source: {file_info.get('file_source', 'Unknown')}
Detection Event: {file_info.get('event_type', 'Unknown')}
Confidence: {file_info.get('confidence', 0.0):.1%}
Probability Ransomware: {file_info.get('prob_ransomware', 0.0):.3f}
Probability Benign: {file_info.get('prob_benign', 0.0):.3f}
File Hash: {file_info.get('file_signature', 'Unknown')}
{'='*50}
WARNING: This file was detected as potential ransomware.
Do NOT execute or open this file without proper security measures.
"""
            
            # Write info file
            with open(info_filepath, 'w') as f:
                f.write(info_content)
            
            # Move the file to quarantine
            shutil.move(file_path, quarantine_filepath)
            
            return True, quarantine_filepath
            
        except Exception as e:
            return False, str(e)

class RansomwareDetectionClient:
    def __init__(self, server_host='http://16.171.59.202', server_port=80):
        self.server_host = server_host
        self.server_port = server_port
        
        self.feature_extractor = PEFeatureExtractor()
        self.quarantine_manager = QuarantineManager()  # Create quarantine manager first
        self.file_monitor = SmartFileMonitor(self.handle_detected_file, self.quarantine_manager.quarantine_path)  # Pass quarantine path
        self.location_finder = AccessibleLocationFinder()
        self.observer = Observer()
        
        # Statistics
        self.files_processed = 0
        self.ransomware_found = 0
        self.benign_found = 0
        self.quarantined_count = 0  # Track quarantined files
        self.start_time = time.time()
        
        # Logging setup
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ransomware_detection_enhanced.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        print(f"\nClient initialized")
        print(f"   Server: {self.server_host}:{self.server_port}")
        print(f"   Auto-quarantine: ALL ransomware detections")
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "hash_calculation_failed"
    
    def send_to_server(self, file_data, features):
        """Send file analysis request to server via HTTP POST (keeps original behavior)."""
        try:
            import requests
            url = f"http://{self.server_host}:{self.server_port}/api/static/predict" if not str(self.server_host).startswith("http") else f"{self.server_host}/api/static/predict"
            payload = {
                "file_data": file_data,
                "features": features,
                "timestamp": time.time()
            }
            response = requests.post(url, json=payload, timeout=15, headers={'Content-Type': 'application/json'})
            if response.status_code == 200:
                return response.json()
            else:
                return {"status": "error", "message": f"HTTP {response.status_code}: {response.text}"}
        except Exception as e:
            self.logger.error(f"HTTP request error: {e}")
            return {"status": "error", "message": str(e)}
    
    def send_quarantine_notification(self, quarantine_data):
        """
        NEW METHOD: Send quarantine notification to server (HTTP POST)
        """
        try:
            print(f"\n   → Sending quarantine notification to server...")
            url = f"http://{self.server_host}:{self.server_port}/api/quarantine/notify" \
                  if not str(self.server_host).startswith("http") else f"{self.server_host}/api/quarantine/notify"
            headers = {'Content-Type': 'application/json'}
            resp = requests.post(url, json={'quarantine_data': quarantine_data}, headers=headers, timeout=10)
            if resp.status_code == 200:
                j = resp.json()
                if j.get('status') == 'success':
                    print("   ✓ Server acknowledged quarantine notification")
                    self.logger.info(f"Quarantine notification sent successfully for {quarantine_data.get('original_file_name','Unknown')}")
                    return True
                else:
                    print(f"   ✗ Server error: {j.get('message','Unknown')}")
                    self.logger.error(f"Server rejected quarantine notification: {j.get('message','Unknown')}")
                    return False
            else:
                print(f"   ✗ HTTP error sending quarantine notification: {resp.status_code}")
                self.logger.error(f"HTTP error sending quarantine notification: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print(f"   ✗ Failed to send quarantine notification: {e}")
            self.logger.error(f"Failed to send quarantine notification: {e}")
            return False
    
    def handle_detected_file(self, file_path, event_type, file_source):
        """Handle file detection and analysis"""
        try:
            self.files_processed += 1
            start_time = time.time()
            
            file_name = os.path.basename(file_path)

            # WAIT for file to be ready (handles .crdownload -> final rename / file locks)
            if not wait_for_file_ready(file_path, timeout=6):
                print(f"   File not ready or missing after retries: {file_path}")
                return

            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            file_signature = self.calculate_file_hash(file_path)
            
            print(f"   Extracting PE features...")
            features = self.feature_extractor.extract_features(file_path)
            
            if features is None:
                print(f"   Feature extraction failed - skipping")
                return
            
            print(f"   Sending to server for analysis...")
            
            file_data = {
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_signature": file_signature,
                "file_source": file_source,
                "event_type": event_type
            }
            
            response = self.send_to_server(file_data, features)
            processing_time = (time.time() - start_time) * 1000
            
            if response.get('status') == 'success':
                prediction = response.get('prediction', 'UNKNOWN')
                confidence = response.get('confidence', 0.0)
                prob_ransomware = response.get('probability_ransomware', 0.0)
                prob_benign = response.get('probability_benign', 0.0)
                is_ransomware = response.get('is_ransomware', False)
                
                if is_ransomware:
                    self.ransomware_found += 1
                    
                    if confidence > 0.9:
                        print(f"   RESULT: HIGH CONFIDENCE RANSOMWARE!")
                        print(f"   Confidence: {confidence:.1%}")
                        print(f"   Probability Ransomware: {prob_ransomware:.3f}")
                        print(f"   Probability Benign: {prob_benign:.3f}")
                        print(f"   *** CRITICAL ALERT - QUARANTINING FILE ***")
                    else:
                        print(f"   RESULT: RANSOMWARE DETECTED!")
                        print(f"   Confidence: {confidence:.1%}")
                        print(f"   Probability Ransomware: {prob_ransomware:.3f}")
                        print(f"   Probability Benign: {prob_benign:.3f}")
                        print(f"   *** ALERT - QUARANTINING FILE ***")
                    
                    # Quarantine ALL ransomware detections
                    if os.path.exists(file_path):
                        file_info = {
                            'file_size': file_size,
                            'file_source': file_source,
                            'event_type': event_type,
                            'confidence': confidence,
                            'prob_ransomware': prob_ransomware,
                            'prob_benign': prob_benign,
                            'file_signature': file_signature
                        }
                        
                        success, result = self.quarantine_manager.quarantine_file(file_path, file_info)
                        
                        if success:
                            self.quarantined_count += 1
                            print(f"   ✓ FILE QUARANTINED SUCCESSFULLY")
                            print(f"   Quarantine location: {result}")
                            self.logger.critical(f"QUARANTINED: {file_name} | Conf: {confidence:.1%} | P(R): {prob_ransomware:.3f} | Location: {result}")
                            
                            # Send quarantine notification to server
                            quarantine_data = {
                                'original_file_path': file_path,
                                'original_file_name': file_name,
                                'quarantine_location': result,
                                'file_size': file_size,
                                'file_hash': file_signature,
                                'file_source': file_source,
                                'confidence': confidence,
                                'probability_ransomware': prob_ransomware,
                                'probability_benign': prob_benign,
                                'client_hostname': socket.gethostname(),
                                'notes': 'Auto-quarantined - Ransomware detected by ML model'
                            }
                            
                            # Send notification to server for blacklisting
                            self.send_quarantine_notification(quarantine_data)
                            
                        else:
                            print(f"   ✗ QUARANTINE FAILED: {result}")
                            self.logger.error(f"Quarantine failed for {file_name}: {result}")
                    
                    self.logger.critical(f"RANSOMWARE: {file_name} | Conf: {confidence:.1%} | P(R): {prob_ransomware:.3f}")
                else:
                    self.benign_found += 1
                    print(f"   RESULT: BENIGN FILE")
                    print(f"   Confidence: {confidence:.1%}")
                    print(f"   Probability Ransomware: {prob_ransomware:.3f}")
                    print(f"   Probability Benign: {prob_benign:.3f}")
                    
                    self.logger.info(f"BENIGN: {file_name} | Conf: {confidence:.1%} | P(B): {prob_benign:.3f}")
                
                print(f"   Processing Time: {processing_time:.1f}ms")
                    
            else:
                print(f"   Server error: {response.get('message', 'Unknown error')}")
                self.logger.error(f"Server error for {file_name}: {response.get('message', 'Unknown error')}")
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            self.logger.error(f"Analysis error for {file_path}: {e}")
    
    def start_monitoring(self):
        print(f"\nStarting enhanced client monitoring...")
        
        monitoring_locations = self.location_finder.get_monitoring_locations()
        
        if not monitoring_locations:
            print("No accessible locations found for monitoring!")
            return False
        
        scheduled_count = 0
        for location in monitoring_locations:
            try:
                self.observer.schedule(self.file_monitor, location, recursive=True)
                print(f"   Monitoring: {location}")
                scheduled_count += 1
            except Exception as e:
                print(f"   Failed to monitor {location}: {e}")
        
        if scheduled_count == 0:
            print("No locations could be monitored!")
            return False
        
        try:
            self.observer.start()
        except Exception as e:
            print(f"Failed to start monitoring: {e}")
            return False
        
        print(f"\nENHANCED CLIENT MONITORING ACTIVE!")
        print(f"   Monitoring {scheduled_count} locations")
        print(f"   Server: {self.server_host}:{self.server_port}")
        print(f"   Enhanced database logging enabled")
        print(f"   System file whitelist ACTIVE")
        print(f"   Auto-quarantine: ALL ransomware detections")
        print(f"   Quarantine notifications to server: ENABLED")
        print(f"   Press Ctrl+C to stop monitoring")
        print("="*50)
        
        try:
            while True:
                time.sleep(5)
                uptime = time.time() - self.start_time
                detection_rate = self.files_processed / (uptime / 60) if uptime > 0 else 0
                
                # ENHANCED STATUS LINE WITH QUARANTINE COUNT
                print(f"\rUptime: {uptime:.0f}s | Files: {self.files_processed} | Ransomware: {self.ransomware_found} | Benign: {self.benign_found} | Quarantined: {self.quarantined_count} | Rate: {detection_rate:.1f}/min", 
                      end="", flush=True)
        except KeyboardInterrupt:
            print(f"\n\nStopping monitoring...")
            self.observer.stop()
        
        self.observer.join()
        print("Monitoring stopped")
        
        # Print final summary
        print(f"\n{'='*50}")
        print(f"MONITORING SESSION SUMMARY")
        print(f"{'='*50}")
        print(f"Total runtime: {(time.time() - self.start_time):.0f}s")
        print(f"Files analyzed: {self.files_processed}")
        print(f"Ransomware detected: {self.ransomware_found}")
        print(f"Benign files: {self.benign_found}")
        print(f"Files quarantined: {self.quarantined_count}")
        if self.quarantined_count > 0:
            print(f"Quarantine location: {self.quarantine_manager.quarantine_path}")
        print(f"{'='*50}")
        
        return True

def main():
    print("ENHANCED RANSOMWARE DETECTION CLIENT v2.1")
    print("="*60)
    print("FEATURES:")
    print("✓ Expanded monitoring locations (25+ directories)")
    print("✓ System file whitelist protection")
    print("✓ Automatic quarantine for ALL ransomware detections")
    print("✓ Quarantine notifications sent to server")
    print("✓ Server blacklist database integration")
    print("✓ Detailed quarantine logging")
    print()
    
    # Configure server (can include scheme)
    SERVER_HOST = 'http://16.171.59.202'
    SERVER_PORT = 80

    # Normalize a base URL for HTTP checks
    base_url = SERVER_HOST if str(SERVER_HOST).startswith("http") else f"http://{SERVER_HOST}"

    # First try an HTTP health check
    try:
        print(f"Testing HTTP connection to {base_url} ...")
        resp = requests.get(base_url, timeout=5)
        print(f"HTTP status: {resp.status_code}")
        client = RansomwareDetectionClient(server_host=SERVER_HOST, server_port=SERVER_PORT)
        client.start_monitoring()
        return
    except Exception as http_err:
        print(f"HTTP test failed: {http_err}")

    # Fallback: try raw socket (strip scheme/paths)
    try:
        host_only = SERVER_HOST.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"Trying socket connect to {host_only}:{SERVER_PORT} ...")
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        test_socket.connect((host_only, SERVER_PORT))
        test_socket.close()
        print("Socket connection successful!")
        client = RansomwareDetectionClient(server_host=SERVER_HOST, server_port=SERVER_PORT)
        client.start_monitoring()
        return
    except Exception as sock_err:
        print(f"Socket test failed: {sock_err}")

    print("Cannot connect to server. Make sure the server is reachable at the configured address.")

if __name__ == "__main__":
    main()