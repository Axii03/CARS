# ransomware_detection_client.py
# CORRECTED COMPLETE CLIENT CODE

import os
import socket
import json
import time
import hashlib
import threading
import logging
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
                
                # Export directory
                features['ExportRVA'] = directories[0].VirtualAddress if len(directories) > 0 else 0
                features['ExportSize'] = directories[0].Size if len(directories) > 0 else 0
                
                # Import directory (IAT)
                features['IatVRA'] = directories[1].VirtualAddress if len(directories) > 1 else 0
                
                # Resource directory
                features['ResourceSize'] = directories[2].Size if len(directories) > 2 else 0
                
                # Debug directory
                features['DebugRVA'] = directories[6].VirtualAddress if len(directories) > 6 else 0
                features['DebugSize'] = directories[6].Size if len(directories) > 6 else 0
                
                # Bitcoin address detection
                features['BitcoinAddresses'] = self.detect_bitcoin_addresses(file_path)
                
                pe.close()
                return features
                
            except FileNotFoundError:
                time.sleep(0.5)  # Wait half a second and try again
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
    def __init__(self, client_callback):
        self.client_callback = client_callback
        self.pe_extensions = {'.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.cpl', '.com', '.pif'}
        self.last_scan_times = {}
        self.scan_cooldown = 3
        self.processed_files = {}
        
        print("Enhanced file monitor initialized")
        print(f"Monitoring file types: {', '.join(self.pe_extensions)}")
    
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
            pass
        return False
    
    def discover_accessible_locations(self):
        print("Discovering accessible locations...")
        
        priority_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            "C:\\Users\\Public\\Downloads",
            "C:\\Users\\Public\\Desktop",
            "C:\\Temp"
        ]
        
        for path in priority_paths:
            if self.is_path_accessible(path):
                self.accessible_paths.append(path)
                print(f"   Accessible: {path}")
        
        print(f"Discovery complete: {len(self.accessible_paths)} locations")
    
    def get_monitoring_locations(self):
        return self.accessible_paths

class RansomwareDetectionClient:
    def __init__(self, server_host='http://13.48.126.25', server_port=80):
        self.server_host = server_host
        self.server_port = server_port
        
        self.feature_extractor = PEFeatureExtractor()
        self.location_finder = AccessibleLocationFinder()
        
        self.observer = Observer()
        self.file_monitor = SmartFileMonitor(self.handle_detected_file)
        
        self.files_processed = 0
        self.ransomware_found = 0
        self.benign_found = 0
        self.start_time = time.time()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ransomware_client.log', encoding='utf-8'),
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        print(f"ENHANCED RANSOMWARE DETECTION CLIENT")
        print(f"="*45)
        #print(f"Server: {self.server_host}:{self.server_port}")
        print(f"Enhanced logging and detailed analysis tracking")
    
    def send_to_server(self, file_data, features):
        try:
            request = {
                "file_data": file_data,
                "features": features,
                "timestamp": time.time()
            }
            
            # Use HTTP POST instead of raw socket
            import requests
            
            url = f"http://13.48.126.253/api/static/predict"
            
            response = requests.post(
                url, 
                json=request,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "status": "error", 
                    "message": f"HTTP {response.status_code}: {response.text}"
                }
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP request error: {e}")
            return {"status": "error", "message": str(e)}
        except Exception as e:
            self.logger.error(f"Error communicating with server: {e}")
            return {"status": "error", "message": str(e)}
    
    def calculate_file_hash(self, file_path):
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()[:32]
        except Exception:
            return "unknown"
    
    def handle_detected_file(self, file_path, event_type, file_source):
        self.files_processed += 1
        start_time = time.time()

        try:
            file_name = os.path.basename(file_path)
            # Wait for file to be ready
            if not wait_for_file_ready(file_path, timeout=5):
                print(f"File not ready or missing after retries: {file_path}")
                return

            file_size = os.path.getsize(file_path)
            file_signature = self.calculate_file_hash(file_path)
            
            print(f"\nANALYZING FILE #{self.files_processed}")
            print(f"   File: {file_name}")
            print(f"   Source: {file_source}")
            print(f"   Event: {event_type}")
            print(f"   Size: {file_size} bytes")
            
            features = self.feature_extractor.extract_features(file_path)
            if features is None:
                print(f"   Feature extraction failed")
                return
            
            print(f"   Features extracted successfully")
            
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
                        print(f"   *** CRITICAL ALERT - BLOCK FILE ***")
                    else:
                        print(f"   RESULT: RANSOMWARE DETECTED!")
                        print(f"   Confidence: {confidence:.1%}")
                        print(f"   Probability Ransomware: {prob_ransomware:.3f}")
                        print(f"   Probability Benign: {prob_benign:.3f}")
                        print(f"   *** ALERT - QUARANTINE RECOMMENDED ***")
                    
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
        #print(f"   Server: {self.server_host}:{self.server_port}")
        print(f"   Enhanced database logging enabled")
        print(f"   Press Ctrl+C to stop monitoring")
        print("="*50)
        
        try:
            while True:
                time.sleep(5)
                uptime = time.time() - self.start_time
                detection_rate = self.files_processed / (uptime / 60) if uptime > 0 else 0
                
                print(f"\rUptime: {uptime:.0f}s | Files: {self.files_processed} | Ransomware: {self.ransomware_found} | Benign: {self.benign_found} | Rate: {detection_rate:.1f}/min", 
                      end="", flush=True)
        except KeyboardInterrupt:
            print(f"\nStopping monitoring...")
            self.observer.stop()
        
        self.observer.join()
        print("Monitoring stopped")
        return True

def main():
    print("ENHANCED RANSOMWARE DETECTION CLIENT")
    print("="*60)
    print("Features:")
    print("- HTTP-based communication")
    print("- Enhanced probability reporting")
    print("- Confidence-based alerting")
    print("- Detailed file analysis logging")
    print("- Compatible with Flask server")
    print()
    
    #SERVER_HOST = 'localhost'
    #SERVER_PORT = 5000  # Changed from 8888 to 5000

    SERVER_HOST = 'http://13.48.126.253'
    SERVER_PORT = 80 
    
    try:
        print("Testing server connection...")
        import requests
        
        # Test HTTP connection instead of socket
        #test_url = f"http://{SERVER_HOST}:{SERVER_PORT}/health"
        test_url = f"http://13.48.126.253/health"
        response = requests.get(test_url, timeout=5)
        
        if response.status_code == 200:
            print("Server connection successful!")
            health_data = response.json()
            if health_data.get('model_loaded'):
                print("✅ ML Model is loaded and ready")
            else:
                print("⚠️ ML Model not loaded on server")
        else:
            print(f"Server responded with status: {response.status_code}")
        
        client = RansomwareDetectionClient(
            server_host=SERVER_HOST,
            server_port=SERVER_PORT
        )
        
        client.start_monitoring()
        
    except requests.exceptions.RequestException as e:
        print(f"Cannot connect to server: {e}")
        print("Make sure the Flask server is running on port 5000!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()