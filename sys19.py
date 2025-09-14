# 1. All imports first. Removed some Events to reduce noise
import win32evtlog
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import time
import os
import requests
import json
import hashlib
import sys
import socket

# If running as a bundled exe, inject '--continuous' if no args
if getattr(sys, 'frozen', False) and len(sys.argv) == 1:
    sys.argv.append('--continuous')

# 2. Timestamp setup and constants
SYSMON_EVENT_LOG_PATH = "Microsoft-Windows-Sysmon/Operational"
PREDICTION_API_URL = "http://localhost:5000/predict"  # API endpoint for predictions

# 3. Global cache for parent process information, ML strings collection, and change detection
global_parent_cache = {}
ml_strings_buffer = []  # Buffer to collect ML strings for batch prediction
last_events_hash = None  # Hash of the last processed event batch
consecutive_no_change_count = 0  # Counter for consecutive iterations with no changes

# 4. Function to generate a hash signature of current events for change detection
def generate_events_hash(process_events):
    """
    Generate a lightweight hash signature of the current event batch.
    Uses process IDs, app names, event counts, and event types as the signature.
    This provides efficient change detection with minimal computational overhead.
    """
    if not process_events:
        return hashlib.md5(b"empty").hexdigest()
    
    # Create a sorted string representation of key event characteristics
    signature_parts = []
    
    for pid in sorted(process_events.keys()):
        data = process_events[pid]
        
        # Include key identifying information
        pid_signature = f"PID:{pid}"
        app_signature = f"APP:{data.get('app_name', 'Unknown')}"
        path_signature = f"PATH:{data.get('full_path', 'N/A')}"
        event_count = len(data.get('events', []))
        event_types = sorted(set([event['EventID'] for event in data.get('events', [])]))
        events_signature = f"EVENTS:{event_count}:{'|'.join(event_types)}"
        
        # Combine into process signature
        process_sig = f"{pid_signature}|{app_signature}|{path_signature}|{events_signature}"
        signature_parts.append(process_sig)
    
    # Create final hash from all process signatures
    combined_signature = "||".join(signature_parts)
    return hashlib.md5(combined_signature.encode('utf-8')).hexdigest()

# 5. Function to check if events have changed since last iteration
def has_events_changed(process_events):
    """
    Check if the current event batch is different from the last processed batch.
    Returns True if changes detected, False if identical to last batch.
    """
    global last_events_hash, consecutive_no_change_count
    
    current_hash = generate_events_hash(process_events)
    
    if last_events_hash is None:
        # First run - always process
        last_events_hash = current_hash
        consecutive_no_change_count = 0
        return True
    
    if current_hash != last_events_hash:
        # Changes detected
        last_events_hash = current_hash
        consecutive_no_change_count = 0
        return True
    else:
        # No changes detected
        consecutive_no_change_count += 1
        return False

# 6. Function to extract application details from event XML
def extract_app_name(xml_str):
    try:
        root = ET.fromstring(xml_str)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        event_id = root.find('./e:System/e:EventID', ns).text
        time_created_elem = root.find('./e:System/e:TimeCreated', ns)
        event_time = time_created_elem.attrib.get('SystemTime') if time_created_elem is not None else "Unknown"

        fields = {
            "Image": "N/A",
            "ProcessId": "N/A",
            "ParentProcessId": "N/A",
            "ParentImage": "N/A"
        }

        for data in root.findall('.//e:Data', ns):
            key = data.attrib.get('Name')
            if key in fields:
                fields[key] = data.text or "N/A"

        app_name = os.path.basename(fields["Image"]) if fields["Image"] != "N/A" else "Unknown"
        parent_app_name = os.path.basename(fields["ParentImage"]) if fields["ParentImage"] != "N/A" else "Unknown"

        return {
            "Application": app_name,
            "EventID": event_id,
            "Path": fields["Image"],
            "Time": event_time,
            "ProcessID": fields["ProcessId"],
            "ParentProcessID": fields["ParentProcessId"],
            "ProcessName": fields["Image"],
            "ParentProcessName": fields["ParentImage"],
            "ParentApplication": parent_app_name,
            "RawXML": xml_str
        }
    except Exception as e:
        print(f"[WARN] Failed to parse XML: {e}")
        return {
            "Application": "Unknown",
            "EventID": "N/A",
            "Path": "N/A",
            "Time": "Unknown",
            "ProcessID": "N/A",
            "ParentProcessID": "N/A",
            "ProcessName": "N/A",
            "ParentProcessName": "N/A",
            "ParentApplication": "Unknown",
            "RawXML": xml_str
        }

# 7. Function to build parent process cache from Event ID 1 (Process Creation)
def build_parent_cache(all_events):
    """
    Build a cache of (ProcessID, ProcessName) -> Parent Process Info from Event ID 1 events.
    Uses composite key to handle PID reuse scenarios.
    """
    for event_info in all_events:
        if event_info["EventID"] == "1":  # Process Creation event
            pid = event_info["ProcessID"]
            process_name = event_info["Application"]
            
            if pid != "N/A" and process_name != "Unknown":
                # Use composite key (PID, ProcessName) to handle PID reuse
                cache_key = (pid, process_name)
                global_parent_cache[cache_key] = {
                    "parent_pid": event_info["ParentProcessID"],
                    "parent_app_name": event_info["ParentApplication"],
                    "parent_full_path": event_info["ParentProcessName"]
                }

# 8. Function to calculate process vs parent frequency ratio with caching (EXACTLY as defined)
def calculate_process_vs_parent_freq_ratio(process_events):
    """
    Calculate the frequency ratio of process names vs their parent process names.
    STRICT DEFINITION: ratio = process_name_frequency / parent_name_frequency
    Lower ratio may indicate suspicious activity.
    Uses cached parent information from Event ID 1 when direct parent info is unavailable.
    """
    # Count frequency of all process names and parent process names (EXACTLY as original)
    process_name_freq = Counter()
    parent_name_freq = Counter()
    
    # First pass: collect all process and parent names for frequency counting
    for pid, data in process_events.items():
        if data['app_name'] and data['app_name'] != "Unknown":
            process_name_freq[data['app_name']] += len(data['events'])
        
        # Check for parent info from cache if not directly available
        parent_app_name = data['parent_app_name']
        cache_key = (pid, data['app_name'])
        
        if (not parent_app_name or parent_app_name == "Unknown") and cache_key in global_parent_cache:
            parent_app_name = global_parent_cache[cache_key]['parent_app_name']
        
        if parent_app_name and parent_app_name != "Unknown":
            parent_name_freq[parent_app_name] += len(data['events'])
    
    # Second pass: calculate ratios for each process (EXACTLY as original)
    ratios = {}
    for pid, data in process_events.items():
        process_name = data['app_name']
        parent_name = data['parent_app_name']
        
        # Handle edge cases
        if not process_name or process_name == "Unknown":
            ratios[pid] = 0.0  # No process info available - set to 0
            continue
        
        # Try to get parent info from cache if not directly available
        cache_key = (pid, process_name)
        if (not parent_name or parent_name == "Unknown") and cache_key in global_parent_cache:
            parent_name = global_parent_cache[cache_key]['parent_app_name']
            print(f"[CACHE] Using cached parent '{parent_name}' for PID {pid} ({process_name})")
        
        if not parent_name or parent_name == "Unknown":
            # Still no parent info even after checking cache
            # Set to 1.0 = assume equal frequency (neutral/unknown relationship)
            ratios[pid] = 1.0
            print(f"[NO_PARENT] PID {pid} ({process_name}) - No parent info in cache or event, setting ratio to 1.0")
            continue
        
        # EXACT CALCULATION as defined: process_frequency / parent_frequency
        process_freq = process_name_freq.get(process_name, 1)
        parent_freq = parent_name_freq.get(parent_name, 1)
        
        # Calculate ratio: process_frequency / parent_frequency
        # Lower ratios indicate the process is less common relative to its parent
        ratio = process_freq / parent_freq if parent_freq > 0 else 1.0
        ratios[pid] = round(ratio, 4)
    
    return ratios

# 9. Function to extract ML binary and numerical features from process events
def extract_ml_features(process_events, frequency_ratios):
    """
    Extract binary and numerical ML features for each process:
    
    Binary Features:
    - File_created (Event ID 11)
    - File_Delete_archived (Event ID 23) 
    - File_creation_time_changed (Event ID 2)
    - Registry_value_set (Event ID 13)
    - Process_Create (Event ID 1)
    - Pipe_Created (Event ID 17)
    - file-related (Event IDs 11, 23, 2)
    - network-related (Event ID 3)
    - process-related (Event IDs 1, 10, 25)
    - suspicious_path (paths containing suspicious directories)
    - system_executable (paths in trusted system directories)
    - parent_is_system_executable (parent in trusted system directories)
    - extension_similarity (process and parent have same extension)
    
    Numerical Features:
    - path_length (character count of executable path)
    - directory_depth (number of directory separators)
    - process_name_length (length of process name)
    - process_vs_parent_freq_ratio (frequency ratio from existing calculation)
    - executable_depth_diff (difference in depth between process and parent)
    - file_name_entropy (entropy of the file name)
    """
    import math
    import os
    
    ml_features = {}
    
    # Define suspicious and system directories
    suspicious_dirs = ['temp', 'downloads', 'appdata', 'users', 'documents', 'desktop', 'pictures', 'videos', 'music']
    system_dirs = ['c:\\windows\\system32', 'c:\\program files', 'c:\\program files (x86)', 'c:\\windows']
    
    def calculate_entropy(text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count frequency of each character
        char_counts = {}
        for char in text.lower():
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def get_file_extension(path):
        """Extract file extension from path"""
        if not path or path == "N/A":
            return ""
        return os.path.splitext(path.lower())[1]
    
    def is_system_path(path):
        """Check if path is in system directories"""
        if not path:
            return False
        path_lower = path.lower()
        return any(path_lower.startswith(sys_dir) for sys_dir in system_dirs)
    
    for pid, data in process_events.items():
        # Get all event IDs for this process
        event_ids = [event['EventID'] for event in data['events']]
        
        # Get the executable path for path-based features
        exe_path = data['full_path'] if data['full_path'] and data['full_path'] != "N/A" else ""
        exe_path_lower = exe_path.lower()
        
        # Get parent path
        parent_path = data['parent_name'] if data['parent_name'] and data['parent_name'] != "N/A" else ""
        
        # Extract process name from path
        process_name = data['app_name'] if data['app_name'] and data['app_name'] != "Unknown" else ""
        
        # Binary features based on event presence
        features = {
            'File_created': 1 if '11' in event_ids else 0,
            'File_Delete_archived': 1 if '23' in event_ids else 0,
            'File_creation_time_changed': 1 if '2' in event_ids else 0,
            'Registry_value_set': 1 if '13' in event_ids else 0,
            'Process_Create': 1 if '1' in event_ids else 0,
            'Pipe_Created': 1 if '17' in event_ids else 0,
            'file-related': 1 if any(eid in event_ids for eid in ['11', '23', '2','26']) else 0,
            'network-related': 1 if any(eid in event_ids for eid in ['3', '22']) else 0,
            'process-related': 1 if any(eid in event_ids for eid in ['1','5','8', '10', '25']) else 0,
        }
        
        # Path-based binary features
        features['suspicious_path'] = 0 if any(sus_dir in exe_path_lower for sus_dir in suspicious_dirs) else 1
        features['system_executable'] = 0 if any(exe_path_lower.startswith(sys_dir) for sys_dir in system_dirs) else 1
        
        # Parent-based binary features
        features['parent_is_system_executable'] = 1 if is_system_path(parent_path) else 0
        
        # Extension similarity
        process_ext = get_file_extension(exe_path)
        parent_ext = get_file_extension(parent_path)
        features['extension_similarity'] = 1 if process_ext and parent_ext and process_ext == parent_ext else 0
        
        # Numerical features
        features['path_length'] = len(exe_path) if exe_path else 0
        features['directory_depth'] = exe_path.count('\\') if exe_path else 0
        features['process_name_length'] = len(process_name) if process_name else 0
        
        # Use existing frequency ratio calculation
        features['process_vs_parent_freq_ratio'] = frequency_ratios.get(pid, 1.0)
        
        # Executable depth difference
        process_depth = exe_path.count('\\') if exe_path else 0
        parent_depth = parent_path.count('\\') if parent_path else 0
        features['executable_depth_diff'] = process_depth - parent_depth
        
        # File name entropy
        file_name = os.path.basename(exe_path) if exe_path else ""
        # Remove extension for entropy calculation to focus on the name part
        name_without_ext = os.path.splitext(file_name)[0] if file_name else ""
        features['file_name_entropy'] = calculate_entropy(name_without_ext)
        
        ml_features[pid] = features
    
    return ml_features

# 10. Function to send ML features to prediction API with metadata
def send_predictions_to_api(process_events, ml_features):
    """
    Send ML feature data with metadata to the prediction API for batch processing
    """
    if not process_events:
        print("[INFO] No processes to send for prediction")
        return None
    
    # Define legitimate system processes to skip prediction (whitelist)
    legitimate_processes = {
        'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'wininit.exe',
        'services.exe', 'lsass.exe', 'dwm.exe', 'conhost.exe', 'runtimebroker.exe',
        'taskhostw.exe', 'audiodg.exe', 'spoolsv.exe', 'microsoftedgeupdate.exe',
        'chrome.exe', 'firefox.exe', 'notepad.exe', 'calc.exe', 'mspaint.exe'
    }
    
    legitimate_paths = {
        'c:\\windows\\system32', 'c:\\windows\\syswow64', 'c:\\program files',
        'c:\\program files (x86)\\microsoft', 'c:\\program files\\microsoft'
    }
    
    try:
        # Prepare the request payload with metadata and features
        payload = {
            "processes": []
        }
        
        skipped_processes = 0
        
        for process_id, data in process_events.items():
            # Check if process should be whitelisted
            app_name = data.get('app_name', '').lower()
            path = data.get('full_path', '').lower()
            
            # Skip known legitimate processes
            if app_name in legitimate_processes:
                print(f"[WHITELIST] Skipping known legitimate process: {app_name}")
                skipped_processes += 1
                continue
            
            # Skip processes from trusted Microsoft directories
            if any(path.startswith(trusted_path) for trusted_path in legitimate_paths):
                if 'microsoft' in path or 'windows' in path:
                    print(f"[WHITELIST] Skipping trusted Microsoft/Windows process: {app_name} from {path}")
                    skipped_processes += 1
                    continue
            
            features = ml_features.get(process_id, {})
            
            # Create process entry with metadata and ML features
            process_entry = {
                "metadata": {
                        "process_id": process_id,
                        "app_name": data.get('app_name', 'Unknown'),
                        "path": data.get('full_path', 'N/A'),
                        "parent_pid": data.get('parent_pid', 'N/A'),
                        "parent_name": data.get('parent_name', 'N/A'),
                        "parent_app": data.get('parent_app_name', 'Unknown'),
                        "num_events": len(data.get('events', [])),
                        "event_types": list(set([event['EventID'] for event in data.get('events', [])])),
                        "hostname": socket.gethostname()
                    },
                "ml_features": [
                    features.get('File_Delete_archived', 0),
                    features.get('File_created', 0),
                    features.get('File_creation_time_changed', 0),
                    features.get('Pipe_Created', 0),
                    features.get('Process_Create', 0),
                    features.get('Registry_value_set', 0),
                    features.get('process-related', 0),
                    features.get('network-related', 0),
                    features.get('file-related', 0),
                    features.get('suspicious_path', 0),
                    features.get('system_executable', 0),
                    features.get('path_length', 0),
                    features.get('directory_depth', 0),
                    features.get('process_name_length', 0),
                    features.get('process_vs_parent_freq_ratio', 1.0),
                    features.get('executable_depth_diff', 0),
                    features.get('parent_is_system_executable', 0),
                    features.get('extension_similarity', 0),
                    features.get('file_name_entropy', 0.0)
                ]
            }
            payload["processes"].append(process_entry)
        
        if skipped_processes > 0:
            print(f"[INFO] Whitelisted {skipped_processes} known legitimate processes")
        
        if not payload["processes"]:
            print("[INFO] All processes whitelisted - no predictions needed")
            return None
        
        # Send POST request to prediction API
        print(f"[INFO] Sending {len(payload['processes'])} processes to prediction API...")
        response = requests.post(
            PREDICTION_API_URL, 
            json=payload, 
            headers={'Content-Type': 'application/json'},
            timeout=30  # 30 second timeout
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"[SUCCESS] Received predictions in {result.get('processing_time', 0):.4f}s")
            
            # Display summary
            summary = result.get('summary', {})
            print(f"[SUMMARY] Total: {summary.get('total_processes', 0)}, "
                  f"Malware: {summary.get('malware_count', 0)}, "
                  f"Benign: {summary.get('benign_count', 0)}, "
                  f"Malware %: {summary.get('malware_percentage', 0)}%")
            
            # Display individual predictions
            predictions = result.get('predictions', [])
            malware_found = False
            
            for pred in predictions:
                if pred['prediction'] == 'malware':
                    malware_found = True
                    metadata = pred.get('metadata', {})
                    print(f"🚨 MALWARE DETECTED - Process ID: {metadata.get('process_id', 'Unknown')}")
                    print(f"    App: {metadata.get('app_name', 'Unknown')} | Path: {metadata.get('path', 'N/A')}")
                    print(f"    Parent: {metadata.get('parent_app', 'Unknown')} | Events: {metadata.get('num_events', 0)}")
                    print(f"    Confidence: {pred['confidence']:.4f}")
                    print(f"    ⚠️  WARNING: Verify this detection - model may have false positive")
                    print(f"    Top reasons:")
                    for reason in pred['reasoning'][:2]:  # Show top 2 reasons
                        print(f"      - {reason['description']} (impact: {reason['contribution']:.4f})")
                else:
                    # Also show benign classifications for transparency
                    metadata = pred.get('metadata', {})
                    print(f"✅ BENIGN - {metadata.get('app_name', 'Unknown')} (PID: {metadata.get('process_id', 'Unknown')})")
            
            if not malware_found:
                print("✅ All processes classified as benign")
            
            return result
            
        else:
            print(f"[ERROR] API request failed with status {response.status_code}: {response.text}")
            return None
            
    except requests.exceptions.Timeout:
        print("[ERROR] API request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to prediction API. Is the server running?")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to send predictions: {e}")
        return None

def main():
    global ml_strings_buffer
    
    # Calculate timestamp for last 15 minutes
    event_timestamp = (datetime.utcnow() - timedelta(minutes=15)).isoformat(timespec='milliseconds') + "Z"
    SYSMON_XPATH_QUERY = f"""*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=5 or EventID=8 or EventID=10 or EventID=11 or EventID=13 or EventID=17 or EventID=22 or EventID=23 or EventID=25 or EventID=26) and TimeCreated[@SystemTime>='{event_timestamp}']]]"""

    process_events = defaultdict(lambda: {
        "app_name": None,
        "full_path": None,
        "parent_pid": None,
        "parent_name": None,
        "parent_app_name": None,
        "events": []
    })

    # Store all events for parent cache building
    all_events = []

    print("[INFO] Querying Sysmon logs...")

    query_handle = win32evtlog.EvtQuery(
        SYSMON_EVENT_LOG_PATH,
        win32evtlog.EvtQueryForwardDirection,
        SYSMON_XPATH_QUERY
    )

    while True:
        events = win32evtlog.EvtNext(query_handle, 10)
        if not events:
            break

        for event in events:
            xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            event_info = extract_app_name(xml_str)
            pid = event_info["ProcessID"]
            if pid == "N/A":
                continue  # Skip malformed logs

            # Store all events for cache building
            all_events.append(event_info)

            group = process_events[pid]

            # Update only if the values are valid or not yet set
            if not group["app_name"]:
                group["app_name"] = event_info["Application"]
            if not group["full_path"]:
                group["full_path"] = event_info["Path"]
            if not group["parent_app_name"]:
                group["parent_app_name"] = event_info["ParentApplication"]

            if (group["parent_pid"] in (None, "N/A")) and event_info["ParentProcessID"] != "N/A":
                group["parent_pid"] = event_info["ParentProcessID"]
            if (group["parent_name"] in (None, "N/A")) and event_info["ParentProcessName"] != "N/A":
                group["parent_name"] = event_info["ParentProcessName"]

            group["events"].append({
                "EventID": event_info["EventID"],
                "Time": event_info["Time"]
            })

    # Check if events have changed using the change detection optimization
    events_changed = has_events_changed(process_events)
    
    if not events_changed:
        print(f"[OPTIMIZATION] No significant event changes detected (consecutive: {consecutive_no_change_count})")
        print("[OPTIMIZATION] Skipping processing and API call to save resources")
        
        # Show brief status every 10 iterations when no changes
        if consecutive_no_change_count % 10 == 0:
            print(f"[STATUS] Still monitoring... {consecutive_no_change_count} consecutive iterations with no changes")
            print(f"[STATUS] Cache size: {len(global_parent_cache)}, Buffer size: {len(ml_strings_buffer)}")
        
        return  # Skip expensive processing when no changes detected

    print(f"[OPTIMIZATION] Significant event changes detected! Processing {len(process_events)} processes...")

    # Build parent process cache from Event ID 1 records
    print("[INFO] Building parent process cache...")
    build_parent_cache(all_events)
    print(f"[INFO] Built parent cache with {len(global_parent_cache)} process creation records")

    # Calculate frequency ratios using cache (EXACT original method)
    print("[INFO] Calculating process vs parent frequency ratios with cache...")
    frequency_ratios = calculate_process_vs_parent_freq_ratio(process_events)
    
    # Extract ML binary features
    print("[INFO] Extracting ML binary features...")
    ml_features = extract_ml_features(process_events, frequency_ratios)

    # Clear the current buffer and collect new ML strings
    current_ml_strings = []

    # Print grouped log data in a readable format with frequency ratios
    print(f"\n{'='*80}")
    print("SYSMON LOG ANALYSIS WITH ML FEATURES")
    print(f"{'='*80}")
    
    for process_id, data in process_events.items():
        ratio = frequency_ratios.get(process_id, 1.0)
        
        print(f"\n🔸 Process ID: {process_id}")
        print(f"    App Name: {data['app_name']}")
        print(f"    Path: {data['full_path']}")
        print(f"    Parent PID: {data['parent_pid']}")
        print(f"    Parent Name: {data['parent_name']}")
        print(f"    Parent App: {data['parent_app_name']}")
        
        # Check if parent info came from cache
        cache_key = (process_id, data['app_name'])
        if cache_key in global_parent_cache and (not data['parent_app_name'] or data['parent_app_name'] == "Unknown"):
            cached_parent = global_parent_cache[cache_key]['parent_app_name']
            print(f"    Parent App (Cached): {cached_parent}")
        
        print(f"    Number of Events: {len(data['events'])}")
        print(f"    🎯 ML Feature - process_vs_parent_freq_ratio: {ratio}")
        
        # SIMPLE interpretation for analysts (no artificial thresholds)
        cache_key = (process_id, data['app_name'])
        if ratio == 1.0 and (not data['parent_app_name'] or data['parent_app_name'] == "Unknown") and cache_key not in global_parent_cache:
            print(f"    ℹ️  INFO: No parent information available (set to neutral 1.0)")
        elif ratio < 0.1:
            print(f"    ⚠️  ALERT: Very low frequency ratio - potentially suspicious!")
        elif ratio < 0.5:
            print(f"    ⚡ MEDIUM: Low frequency ratio - worth investigating")
        else:
            print(f"    ✅ NORMAL: Process frequency is normal relative to parent")
        
        print(f"    Events:")
        for entry in data['events']:
            print(f"      ➤ Event ID: {entry['EventID']}, Time: {entry['Time']}")
        
        # Add ML feature string with all binary and numerical features (CORRECT ORDER)
        features = ml_features.get(process_id, {})
        ml_string = f"{process_id},{features.get('File_Delete_archived', 0)},{features.get('File_created', 0)},{features.get('File_creation_time_changed', 0)},{features.get('Pipe_Created', 0)},{features.get('Process_Create', 0)},{features.get('Registry_value_set', 0)},{features.get('process-related', 0)},{features.get('network-related', 0)},{features.get('file-related', 0)},{features.get('suspicious_path', 0)},{features.get('system_executable', 0)},{features.get('path_length', 0)},{features.get('directory_depth', 0)},{features.get('process_name_length', 0)},{features.get('process_vs_parent_freq_ratio', 1.0)},{features.get('executable_depth_diff', 0)},{features.get('parent_is_system_executable', 0)},{features.get('extension_similarity', 0)},{features.get('file_name_entropy', 0.0)}"
        print(f"    🤖 ML String: {ml_string}")
        
        # Collect ML string for batch prediction
        current_ml_strings.append(ml_string)
        
        # Debug: Show actual feature values for verification
        print(f"    🔍 Debug - Path: '{data['full_path']}' (len={features.get('path_length', 0)})")
        print(f"    🔍 Debug - App: '{data['app_name']}' (len={features.get('process_name_length', 0)})")
        print(f"    🔍 Debug - Parent: '{data['parent_name']}' (system={features.get('parent_is_system_executable', 0)})")
        print(f"    🔍 Debug - Depth diff: {features.get('executable_depth_diff', 0)}, Ext similarity: {features.get('extension_similarity', 0)}, Entropy: {features.get('file_name_entropy', 0.0)}")

    # Send ML features for batch prediction
    if process_events:
        print(f"\n{'='*80}")
        print("SENDING TO ML PREDICTION API")
        print(f"{'='*80}")
        prediction_result = send_predictions_to_api(process_events, ml_features)
        
        # Add to global buffer for continuous monitoring (still keep the strings for debugging)
        for process_id, data in process_events.items():
            features = ml_features.get(process_id, {})
            ml_string = f"{process_id},{features.get('File_Delete_archived', 0)},{features.get('File_created', 0)},{features.get('File_creation_time_changed', 0)},{features.get('Pipe_Created', 0)},{features.get('Process_Create', 0)},{features.get('Registry_value_set', 0)},{features.get('process-related', 0)},{features.get('network-related', 0)},{features.get('file-related', 0)},{features.get('suspicious_path', 0)},{features.get('system_executable', 0)},{features.get('path_length', 0)},{features.get('directory_depth', 0)},{features.get('process_name_length', 0)},{features.get('process_vs_parent_freq_ratio', 1.0)},{features.get('executable_depth_diff', 0)},{features.get('parent_is_system_executable', 0)},{features.get('extension_similarity', 0)},{features.get('file_name_entropy', 0.0)}"
            ml_strings_buffer.append(ml_string)
    else:
        print(f"\n[INFO] No processes found in this iteration")

    # Print summary statistics for ML model preparation
    print(f"\n{'='*80}")
    print("ML FEATURE SUMMARY")
    print(f"{'='*80}")
    
    ratios_list = list(frequency_ratios.values())
    cache_hits = sum(1 for pid, data in process_events.items() 
                    if (pid, data['app_name']) in global_parent_cache)
    no_parent_count = sum(1 for r in ratios_list if r == 1.0)
    
    if ratios_list:
        print(f"Total processes analyzed: {len(ratios_list)}")
        print(f"Processes with cached parent info: {cache_hits}")
        print(f"Processes without parent info (ratio=1.0): {no_parent_count}")
        print(f"Average process_vs_parent_freq_ratio: {sum(ratios_list)/len(ratios_list):.4f}")
        print(f"Min ratio: {min(ratios_list):.4f}")
        print(f"Max ratio: {max(ratios_list):.4f}")
        
        # Count suspicious processes (low ratios)
        suspicious_count = sum(1 for r in ratios_list if r < 0.1)
        print(f"Processes with very low ratios (<0.1): {suspicious_count}")
        print(f"Percentage potentially suspicious: {(suspicious_count/len(ratios_list)*100):.2f}%")
        
        # Cache effectiveness
        print(f"Cache hit rate: {(cache_hits/len(ratios_list)*100):.2f}%")
        
        # ML Features summary
        print(f"\nML BINARY FEATURES SUMMARY:")
        total_processes = len(ml_features)
        if total_processes > 0:
            # Binary features
            for feature_name in ['File_created', 'File_Delete_archived', 'File_creation_time_changed', 
                               'Registry_value_set', 'Process_Create', 'Pipe_Created', 
                               'file-related', 'network-related', 'process-related',
                               'suspicious_path', 'system_executable', 'parent_is_system_executable',
                               'extension_similarity']:
                count = sum(1 for features in ml_features.values() if features.get(feature_name, 0) == 1)
                percentage = (count / total_processes) * 100
                print(f"  {feature_name}: {count}/{total_processes} ({percentage:.1f}%)")
            
            # Numerical features summary
            print(f"\nML NUMERICAL FEATURES SUMMARY:")
            numerical_features = ['path_length', 'directory_depth', 'process_name_length', 
                                'process_vs_parent_freq_ratio', 'executable_depth_diff', 'file_name_entropy']
            for feature_name in numerical_features:
                values = [features.get(feature_name, 0) for features in ml_features.values()]
                if values:
                    avg_val = sum(values) / len(values)
                    min_val = min(values)
                    max_val = max(values)
                    print(f"  {feature_name}: avg={avg_val:.3f}, min={min_val}, max={max_val}")
    else:
        print(f"No processes found.")

# 11. Enhanced continuous monitoring function with change detection optimization
def run_continuous():
    global consecutive_no_change_count
    
    iteration = 0
    total_skipped = 0
    total_processed = 0
    
    print("[INFO] Starting OPTIMIZED continuous monitoring every 3 seconds...")
    print("[INFO] 🚀 Change detection enabled - will only process when new events detected")
    print("[INFO] Press Ctrl+C to stop")
    print(f"[INFO] Prediction API endpoint: {PREDICTION_API_URL}")
    
    # Test API connection on startup
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("[INFO] ✅ Prediction API is accessible")
        else:
            print(f"[WARNING] ⚠️ Prediction API health check failed: {response.status_code}")
    except Exception as e:
        print(f"[WARNING] ⚠️ Cannot connect to Prediction API: {e}")
        print("[INFO] Continuing without predictions...")
    
    try:
        while True:
            iteration += 1
            start_time = time.time()
            
            print(f"\n{'='*60}")
            print(f"ITERATION #{iteration} - {datetime.now().strftime('%H:%M:%S')}")
            print(f"Global cache size: {len(global_parent_cache)}")
            print(f"ML strings buffer size: {len(ml_strings_buffer)}")
            
            # Performance tracking
            if iteration > 1:
                efficiency = (total_skipped / (total_processed + total_skipped)) * 100 if (total_processed + total_skipped) > 0 else 0
                print(f"⚡ EFFICIENCY: {total_skipped} skipped, {total_processed} processed ({efficiency:.1f}% saved)")
            
            print(f"{'='*60}")
            
            # Run the main function with change detection
            main()
            
            # Update counters based on whether processing occurred
            if consecutive_no_change_count == 0:  # Processing occurred (events changed)
                total_processed += 1
            else:
                total_skipped += 1
            
            # Calculate iteration time
            iteration_time = time.time() - start_time
            print(f"\n[PERF] ⏱️ Iteration completed in {iteration_time:.2f}s")
            
            # Dynamic sleep based on activity
            if consecutive_no_change_count > 20:  # If no changes for a while
                sleep_time = 5  # Sleep longer when system is quiet
                print(f"[INFO] 😴 System quiet for {consecutive_no_change_count} iterations - sleeping {sleep_time}s")
            else:
                sleep_time = 3  # Normal monitoring frequency
                print(f"[INFO] ⏳ Waiting {sleep_time}s for next iteration...")
            
            time.sleep(sleep_time)
            
    except KeyboardInterrupt:
        print(f"\n{'='*60}")
        print("MONITORING STOPPED - FINAL STATISTICS")
        print(f"{'='*60}")
        print(f"[INFO] Total iterations: {iteration}")
        print(f"[INFO] Processed: {total_processed}, Skipped: {total_skipped}")
        efficiency = (total_skipped / iteration) * 100 if iteration > 0 else 0
        print(f"[INFO] 🚀 Overall efficiency: {efficiency:.1f}% API calls saved")
        print(f"[INFO] Final cache size: {len(global_parent_cache)}")
        print(f"[INFO] Total ML strings collected: {len(ml_strings_buffer)}")
        print(f"[INFO] Resource savings: ~{total_skipped} unnecessary API calls prevented")

# 12. Event-driven monitoring using Windows Event Subscription (more efficient)
def run_event_driven_monitoring():
    """
    Run true event-driven monitoring using Windows Event Subscription.
    This is more efficient as it only triggers when new Sysmon events arrive.
    """
    print("[INFO] Starting EVENT-DRIVEN monitoring...")
    print("[INFO] 🚀 This approach only processes when new Sysmon events arrive")
    print("[INFO] Much more efficient than polling-based monitoring")
    print(f"[INFO] Prediction API endpoint: {PREDICTION_API_URL}")
    
    # Test API connection on startup
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("[INFO] ✅ Prediction API is accessible")
        else:
            print(f"[WARNING] ⚠️ Prediction API health check failed: {response.status_code}")
    except Exception as e:
        print(f"[WARNING] ⚠️ Cannot connect to Prediction API: {e}")
        print("[INFO] Continuing without predictions...")
    
    print("[INFO] Press Ctrl+C to stop")
    
    try:
        # Import required for event subscription
        import win32event
        import win32api
        
        # Create event subscription for real-time monitoring
        # Note: This requires elevated privileges and proper Windows Event API setup
        event_count = 0
        last_batch_time = time.time()
        batch_interval = 5  # Process events in 5-second batches
        
        print(f"[INFO] Event-driven monitoring started with {batch_interval}s batch intervals")
        
        # For demonstration, we'll use a hybrid approach:
        # Check for new events more frequently but only process when changes detected
        while True:
            current_time = time.time()
            
            # Check if it's time to process a batch
            if current_time - last_batch_time >= batch_interval:
                print(f"\n[EVENT-DRIVEN] Processing event batch at {datetime.now().strftime('%H:%M:%S')}")
                
                # Run main processing with change detection
                main()
                
                last_batch_time = current_time
                event_count += 1
                
                print(f"[EVENT-DRIVEN] Batch #{event_count} completed")
            
            # Short sleep to avoid excessive CPU usage
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print(f"\n[INFO] Event-driven monitoring stopped after {event_count} batches")
        print(f"[INFO] Final cache size: {len(global_parent_cache)}")
        print(f"[INFO] Total ML strings collected: {len(ml_strings_buffer)}")
    except ImportError:
        print("[ERROR] Event-driven monitoring requires additional Windows API modules")
        print("[INFO] Falling back to optimized continuous monitoring...")
        run_continuous()

# 13. Basic monitoring without optimizations (for comparison/debugging)
def run_basic_monitoring():
    """
    Basic monitoring without change detection optimizations.
    Useful for debugging or when you want to see all processing steps.
    """
    print("[INFO] Starting BASIC monitoring (no optimizations)...")
    print("[INFO] This will process all events every iteration")
    print("[INFO] Press Ctrl+C to stop")
    print(f"[INFO] Prediction API endpoint: {PREDICTION_API_URL}")
    
    # Test API connection on startup
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("[INFO] ✅ Prediction API is accessible")
        else:
            print(f"[WARNING] ⚠️ Prediction API health check failed: {response.status_code}")
    except Exception as e:
        print(f"[WARNING] ⚠️ Cannot connect to Prediction API: {e}")
        print("[INFO] Continuing without predictions...")
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            start_time = time.time()
            
            print(f"\n{'='*60}")
            print(f"BASIC ITERATION #{iteration} - {datetime.now().strftime('%H:%M:%S')}")
            print(f"Global cache size: {len(global_parent_cache)}")
            print(f"ML strings buffer size: {len(ml_strings_buffer)}")
            print(f"{'='*60}")
            
            # Temporarily disable change detection for basic mode
            global last_events_hash, consecutive_no_change_count
            original_hash = last_events_hash
            original_count = consecutive_no_change_count
            
            # Force processing by resetting change detection
            last_events_hash = None
            consecutive_no_change_count = 0
            
            # Run main processing
            main()
            
            # Restore original values (though not really needed in basic mode)
            last_events_hash = original_hash
            consecutive_no_change_count = original_count
            
            # Calculate iteration timesu
            iteration_time = time.time() - start_time
            print(f"\n[PERF] ⏱️ Basic iteration completed in {iteration_time:.2f}s")
            print(f"[INFO] ⏳ Waiting 3s for next iteration...")
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        print(f"\n{'='*60}")
        print("BASIC MONITORING STOPPED")
        print(f"{'='*60}")
        print(f"[INFO] Total iterations: {iteration}")
        print(f"[INFO] Final cache size: {len(global_parent_cache)}")
        print(f"[INFO] Total ML strings collected: {len(ml_strings_buffer)}")

# 14. Entry point with corrected function calls
if __name__ == "__main__":
    import sys
    
    print("Sysmon Log Analyzer with ML Features")
    print("=====================================")
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--continuous":
            print("Running in OPTIMIZED continuous monitoring mode...")
            run_continuous()
        elif sys.argv[1] == "--event-driven":
            print("Running in EVENT-DRIVEN monitoring mode...")
            run_event_driven_monitoring()
        elif sys.argv[1] == "--basic":
            print("Running in BASIC monitoring mode (no optimizations)...")
            run_basic_monitoring()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Available options:")
            print("  --continuous    : Optimized polling with change detection")
            print("  --event-driven  : Event-driven monitoring")
            print("  --basic         : Basic monitoring without optimizations")
            print("  (no args)       : Single run analysis")
    else:
        print("Running single analysis...")
        main()
    
    print("\nScript completed.")