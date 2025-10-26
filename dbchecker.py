# database_alert_manager.py
# Comprehensive database management tool for Sysmon and Static analysis databases

import sqlite3
import os
import json
from datetime import datetime, timedelta
import pandas as pd

class DatabaseAlertManager:
    def __init__(self):
        # Database paths based on your cloud predictor configuration
        self.sysmon_db = 'malware_predictions.db'
        self.static_db = 'static_detections.db'
        self.ja3_db = 'ja3_database.db'
        
        print("🗄️  DATABASE ALERT MANAGER")
        print("=" * 50)
        print(f"Sysmon DB: {self.sysmon_db}")
        print(f"Static DB: {self.static_db}")
        print(f"JA3 DB: {self.ja3_db}")
        print("=" * 50)
    
    def check_databases(self):
        """Check which databases exist and are accessible"""
        databases = {
            'Sysmon': self.sysmon_db,
            'Static': self.static_db,
            'JA3': self.ja3_db
        }
        
        available = {}
        for name, path in databases.items():
            if os.path.exists(path):
                try:
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]
                    conn.close()
                    available[name] = {'path': path, 'tables': tables}
                    print(f"✅ {name}: {len(tables)} tables")
                except Exception as e:
                    print(f"❌ {name}: Error accessing - {e}")
            else:
                print(f"❌ {name}: File not found")
        
        return available
    
    def show_sysmon_summary(self):
        """Show summary of sysmon database contents"""
        if not os.path.exists(self.sysmon_db):
            print("❌ Sysmon database not found")
            return
        
        try:
            conn = sqlite3.connect(self.sysmon_db)
            cursor = conn.cursor()
            
            print("\n📊 SYSMON DATABASE SUMMARY")
            print("-" * 40)
            
            # Predictions summary
            cursor.execute('''
                SELECT 
                    prediction,
                    COUNT(*) as count,
                    COUNT(DISTINCT process_id) as unique_processes,
                    AVG(confidence) as avg_confidence,
                    MIN(created_at) as first_seen,
                    MAX(created_at) as last_seen
                FROM predictions 
                GROUP BY prediction
            ''')
            
            results = cursor.fetchall()
            for row in results:
                prediction, count, unique, avg_conf, first, last = row
                print(f"🔍 {prediction.upper()}:")
                print(f"   Total records: {count}")
                print(f"   Unique processes: {unique}")
                print(f"   Avg confidence: {avg_conf:.3f}")
                print(f"   First seen: {first}")
                print(f"   Last seen: {last}")
                print()
            
            # Recent malware detections
            cursor.execute('''
                SELECT app_name, process_id, confidence, created_at, path
                FROM predictions 
                WHERE prediction = 'malware'
                ORDER BY created_at DESC 
                LIMIT 10
            ''')
            
            malware_results = cursor.fetchall()
            if malware_results:
                print("🚨 RECENT MALWARE DETECTIONS (Last 10):")
                for i, (app, pid, conf, date, path) in enumerate(malware_results, 1):
                    print(f"   {i}. {app} (PID: {pid}) - {conf:.3f} confidence")
                    print(f"      Date: {date}")
                    print(f"      Path: {path[:60]}..." if len(path) > 60 else f"      Path: {path}")
                    print()
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error reading sysmon database: {e}")
    
    def show_static_summary(self):
        """Show summary of static analysis database contents"""
        if not os.path.exists(self.static_db):
            print("❌ Static database not found")
            return
        
        try:
            conn = sqlite3.connect(self.static_db)
            cursor = conn.cursor()
            
            print("\n📊 STATIC ANALYSIS DATABASE SUMMARY")
            print("-" * 40)
            
            # Detection summary
            cursor.execute('''
                SELECT 
                    prediction_result,
                    risk_level,
                    COUNT(*) as count,
                    AVG(confidence_score) as avg_confidence,
                    MIN(detection_time) as first_seen,
                    MAX(detection_time) as last_seen
                FROM detections 
                GROUP BY prediction_result, risk_level
                ORDER BY prediction_result, risk_level
            ''')
            
            results = cursor.fetchall()
            for row in results:
                pred, risk, count, avg_conf, first, last = row
                print(f"🔍 {pred} - {risk} RISK:")
                print(f"   Count: {count}")
                print(f"   Avg confidence: {avg_conf:.3f}")
                print(f"   First seen: {first}")
                print(f"   Last seen: {last}")
                print()
            
            # Recent ransomware detections
            cursor.execute('''
                SELECT file_name, file_source, confidence_score, detection_time, file_path
                FROM detections 
                WHERE prediction_result = 'RANSOMWARE'
                ORDER BY detection_time DESC 
                LIMIT 10
            ''')
            
            ransomware_results = cursor.fetchall()
            if ransomware_results:
                print("🚨 RECENT RANSOMWARE DETECTIONS (Last 10):")
                for i, (name, source, conf, date, path) in enumerate(ransomware_results, 1):
                    print(f"   {i}. {name} from {source} - {conf:.3f} confidence")
                    print(f"      Date: {date}")
                    print(f"      Path: {path[:60]}..." if len(path) > 60 else f"      Path: {path}")
                    print()
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error reading static database: {e}")
    
    def delete_sysmon_alerts(self):
        """Interactive deletion of sysmon alerts"""
        if not os.path.exists(self.sysmon_db):
            print("❌ Sysmon database not found")
            return
        
        print("\n🗑️  SYSMON ALERT DELETION")
        print("-" * 30)
        print("1. Delete by app name")
        print("2. Delete by process ID")
        print("3. Delete by confidence threshold")
        print("4. Delete by date range")
        print("5. Delete by prediction type")
        print("6. View and delete specific records")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        try:
            conn = sqlite3.connect(self.sysmon_db)
            cursor = conn.cursor()
            
            if choice == '1':
                app_name = input("Enter app name to delete: ").strip()
                cursor.execute('SELECT COUNT(*) FROM predictions WHERE app_name LIKE ?', (f'%{app_name}%',))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records for app '{app_name}'? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM predictions WHERE app_name LIKE ?', (f'%{app_name}%',))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '2':
                process_id = input("Enter process ID to delete: ").strip()
                cursor.execute('SELECT COUNT(*) FROM predictions WHERE process_id = ?', (process_id,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records for process ID '{process_id}'? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM predictions WHERE process_id = ?', (process_id,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '3':
                threshold = float(input("Enter confidence threshold (delete records BELOW this value): "))
                cursor.execute('SELECT COUNT(*) FROM predictions WHERE confidence < ?', (threshold,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records with confidence < {threshold}? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM predictions WHERE confidence < ?', (threshold,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '4':
                days = int(input("Delete records older than how many days? "))
                cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
                cursor.execute('SELECT COUNT(*) FROM predictions WHERE created_at < ?', (cutoff_date,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records older than {days} days? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM predictions WHERE created_at < ?', (cutoff_date,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '5':
                pred_type = input("Enter prediction type to delete (malware/benign): ").strip().lower()
                cursor.execute('SELECT COUNT(*) FROM predictions WHERE prediction = ?', (pred_type,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete ALL {count} '{pred_type}' records? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM predictions WHERE prediction = ?', (pred_type,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '6':
                # Show recent records for manual selection
                cursor.execute('''
                    SELECT id, app_name, process_id, prediction, confidence, created_at 
                    FROM predictions 
                    ORDER BY created_at DESC 
                    LIMIT 20
                ''')
                
                records = cursor.fetchall()
                if records:
                    print("\n📋 RECENT RECORDS:")
                    for record in records:
                        id_, app, pid, pred, conf, date = record
                        print(f"ID: {id_} | {app} | PID: {pid} | {pred} | {conf:.3f} | {date}")
                    
                    record_id = input("\nEnter record ID to delete (or 'cancel'): ").strip()
                    if record_id.isdigit():
                        cursor.execute('DELETE FROM predictions WHERE id = ?', (int(record_id),))
                        conn.commit()
                        print(f"✅ Deleted record ID {record_id}")
                    else:
                        print("❌ Cancelled")
                else:
                    print("❌ No records found")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error deleting sysmon records: {e}")
    
    def delete_static_alerts(self):
        """Interactive deletion of static analysis alerts"""
        if not os.path.exists(self.static_db):
            print("❌ Static database not found")
            return
        
        print("\n🗑️  STATIC ANALYSIS ALERT DELETION")
        print("-" * 35)
        print("1. Delete by file name")
        print("2. Delete by file source")
        print("3. Delete by risk level")
        print("4. Delete by confidence threshold")
        print("5. Delete by prediction result")
        print("6. Delete by date range")
        print("7. View and delete specific records")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        try:
            conn = sqlite3.connect(self.static_db)
            cursor = conn.cursor()
            
            if choice == '1':
                file_name = input("Enter file name to delete: ").strip()
                cursor.execute('SELECT COUNT(*) FROM detections WHERE file_name LIKE ?', (f'%{file_name}%',))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records for file '{file_name}'? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE file_name LIKE ?', (f'%{file_name}%',))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '2':
                file_source = input("Enter file source (DOWNLOADS/DESKTOP/TEMP/etc): ").strip().upper()
                cursor.execute('SELECT COUNT(*) FROM detections WHERE file_source = ?', (file_source,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records from source '{file_source}'? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE file_source = ?', (file_source,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '3':
                risk_level = input("Enter risk level (CRITICAL/HIGH/MEDIUM/LOW): ").strip().upper()
                cursor.execute('SELECT COUNT(*) FROM detections WHERE risk_level = ?', (risk_level,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records with risk '{risk_level}'? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE risk_level = ?', (risk_level,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '4':
                threshold = float(input("Enter confidence threshold (delete records BELOW this value): "))
                cursor.execute('SELECT COUNT(*) FROM detections WHERE confidence_score < ?', (threshold,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records with confidence < {threshold}? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE confidence_score < ?', (threshold,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '5':
                pred_result = input("Enter prediction result (RANSOMWARE/BENIGN): ").strip().upper()
                cursor.execute('SELECT COUNT(*) FROM detections WHERE prediction_result = ?', (pred_result,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete ALL {count} '{pred_result}' records? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE prediction_result = ?', (pred_result,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '6':
                days = int(input("Delete records older than how many days? "))
                cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
                cursor.execute('SELECT COUNT(*) FROM detections WHERE detection_time < ?', (cutoff_date,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    confirm = input(f"Delete {count} records older than {days} days? (yes/no): ")
                    if confirm.lower() == 'yes':
                        cursor.execute('DELETE FROM detections WHERE detection_time < ?', (cutoff_date,))
                        conn.commit()
                        print(f"✅ Deleted {cursor.rowcount} records")
                else:
                    print("❌ No records found")
            
            elif choice == '7':
                # Show recent records for manual selection
                cursor.execute('''
                    SELECT id, file_name, file_source, prediction_result, confidence_score, detection_time 
                    FROM detections 
                    ORDER BY detection_time DESC 
                    LIMIT 20
                ''')
                
                records = cursor.fetchall()
                if records:
                    print("\n📋 RECENT RECORDS:")
                    for record in records:
                        id_, name, source, pred, conf, date = record
                        print(f"ID: {id_} | {name} | {source} | {pred} | {conf:.3f} | {date}")
                    
                    record_id = input("\nEnter record ID to delete (or 'cancel'): ").strip()
                    if record_id.isdigit():
                        cursor.execute('DELETE FROM detections WHERE id = ?', (int(record_id),))
                        conn.commit()
                        print(f"✅ Deleted record ID {record_id}")
                    else:
                        print("❌ Cancelled")
                else:
                    print("❌ No records found")
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error deleting static records: {e}")
    
    def export_database_data(self):
        """Export database data to CSV files"""
        print("\n📤 EXPORT DATABASE DATA")
        print("-" * 25)
        print("1. Export Sysmon predictions")
        print("2. Export Static detections")
        print("3. Export both databases")
        print("0. Back to main menu")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice in ['1', '3']:
            if os.path.exists(self.sysmon_db):
                try:
                    conn = sqlite3.connect(self.sysmon_db)
                    df = pd.read_sql_query('SELECT * FROM predictions', conn)
                    filename = f'sysmon_predictions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                    df.to_csv(filename, index=False)
                    conn.close()
                    print(f"✅ Sysmon data exported to {filename}")
                except Exception as e:
                    print(f"❌ Error exporting sysmon data: {e}")
        
        if choice in ['2', '3']:
            if os.path.exists(self.static_db):
                try:
                    conn = sqlite3.connect(self.static_db)
                    df = pd.read_sql_query('SELECT * FROM detections', conn)
                    filename = f'static_detections_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                    df.to_csv(filename, index=False)
                    conn.close()
                    print(f"✅ Static data exported to {filename}")
                except Exception as e:
                    print(f"❌ Error exporting static data: {e}")
    
    def vacuum_databases(self):
        """Optimize databases after deletions"""
        print("\n🧹 OPTIMIZING DATABASES...")
        
        databases = [
            ('Sysmon', self.sysmon_db),
            ('Static', self.static_db),
            ('JA3', self.ja3_db)
        ]
        
        for name, db_path in databases:
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    
                    # Get database size before
                    size_before = os.path.getsize(db_path)
                    
                    # Vacuum the database
                    cursor.execute('VACUUM')
                    conn.commit()
                    conn.close()
                    
                    # Get database size after
                    size_after = os.path.getsize(db_path)
                    space_saved = size_before - size_after
                    
                    print(f"✅ {name}: {space_saved:,} bytes saved")
                    
                except Exception as e:
                    print(f"❌ Error optimizing {name}: {e}")
    
    def run(self):
        """Main interactive menu"""
        while True:
            print(f"\n🎯 DATABASE ALERT MANAGER")
            print("=" * 30)
            
            available_dbs = self.check_databases()
            
            print("\nMain Menu:")
            print("1. Show Sysmon summary")
            print("2. Show Static analysis summary")
            print("3. Delete Sysmon alerts")
            print("4. Delete Static analysis alerts")
            print("5. Export database data")
            print("6. Optimize databases (VACUUM)")
            print("0. Exit")
            
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '1':
                self.show_sysmon_summary()
            elif choice == '2':
                self.show_static_summary()
            elif choice == '3':
                self.delete_sysmon_alerts()
            elif choice == '4':
                self.delete_static_alerts()
            elif choice == '5':
                self.export_database_data()
            elif choice == '6':
                self.vacuum_databases()
            elif choice == '0':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice")
            
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        manager = DatabaseAlertManager()
        manager.run()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")