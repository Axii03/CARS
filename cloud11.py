from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import pandas as pd
import time
import shap
import logging
import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration
DB_PATH = 'malware_predictions.db'
JA3_DB_PATH = 'ja3_database.db'
STATIC_MODEL_PATH = "models/ransomware_lgb_model_optimized_final.joblib"

# Load model and create explainer once at startup
try:
    model = joblib.load('models/xgb_detector.joblib')
    explainer = shap.TreeExplainer(model)
    logger.info("Model and SHAP explainer loaded successfully")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None
    explainer = None

# Feature names in exact order as model expects
FEATURE_NAMES = [
    "File_Delete_archived", "File_created", "File_creation_time_changed", "Pipe_Created",
    "Process_Create", "Registry_value_set", "process-related", "network-related",
    "file-related", "suspicious_path", "system_executable", "path_length",
    "directory_depth", "process_name_length", "process_vs_parent_freq_ratio",
    "executable_depth_diff", "parent_is_system_executable", "extension_similarity",
    "file_name_entropy"
]


class StaticRansomwareMLModel:
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = None
        self.model_loaded = False
        self.load_model()
    
    def load_model(self):
        try:
            logger.info(f"Loading static ML model from: {self.model_path}")
            self.model = joblib.load(self.model_path)
            self.model_loaded = True
            logger.info("Static model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading static model: {e}")
            self.model_loaded = False
    
    def predict_ransomware_with_confidence(self, features_dict):
        """Predict ransomware with confidence scores"""
        if not self.model_loaded:
            return {
                'prediction': 'ERROR',
                'confidence': 0.0,
                'probability_ransomware': 0.0,
                'probability_benign': 0.0,
                'binary_prediction': -1,
                'error': 'Model not loaded'
            }
        
        # Feature names in exact order used during training
        feature_names = [
            'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 
            'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA', 
            'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections', 
            'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 'BitcoinAddresses'
        ]
        
        try:
            # Prepare features in correct order with proper DataFrame format
            feature_data = {name: features_dict.get(name, 0.0) for name in feature_names}
            features_df = pd.DataFrame([feature_data])
            
            # Get prediction and probabilities
            binary_prediction = self.model.predict(features_df)[0]  # 0 or 1
            probabilities = self.model.predict_proba(features_df)[0]  # [prob_ransomware, prob_benign]
            
            # Calculate confidence (probability of predicted class)
            confidence = probabilities[binary_prediction]
            
            # Convert binary prediction to label (0=Ransomware, 1=Benign)
            prediction_label = "BENIGN" if binary_prediction == 1 else "RANSOMWARE"
            
            return {
                'prediction': prediction_label,
                'confidence': float(confidence),
                'probability_ransomware': float(probabilities[0]),
                'probability_benign': float(probabilities[1]),
                'binary_prediction': int(binary_prediction),
                'is_ransomware': bool(binary_prediction == 0)
            }
            
        except Exception as e:
            logger.error(f"Static prediction error: {e}")
            return {
                'prediction': 'ERROR',
                'confidence': 0.0,
                'probability_ransomware': 0.0,
                'probability_benign': 0.0,
                'binary_prediction': -1,
                'error': str(e)
            }


@contextmanager
def get_db_connection(db_path=None):
    """Context manager for database connections"""
    if db_path is None:
        db_path = DB_PATH  # Default to ML predictions database
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_ja3_db_connection():
    """Context manager for JA3 detection database connections"""
    conn = sqlite3.connect(JA3_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_static_db_connection():
    """Context manager for static analysis database connections"""
    static_db_path = 'static_detections.db'  
    conn = sqlite3.connect(static_db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_static_db_connection():
    """Context manager for static analysis database connections"""
    static_db_path = 'static_detections.db'  
    conn = sqlite3.connect(static_db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_static_database():
    """Initialize the static analysis database with required tables"""
    try:
        with get_static_db_connection() as conn:
            cursor = conn.cursor()
            
            # Main detections table (matches your static.html expectations)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    file_signature TEXT,
                    file_source TEXT,
                    prediction_result TEXT NOT NULL,
                    confidence_score REAL,
                    probability_ransomware REAL,
                    probability_benign REAL,
                    risk_level TEXT,
                    processing_time_ms REAL,
                    client_ip TEXT,
                    model_version TEXT DEFAULT 'LightGBM_v1.0'
                )
            ''')
            
            # Summary statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS static_summary (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    total_files_analyzed INTEGER DEFAULT 0,
                    total_ransomware_detected INTEGER DEFAULT 0,
                    total_benign_files INTEGER DEFAULT 0,
                    avg_confidence_score REAL DEFAULT 0,
                    highest_confidence_score REAL DEFAULT 0,
                    lowest_confidence_score REAL DEFAULT 1.0,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Initialize summary if empty
            cursor.execute('SELECT COUNT(*) FROM static_summary')
            if cursor.fetchone()[0] == 0:
                cursor.execute('''
                    INSERT INTO static_summary (
                        total_files_analyzed, total_ransomware_detected, total_benign_files
                    ) VALUES (0, 0, 0)
                ''')
            
            conn.commit()
            logger.info("Static analysis database initialized successfully")
            
    except Exception as e:
        logger.error(f"Error initializing static database: {e}")

def init_database():
    """Initialize the SQLite database with required tables including whitelist"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create predictions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process_id TEXT NOT NULL,
                app_name TEXT,
                path TEXT,
                parent_pid TEXT,
                parent_name TEXT,
                parent_app TEXT,
                hostname TEXT,
                num_events INTEGER,
                event_types TEXT,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                processing_time REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create feature explanations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feature_explanations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prediction_id INTEGER NOT NULL,
                feature_name TEXT NOT NULL,
                feature_value REAL NOT NULL,
                contribution REAL NOT NULL,
                direction TEXT NOT NULL,
                description TEXT,
                FOREIGN KEY (prediction_id) REFERENCES predictions (id)
            )
        ''')
        
        # Create batch summaries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS batch_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_processes INTEGER NOT NULL,
                malware_count INTEGER NOT NULL,
                benign_count INTEGER NOT NULL,
                malware_percentage REAL NOT NULL,
                processing_time REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create whitelist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelisted_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL,
                absolute_path TEXT,
                whitelist_type TEXT NOT NULL DEFAULT 'manual',
                reason TEXT,
                added_by TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create whitelist activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                process_name TEXT NOT NULL,
                absolute_path TEXT,
                reason TEXT,
                performed_by TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for faster whitelist lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_whitelist_process_name 
            ON whitelisted_apps (process_name, is_active)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_whitelist_path 
            ON whitelisted_apps (absolute_path, is_active)
        ''')
        
        conn.commit()
        logger.info("Database initialized successfully with whitelist tables")

def check_if_whitelisted(app_name, path=None):
    """Check if a process is whitelisted based on name and/or path"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # First check by exact process name
            cursor.execute('''
                SELECT id FROM whitelisted_apps 
                WHERE process_name = ? AND is_active = 1
            ''', (app_name,))
            
            if cursor.fetchone():
                return True
            
            # If path is provided, check by exact path match
            if path:
                cursor.execute('''
                    SELECT id FROM whitelisted_apps 
                    WHERE absolute_path = ? AND is_active = 1
                ''', (path,))
                
                if cursor.fetchone():
                    return True
            
            return False
            
    except Exception as e:
        logger.error(f"Error checking whitelist status: {e}")
        return False

def store_predictions_to_db(predictions_data):
    """Store prediction results to database with whitelist checking"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Count unique processes for summary (excluding whitelisted from malware count)
            unique_processes = set()
            malware_processes = set()
            whitelisted_malware_processes = set()
            
            for prediction in predictions_data['predictions']:
                process_id = prediction['metadata'].get('process_id', '')
                app_name = prediction['metadata'].get('app_name', '')
                path = prediction['metadata'].get('path', '')
                
                unique_processes.add(process_id)
                
                if prediction['prediction'] == 'malware':
                    # Check if this process is whitelisted
                    if check_if_whitelisted(app_name, path):
                        whitelisted_malware_processes.add(process_id)
                        logger.info(f"Whitelisted malware detection: {app_name} (PID: {process_id})")
                    else:
                        malware_processes.add(process_id)
            
            total_unique = len(unique_processes)
            # Only count non-whitelisted malware for dashboard stats
            malware_unique = len(malware_processes)
            benign_unique = total_unique - len(malware_processes) - len(whitelisted_malware_processes)
            malware_percentage = (malware_unique / total_unique * 100) if total_unique > 0 else 0
            
            # Store batch summary with adjusted counts (excluding whitelisted malware)
            cursor.execute('''
                INSERT INTO batch_summaries 
                (timestamp, total_processes, malware_count, benign_count, malware_percentage, processing_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                predictions_data['timestamp'],
                total_unique - len(whitelisted_malware_processes),  # Exclude whitelisted from totals
                malware_unique,
                benign_unique,
                malware_percentage,
                predictions_data['processing_time']
            ))
            
            # Store individual predictions (all of them, including whitelisted)
            for prediction in predictions_data['predictions']:
                metadata = prediction['metadata']
                
                # Insert prediction record
                cursor.execute('''
                    INSERT INTO predictions 
                    (timestamp, process_id, app_name, path, parent_pid, parent_name, 
                     parent_app,hostname, num_events, event_types, prediction, confidence, processing_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
                ''', (
                    predictions_data['timestamp'],
                    metadata.get('process_id', ''),
                    metadata.get('app_name', ''),
                    metadata.get('path', ''),
                    metadata.get('parent_pid', ''),
                    metadata.get('parent_name', ''),
                    metadata.get('parent_app', ''),
                    metadata.get('hostname', 'Unknown'),
                    metadata.get('num_events', 0),
                    json.dumps(metadata.get('event_types', [])),
                    prediction['prediction'],
                    prediction['confidence'],
                    predictions_data['processing_time']
                ))
                
                prediction_id = cursor.lastrowid
                
                # Store feature explanations
                for reason in prediction['reasoning']:
                    cursor.execute('''
                        INSERT INTO feature_explanations 
                        (prediction_id, feature_name, feature_value, contribution, direction, description)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        prediction_id,
                        reason['feature'],
                        reason['value'],
                        reason['contribution'],
                        reason['direction'],
                        reason['description']
                    ))
            
            conn.commit()
            logger.info(f"Stored {len(predictions_data['predictions'])} predictions ({total_unique} unique processes, {len(whitelisted_malware_processes)} whitelisted malware) to database")
            
    except Exception as e:
        logger.error(f"Error storing predictions to database: {e}")
        raise

# Add this RIGHT AFTER the store_predictions_to_db function (around line 250)
def store_static_analysis_to_db(file_data, prediction_result, client_ip):
    """Store static analysis results to database"""
    try:
        with get_static_db_connection() as conn:
            cursor = conn.cursor()
            
            # Calculate risk level based on prediction and confidence
            risk_level = calculate_display_risk_level(
                prediction_result.get('prediction', 'BENIGN'),
                prediction_result.get('confidence', 0.0)
            )
            
            # Insert detailed analysis record
            cursor.execute('''
                INSERT INTO detections 
                (file_path, file_name, file_size, file_signature, file_source,
                 prediction_result, confidence_score, probability_ransomware, probability_benign,
                 risk_level, processing_time_ms, client_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_data.get('file_path', ''),
                file_data.get('file_name', ''),
                file_data.get('file_size', 0),
                file_data.get('file_signature', ''),
                file_data.get('file_source', 'UNKNOWN'),
                prediction_result.get('prediction', ''),
                prediction_result.get('confidence', 0.0),
                prediction_result.get('probability_ransomware', 0.0),
                prediction_result.get('probability_benign', 0.0),
                risk_level,
                prediction_result.get('processing_time', 0.0),
                client_ip
            ))
            
            # Update summary statistics
            is_ransomware = prediction_result.get('is_ransomware', False)
            confidence = prediction_result.get('confidence', 0.0)
            
            cursor.execute('''
                UPDATE static_summary SET 
                    total_files_analyzed = total_files_analyzed + 1,
                    total_ransomware_detected = total_ransomware_detected + ?,
                    total_benign_files = total_benign_files + ?,
                    highest_confidence_score = MAX(highest_confidence_score, ?),
                    lowest_confidence_score = MIN(lowest_confidence_score, ?),
                    last_updated = CURRENT_TIMESTAMP
                WHERE id = 1
            ''', (1 if is_ransomware else 0, 0 if is_ransomware else 1, confidence, confidence))
            
            # Update average confidence score
            cursor.execute('''
                UPDATE static_summary SET 
                    avg_confidence_score = (
                        SELECT AVG(confidence_score) FROM detections
                    )
                WHERE id = 1
            ''')
            
            conn.commit()
            logger.info(f"Stored static analysis for: {file_data.get('file_name', 'Unknown')}")
            
    except Exception as e:
        logger.error(f"Error storing static analysis: {e}")


def explain_prediction(sample_data, shap_values, predictions, probabilities, metadata_list):
    """Generate explanations for predictions with metadata and proper confidence scores"""
    explanations = []
    for i in range(len(sample_data)):
        pred_label = 'malware' if predictions[i] == 1 else 'benign'
        # Use probability of predicted class as confidence
        if predictions[i] == 1:
            confidence = probabilities[i][1]  # Probability of malware class
        else:
            confidence = probabilities[i][0]  # Probability of benign class
        
        explanation = {
            "metadata": metadata_list[i],
            "prediction": pred_label,
            "confidence": float(confidence),
            "reasoning": []
        }

        # Get top 3 features by absolute SHAP value
        shap_vals = shap_values[i]
        top_indices = np.argsort(np.abs(shap_vals))[-3:][::-1]

        for idx in top_indices:
            feature_name = FEATURE_NAMES[idx]
            feature_value = sample_data.iloc[i, idx]
            contribution = shap_vals[idx]
            direction = "increased" if contribution > 0 else "decreased"
            
            explanation["reasoning"].append({
                "feature": feature_name,
                "value": float(feature_value),
                "contribution": float(contribution),
                "direction": direction,
                "description": f"'{feature_name}' with value {feature_value} {direction} malware likelihood"
            })
        
        explanations.append(explanation)
    return explanations



# WHITELIST API ROUTES
@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    """Get all whitelist entries"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM whitelisted_apps 
                ORDER BY created_at DESC
            ''')
            
            entries = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "count": len(entries),
                "entries": entries
            })
            
    except Exception as e:
        logger.error(f"Error getting whitelist: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/whitelist', methods=['POST'])
def add_to_whitelist():
    """Add process to whitelist"""
    try:
        data = request.get_json()
        
        process_name = data.get('process_name')
        absolute_path = data.get('absolute_path')
        whitelist_type = data.get('whitelist_type', 'manual')
        reason = data.get('reason', '')
        added_by = data.get('added_by', 'system')
        
        if not process_name:
            return jsonify({"status": "error", "error": "Process name is required"}), 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if already exists
            cursor.execute('''
                SELECT id FROM whitelisted_apps 
                WHERE process_name = ? AND (absolute_path = ? OR (absolute_path IS NULL AND ? IS NULL))
                AND is_active = 1
            ''', (process_name, absolute_path, absolute_path))
            
            if cursor.fetchone():
                return jsonify({"status": "error", "error": "Process already whitelisted"}), 400
            
            # Add to whitelist
            cursor.execute('''
                INSERT INTO whitelisted_apps 
                (process_name, absolute_path, whitelist_type, reason, added_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (process_name, absolute_path, whitelist_type, reason, added_by))
            
            # Log the action
            cursor.execute('''
                INSERT INTO whitelist_logs 
                (action, process_name, absolute_path, reason, performed_by)
                VALUES ('ADD', ?, ?, ?, ?)
            ''', (process_name, absolute_path, reason, added_by))
            
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": f"Process '{process_name}' added to whitelist"
            })
            
    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/whitelist/<int:entry_id>', methods=['DELETE'])
def remove_from_whitelist(entry_id):
    """Remove process from whitelist"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get entry details for logging
            cursor.execute('SELECT * FROM whitelisted_apps WHERE id = ?', (entry_id,))
            entry = cursor.fetchone()
            
            if not entry:
                return jsonify({"status": "error", "error": "Entry not found"}), 404
            
            # Deactivate instead of delete
            cursor.execute('''
                UPDATE whitelisted_apps 
                SET is_active = 0, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (entry_id,))
            
            # Log the action
            cursor.execute('''
                INSERT INTO whitelist_logs 
                (action, process_name, absolute_path, reason, performed_by)
                VALUES ('REMOVE', ?, ?, 'Removed via API', 'system')
            ''', (entry['process_name'], entry['absolute_path']))
            
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": f"Process '{entry['process_name']}' removed from whitelist"
            })
            
    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/whitelist/logs')
def get_whitelist_logs():
    """Get whitelist activity logs"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM whitelist_logs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            logs = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "count": len(logs),
                "logs": logs
            })
            
    except Exception as e:
        logger.error(f"Error getting whitelist logs: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/whitelist/bulk', methods=['POST'])
def bulk_whitelist_action():
    """Bulk add/remove from whitelist"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'add' or 'remove'
        process_ids = data.get('process_ids', [])
        reason = data.get('reason', '')
        
        if not action or not process_ids:
            return jsonify({"status": "error", "error": "Action and process_ids are required"}), 400
        
        success_count = 0
        error_count = 0
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            for process_id in process_ids:
                try:
                    if action == 'remove':
                        # Get entry details
                        cursor.execute('SELECT * FROM whitelisted_apps WHERE id = ?', (process_id,))
                        entry = cursor.fetchone()
                        
                        if entry:
                            # Deactivate entry
                            cursor.execute('''
                                UPDATE whitelisted_apps 
                                SET is_active = 0, updated_at = CURRENT_TIMESTAMP 
                                WHERE id = ?
                            ''', (process_id,))
                            
                            # Log action
                            cursor.execute('''
                                INSERT INTO whitelist_logs 
                                (action, process_name, absolute_path, reason, performed_by)
                                VALUES ('BULK_REMOVE', ?, ?, ?, 'system')
                            ''', (entry['process_name'], entry['absolute_path'], reason))
                            
                            success_count += 1
                        else:
                            error_count += 1
                            
                except Exception as e:
                    logger.error(f"Error processing bulk action for ID {process_id}: {e}")
                    error_count += 1
            
            conn.commit()
        
        return jsonify({
            "status": "success",
            "message": f"Bulk {action} completed",
            "success_count": success_count,
            "error_count": error_count
        })
        
    except Exception as e:
        logger.error(f"Error in bulk whitelist action: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/static')
def static_dashboard():
    """Static analysis dashboard page"""
    return render_template('static.html')

@app.route('/api/static/data')
def get_static_data():
    """Get static analysis data with corrected statistics"""
    try:
        with get_static_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get overall statistics - calculate risk levels dynamically
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_files,
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' THEN 1 ELSE 0 END) as ransomware_detected,
                    SUM(CASE WHEN prediction_result = 'BENIGN' THEN 1 ELSE 0 END) as benign_files,
                    -- Only count risk for RANSOMWARE based on confidence
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' AND confidence_score >= 0.9 THEN 1 ELSE 0 END) as critical_risk,
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' AND confidence_score >= 0.75 AND confidence_score < 0.9 THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' AND confidence_score >= 0.6 AND confidence_score < 0.75 THEN 1 ELSE 0 END) as medium_risk,
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' AND confidence_score < 0.6 THEN 1 ELSE 0 END) as low_risk,
                    MAX(detection_time) as last_detection
                FROM detections
            ''')
            
            stats = dict(cursor.fetchone())
            
            # Get all files and calculate risk dynamically
            cursor.execute('''
                SELECT * FROM detections 
                ORDER BY detection_time DESC 
                LIMIT 500
            ''')
            
            files = []
            for row in cursor.fetchall():
                file_data = dict(row)
                # Override risk_level based on our logic
                file_data['risk_level'] = calculate_display_risk_level(
                    file_data['prediction_result'], 
                    file_data['confidence_score']
                )
                files.append(file_data)
            
            # Get recent files
            cursor.execute('''
                SELECT * FROM detections 
                ORDER BY detection_time DESC 
                LIMIT 20
            ''')
            
            recent_files = []
            for row in cursor.fetchall():
                file_data = dict(row)
                file_data['risk_level'] = calculate_display_risk_level(
                    file_data['prediction_result'], 
                    file_data['confidence_score']
                )
                recent_files.append(file_data)
            
            # Hourly stats remain the same
            cursor.execute('''
                SELECT 
                    strftime('%H:00', detection_time) as hour,
                    COUNT(*) as total_count,
                    SUM(CASE WHEN prediction_result = 'RANSOMWARE' THEN 1 ELSE 0 END) as ransomware_count,
                    SUM(CASE WHEN prediction_result = 'BENIGN' THEN 1 ELSE 0 END) as benign_count
                FROM detections 
                WHERE detection_time >= datetime('now', '-24 hours')
                GROUP BY strftime('%H', detection_time)
                ORDER BY hour
            ''')
            
            hourly_stats = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "stats": stats,
                "files": files,
                "recent_files": recent_files,
                "hourly_stats": hourly_stats
            })
            
    except Exception as e:
        logger.error(f"Error getting static data: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

def calculate_display_risk_level(prediction_result, confidence_score):
    """Calculate risk level for display purposes only"""
    if prediction_result == 'RANSOMWARE':
        if confidence_score >= 0.9:
            return 'CRITICAL'
        elif confidence_score >= 0.75:
            return 'HIGH'
        elif confidence_score >= 0.6:
            return 'MEDIUM'
        else:
            return 'LOW'
    else:  # BENIGN
        return 'NONE'

@app.route('/api/static/file/<int:file_id>')
def get_static_file_details(file_id):
    """Get detailed information for a specific file"""
    try:
        with get_static_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM detections 
                WHERE id = ?
            ''', (file_id,))
            
            file_data = cursor.fetchone()
            
            if not file_data:
                return jsonify({"status": "error", "error": "File not found"}), 404
            
            file_dict = dict(file_data)
            # Override risk_level with calculated value
            file_dict['risk_level'] = calculate_display_risk_level(
                file_dict['prediction_result'], 
                file_dict['confidence_score']
            )
            
            return jsonify({
                "status": "success",
                "file": file_dict
            })
            
    except Exception as e:
        logger.error(f"Error getting file details for ID {file_id}: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/static/files')
def get_static_files_filtered():
    """Get filtered static files with pagination"""
    try:
        result_filter = request.args.get('result', 'all')
        risk_filter = request.args.get('risk', 'all')
        source_filter = request.args.get('source', 'all')
        search_term = request.args.get('search', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        with get_static_db_connection() as conn:
            cursor = conn.cursor()
            
            # Build WHERE clause
            where_clauses = []
            params = []
            
            if result_filter != 'all':
                where_clauses.append("prediction_result = ?")
                params.append(result_filter)
            
            if risk_filter != 'all':
                where_clauses.append("risk_level = ?")
                params.append(risk_filter)
            
            if source_filter != 'all':
                where_clauses.append("file_source = ?")
                params.append(source_filter)
            
            if search_term:
                where_clauses.append("(file_name LIKE ? OR file_path LIKE ?)")
                params.extend([f"%{search_term}%", f"%{search_term}%"])
            
            where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            # Get total count
            count_query = f"SELECT COUNT(*) FROM detections {where_clause}"
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()[0]
            
            # Get paginated results
            offset = (page - 1) * per_page
            query = f'''
                SELECT * FROM detections 
                {where_clause}
                ORDER BY detection_time DESC 
                LIMIT ? OFFSET ?
            '''
            
            params.extend([per_page, offset])
            cursor.execute(query, params)
            
            files = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "files": files,
                "total_count": total_count,
                "page": page,
                "per_page": per_page,
                "total_pages": (total_count + per_page - 1) // per_page
            })
            
    except Exception as e:
        logger.error(f"Error getting filtered files: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

# ENHANCED DASHBOARD API ROUTES WITH WHITELIST FILTERING
@app.route('/dashboard/data')
def dashboard_data():
    """API endpoint for dashboard data with whitelist filtering"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get overall stats excluding whitelisted malware from counts
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT p.process_id) as total_unique_processes,
                    COUNT(DISTINCT CASE 
                        WHEN p.prediction = 'malware' 
                        AND NOT EXISTS (
                            SELECT 1 FROM whitelisted_apps w 
                            WHERE w.process_name = p.app_name 
                            AND w.is_active = 1 
                            AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                        ) 
                        THEN p.process_id 
                    END) as unique_malware_count,
                    COUNT(DISTINCT CASE 
                        WHEN p.prediction = 'benign' 
                        OR EXISTS (
                            SELECT 1 FROM whitelisted_apps w 
                            WHERE w.process_name = p.app_name 
                            AND w.is_active = 1 
                            AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                        ) 
                        THEN p.process_id 
                    END) as unique_benign_count,
                    AVG(p.confidence) as avg_confidence,
                    MAX(p.created_at) as last_prediction
                FROM predictions p
            ''')
            
            stats = dict(cursor.fetchone())
            
            # Calculate malware percentage for unique processes (excluding whitelisted)
            total_unique = stats['total_unique_processes'] or 0
            stats['malware_percentage'] = (stats['unique_malware_count'] / total_unique * 100) if total_unique > 0 else 0
            
            # Get recent unique processes (latest prediction for each process_id, excluding whitelisted malware from main list)
            cursor.execute('''
                SELECT DISTINCT p1.process_id, p1.app_name, p1.prediction, p1.confidence, 
                       p1.created_at, p1.path, p1.parent_name,p1.hostname,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM whitelisted_apps w 
                           WHERE w.process_name = p1.app_name 
                           AND w.is_active = 1 
                           AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                       ) THEN 1 ELSE 0 END as is_whitelisted
                FROM predictions p1
                INNER JOIN (
                    SELECT process_id, MAX(created_at) as max_date
                    FROM predictions
                    GROUP BY process_id
                ) p2 ON p1.process_id = p2.process_id AND p1.created_at = p2.max_date
                WHERE NOT (
                    p1.prediction = 'malware' 
                    AND EXISTS (
                        SELECT 1 FROM whitelisted_apps w 
                        WHERE w.process_name = p1.app_name 
                        AND w.is_active = 1 
                        AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                    )
                )
                ORDER BY p1.created_at DESC 
                LIMIT 100
            ''')
            
            recent_predictions = [dict(row) for row in cursor.fetchall()]
            
            # Get hourly stats for unique processes (excluding whitelisted malware)
            cursor.execute('''
                SELECT 
                    strftime('%H:00', p.created_at) as hour,
                    COUNT(DISTINCT p.process_id) as total_unique,
                    COUNT(DISTINCT CASE 
                        WHEN p.prediction = 'malware' 
                        AND NOT EXISTS (
                            SELECT 1 FROM whitelisted_apps w 
                            WHERE w.process_name = p.app_name 
                            AND w.is_active = 1 
                            AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                        ) 
                        THEN p.process_id 
                    END) as unique_malware
                FROM predictions p 
                WHERE p.created_at >= datetime('now', '-24 hours')
                GROUP BY strftime('%H', p.created_at)
                ORDER BY hour
            ''')
            
            hourly_stats = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "stats": stats,
                "recent_predictions": recent_predictions,
                "hourly_stats": hourly_stats
            })
            
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/processes')
def get_processes():
    """API endpoint to get filtered process list with whitelist awareness"""
    try:
        filter_type = request.args.get('filter', 'all')
        limit = request.args.get('limit', 100, type=int)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Build the WHERE clause based on filter
            where_clause = ""
            params = []
            
            if filter_type == 'malware':
                # Show non-whitelisted malware only
                where_clause = '''WHERE p1.prediction = 'malware' 
                    AND NOT EXISTS (
                        SELECT 1 FROM whitelisted_apps w 
                        WHERE w.process_name = p1.app_name 
                        AND w.is_active = 1 
                        AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                    )'''
            elif filter_type == 'benign':
                # Show benign processes (including whitelisted malware that appears as benign)
                where_clause = '''WHERE p1.prediction = 'benign' 
                    OR EXISTS (
                        SELECT 1 FROM whitelisted_apps w 
                        WHERE w.process_name = p1.app_name 
                        AND w.is_active = 1 
                        AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                        AND p1.prediction = 'malware'
                    )'''
            elif filter_type == 'whitelisted_alerts':
                # Show whitelisted processes that were classified as malware
                where_clause = '''WHERE p1.prediction = 'malware' 
                    AND EXISTS (
                        SELECT 1 FROM whitelisted_apps w 
                        WHERE w.process_name = p1.app_name 
                        AND w.is_active = 1 
                        AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                    )'''
            # 'all' filter shows everything except whitelisted malware
            else:
                where_clause = '''WHERE NOT (
                    p1.prediction = 'malware' 
                    AND EXISTS (
                        SELECT 1 FROM whitelisted_apps w 
                        WHERE w.process_name = p1.app_name 
                        AND w.is_active = 1 
                        AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                    )
                )'''
            
            # Get unique processes (latest prediction for each process_id) with filter
            query = f'''
                SELECT DISTINCT p1.process_id, p1.app_name, p1.prediction, p1.confidence, 
                       p1.created_at, p1.path, p1.parent_name,p1.hostname, p1.num_events, p1.event_types,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM whitelisted_apps w 
                           WHERE w.process_name = p1.app_name 
                           AND w.is_active = 1 
                           AND (w.absolute_path = p1.path OR w.absolute_path IS NULL)
                       ) THEN 1 ELSE 0 END as is_whitelisted
                FROM predictions p1
                INNER JOIN (
                    SELECT process_id, MAX(created_at) as max_date
                    FROM predictions
                    GROUP BY process_id
                ) p2 ON p1.process_id = p2.process_id AND p1.created_at = p2.max_date
                {where_clause}
                ORDER BY p1.created_at DESC 
                LIMIT ?
            '''
            
            params.append(limit)
            cursor.execute(query, params)
            
            processes = []
            for row in cursor.fetchall():
                process = dict(row)
                # Parse event_types JSON if it exists
                if process['event_types']:
                    try:
                        process['event_types'] = json.loads(process['event_types'])
                    except:
                        process['event_types'] = []
                else:
                    process['event_types'] = []
                processes.append(process)
            
            return jsonify({
                "status": "success",
                "filter": filter_type,
                "count": len(processes),
                "processes": processes
            })
            
    except Exception as e:
        logger.error(f"Error getting filtered processes: {e}")
        return jsonify({"error": str(e)}), 500

# WEB ROUTES FOR DASHBOARD
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard3.html')

@app.route('/processes')
def processes_page():
    return render_template('processes.html')

@app.route('/whitelist')
def whitelist_page():
    return render_template('whitelist.html')

# [Include all other existing routes from the original file...]
# Network routes, JA3 routes, etc. remain the same

@app.route('/process/<process_id>/details')
def get_process_details(process_id):
    """Get detailed information for a specific process ID with whitelist info"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get all predictions for this process
            cursor.execute('''
                SELECT p.*, 
                       CASE WHEN EXISTS (
                           SELECT 1 FROM whitelisted_apps w 
                           WHERE w.process_name = p.app_name 
                           AND w.is_active = 1 
                           AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                       ) THEN 1 ELSE 0 END as is_whitelisted
                FROM predictions p
                WHERE p.process_id = ?
                ORDER BY p.created_at DESC
            ''', (process_id,))
            
            predictions = [dict(row) for row in cursor.fetchall()]
            
            if not predictions:
                return jsonify({"error": "Process not found"}), 404
            
            # Get feature explanations for all predictions of this process
            prediction_ids = [p['id'] for p in predictions]
            placeholders = ','.join('?' * len(prediction_ids))
            
            cursor.execute(f'''
                SELECT fe.*, p.created_at as prediction_time
                FROM feature_explanations fe
                JOIN predictions p ON fe.prediction_id = p.id
                WHERE fe.prediction_id IN ({placeholders})
                ORDER BY fe.prediction_id, ABS(fe.contribution) DESC
            ''', prediction_ids)
            
            explanations = [dict(row) for row in cursor.fetchall()]
            
            # Group explanations by prediction_id
            explanations_by_prediction = {}
            for exp in explanations:
                pred_id = exp['prediction_id']
                if pred_id not in explanations_by_prediction:
                    explanations_by_prediction[pred_id] = []
                explanations_by_prediction[pred_id].append(exp)
            
            # Add explanations to predictions
            for pred in predictions:
                pred['feature_explanations'] = explanations_by_prediction.get(pred['id'], [])
                # Parse event_types JSON
                if pred['event_types']:
                    try:
                        pred['event_types'] = json.loads(pred['event_types'])
                    except:
                        pred['event_types'] = []
            
            # Calculate summary stats for this process
            summary = {
                "total_predictions": len(predictions),
                "malware_predictions": len([p for p in predictions if p['prediction'] == 'malware']),
                "benign_predictions": len([p for p in predictions if p['prediction'] == 'benign']),
                "avg_confidence": sum(p['confidence'] for p in predictions) / len(predictions),
                "first_seen": min(p['created_at'] for p in predictions),
                "last_seen": max(p['created_at'] for p in predictions),
                "unique_event_types": list(set([event for p in predictions for event in (p['event_types'] or [])])),
                "is_whitelisted": predictions[0]['is_whitelisted'] if predictions else 0
            }
            
            return jsonify({
                "status": "success",
                "process_id": process_id,
                "summary": summary,
                "predictions": predictions
            })
            
    except Exception as e:
        logger.error(f"Error getting process details for {process_id}: {e}")
        return jsonify({"error": str(e)}), 500



#static predict
@app.route('/api/static/predict', methods=['POST'])
def predict_static_file():
    """HTTP endpoint for static file analysis predictions"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "error": "No data provided"}), 400
        
        file_data = data.get('file_data', {})
        features = data.get('features', {})
        
        if not features:
            return jsonify({"status": "error", "error": "No features provided"}), 400
        
        file_name = file_data.get('file_name', 'Unknown')
        client_ip = request.remote_addr
        
        logger.info(f"Static analysis request: {file_name} from {client_ip}")
        
        # Load static model if not already loaded
        if not hasattr(predict_static_file, 'static_model'):
            if os.path.exists(STATIC_MODEL_PATH):
                predict_static_file.static_model = StaticRansomwareMLModel(STATIC_MODEL_PATH)
            else:
                return jsonify({"status": "error", "error": "Static model not found"}), 500
        
        start_time = time.time()
        prediction_result = predict_static_file.static_model.predict_ransomware_with_confidence(features)
        processing_time = (time.time() - start_time) * 1000
        prediction_result['processing_time'] = processing_time
        
        # Log results
        if prediction_result.get('is_ransomware', False):
            confidence = prediction_result.get('confidence', 0.0)
            if confidence > 0.9:
                logger.critical(f"HIGH CONFIDENCE RANSOMWARE: {file_name} ({confidence:.1%})")
            else:
                logger.warning(f"RANSOMWARE DETECTED: {file_name} ({confidence:.1%})")
        else:
            logger.info(f"BENIGN FILE: {file_name}")
        
        # Save to database
        store_static_analysis_to_db(file_data, prediction_result, client_ip)
        
        # Return response
        return jsonify({
            "status": "success",
            "prediction": prediction_result.get('prediction', 'ERROR'),
            "confidence": prediction_result.get('confidence', 0.0),
            "probability_ransomware": prediction_result.get('probability_ransomware', 0.0),
            "probability_benign": prediction_result.get('probability_benign', 0.0),
            "is_ransomware": prediction_result.get('is_ransomware', False),
            "processing_time": processing_time
        })
        
    except Exception as e:
        logger.error(f"Static prediction error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


# Network routes from original file
@app.route('/network')
def network_dashboard():
    """Network detection dashboard page"""
    return render_template('network.html')
# Add these updated network API endpoints to your cloud predictor.py file
# Replace the existing network endpoints (around line 200-400) with these improved versions

@app.route('/api/network/data')
def get_network_data_fixed():
    """Get network security data with proper error handling for missing database"""
    try:
        # Check if JA3 database exists
        if not os.path.exists(JA3_DB_PATH):
            return jsonify({
                "status": "warning",
                "message": f"JA3 database not found: {JA3_DB_PATH}",
                "stats": {
                    'total_alerts': 0,
                    'critical_alerts': 0,
                    'high_alerts': 0,
                    'medium_alerts': 0,
                    'low_alerts': 0,
                    'ja3_threats': 0,
                    'threat_level': 'Unknown',
                    'scan_coverage': 0
                },
                "alerts": [],
                "hourly_stats": [],
                "ja3_threats": []
            })
        
        with get_ja3_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check available tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            logger.info(f"Available tables in JA3 database: {tables}")
            
            # Initialize default stats
            stats = {
                'total_alerts': 0,
                'critical_alerts': 0,
                'high_alerts': 0,
                'medium_alerts': 0,
                'low_alerts': 0,
                'ja3_threats': 0,
                'last_alert': None,
                'threat_level': 'Low',
                'scan_coverage': 0
            }
            
            alerts = []
            hourly_stats = []
            ja3_threats = []
            
            # Get security alerts if table exists
            if 'security_alerts' in tables:
                try:
                    # Get alert statistics
                    cursor.execute('''
                        SELECT 
                            COUNT(*) as total_alerts,
                            COUNT(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 END) as critical_alerts,
                            COUNT(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 END) as high_alerts,
                            COUNT(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 END) as medium_alerts,
                            COUNT(CASE WHEN UPPER(severity) = 'LOW' THEN 1 END) as low_alerts,
                            MAX(timestamp) as last_alert
                        FROM security_alerts
                        WHERE timestamp >= datetime('now', '-7 days')
                    ''')
                    
                    row = cursor.fetchone()
                    if row:
                        stats.update({
                            'total_alerts': row[0] or 0,
                            'critical_alerts': row[1] or 0,
                            'high_alerts': row[2] or 0,
                            'medium_alerts': row[3] or 0,
                            'low_alerts': row[4] or 0,
                            'last_alert': row[5]
                        })
                    
                    # Get recent alerts
                    cursor.execute('''
                        SELECT alert_id, timestamp, alert_Type, severity, source, details, 
                               confidence_score, ja3_hash
                        FROM security_alerts 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    ''')
                    
                    for row in cursor.fetchall():
                        alert = {
                            'alert_id': row[0],
                            'timestamp': row[1],
                            'alert_Type': row[2],
                            'severity': row[3],
                            'source': row[4],
                            'details': row[5],
                            'confidence_score': row[6] or 0.0,
                            'ja3_hash': row[7]
                        }
                        alerts.append(alert)
                    
                    # Get hourly statistics
                    cursor.execute('''
                        SELECT 
                            strftime('%H:00', timestamp) as hour,
                            COUNT(*) as total,
                            COUNT(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 END) as critical,
                            COUNT(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 END) as high,
                            COUNT(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 END) as medium,
                            COUNT(CASE WHEN UPPER(severity) = 'LOW' THEN 1 END) as low
                        FROM security_alerts 
                        WHERE timestamp >= datetime('now', '-24 hours')
                        GROUP BY strftime('%H', timestamp)
                        ORDER BY hour
                    ''')
                    
                    for row in cursor.fetchall():
                        hourly_stats.append({
                            'hour': row[0],
                            'total': row[1] or 0,
                            'critical': row[2] or 0,
                            'high': row[3] or 0,
                            'medium': row[4] or 0,
                            'low': row[5] or 0
                        })
                    
                    logger.info(f"Retrieved {len(alerts)} alerts and {len(hourly_stats)} hourly stats")
                    
                except sqlite3.Error as e:
                    logger.error(f"Error querying security_alerts: {e}")
            
            # Get JA3 threat data if table exists
            if 'ja3_data' in tables:
                try:
                    cursor.execute('SELECT COUNT(*) FROM ja3_data')
                    stats['ja3_threats'] = cursor.fetchone()[0]
                    
                    cursor.execute('''
                        SELECT ja3_md5, Firstseen, Lastseen, Type, confidence
                        FROM ja3_data 
                        ORDER BY Lastseen DESC 
                        LIMIT 50
                    ''')
                    
                    for row in cursor.fetchall():
                        ja3_threats.append({
                            'ja3_md5': row[0],
                            'firstseen': row[1],
                            'lastseen': row[2],
                            'type': row[3],
                            'confidence': row[4] or 0.5
                        })
                    
                    logger.info(f"Retrieved {len(ja3_threats)} JA3 threats")
                    
                except sqlite3.Error as e:
                    logger.error(f"Error querying ja3_data: {e}")
            
            # Calculate threat level
            critical = stats.get('critical_alerts', 0)
            high = stats.get('high_alerts', 0)
            medium = stats.get('medium_alerts', 0)
            
            if critical > 3:
                stats['threat_level'] = 'Critical'
            elif critical > 0 or high > 5:
                stats['threat_level'] = 'High'
            elif high > 0 or medium > 10:
                stats['threat_level'] = 'Medium'
            else:
                stats['threat_level'] = 'Low'
            
            # Calculate coverage based on data availability
            coverage = 0
            if 'security_alerts' in tables and len(alerts) > 0:
                coverage += 40
            if 'ja3_data' in tables and len(ja3_threats) > 0:
                coverage += 30
            if 'virustotal_results' in tables:
                coverage += 30
            
            stats['scan_coverage'] = coverage
            
            logger.info(f"Network data summary - Alerts: {len(alerts)}, JA3: {len(ja3_threats)}, Coverage: {coverage}%")
            
            return jsonify({
                "status": "success",
                "stats": stats,
                "alerts": alerts,
                "hourly_stats": hourly_stats,
                "ja3_threats": ja3_threats,
                "available_tables": tables
            })
            
    except Exception as e:
        logger.error(f"Error in get_network_data: {e}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "stats": {
                'total_alerts': 0,
                'critical_alerts': 0,
                'high_alerts': 0,
                'medium_alerts': 0,
                'low_alerts': 0,
                'ja3_threats': 0,
                'threat_level': 'Error',
                'scan_coverage': 0
            },
            "alerts": [],
            "hourly_stats": [],
            "ja3_threats": []
        }), 500

@app.route('/api/network/alerts')
def get_network_alerts():
    """Get filtered network alerts with proper error handling"""
    try:
        severity_filter = request.args.get('severity', 'all').upper()
        type_filter = request.args.get('type', 'all')
        time_filter = request.args.get('time', '24h')
        limit = request.args.get('limit', 50, type=int)
        
        with get_ja3_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if security_alerts table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_alerts'")
            if not cursor.fetchone():
                return jsonify({
                    "status": "success",
                    "alerts": [],
                    "message": "No security_alerts table found in database",
                    "filters": {
                        "severity": severity_filter,
                        "type": type_filter,
                        "time": time_filter
                    }
                })
            
            # Build WHERE clause based on filters
            where_clauses = []
            params = []
            
            # Time filter
            if time_filter == '24h':
                where_clauses.append("timestamp >= datetime('now', '-24 hours')")
            elif time_filter == '7d':
                where_clauses.append("timestamp >= datetime('now', '-7 days')")
            elif time_filter == '30d':
                where_clauses.append("timestamp >= datetime('now', '-30 days')")
            
            # Severity filter (case insensitive)
            if severity_filter != 'ALL':
                where_clauses.append("UPPER(severity) = ?")
                params.append(severity_filter)
            
            # Type filter
            if type_filter != 'all':
                where_clauses.append("alert_Type = ?")
                params.append(type_filter)
            
            where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            query = f'''
                SELECT alert_id, timestamp, alert_Type, severity, source, details, 
                       confidence_score, ja3_hash
                FROM security_alerts 
                {where_clause}
                ORDER BY timestamp DESC 
                LIMIT ?
            '''
            
            params.append(limit)
            cursor.execute(query, params)
            
            alerts = []
            for row in cursor.fetchall():
                alert = dict(zip(['alert_id', 'timestamp', 'alert_Type', 'severity', 
                                'source', 'details', 'confidence_score', 'ja3_hash'], row))
                alerts.append(alert)
            
            return jsonify({
                "status": "success",
                "alerts": alerts,
                "count": len(alerts),
                "filters": {
                    "severity": severity_filter.lower(),
                    "type": type_filter,
                    "time": time_filter
                }
            })
                
    except Exception as e:
        logger.error(f"Error getting filtered alerts: {e}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "alerts": [],
            "filters": {
                "severity": severity_filter,
                "type": type_filter,
                "time": time_filter
            }
        }), 500

@app.route('/api/network/ja3/<ja3_hash>')
def get_ja3_details(ja3_hash):
    """Get detailed information for a specific JA3 hash"""
    try:
        with get_ja3_db_connection() as conn:
            cursor = conn.cursor()
            
            ja3_info = None
            vt_results = []
            related_alerts = []
            
            # Get JA3 data if table exists
            try:
                cursor.execute('''
                    SELECT ja3_md5, Firstseen, Lastseen, Type, confidence
                    FROM ja3_data 
                    WHERE ja3_md5 = ?
                    ORDER BY Lastseen DESC
                    LIMIT 1
                ''', (ja3_hash,))
                
                row = cursor.fetchone()
                if row:
                    ja3_info = dict(zip(['ja3_md5', 'firstseen', 'lastseen', 'type', 'confidence'], row))
            except sqlite3.OperationalError:
                pass
            
            # Get VirusTotal results if table exists
            try:
                cursor.execute('''
                    SELECT ja3_hash, scan_date, malicious_count, total_engines, scan_result
                    FROM virustotal_results 
                    WHERE ja3_hash = ?
                    ORDER BY scan_date DESC
                    LIMIT 5
                ''', (ja3_hash,))
                
                for row in cursor.fetchall():
                    vt_result = dict(zip(['ja3_hash', 'scan_date', 'malicious_count', 'total_engines', 'scan_result'], row))
                    vt_results.append(vt_result)
            except sqlite3.OperationalError:
                pass
            
            # Get related security alerts if table exists
            try:
                cursor.execute('''
                    SELECT alert_id, timestamp, alert_Type, severity, source, details
                    FROM security_alerts 
                    WHERE ja3_hash = ?
                    ORDER BY timestamp DESC
                    LIMIT 10
                ''', (ja3_hash,))
                
                for row in cursor.fetchall():
                    alert = dict(zip(['alert_id', 'timestamp', 'alert_Type', 'severity', 'source', 'details'], row))
                    related_alerts.append(alert)
            except sqlite3.OperationalError:
                pass
            
            # Assess threat level
            threat_assessment = assess_ja3_threat_level(ja3_info, vt_results)
            
            return jsonify({
                "status": "success",
                "ja3_hash": ja3_hash,
                "ja3_info": ja3_info,
                "virustotal_results": vt_results,
                "related_alerts": related_alerts,
                "threat_assessment": threat_assessment
            })
            
    except Exception as e:
        logger.error(f"Error getting JA3 details for {ja3_hash}: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

def assess_ja3_threat_level(ja3_info, vt_results):
    """Assess threat level based on JA3 and VirusTotal data"""
    assessment = {
        "threat_level": "unknown",
        "confidence": 0.5,
        "reasons": []
    }
    
    threat_score = 0
    reasons = []
    
    # Analyze JA3 data
    if ja3_info:
        ja3_type = ja3_info.get('type', '').lower()
        confidence = ja3_info.get('confidence', 0)
        
        if any(malware in ja3_type for malware in ['dridex', 'trickbot', 'ransomware', 'trojan']):
            threat_score += 4
            reasons.append(f"JA3 fingerprint associated with known malware: {ja3_info.get('type')}")
        elif 'adware' in ja3_type:
            threat_score += 2
            reasons.append(f"JA3 fingerprint associated with adware")
        elif 'suspicious' in ja3_type:
            threat_score += 3
            reasons.append(f"JA3 fingerprint flagged as suspicious")
        
        # Factor in JA3 confidence
        threat_score += confidence * 2
        reasons.append(f"JA3 detection confidence: {confidence * 100:.1f}%")
    
    # Analyze VirusTotal results
    if vt_results:
        latest_vt = vt_results[0]
        malicious_count = latest_vt.get('malicious_count', 0)
        total_engines = latest_vt.get('total_engines', 1)
        
        if malicious_count > 10:
            threat_score += 4
            reasons.append(f"High VirusTotal detection: {malicious_count}/{total_engines} engines")
        elif malicious_count > 5:
            threat_score += 3
            reasons.append(f"Medium VirusTotal detection: {malicious_count}/{total_engines} engines")
        elif malicious_count > 0:
            threat_score += 2
            reasons.append(f"Low VirusTotal detection: {malicious_count}/{total_engines} engines")
    
    # Determine final threat level
    if threat_score >= 7:
        assessment["threat_level"] = "critical"
        assessment["confidence"] = 0.9
    elif threat_score >= 5:
        assessment["threat_level"] = "high"
        assessment["confidence"] = 0.8
    elif threat_score >= 3:
        assessment["threat_level"] = "medium"
        assessment["confidence"] = 0.7
    elif threat_score > 0:
        assessment["threat_level"] = "low"
        assessment["confidence"] = 0.6
    else:
        assessment["threat_level"] = "clean"
        assessment["confidence"] = 0.8
    
    assessment["reasons"] = reasons
    assessment["score"] = threat_score
    
    return assessment

@app.route('/api/network/threats/summary')
def get_threats_summary():
    """Get summary of all network threats"""
    try:
        with get_ja3_db_connection() as conn:
            cursor = conn.cursor()
            
            summary = {
                "ja3_threats": [],
                "threat_types": {},
                "timeline": {}
            }
            
            # Get JA3 threat summary
            try:
                cursor.execute('''
                    SELECT Type, COUNT(*) as count, AVG(confidence) as avg_confidence
                    FROM ja3_data 
                    GROUP BY Type
                    ORDER BY count DESC
                ''')
                
                for row in cursor.fetchall():
                    threat_type, count, avg_conf = row
                    summary["threat_types"][threat_type] = {
                        "count": count,
                        "avg_confidence": avg_conf
                    }
                
                # Get recent JA3 threats
                cursor.execute('''
                    SELECT ja3_md5, Type, confidence, Lastseen
                    FROM ja3_data 
                    ORDER BY Lastseen DESC 
                    LIMIT 10
                ''')
                
                for row in cursor.fetchall():
                    ja3_hash, threat_type, confidence, last_seen = row
                    summary["ja3_threats"].append({
                        "ja3_hash": ja3_hash,
                        "type": threat_type,
                        "confidence": confidence,
                        "last_seen": last_seen
                    })
                    
            except sqlite3.OperationalError as e:
                logger.warning(f"Error querying ja3_data: {e}")
            
            return jsonify({
                "status": "success",
                "summary": summary
            })
            
    except Exception as e:
        logger.error(f"Error getting threats summary: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


# API ROUTES
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "database_connected": True,
        "whitelist_enabled": True,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Predict endpoint - stores results to database"""
    return predict_batch()

@app.route('/predict/single', methods=['POST'])
def predict_single():
    """Single prediction endpoint - stores results to database"""
    try:
        if model is None:
            return jsonify({"error": "Model not loaded"}), 500
        
        data = request.get_json()
        if not data or 'process' not in data:
            return jsonify({"error": "Missing 'process' in request"}), 400
        
        # Use the batch endpoint with a single process
        batch_data = {"processes": [data['process']]}
        return predict_batch(batch_data)
        
    except Exception as e:
        logger.error(f"Single prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/results', methods=['GET'])
def get_results():
    """Get recent prediction results from database"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get recent predictions with their explanations
            cursor.execute('''
                SELECT p.*, GROUP_CONCAT(fe.feature_name || ':' || fe.contribution) as features
                FROM predictions p
                LEFT JOIN feature_explanations fe ON p.id = fe.prediction_id
                GROUP BY p.id
                ORDER BY p.created_at DESC
                LIMIT ?
            ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                results.append(result)
            
            return jsonify({
                "status": "success",
                "count": len(results),
                "results": results
            })
            
    except Exception as e:
        logger.error(f"Error retrieving results: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get prediction statistics from database with whitelist awareness"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get overall stats excluding whitelisted malware
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT p.process_id) as total_unique_processes,
                    COUNT(DISTINCT CASE 
                        WHEN p.prediction = 'malware' 
                        AND NOT EXISTS (
                            SELECT 1 FROM whitelisted_apps w 
                            WHERE w.process_name = p.app_name 
                            AND w.is_active = 1 
                            AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                        ) 
                        THEN p.process_id 
                    END) as unique_malware_count,
                    COUNT(DISTINCT CASE 
                        WHEN p.prediction = 'benign' 
                        OR EXISTS (
                            SELECT 1 FROM whitelisted_apps w 
                            WHERE w.process_name = p.app_name 
                            AND w.is_active = 1 
                            AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                        ) 
                        THEN p.process_id 
                    END) as unique_benign_count,
                    AVG(p.confidence) as avg_confidence,
                    AVG(p.processing_time) as avg_processing_time
                FROM predictions p
            ''')
            
            unique_stats = dict(cursor.fetchone())
            
            # Get raw prediction counts for reference
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_predictions,
                    SUM(CASE WHEN prediction = 'malware' THEN 1 ELSE 0 END) as malware_predictions,
                    SUM(CASE WHEN prediction = 'benign' THEN 1 ELSE 0 END) as benign_predictions
                FROM predictions
            ''')
            
            raw_stats = dict(cursor.fetchone())
            
            # Get whitelisted malware count
            cursor.execute('''
                SELECT COUNT(DISTINCT p.process_id) as whitelisted_malware_count
                FROM predictions p
                WHERE p.prediction = 'malware' 
                AND EXISTS (
                    SELECT 1 FROM whitelisted_apps w 
                    WHERE w.process_name = p.app_name 
                    AND w.is_active = 1 
                    AND (w.absolute_path = p.path OR w.absolute_path IS NULL)
                )
            ''')
            
            whitelist_stats = dict(cursor.fetchone())
            
            # Get recent batch summaries
            cursor.execute('''
                SELECT * FROM batch_summaries 
                ORDER BY created_at DESC 
                LIMIT 10
            ''')
            
            recent_batches = [dict(row) for row in cursor.fetchall()]
            
            return jsonify({
                "status": "success",
                "unique_process_stats": unique_stats,
                "raw_prediction_stats": raw_stats,
                "whitelist_stats": whitelist_stats,
                "recent_batches": recent_batches
            })
            
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        return jsonify({"error": str(e)}), 500

def predict_batch(data=None):
    """Internal batch prediction function that stores results to database"""
    if data is None:
        data = request.get_json()
    
    try:
        if model is None:
            return jsonify({"error": "Model not loaded"}), 500
        
        if not data or 'processes' not in data:
            return jsonify({"error": "Missing 'processes' in request"}), 400
        
        processes = data['processes']
        if not processes:
            return jsonify({"error": "Empty processes list"}), 400
        
        # Extract metadata and features
        metadata_list = []
        feature_arrays = []
        
        for process in processes:
            if 'metadata' not in process or 'ml_features' not in process:
                logger.warning(f"Skipping process with missing metadata or ml_features")
                continue
            
            metadata = process['metadata']
            features = process['ml_features']
            
            if len(features) != len(FEATURE_NAMES):
                logger.warning(f"Skipping process {metadata.get('process_id', 'Unknown')}: expected {len(FEATURE_NAMES)} features, got {len(features)}")
                continue
            
            metadata_list.append(metadata)
            feature_arrays.append(features)
        
        if not feature_arrays:
            return jsonify({"error": "No valid processes found"}), 400
        
        # Create DataFrame for prediction
        sample_data = pd.DataFrame(feature_arrays, columns=FEATURE_NAMES)
        
        # Make predictions
        start_time = time.time()
        predictions = model.predict(sample_data)
        probabilities = model.predict_proba(sample_data)
        
        # Get SHAP explanations
        shap_values = explainer.shap_values(sample_data)
        end_time = time.time()
        
        # Generate explanations with metadata
        explanations = explain_prediction(sample_data, shap_values, predictions, probabilities, metadata_list)
        
        # Count unique processes for summary
        unique_processes = set(meta.get('process_id', '') for meta in metadata_list)
        malware_processes = set(exp['metadata'].get('process_id', '') for exp in explanations if exp['prediction'] == 'malware')
        
        total_unique = len(unique_processes)
        malware_unique = len(malware_processes)
        
        # Prepare response data
        response_data = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "processing_time": round(end_time - start_time, 4),
            "total_processes": total_unique,
            "predictions": explanations,
            "summary": {
                "malware_count": malware_unique,
                "benign_count": total_unique - malware_unique,
                "malware_percentage": round((malware_unique / total_unique) * 100, 2) if total_unique > 0 else 0
            }
        }
        
        # Store to database (this function now handles whitelist checking)
        store_predictions_to_db(response_data)
        
        logger.info(f"Processed and stored {len(predictions)} predictions ({total_unique} unique processes) in {response_data['processing_time']:.4f}s")
        
        # Return simple success response
        return jsonify({
            "status": "success",
            "message": f"Processed {total_unique} unique processes and stored to database",
            "malware_detected": response_data['summary']['malware_count'],
            "total_processed": total_unique
        })
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting ML Prediction API Server with SQLite Database and Whitelist System...")
    print(f"Database: {DB_PATH}")
    print(f"Feature order expected by model: {FEATURE_NAMES}")
    
    # Initialize database
    init_database()
    
    print("Available endpoints:")
    print("  GET  / - Web Dashboard")
    print("  GET  /processes - Processes listing page")
    print("  GET  /whitelist - Whitelist management page")
    print("  GET  /health - Health check")
    print("  POST /predict - Batch predictions (stores to DB)")
    print("  POST /predict/single - Single prediction (stores to DB)")
    print("  GET  /results?limit=50 - Get recent results from DB")
    print("  GET  /stats - Get prediction statistics")
    print("  GET  /dashboard/data - Dashboard API data")
    print("  GET  /api/processes?filter=all|malware|benign|whitelisted_alerts - Get filtered processes")
    print("  GET  /process/<process_id>/details - Get detailed process information")
    print("  GET  /api/whitelist - Get whitelist entries")
    print("  POST /api/whitelist - Add to whitelist")
    print("  DELETE /api/whitelist/<id> - Remove from whitelist")
    print("  POST /api/whitelist/bulk - Bulk whitelist operations")
    print("  GET  /api/whitelist/logs - Get whitelist activity logs")
    print("  GET  /static - Static Analysis Dashboard")
    print("  GET  /api/static/data - Static analysis data")
    print("  GET  /api/static/file/<id> - Get static file details")
    print("  GET  /api/static/files - Get filtered static files")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)