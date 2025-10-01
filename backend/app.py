from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import sqlite3
import os
from datetime import timedelta
import threading
from utils.database import init_db, get_db_connection
from scanner.vulnerability_scanner import VulnerabilityScanner
from scanner.port_scanner import PortScanner

app = Flask(__name__)

# Configuration - FIXED JWT SETTINGS
app.config['JWT_SECRET_KEY'] = 'vulnscan-pro-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_ALGORITHM'] = 'HS256'

# Initialize extensions
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# CORS configuration - FIXED
CORS(app, 
     origins=["http://localhost:3000"], 
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Initialize database on startup
init_db()

# In-memory storage for scan results
scan_results = {}
scan_status = {}

# JWT error handlers - IMPROVED
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("🔴 Token expired")
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    print(f"🔴 Invalid token error: {error_string}")
    return jsonify({'error': 'Invalid token', 'debug': str(error_string)}), 401

@jwt.unauthorized_loader
def missing_token_callback(error_string):
    print(f"🔴 Missing token error: {error_string}")
    return jsonify({'error': 'Token is required', 'debug': str(error_string)}), 401

# Debug route
@app.route('/api/debug-token', methods=['GET'])
@jwt_required()
def debug_token():
    current_user = get_jwt_identity()
    print(f"🟢 Debug token - user: {current_user}")
    return jsonify({'message': 'Token valid', 'user': current_user}), 200

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        username = data.get('username')
        email = data.get('email')  
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
            
        # Check if user exists
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
            
        # Hash password and create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (username, email, hashed_password)
        )
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User registered successfully'}), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password required'}), 400
            
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, email, password FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            # FIXED: Use string identity instead of dict
            access_token = create_access_token(identity=str(user['id']))
            
            print(f"Created token for user ID: {user['id']}")
            
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                }
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    try:
        # Get user ID from JWT token (now it's a string)
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        print(f"Dashboard stats - user_id: {user_id}")
        
        # Get user info from database
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 401
        
        # Get scan statistics
        total_scans_result = conn.execute(
            'SELECT COUNT(*) as count FROM scans WHERE user_id = ?',
            (user_id,)
        ).fetchone()
        
        total_scans = total_scans_result['count'] if total_scans_result else 0
        
        recent_scans = conn.execute(
            '''SELECT id, target, scan_type, status, created_at, 
                      vulnerabilities_found, critical_count, high_count, medium_count, low_count
               FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5''',
            (user_id,)
        ).fetchall()
        
        # Convert to dict for JSON serialization
        recent_scans_list = [dict(scan) for scan in recent_scans]
        
        conn.close()
        
        return jsonify({
            'total_scans': total_scans,
            'recent_scans': recent_scans_list,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        }), 200
        
    except Exception as e:
        print(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
@jwt_required()
def start_scan():
    try:
        # Get user ID from JWT token (now it's a string)
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        print(f"Start scan - user_id: {user_id}")
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        target = data.get('target')
        scan_type = data.get('scan_type', 'comprehensive')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
            
        # Create scan record in database
        conn = get_db_connection()
        cursor = conn.execute(
            '''INSERT INTO scans (user_id, target, scan_type, status) 
               VALUES (?, ?, ?, ?)''',
            (user_id, target, scan_type, 'running')
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'current_task': 'Initializing scan...',
            'vulnerabilities': []
        }
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=run_vulnerability_scan,
            args=(scan_id, target, scan_type, user_id)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully',
            'status': 'running'
        }), 202
        
    except Exception as e:
        print(f"Start scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    try:
        # Get user ID from JWT token (now it's a string)
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        # Get scan from database
        conn = get_db_connection()
        scan = conn.execute(
            'SELECT * FROM scans WHERE id = ? AND user_id = ?',
            (scan_id, user_id)
        ).fetchone()
        conn.close()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
            
        # Get current status from memory or database
        if scan_id in scan_status:
            status_data = scan_status[scan_id]
        else:
            status_data = {
                'status': scan['status'],
                'progress': 100 if scan['status'] == 'completed' else 0,
                'current_task': 'Scan completed' if scan['status'] == 'completed' else 'Unknown',
                'vulnerabilities': []
            }
            
        scan_data = dict(scan)
        scan_data.update(status_data)
        
        return jsonify(scan_data), 200
        
    except Exception as e:
        print(f"Get scan status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans', methods=['GET'])
@jwt_required()
def get_user_scans():
    try:
        # Get user ID from JWT token (now it's a string)
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        print(f"Get scans - user_id: {user_id}")
        
        conn = get_db_connection()
        scans = conn.execute(
            '''SELECT id, target, scan_type, status, created_at, 
                      vulnerabilities_found, critical_count, high_count, medium_count, low_count
               FROM scans WHERE user_id = ? ORDER BY created_at DESC''',
            (user_id,)
        ).fetchall()
        conn.close()
        
        scans_list = [dict(scan) for scan in scans]
        
        return jsonify({'scans': scans_list}), 200
        
    except Exception as e:
        print(f"Get user scans error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_vulnerability_scan(scan_id, target, scan_type, user_id):
    """Run vulnerability scan in background thread"""
    try:
        print(f"Starting scan {scan_id} for target {target}")
        
        # Update scan status
        scan_status[scan_id]['current_task'] = 'Starting vulnerability scan...'
        scan_status[scan_id]['progress'] = 10
        
        # Initialize scanner
        scanner = VulnerabilityScanner(target)
        vulnerabilities = []
        
        if scan_type in ['comprehensive', 'web']:
            scan_status[scan_id]['current_task'] = 'Scanning for web vulnerabilities...'
            scan_status[scan_id]['progress'] = 30
            web_vulns = scanner.scan_web_vulnerabilities()
            vulnerabilities.extend(web_vulns)
        
        if scan_type in ['comprehensive', 'port']:
            scan_status[scan_id]['current_task'] = 'Scanning ports...'
            scan_status[scan_id]['progress'] = 60
            port_scanner = PortScanner(target)
            port_results = port_scanner.scan_ports()
            vulnerabilities.extend(port_results)
        
        # Categorize vulnerabilities by severity
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
        low_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
        
        print(f"Scan {scan_id} found {len(vulnerabilities)} vulnerabilities")
        
        # Update database with results
        conn = get_db_connection()
        conn.execute(
            '''UPDATE scans SET status = ?, vulnerabilities_found = ?, 
               critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, 
               completed_at = datetime('now')
               WHERE id = ?''',
            ('completed', len(vulnerabilities), critical_count, high_count, 
             medium_count, low_count, scan_id)
        )
        conn.commit()
        conn.close()
        
        # Update scan status
        scan_status[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'current_task': 'Scan completed successfully',
            'vulnerabilities': vulnerabilities
        }
        
        print(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        print(f"Scan {scan_id} failed: {str(e)}")
        
        # Update scan status with error
        scan_status[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'current_task': f'Scan failed: {str(e)}',
            'vulnerabilities': []
        }
        
        # Update database
        conn = get_db_connection()
        conn.execute(
            'UPDATE scans SET status = ?, completed_at = datetime("now") WHERE id = ?',
            ('failed', scan_id)
        )
        conn.commit()
        conn.close()

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'VulnScan Pro API is running'}), 200

if __name__ == '__main__':
    print("🔍 VulnScan Pro Backend Starting...")
    print("📡 Server: http://localhost:5000")
    print("🔐 CORS enabled for: http://localhost:3000")
    app.run(host='0.0.0.0', port=5000, debug=True)