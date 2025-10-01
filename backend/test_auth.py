#!/usr/bin/env python3
"""Test script to debug JWT authentication issues"""

import requests
import json

BASE_URL = "http://localhost:5000"

def test_registration_and_login():
    """Test user registration and login flow"""
    
    # Test registration
    print("🧪 Testing Registration...")
    reg_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    }
    
    try:
        reg_response = requests.post(f"{BASE_URL}/api/register", json=reg_data)
        print(f"Registration Status: {reg_response.status_code}")
        print(f"Registration Response: {reg_response.json()}")
    except Exception as e:
        print(f"Registration Error: {e}")
        return False
    
    # Test login
    print("\n🧪 Testing Login...")
    login_data = {
        "username": "testuser",
        "password": "password123"
    }
    
    try:
        login_response = requests.post(f"{BASE_URL}/api/login", json=login_data)
        print(f"Login Status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            login_json = login_response.json()
            print(f"Login Success: {login_json}")
            token = login_json.get('access_token')
            
            if token:
                test_protected_routes(token)
                return True
            else:
                print("❌ No access token received")
                return False
        else:
            print(f"❌ Login failed: {login_response.json()}")
            return False
            
    except Exception as e:
        print(f"Login Error: {e}")
        return False

def test_protected_routes(token):
    """Test protected routes with JWT token"""
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Test debug token endpoint first
    print("\n🧪 Testing Debug Token...")
    try:
        debug_response = requests.get(f"{BASE_URL}/api/debug-token", headers=headers)
        print(f"Debug Token Status: {debug_response.status_code}")
        if debug_response.status_code == 200:
            print(f"✅ Debug token: {debug_response.json()}")
        else:
            print(f"❌ Debug token error: {debug_response.json()}")
    except Exception as e:
        print(f"Debug Token Error: {e}")
    
    # Test dashboard stats
    print("\n🧪 Testing Dashboard Stats...")
    try:
        stats_response = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=headers)
        print(f"Dashboard Stats Status: {stats_response.status_code}")
        if stats_response.status_code == 200:
            print(f"✅ Dashboard stats: {stats_response.json()}")
        else:
            print(f"❌ Dashboard stats error: {stats_response.json()}")
    except Exception as e:
        print(f"Dashboard Stats Error: {e}")
    
    # Test scans
    print("\n🧪 Testing Scans...")
    try:
        scans_response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
        print(f"Scans Status: {scans_response.status_code}")
        if scans_response.status_code == 200:
            print(f"✅ Scans: {scans_response.json()}")
        else:
            print(f"❌ Scans error: {scans_response.json()}")
    except Exception as e:
        print(f"Scans Error: {e}")
    
    # Test start scan
    print("\n🧪 Testing Start Scan...")
    scan_data = {
        "target": "example.com",
        "scan_type": "web"
    }
    
    try:
        scan_response = requests.post(f"{BASE_URL}/api/scan", json=scan_data, headers=headers)
        print(f"Start Scan Status: {scan_response.status_code}")
        if scan_response.status_code == 202:
            scan_result = scan_response.json()
            print(f"✅ Scan started: {scan_result}")
            
            # Test get scan status
            scan_id = scan_result.get('scan_id')
            if scan_id:
                print(f"\n🧪 Testing Get Scan Status for ID {scan_id}...")
                try:
                    status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}", headers=headers)
                    print(f"Scan Status Status: {status_response.status_code}")
                    if status_response.status_code == 200:
                        print(f"✅ Scan status: {status_response.json()}")
                    else:
                        print(f"❌ Scan status error: {status_response.json()}")
                except Exception as e:
                    print(f"Scan Status Error: {e}")
        else:
            print(f"❌ Scan start error: {scan_response.json()}")
    except Exception as e:
        print(f"Start Scan Error: {e}")

def test_health():
    """Test health endpoint"""
    print("🧪 Testing Health Endpoint...")
    try:
        health_response = requests.get(f"{BASE_URL}/api/health")
        print(f"Health Status: {health_response.status_code}")
        print(f"Health Response: {health_response.json()}")
        return health_response.status_code == 200
    except Exception as e:
        print(f"Health Error: {e}")
        return False

def test_with_new_user():
    """Test with a completely new user"""
    print("\n" + "="*50)
    print("🆕 Testing with New User")
    print("="*50)
    
    import random
    random_num = random.randint(1000, 9999)
    
    # Test registration with new user
    print("🧪 Testing Registration with New User...")
    reg_data = {
        "username": f"newuser{random_num}",
        "email": f"newuser{random_num}@example.com",
        "password": "password123"
    }
    
    try:
        reg_response = requests.post(f"{BASE_URL}/api/register", json=reg_data)
        print(f"New Registration Status: {reg_response.status_code}")
        print(f"New Registration Response: {reg_response.json()}")
        
        if reg_response.status_code == 201:
            # Login with new user
            login_data = {
                "username": f"newuser{random_num}",
                "password": "password123"
            }
            
            login_response = requests.post(f"{BASE_URL}/api/login", json=login_data)
            print(f"New Login Status: {login_response.status_code}")
            
            if login_response.status_code == 200:
                login_json = login_response.json()
                token = login_json.get('access_token')
                print(f"✅ New user login successful!")
                test_protected_routes(token)
            else:
                print(f"❌ New user login failed: {login_response.json()}")
        
    except Exception as e:
        print(f"New User Test Error: {e}")

if __name__ == "__main__":
    print("🔍 VulnScan Pro API Testing")
    print("=" * 40)
    
    # Test if backend is running
    if test_health():
        print("✅ Backend is running")
        
        # Test with existing user
        test_registration_and_login()
        
        # Test with new user
        test_with_new_user()
    else:
        print("❌ Backend is not responding")
        print("Make sure Flask backend is running on port 5000")