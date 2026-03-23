#!/usr/bin/env python
"""
Quick System Launcher - Start all components with one command
"""

import subprocess
import time
import os
from pathlib import Path

def main():
    print("=" * 80)
    print("DNS THREAT DETECTION SYSTEM - QUICK LAUNCHER")
    print("=" * 80)
    
    # Check if models exist
    if not Path("models/dns_best_model.pkl").exists():
        print("\n[ERROR] Trained model not found!")
        print("Run: python retrain_model.py")
        return
    
    print("\nStarting system components...\n")
    
    # Component 1: API Server
    print("[1/3] Starting API Server (port 5000)...")
    api_proc = subprocess.Popen(
        ["python", "api_service.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print("      Running in background...")
    time.sleep(3)
    
    # Component 2: Dashboard
    print("[2/3] Starting Streamlit Dashboard (port 8501)...")
    dashboard_proc = subprocess.Popen(
        ["python", "-m", "streamlit", "run", "dashboard_premium.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print("      Running in background...")
    time.sleep(2)
    
    # Component 3: DNS Sniffer GUI
    print("[3/3] Starting DNS Sniffer GUI...")
    print("      [Note: GUI will open in a new window]")
    print("      [Note: Requires admin privileges for packet capture]")
    
    try:
        sniffer_proc = subprocess.Popen(
            ["python", "dns_sniffer_gui.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("      Running...")
    except Exception as e:
        print(f"      [WARNING] Could not start DNS sniffer: {e}")
    
    print("\n" + "=" * 80)
    print("SYSTEM STARTED SUCCESSFULLY!")
    print("=" * 80)
    print("\nAccess Points:")
    print("  • API:       http://localhost:5000")
    print("  • Dashboard: http://localhost:8501")
    print("  • Sniffer:   GUI Window (if admin mode enabled)")
    print("\nNext Steps:")
    print("  1. Open the dashboard in your browser")
    print("  2. Test the Analysis tab with sample domains")
    print("  3. Monitor DNS traffic in real-time")
    print("\nTo stop all services: Kill the terminals (Ctrl+C)")
    print("=" * 80)
    
    # Keep the processes running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down system...")
        api_proc.terminate()
        dashboard_proc.terminate()
        try:
            sniffer_proc.terminate()
        except:
            pass
        print("System stopped.")

if __name__ == "__main__":
    main()
