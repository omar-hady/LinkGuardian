#!/usr/bin/env python3
"""
Advanced URL Phishing Detector Runner
Advanced AI-powered tool for detecting phishing URLs with enhanced features
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'fastapi', 'uvicorn', 'jinja2', 'requests', 'tldextract', 
        'aiohttp', 'whois'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing dependencies: {missing_packages}")
        print("Please install dependencies: pip install -r requirements.txt")
        return False
    
    return True

def run_web_server(host="127.0.0.1", port=8000):
    """Run the enhanced web server"""
    print(f"🌐 Starting Advanced Web Server at http://{host}:{port}")
    print("📊 Advanced URL Phishing Detector with AI")
    print("🔧 Features: Real-time analysis, Threat intelligence, SSL validation")
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn", "app.api:app",
            "--host", host, "--port", str(port), "--reload"
        ])
    except KeyboardInterrupt:
        print("\n👋 Server stopped")

def run_cli_predict(url):
    """Run enhanced CLI prediction"""
    print(f"🔍 Analyzing URL with advanced AI: {url}")
    try:
        subprocess.run([
            sys.executable, "app/cli.py", url
        ])
    except Exception as e:
        print(f"❌ Error: {e}")

def run_cli_batch(file_path):
    """Run enhanced CLI batch prediction"""
    print(f"📁 Batch analyzing URLs with advanced features from: {file_path}")
    try:
        subprocess.run([
            sys.executable, "app/cli.py", "--batch", file_path
        ])
    except Exception as e:
        print(f"❌ Error: {e}")

def show_system_info():
    """Show detailed system information"""
    print("🔍 Advanced URL Phishing Detector - System Information")
    print("="*60)
    
    if check_dependencies():
        print("✅ All dependencies are installed")
        
        # Check for additional features
        try:
            import whois
            print("✅ WHOIS lookup capability available")
        except:
            print("⚠️  WHOIS lookup not available")
        
        try:
            import aiohttp
            print("✅ Async HTTP client available")
        except:
            print("⚠️  Async HTTP client not available")
        
        print("✅ System is ready for advanced analysis")
        print("\n🚀 Available Features:")
        print("  • Real-time SSL certificate validation")
        print("  • Domain age analysis")
        print("  • Threat intelligence integration")
        print("  • Advanced AI scoring algorithm")
        print("  • Response time analysis")
        print("  • Batch processing with caching")
        print("  • Enhanced web interface")
    else:
        print("❌ System needs setup")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced URL Phishing Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py web                    # Start advanced web server
  python run.py predict <url>          # Predict single URL with advanced AI
  python run.py batch <file>           # Batch predict from file
  python run.py info                   # Show system information
  python run.py check                  # Check system status
        """
    )
    
    parser.add_argument('command', choices=['web', 'predict', 'batch', 'check', 'info'],
                       help='Command to run')
    parser.add_argument('target', nargs='?', help='URL or file path')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host')
    parser.add_argument('--port', type=int, default=8000, help='Web server port')
    
    args = parser.parse_args()
    
    # If a project venv exists and we are not using it, relaunch with venv's Python
    project_root = Path(__file__).resolve().parent
    venv_python = project_root / 'venv' / 'bin' / 'python'
    if venv_python.exists() and Path(sys.executable) != venv_python:
        try:
            print(f"🔁 Switching to project venv interpreter: {venv_python}")
            os.execv(str(venv_python), [str(venv_python), __file__] + sys.argv[1:])
        except Exception as e:
            print(f"⚠️  Could not switch to venv automatically: {e}")

    if args.command == 'check':
        print("🔍 Checking system status...")
        if check_dependencies():
            print("✅ All dependencies are installed")
            print("✅ System is ready to use")
        else:
            print("❌ System needs setup")
        return
    
    if args.command == 'info':
        show_system_info()
        return
    
    if not check_dependencies():
        return
    
    if args.command == 'web':
        run_web_server(args.host, args.port)
    elif args.command == 'predict':
        if not args.target:
            print("❌ Please provide a URL to analyze")
            return
        run_cli_predict(args.target)
    elif args.command == 'batch':
        if not args.target:
            print("❌ Please provide a file path")
            return
        if not Path(args.target).exists():
            print(f"❌ File not found: {args.target}")
            return
        run_cli_batch(args.target)

if __name__ == "__main__":
    main()
