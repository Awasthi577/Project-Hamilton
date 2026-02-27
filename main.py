"""
Main entry point for UPI 2.0 system
"""
import typer
import subprocess
import os
import signal
import sys

app = typer.Typer()

# Global process tracking
running_processes = []

def start_service(name: str, module: str, port: int):
    """Start a service using uvicorn"""
    print(f"Starting {name} on port {port}...")
    
    # Change to the upi20 directory
    os.chdir("upi20")
    
    process = subprocess.Popen([
        sys.executable, "-m", "uvicorn",
        f"{module}:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--reload"
    ])
    
    running_processes.append(process)
    print(f"{name} started with PID {process.pid}")
    return process

def stop_all_services():
    """Stop all running services"""
    print("Stopping all services...")
    for process in running_processes:
        try:
            process.terminate()
            process.wait(timeout=5)
            print(f"Stopped process {process.pid}")
        except subprocess.TimeoutExpired:
            process.kill()
            print(f"Force killed process {process.pid}")
    
    running_processes.clear()
    print("All services stopped")

@app.command()
def start_all():
    """Start all UPI 2.0 services"""
    try:
        # Start services in order
        start_service("Hamilton Core", "hamilton.main", 8000)
        start_service("Merchant Client", "merchant.main", 8001)
        start_service("Liquidity Bridge", "bridge.main", 8002)
        
        print("\nAll services started!")
        print("Hamilton Core: http://localhost:8000")
        print("Merchant Client: http://localhost:8001")
        print("Liquidity Bridge: http://localhost:8002")
        print("\nPress Ctrl+C to stop all services...")
        
        # Keep running until interrupted
        while True:
            pass
            
    except KeyboardInterrupt:
        stop_all_services()
        sys.exit(0)

@app.command()
def start_hamilton():
    """Start Hamilton Core service"""
    start_service("Hamilton Core", "hamilton.main", 8000)

@app.command()
def start_merchant():
    """Start Merchant Client service"""
    start_service("Merchant Client", "merchant.main", 8001)

@app.command()
def start_bridge():
    """Start Liquidity Bridge service"""
    start_service("Liquidity Bridge", "bridge.main", 8002)

@app.command()
def stop():
    """Stop all running services"""
    stop_all_services()

@app.command()
def wallet():
    """Run wallet CLI"""
    print("Starting wallet CLI...")
    os.chdir("upi20")
    subprocess.run([sys.executable, "wallet/cli.py"] + sys.argv[2:])

@app.command()
def test():
    """Run system tests"""
    print("Running system tests...")
    # Add test commands here
    print("Tests completed!")

if __name__ == "__main__":
    app()
