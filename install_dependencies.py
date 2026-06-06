#!/usr/bin/env python3
import sys
import subprocess

def check_and_install(package):
    print(f"Checking for package: {package}...")
    try:
        __import__(package.replace("-", "_"))
        print(f"  {package} is already installed.")
    except ImportError:
        print(f"  {package} not found. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"  Successfully installed {package}.")
        except subprocess.CalledProcessError as e:
            print(f"  Error installing {package}: {e}")
            sys.exit(1)

def main():
    print("TP-Link Deco P7-upgrade toolset dependency installer")
    print("====================================================")
    check_and_install("cryptography")
    check_and_install("ubi-reader")
    print("\nAll dependencies are satisfied!")

if __name__ == "__main__":
    main()
