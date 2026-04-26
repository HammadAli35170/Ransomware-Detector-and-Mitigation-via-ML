#!/usr/bin/env python3
"""
Automated Setup Script for RDNXSYS EDR System
=============================================

This script automates the installation and configuration of:
1. Sysmon (System Monitor) - Event collection
2. NxLog - Log forwarding
3. Python dependencies
4. Configuration files

Requirements:
- Windows 10/11
- Administrator privileges
- Internet connection

Usage:
    python setup_windows.py
"""

import os
import sys
import subprocess
import urllib.request
import shutil
import ssl
import tempfile
import ctypes
from pathlib import Path
from typing import Optional, Tuple

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

def is_admin() -> bool:
    """Check if script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-run the script with administrator privileges"""
    if is_admin():
        return True
    else:
        print_warning("This script requires administrator privileges.")
        print_info("Attempting to elevate privileges...")
        try:
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            return False
        except Exception as e:
            print_error(f"Failed to elevate privileges: {e}")
            return False

def download_file(url: str, dest_path: Path, verify_ssl: bool = False) -> bool:
    """
    Download a file from URL to destination.
    
    Args:
        url: URL to download from
        dest_path: Destination file path
        verify_ssl: If False, disable SSL certificate verification (for sites with cert issues)
    """
    try:
        print_info(f"Downloading {url}...")
        if not verify_ssl:
            print_warning("SSL certificate verification disabled for this download")
            # Create unverified SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Use urlopen with custom SSL context
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ssl_context) as response:
                with open(dest_path, 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)
        else:
            # Normal download with SSL verification
            urllib.request.urlretrieve(url, dest_path)
        
        print_success(f"Downloaded to {dest_path}")
        return True
    except Exception as e:
        print_error(f"Download failed: {e}")
        return False

def run_command(cmd: list, check: bool = True, shell: bool = False) -> Tuple[bool, str]:
    """Run a command and return success status and output"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            shell=shell
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def check_sysmon_installed() -> bool:
    """Check if Sysmon is already installed"""
    # Standardize on C:\\Tools\\Sysmon as the Sysmon install location
    sysmon_install_dir = Path("C:/Tools/Sysmon")
    for exe_name in ("Sysmon64.exe", "Sysmon.exe"):
        sysmon_path = sysmon_install_dir / exe_name
        if sysmon_path.exists():
            print_success(f"Sysmon is already installed at {sysmon_path}")
            return True
    return False

def install_sysmon() -> bool:
    """Download and install Sysmon"""
    print_header("Installing Sysmon")
    
    if check_sysmon_installed():
        print_info("Sysmon already installed. Skipping download.")
        return True
    
    # Sysmon download URL (latest version from Microsoft Sysinternals)
    # Note: This is the direct download link - may need to be updated
    sysmon_url = "https://download.sysinternals.com/files/Sysmon.zip"
    
    temp_dir = Path(tempfile.gettempdir()) / "rdnxsys_setup"
    temp_dir.mkdir(exist_ok=True)
    
    zip_path = temp_dir / "Sysmon.zip"
    extract_dir = temp_dir / "Sysmon"
    
    # Download Sysmon
    if not download_file(sysmon_url, zip_path):
        print_error("Failed to download Sysmon")
        return False
    
    # Extract zip file
    print_info("Extracting Sysmon...")
    try:
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        print_success("Extracted Sysmon")
    except Exception as e:
        print_error(f"Failed to extract Sysmon: {e}")
        return False
    
    # Create Sysmon install directory under C:\Tools\Sysmon
    sysmon_install_dir = Path("C:/Tools/Sysmon")
    sysmon_install_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy ALL files from extracted Sysmon directory to C:\Tools\Sysmon
    print_info("Copying all Sysmon files to C:\\Tools\\Sysmon...")
    files_copied = 0
    sysmon_exe = None
    for item in extract_dir.rglob("*"):
        if item.is_file():
            # Calculate relative path to preserve structure
            rel_path = item.relative_to(extract_dir)
            dest_path = sysmon_install_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(item, dest_path)
                files_copied += 1
                # Track Sysmon64.exe or Sysmon.exe for service installation
                if item.name in ("Sysmon64.exe", "Sysmon.exe") and sysmon_exe is None:
                    sysmon_exe = dest_path
            except Exception as e:
                print_warning(f"Failed to copy {item.name}: {e}")
    
    print_success(f"Copied {files_copied} files to {sysmon_install_dir}")
    
    # Find Sysmon64.exe (preferred) or Sysmon.exe for service installation
    if not sysmon_exe:
        for exe_name in ("Sysmon64.exe", "Sysmon.exe"):
            exe_path = sysmon_install_dir / exe_name
            if exe_path.exists():
                sysmon_exe = exe_path
                break
    
    if not sysmon_exe or not sysmon_exe.exists():
        print_error("Sysmon64.exe / Sysmon.exe not found after copying files")
        return False
    
    print_success(f"Found Sysmon executable: {sysmon_exe.name}")
    
    # Determine Sysmon configuration source:
    # 1) Use user-provided config if present (sysmon/sysmonconfig.xml or sysmonconfig.xml in repo root)
    # 2) Otherwise, generate a default config
    repo_root = Path(__file__).parent
    user_config_candidates = [
        repo_root / "sysmon" / "sysmonconfig.xml",
        repo_root / "sysmonconfig.xml",
    ]
    user_config = None
    for candidate in user_config_candidates:
        if candidate.exists():
            user_config = candidate
            break

    sysmon_config = sysmon_install_dir / "sysmonconfig.xml"
    if user_config:
        try:
            shutil.copy2(user_config, sysmon_config)
            print_success(f"Using user Sysmon config from {user_config} → {sysmon_config}")
        except Exception as e:
            print_error(f"Failed to copy user Sysmon config: {e}")
            return False
    else:
        # Fall back to generating a default config
        create_sysmon_config(sysmon_config)
    
    # Install Sysmon with configuration
    # Command: Sysmon64.exe -accepteula -i sysmonconfig.xml
    print_info(f"Installing Sysmon service with: {sysmon_exe.name} -accepteula -i sysmonconfig.xml")
    success, output = run_command(
        [str(sysmon_exe), "-accepteula", "-i", str(sysmon_config)],
        check=False
    )
    
    if success:
        print_success("Sysmon installed successfully")
        return True
    else:
        print_warning(f"Sysmon installation output: {output}")
        # Check if it's already installed
        if "already installed" in output.lower() or "already running" in output.lower():
            print_success("Sysmon is already installed")
            return True
        print_error("Failed to install Sysmon service")
        return False

def create_sysmon_config(config_path: Path):
    """Create a basic Sysmon configuration file"""
    print_info(f"Creating Sysmon configuration at {config_path}...")
    
    # Basic Sysmon config - comprehensive event collection
    sysmon_config_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.81">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Process Creation -->
    <ProcessCreate onmatch="exclude">
      <Image condition="end with">chrome.exe</Image>
      <Image condition="end with">firefox.exe</Image>
      <Image condition="end with">msedge.exe</Image>
    </ProcessCreate>
    
    <!-- File Creation -->
    <FileCreateTime onmatch="exclude" />
    
    <!-- Network Connection -->
    <NetworkConnect onmatch="exclude">
      <DestinationIp>127.0.0.1</DestinationIp>
      <DestinationIp condition="is">::1</DestinationIp>
    </NetworkConnect>
    
    <!-- Process Termination -->
    <ProcessTerminate onmatch="exclude" />
    
    <!-- Image Load -->
    <ImageLoad onmatch="exclude" />
    
    <!-- Registry Events -->
    <RegistryEvent onmatch="exclude" />
    
    <!-- File Creation -->
    <FileCreate onmatch="exclude" />
    
    <!-- File Creation Time Changed -->
    <FileCreateTime onmatch="exclude" />
    
    <!-- Pipe Created -->
    <PipeEvent onmatch="exclude" />
    
    <!-- WMI Events -->
    <WmiEvent onmatch="exclude" />
    
    <!-- DNS Query -->
    <DnsQuery onmatch="exclude" />
  </EventFiltering>
</Sysmon>
"""
    
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(sysmon_config_xml)
        print_success(f"Sysmon configuration created at {config_path}")
    except Exception as e:
        print_error(f"Failed to create Sysmon config: {e}")

def check_nxlog_installed() -> bool:
    """Check if NxLog is already installed in C:\Tools\nxlog"""
    nxlog_path = Path("C:/Tools/nxlog/nxlog.exe")
    if nxlog_path.exists():
        print_success("NxLog is already installed in C:\\Tools\\nxlog")
        return True
    # Also check Program Files (x86) as fallback
    nxlog_path_pf = Path("C:/Program Files (x86)/nxlog/nxlog.exe")
    if nxlog_path_pf.exists():
        print_info("NxLog found in Program Files (x86), will copy to C:\\Tools\\nxlog")
        return False  # Return False to trigger copy operation
    return False

def install_nxlog() -> bool:
    """Download and install NxLog to C:\\Tools\\nxlog (prefer direct install, fallback to copy)."""
    print_header("Installing NxLog")
    
    nxlog_tools_dir = Path("C:/Tools/nxlog")
    nxlog_pf_dir = Path("C:/Program Files (x86)/nxlog")
    
    # Check if already in Tools directory (preferred final location)
    if (nxlog_tools_dir / "nxlog.exe").exists():
        print_info("NxLog already installed in C:\\Tools\\nxlog. Skipping.")
        return True
    
    # Check if installed in Program Files (x86) - we'll copy it
    if (nxlog_pf_dir / "nxlog.exe").exists():
        print_info("NxLog found in Program Files (x86), copying to C:\\Tools\\nxlog...")
        try:
            # Copy entire NxLog directory to C:\Tools\nxlog
            if nxlog_tools_dir.exists():
                shutil.rmtree(nxlog_tools_dir)
            shutil.copytree(nxlog_pf_dir, nxlog_tools_dir)
            print_success(f"Copied NxLog to {nxlog_tools_dir}")
            return True
        except Exception as e:
            print_error(f"Failed to copy NxLog: {e}")
            return False
    
    # Download and install NxLog if not found
    nxlog_url = "https://nxlog.co/system/files/products/files/348/nxlog-ce-3.2.2329.msi"
    
    temp_dir = Path(tempfile.gettempdir()) / "rdnxsys_setup"
    temp_dir.mkdir(exist_ok=True)
    
    msi_path = temp_dir / "nxlog.msi"
    
    # Download NxLog (disable SSL verification to avoid certificate errors)
    if not download_file(nxlog_url, msi_path, verify_ssl=False):
        print_error("Failed to download NxLog")
        print_warning("You may need to download NxLog manually from: https://nxlog.co/products/nxlog-community-edition/download")
        return False
    
    # Install NxLog using msiexec
    # Try to install directly into C:\Tools\nxlog using INSTALLDIR property.
    print_info("Installing NxLog via MSI into C:\\Tools\\nxlog (this may take a moment)...")
    msiexec_cmd = [
        "msiexec.exe",
        "/i", str(msi_path),
        "/quiet",
        "/norestart",
        # INSTALLDIR is a common MSI property to control target directory; if ignored by this MSI,
        # we'll fall back to copying from Program Files (x86) below.
        f"INSTALLDIR={nxlog_tools_dir}",
        "/L*v", str(temp_dir / "nxlog_install.log"),
    ]
    success, output = run_command(msiexec_cmd, check=False)
    
    if not success:
        print_warning(f"NxLog MSI installation output: {output}")
    
    # Wait a moment for installation to complete
    import time
    time.sleep(5)  # Increased wait time for MSI installation to complete
    
    # First, check if direct install to C:\Tools\nxlog succeeded
    max_retries = 10
    retry_count = 0
    while retry_count < max_retries and not (nxlog_tools_dir / "nxlog.exe").exists():
        time.sleep(2)
        retry_count += 1
        print_info(f"Waiting for NxLog installation to complete in C:\\Tools\\nxlog... ({retry_count}/{max_retries})")

    # If nxlog.exe exists in Tools directory, we're done
    if (nxlog_tools_dir / "nxlog.exe").exists():
        print_success(f"NxLog installed directly to {nxlog_tools_dir}")
        # Count files installed
        file_count = sum(1 for _ in nxlog_tools_dir.rglob("*") if _.is_file())
        print_success(f"{file_count} NxLog files present in C:\\Tools\\nxlog")
        return True

    # Otherwise, fall back to the older behavior: copy from Program Files (x86)
    print_warning("Direct install to C:\\Tools\\nxlog not detected; falling back to copy from Program Files (x86).")

    # Verify MSI placed files in Program Files (x86)
    max_retries = 10
    retry_count = 0
    while retry_count < max_retries and not (nxlog_pf_dir / "nxlog.exe").exists():
        time.sleep(2)
        retry_count += 1
        print_info(f"Waiting for NxLog installation to complete in Program Files (x86)... ({retry_count}/{max_retries})")
    
    # Copy from Program Files (x86) to C:\Tools\nxlog as fallback
    if (nxlog_pf_dir / "nxlog.exe").exists():
        print_info("Copying NxLog from Program Files (x86) to C:\\Tools\\nxlog...")
        try:
            # Remove existing Tools directory if it exists
            if nxlog_tools_dir.exists():
                print_info("Removing existing C:\\Tools\\nxlog directory...")
                shutil.rmtree(nxlog_tools_dir)
            
            # Copy entire NxLog directory structure
            print_info("Copying all NxLog files...")
            shutil.copytree(nxlog_pf_dir, nxlog_tools_dir)
            
            # Verify copy was successful
            if (nxlog_tools_dir / "nxlog.exe").exists():
                print_success(f"Copied NxLog to {nxlog_tools_dir}")
                # Count files copied
                file_count = sum(1 for _ in nxlog_tools_dir.rglob("*") if _.is_file())
                print_success(f"Copied {file_count} files to C:\\Tools\\nxlog")
                return True
            else:
                print_error("Copy completed but nxlog.exe not found in destination")
                return False
        except PermissionError as e:
            print_error(f"Permission denied while copying NxLog: {e}")
            print_warning("Make sure you're running as Administrator and no processes are using NxLog files")
            return False
        except Exception as e:
            print_error(f"Failed to copy NxLog: {e}")
            return False
    else:
        print_error("NxLog installation completed but nxlog.exe not found in Program Files (x86)")
        print_info("Check the installation log: " + str(temp_dir / "nxlog_install.log"))
        return False

def configure_nxlog() -> bool:
    """Configure NxLog with our configuration file"""
    print_header("Configuring NxLog")
    
    # Use C:\Tools\nxlog as primary location, fallback to Program Files (x86)
    nxlog_install_dir = Path("C:/Tools/nxlog")
    if not (nxlog_install_dir / "nxlog.exe").exists():
        print_warning("NxLog not found in C:\\Tools\\nxlog, checking Program Files (x86)...")
        nxlog_install_dir = Path("C:/Program Files (x86)/nxlog")
        if not (nxlog_install_dir / "nxlog.exe").exists():
            print_error("NxLog not found in either location")
            return False
    
    print_info(f"Using NxLog installation at: {nxlog_install_dir}")
    nxlog_conf = nxlog_install_dir / "conf" / "nxlog.conf"
    
    # Check if our config file exists
    local_config = Path(__file__).parent / "nxlog" / "nxlog.conf"
    if not local_config.exists():
        print_error(f"Configuration file not found: {local_config}")
        return False
    
    try:
        # Read our config
        with open(local_config, 'r', encoding='utf-8') as f:
            config_content = f.read()
        
        # Backup existing config if it exists
        if nxlog_conf.exists():
            backup_path = nxlog_conf.with_suffix('.conf.backup')
            shutil.copy2(nxlog_conf, backup_path)
            print_success(f"Backed up existing config to {backup_path}")
        
        # Write new config
        nxlog_conf.parent.mkdir(parents=True, exist_ok=True)
        with open(nxlog_conf, 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        print_success(f"NxLog configuration written to {nxlog_conf}")
        
        # Restart NxLog service to apply changes
        print_info("Restarting NxLog service...")
        run_command(["net", "stop", "nxlog"], check=False)
        run_command(["net", "start", "nxlog"], check=False)
        print_success("NxLog service restarted")
        
        return True
    except Exception as e:
        print_error(f"Failed to configure NxLog: {e}")
        return False

def install_python_dependencies(venv_python: Optional[Path] = None) -> bool:
    """Install Python dependencies from requirements.txt into the virtual environment (if provided)."""
    print_header("Installing Python Dependencies")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print_error(f"requirements.txt not found: {requirements_file}")
        return False
    
    # Decide which Python interpreter to use for installing packages
    python_exe = venv_python if venv_python is not None else Path(sys.executable)
    
    print_info(f"Installing packages from requirements.txt using {python_exe}...")
    success, output = run_command([
        str(python_exe), "-m", "pip", "install", "-r", str(requirements_file)
    ], check=False)
    
    if success:
        print_success("Python dependencies installed successfully")
        return True
    else:
        print_warning(f"Some packages may have failed to install: {output}")
        print_info("You can manually install with: pip install -r requirements.txt")
        return False

def verify_installation(venv_python: Optional[Path] = None) -> bool:
    """Verify that all components are installed and configured"""
    print_header("Verifying Installation")
    
    all_ok = True
    
    # Check Sysmon in C:\Tools\Sysmon (check for Sysmon64.exe or Sysmon.exe)
    sysmon_found = False
    sysmon_install_dir = Path("C:/Tools/Sysmon")
    for exe_name in ("Sysmon64.exe", "Sysmon.exe"):
        sysmon_path = sysmon_install_dir / exe_name
        if sysmon_path.exists():
            print_success(f"Sysmon: Installed at {sysmon_path}")
            sysmon_found = True
            break
    
    if not sysmon_found:
        print_error("Sysmon: Not found in C:\\Tools\\Sysmon (checked for Sysmon64.exe and Sysmon.exe)")
        all_ok = False
    
    # Check NxLog - prioritize C:\Tools\nxlog, then check other locations
    nxlog_paths = [
        Path("C:/Tools/nxlog/nxlog.exe"),  # Primary location
        Path("C:/Program Files (x86)/nxlog/nxlog.exe"),
        Path("C:/Program Files/nxlog/nxlog.exe"),
        Path("C:/nxlog/nxlog.exe"),
    ]
    
    nxlog_found = False
    nxlog_install_dir = None
    for nxlog_path in nxlog_paths:
        if nxlog_path.exists():
            print_success(f"NxLog: Installed at {nxlog_path.parent}")
            nxlog_found = True
            nxlog_install_dir = nxlog_path.parent
            break
    
    # Also check if NxLog service exists (alternative verification)
    if not nxlog_found:
        success, output = run_command(["sc", "query", "nxlog"], check=False)
        if success and "nxlog" in output.lower():
            print_success("NxLog: Service found (executable path may differ)")
            nxlog_found = True
            # Try to find the actual path from service
            nxlog_install_dir = Path("C:/Program Files (x86)/nxlog")
        else:
            print_error("NxLog: Not found (checked multiple paths and service)")
            all_ok = False
    
    # Check NxLog config - prioritize C:\Tools\nxlog, then check other locations
    if nxlog_found:
        nxlog_conf_paths = [
            Path("C:/Tools/nxlog/conf/nxlog.conf"),  # Primary location
            Path("C:/Program Files (x86)/nxlog/conf/nxlog.conf"),
            Path("C:/Program Files/nxlog/conf/nxlog.conf"),
        ]
        if nxlog_install_dir:
            # Ensure the install directory's config is checked first
            install_conf = nxlog_install_dir / "conf" / "nxlog.conf"
            if install_conf not in nxlog_conf_paths:
                nxlog_conf_paths.insert(0, install_conf)
        
        config_found = False
        for conf_path in nxlog_conf_paths:
            if conf_path.exists():
                print_success(f"NxLog: Configuration found at {conf_path}")
                config_found = True
                break
        
        if not config_found:
            print_error("NxLog: Configuration not found")
            all_ok = False
    
    # Check Python packages using the virtual environment's Python (if provided),
    # otherwise fall back to the current interpreter.
    print_info("Checking Python packages (using virtual environment if available)...")
    python_exe = venv_python if venv_python is not None else Path(sys.executable)

    def _check_import(module_name: str, required: bool = True, note: str = "") -> bool:
        cmd = [str(python_exe), "-c", f"import {module_name}"]
        ok, _ = run_command(cmd, check=False)
        if ok:
            print_success(f"  ✓ {module_name}")
            return True
        else:
            message = f"  ✗ {module_name} - Run: {python_exe} -m pip install {module_name}"
            if note:
                message += f" ({note})"
            if required:
                print_error(message)
            else:
                print_warning(message)
            return False

    if not _check_import("fastapi", required=True):
        all_ok = False
    if not _check_import("uvicorn", required=True):
        all_ok = False
    _check_import("lightgbm", required=False, note="optional but recommended for ML scoring")
    if not _check_import("numpy", required=True):
        all_ok = False
    if not _check_import("pywin32", required=True):
        all_ok = False
    
    if all_ok:
        print_success("Python packages: Core packages installed")
    else:
        print_warning("Python packages: Some packages missing - install with: pip install -r requirements.txt")
    
    return all_ok

def main():
    """Main setup function"""
    print_header("RDNXSYS EDR System - Automated Setup")
    
    # Check admin privileges
    if not is_admin():
        print_error("This script requires administrator privileges!")
        print_info("Please run this script as Administrator")
        if not run_as_admin():
            sys.exit(1)
        return
    
    print_success("Running with administrator privileges")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print_error("Python 3.8 or higher is required")
        sys.exit(1)
    
    print_success(f"Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    results = {
        "Sysmon": False,
        "NxLog": False,
        "NxLog Config": False,
        "Python Dependencies": False
    }

    # ------------------------------------------------------------------
    # 1) Create / reuse virtual environment and install Python packages
    # ------------------------------------------------------------------
    venv_dir = Path("myenv")
    venv_python = venv_dir / "Scripts" / "python.exe"

    # Create virtual environment if it does not exist
    if not venv_python.exists():
        print_header("Creating Python Virtual Environment (myenv)")
        success, output = run_command([
            sys.executable, "-m", "venv", str(venv_dir)
        ], check=False)
        if success:
            print_success(f"Virtual environment created at {venv_dir}")
        else:
            print_error(f"Failed to create virtual environment: {output}")
            print_warning("Proceeding with current Python interpreter as fallback")
            venv_python = Path(sys.executable)
    else:
        print_success(f"Reusing existing virtual environment at {venv_dir}")

    # Install Python dependencies into the virtual environment
    results["Python Dependencies"] = install_python_dependencies(venv_python=venv_python)

    # ------------------------------------------------------------------
    # 2) Install Sysmon and NxLog
    # ------------------------------------------------------------------
    results["Sysmon"] = install_sysmon()
    results["NxLog"] = install_nxlog()

    if results["NxLog"]:
        results["NxLog Config"] = configure_nxlog()

    # ------------------------------------------------------------------
    # 3) Final verification
    # ------------------------------------------------------------------
    verify_result = verify_installation(venv_python=venv_python)
    
    print_header("Setup Summary")
    if verify_result:
        print_success("All components installed and configured successfully")
    else:
        print_warning("Some components may need attention")
    
    print_info("\nNext steps:")
    print_info("1. Activate the virtual environment before running the EDR:")
    print_info("   myenv\\Scripts\\activate")
    print_info("2. If you need to reinstall packages:")
    print_info(f"   {venv_python} -m pip install -r requirements.txt")
    print_info("3. Start the EDR system from the activated environment:")
    print_info("   python src/unified_launcher.py")
    print_info("4. Access the dashboard at: http://localhost:8000")
    print_info("5. Verify NxLog service is running:")
    print_info("   net start nxlog  (if not already running)")
    
    if not verify_result:
        print_warning("\nNote: If Python packages are missing, they may be installed in a different")
        print_warning("Python environment. Make sure to activate your virtual environment first.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)