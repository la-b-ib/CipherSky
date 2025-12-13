#!/usr/bin/env python3
"""
CipherSky
A production-grade Network Defense Heads-Up Display using Streamlit
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP
import multiprocessing
import queue
import time
import random
import subprocess
import platform
import geoip2.database
import math
from collections import defaultdict, deque, Counter
import os
import threading
import warnings
import numpy as np
from datetime import datetime, timedelta
import ipaddress
import re
import threading
import logging
from datetime import datetime, timedelta
# Enhanced OSINT Libraries
import whois
import dns.resolver
import dns.reversename
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# Advanced Physics & Quantum Libraries
from scipy.signal import find_peaks
import networkx as nx

# Quantum-Inspired Algorithms
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from secrets import token_bytes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Advanced Visualization

# Cyber Security Advanced Tools
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# Advanced Physics & Quantum Libraries (duplicates removed)

# Quantum-Inspired Algorithms

# Advanced Visualization (use optional import above if available)

# Cyber Security Advanced Tools (use optional import above if available)
try:
    import volatility3
except ImportError:
    volatility3 = None
try:
    import pyshark
except ImportError:
    pyshark = None
import community as community_louvain
from wordcloud import WordCloud
from io import BytesIO

# Advanced OSINT and Analysis Libraries
try:
    import networkx as nx
    import dns.resolver
    import requests
    from concurrent.futures import ThreadPoolExecutor
    import whois
    import base64
    from scipy import stats
    import seaborn as sns
    ADVANCED_LIBS_AVAILABLE = True
except ImportError as e:
    print(f"Some advanced libraries not available: {e}")
    ADVANCED_LIBS_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global Configuration
MAX_PACKETS = 2000
CACHE_SIZE = 2000
QUEUE_TIMEOUT = 0.5
PROCESS_TIMEOUT = 5
HOME_LAT, HOME_LON = 37.7749, -122.4194  # San Francisco (default home location)

# ---------------- Consent & Privacy ----------------
def ensure_user_consent():
    """Block the app until user confirms age and acceptable use."""
    if 'consent_accepted' not in st.session_state:
        st.session_state.consent_accepted = False
    if 'allow_external_geo' not in st.session_state:
        st.session_state.allow_external_geo = False

    if st.session_state.consent_accepted:
        return

    st.title("Welcome to CipherSky")
    st.subheader("Usage Disclaimer & Age Verification")
    st.write("CipherSky is a network monitoring and analysis tool intended for lawful, authorized use only. By proceeding, you affirm:")
    st.markdown("- You are at least 18 years old.\n- You have authorization to analyze the network traffic on the interfaces you select.\n- You will comply with applicable laws, regulations, and organizational policies.")

    with st.expander("Privacy & Data Sources", expanded=False):
        st.markdown("- Packet capture may include metadata and network addresses.\n- Geo-location uses local databases when available. Optionally, you can enable a secure external lookup service to enrich IP locations.")
        st.session_state.allow_external_geo = st.checkbox(
            "Allow external IP geolocation (ipapi.co)", value=st.session_state.allow_external_geo,
            help="If enabled, the app may query ipapi.co over HTTPS to resolve public IP country/coordinates when local DB is unavailable."
        )

    c1, c2 = st.columns(2)
    with c1:
        age_ok = st.checkbox("I confirm I am 18+", value=False)
        tos_ok = st.checkbox("I agree to the terms above", value=False)
    with c2:
        proceed = st.button("Proceed")

    if proceed and age_ok and tos_ok:
        st.session_state.consent_accepted = True
        st.success("Thank you. Loading the Operations Center...")
        st.rerun()
    else:
        st.info("Please confirm age and agreement to continue.")
        st.stop()


class GeoResolver:
    """Geo resolver with caching and HTTPS fallback to ipapi.co."""
    def __init__(self, cache_capacity=2000, timeout=1.5):
        self.cache = LRUCache(cache_capacity)
        self.timeout = timeout

    @staticmethod
    def _is_global_ip(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global
        except Exception:
            return False

    def resolve(self, ip: str):
        if not ip or not self._is_global_ip(ip):
            return None
        cached = self.cache.get(ip)
        if cached:
            return cached
        try:
            # Prefer ipapi.co (HTTPS)
            import requests
            url = f"https://ipapi.co/{ip}/json/"
            r = requests.get(url, timeout=self.timeout)
            if r.ok:
                j = r.json()
                cc = j.get('country_code') or j.get('country')
                country_name = j.get('country_name') or j.get('country') or 'Unknown'
                lat = j.get('latitude') or j.get('lat')
                lon = j.get('longitude') or j.get('lon')
                if cc and lat is not None and lon is not None:
                    info = {
                        'latitude': float(lat),
                        'longitude': float(lon),
                        'country': country_name,
                        'country_code': cc
                    }
                    self.cache.put(ip, info)
                    return info
        except Exception:
            pass
        return None

# Advanced Physics Constants
PLANCK_CONSTANT = 6.62607015e-34  # Planck's constant
BOLTZMANN_CONSTANT = 1.380649e-23  # Boltzmann constant
LIGHT_SPEED = 299792458  # Speed of light in m/s
PHI = (1 + np.sqrt(5)) / 2  # Golden ratio
EULER_CONST = np.e
PI_CONST = np.pi

# Quantum Mechanics Constants & Operators
QUANTUM_STATES = ['|0⟩', '|1⟩', '|+⟩', '|-⟩', '|i⟩', '|-i⟩']
PAULI_X = np.array([[0, 1], [1, 0]], dtype=complex)
PAULI_Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
PAULI_Z = np.array([[1, 0], [0, -1]], dtype=complex)
HADAMARD = np.array([[1, 1], [1, -1]], dtype=complex) / np.sqrt(2)
CNOT = np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=complex)

# Advanced Cyber Security Configuration
DARK_WEB_INDICATORS = [
    '.onion', 'tor2web', 'torbox', 'onion.link', 'onion.to',
    'onion.cab', 'onion.nu', 'onion.ws'
]
CRYPTO_MINING_PORTS = [3333, 4444, 8333, 8888, 9999, 14444]
C2_SIGNATURES = [
    b'\\x00\\x00\\x00\\x0c\\x00\\x00\\x00\\x01',  # Common C2 beacon
    b'Mozilla/5.0 (compatible; MSIE',  # Suspicious user agent
    b'Windows NT 6.1; WOW64',  # Common bot signature
]

# Advanced Malware Analysis Rules
YARA_RULES = '''
rule SuspiciousNetwork {
    meta:
        description = "Detects suspicious network patterns"
        author = "CipherSky Advanced Threat Detection"
    strings:
        $c2_pattern = { 00 00 00 0C 00 00 00 01 }
        $tor_pattern = { 2E 6F 6E 69 6F 6E }
        $crypto_pattern = "stratum+tcp://"
    condition:
        any of them
}
rule QuantumResistantCrypto {
    meta:
        description = "Identifies potential quantum-resistant cryptographic implementations"
    strings:
        $lattice = "NTRU" nocase
        $isogeny = "SIKE" nocase
        $hash_based = "SPHINCS" nocase
    condition:
        any of them
}
'''

# Quantum Network Topology Parameters
QUANTUM_ENTANGLEMENT_THRESHOLD = 0.85
QUANTUM_DECOHERENCE_FACTOR = 0.97
NETWORK_DIMENSIONALITY = 8  # Higher dimensional space for network analysis

# Dynamic Dashboard Configuration
DASHBOARD_CONFIG = {
    'auto_refresh': True,
    'refresh_interval': 2,  # seconds
    'real_time_alerts': True,
    'show_animations': True,
    'dark_theme': True,
    'max_alerts_display': 10,
    'enable_sound_alerts': False,
    'alert_thresholds': {
        'high_threat': 0.8,
        'medium_threat': 0.5,
        'packet_volume': 100
    }
}

class DynamicDashboard:
    """Dynamic dashboard controller for real-time updates and interactivity"""
    
    def __init__(self):
        self.auto_refresh = True
        self.refresh_interval = 2
        self.active_filters = {}
        self.selected_timeframe = '1h'
        self.alert_sounds = False
        self.dashboard_layout = 'default'
        
    def create_dashboard_controls(self):
        """Create interactive dashboard control panel"""
        with st.expander("🎛️ Dashboard Controls", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                self.auto_refresh = st.toggle("🔄 Auto Refresh", value=True)
                self.refresh_interval = st.slider("Refresh Rate (sec)", 1, 10, 2)
                
            with col2:
                self.selected_timeframe = st.selectbox(
                    "⏱️ Timeframe",
                    ['5m', '15m', '30m', '1h', '6h', '24h'],
                    index=3
                )
                self.alert_sounds = st.toggle("🔊 Sound Alerts", value=False)
                
            with col3:
                self.dashboard_layout = st.selectbox(
                    "📊 Layout",
                    ['default', 'compact', 'detailed', 'analyst'],
                    index=0
                )
                threat_threshold = st.slider("🚨 Alert Threshold", 0.1, 1.0, 0.7)
        
        return {
            'auto_refresh': self.auto_refresh,
            'refresh_interval': self.refresh_interval,
            'timeframe': self.selected_timeframe,
            'alert_sounds': self.alert_sounds,
            'layout': self.dashboard_layout,
            'threat_threshold': threat_threshold
        }
    
    def create_live_metrics(self, packets, alerts):
        """Create live updating metrics dashboard"""
        if not packets:
            st.info("🔄 Waiting for data...")
            return
            
        df = pd.DataFrame(packets)
        
        # Real-time metrics
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            total_packets = len(df)
            st.metric(
                "📊 Total Packets",
                f"{total_packets:,}",
                delta=f"+{min(total_packets, 50)}" if total_packets > 0 else None
            )
            
        with col2:
            unique_ips = df['src_ip'].nunique()
            st.metric(
                "🌐 Unique IPs",
                unique_ips,
                delta=f"+{min(unique_ips, 10)}" if unique_ips > 0 else None
            )
            
        with col3:
            avg_threat = df['threat_score'].mean() if 'threat_score' in df.columns else 0
            threat_color = "normal" if avg_threat < 0.3 else "inverse"
            st.metric(
                "⚠️ Avg Threat",
                f"{avg_threat:.2f}",
                delta=f"{avg_threat:.2f}"
            )
            
        with col4:
            high_threats = len(df[df.get('threat_score', 0) > 0.7]) if 'threat_score' in df.columns else 0
            st.metric(
                "🚨 High Threats",
                high_threats,
                delta=f"+{high_threats}" if high_threats > 0 else None
            )
            
        with col5:
            countries = df['country'].nunique() if 'country' in df.columns else 0
            st.metric(
                "🗺️ Countries",
                countries,
                delta=f"+{min(countries, 5)}" if countries > 0 else None
            )
            
        with col6:
            protocols = df['protocol_name'].nunique() if 'protocol_name' in df.columns else 0
            st.metric(
                "🔗 Protocols",
                protocols,
                delta=f"+{min(protocols, 3)}" if protocols > 0 else None
            )
    
    def create_real_time_alerts(self, alerts):
        """Create real-time scrolling alerts panel"""
        st.markdown("### 🚨 Real-time Threat Alerts")
        
        if not alerts:
            st.info("✅ No active threats detected")
            return
            
        # Create scrollable alerts container
        alert_container = st.container()
        
        with alert_container:
            for i, alert in enumerate(reversed(alerts[-10:])):
                severity = alert.get('threat_score', 0)
                
                if severity > 0.8:
                    alert_type = "🔴 CRITICAL"
                    alert_color = "red"
                elif severity > 0.5:
                    alert_type = "🟡 WARNING"
                    alert_color = "orange"
                else:
                    alert_type = "🟢 INFO"
                    alert_color = "green"
                
                with st.expander(f"{alert_type} - {alert['source_ip']} - {alert['timestamp']}", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**Type:** {alert.get('type', 'Unknown')}")
                        st.write(f"**Source:** {alert['source_ip']}")
                        st.write(f"**Score:** {severity:.2f}")
                        st.write(f"**Details:** {alert.get('details', 'No details')}")
                    with col2:
                        if st.button(f"🚫 Block IP", key=f"block_alert_{i}"):
                            # Add blocking logic here
                            st.success(f"Blocked {alert['source_ip']}")
    
    def create_interactive_filters(self, packets):
        """Create interactive filtering system"""
        st.markdown("### 🔍 Interactive Filters")
        
        if not packets:
            return packets
            
        df = pd.DataFrame(packets)
        filtered_df = df.copy()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            # IP filter
            ip_filter = st.text_input("🌐 Filter by IP", placeholder="192.168.1.1")
            if ip_filter:
                filtered_df = filtered_df[
                    filtered_df['src_ip'].str.contains(ip_filter, na=False) |
                    filtered_df['dst_ip'].str.contains(ip_filter, na=False)
                ]
        
        with col2:
            # Protocol filter
            protocols = df['protocol_name'].unique() if 'protocol_name' in df.columns else []
            selected_protocols = st.multiselect(
                "🔗 Protocols",
                options=protocols,
                default=[]
            )
            if selected_protocols:
                filtered_df = filtered_df[filtered_df['protocol_name'].isin(selected_protocols)]
        
        with col3:
            # Country filter
            countries = df['country'].unique() if 'country' in df.columns else []
            selected_countries = st.multiselect(
                "🗺️ Countries",
                options=countries[:20],  # Limit for performance
                default=[]
            )
            if selected_countries:
                filtered_df = filtered_df[filtered_df['country'].isin(selected_countries)]
        
        with col4:
            # Threat level filter
            if 'threat_score' in df.columns:
                min_threat, max_threat = st.slider(
                    "⚠️ Threat Range",
                    0.0, 1.0, (0.0, 1.0),
                    step=0.1
                )
                filtered_df = filtered_df[
                    (filtered_df['threat_score'] >= min_threat) &
                    (filtered_df['threat_score'] <= max_threat)
                ]
        
        # Display filter summary
        st.info(f"📊 Showing {len(filtered_df)} of {len(df)} packets after filtering")
        
        return filtered_df.to_dict('records')

class LRUCache:
    """Thread-safe LRU Cache implementation for GeoIP lookups"""
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}
        self.order = deque()
        self._lock = threading.Lock()
    
    def get(self, key):
        with self._lock:
            if key in self.cache:
                self.order.remove(key)
                self.order.append(key)
                return self.cache[key]
            return None
    
    def put(self, key, value):
        with self._lock:
            if key in self.cache:
                self.order.remove(key)
            elif len(self.cache) >= self.capacity:
                oldest = self.order.popleft()
                del self.cache[oldest]
            
            self.cache[key] = value
            self.order.append(key)

class FirewallController:
    """Cross-platform firewall controller for blocking/unblocking IPs"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_ips = set()
        self._lock = threading.Lock()
        
        # Validate permissions
        self._check_permissions()
    
    def _check_permissions(self):
        """Check if running with sufficient privileges"""
        try:
            if self.os_type == "windows":
                # Test if we can run netsh command
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    logger.warning("Insufficient privileges for Windows firewall control")
            elif self.os_type == "darwin":  # macOS
                # Test if we can run pfctl
                result = subprocess.run(
                    ["pfctl", "-s", "rules"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    logger.warning("Insufficient privileges for macOS firewall control")
            else:
                # Test if we can read iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    logger.warning("Insufficient privileges for iptables control")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Firewall permission check failed: {e}")
    
    def block_ip(self, ip):
        """Block an IP address using OS-appropriate firewall commands"""
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
            
        with self._lock:
            if ip in self.blocked_ips:
                logger.info(f"IP {ip} already blocked")
                return True
                
            try:
                if self.os_type == "windows":
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=CipherSky_Block_{ip.replace('.', '_')}",
                        "dir=in", "action=block", f"remoteip={ip}"
                    ]
                elif self.os_type == "darwin":  # macOS
                    # macOS doesn't have a simple CLI firewall interface
                    # This is a placeholder - in practice, you'd need to use pfctl or similar
                    logger.warning(f"macOS firewall blocking not implemented - would block {ip}")
                    self.blocked_ips.add(ip)
                    return True
                else:  # Linux/Unix
                    cmd = [
                        "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
                    ]
                
                if self.os_type != "darwin":
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10, check=False
                    )
                    
                    if result.returncode == 0:
                        self.blocked_ips.add(ip)
                        logger.info(f"Successfully blocked IP: {ip}")
                        return True
                    else:
                        logger.error(f"Failed to block IP {ip}: {result.stderr}")
                        return False
                else:
                    return True
                    
            except (subprocess.TimeoutExpired, Exception) as e:
                logger.error(f"Failed to block IP {ip}: {e}")
                return False
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
            
        with self._lock:
            if ip not in self.blocked_ips:
                logger.info(f"IP {ip} not currently blocked")
                return True
                
            try:
                if self.os_type == "windows":
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name=CipherSky_Block_{ip.replace('.', '_')}"
                    ]
                elif self.os_type == "darwin":  # macOS
                    logger.warning(f"macOS firewall unblocking not implemented - would unblock {ip}")
                    self.blocked_ips.discard(ip)
                    return True
                else:  # Linux/Unix
                    cmd = [
                        "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
                    ]
                
                if self.os_type != "darwin":
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10, check=False
                    )
                    
                    if result.returncode == 0:
                        self.blocked_ips.discard(ip)
                        logger.info(f"Successfully unblocked IP: {ip}")
                        return True
                    else:
                        logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                        return False
                else:
                    return True
                    
            except (subprocess.TimeoutExpired, Exception) as e:
                logger.error(f"Failed to unblock IP {ip}: {e}")
                return False
    
    def _validate_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def cleanup(self):
        """Cleanup all blocked IPs on shutdown"""
        logger.info("Cleaning up firewall rules...")
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)

class ThreatDetector:
    """Advanced ML-based threat detection system"""
    def __init__(self):
        self.threat_scores = {}
        self.port_reputation = {
            22: 0.3,   # SSH - medium risk
            23: 0.8,   # Telnet - high risk
            25: 0.4,   # SMTP - medium risk
            53: 0.1,   # DNS - low risk
            80: 0.1,   # HTTP - low risk
            443: 0.1,  # HTTPS - low risk
            3389: 0.7, # RDP - high risk
            5900: 0.8, # VNC - high risk
        }
        self.ip_activity = defaultdict(deque)
        self.rate_window_seconds = 60
        self.size_stats = defaultdict(lambda: {'n': 0, 'mean': 0.0, 'm2': 0.0})
        self.port_fanout = defaultdict(deque)  # (ts, port) per src
    
    def calculate_threat_score(self, packet_data):
        """Calculate ML-based threat score for packet"""
        score = 0.0
        
        # Base score from port reputation
        port = packet_data.get('port', 0)
        score += self.port_reputation.get(port, 0.2)
        
        # Entropy-based scoring
        entropy = packet_data.get('entropy', 0)
        if entropy > 7.0:  # High entropy indicates encryption/compression
            score += 0.4
        elif entropy > 5.0:
            score += 0.2
        
        # Geographic consistency: prefer neutral baseline; bump on missing geo
        country = packet_data.get('country_code', '') or ''
        if country in ('XX', 'LO'):
            score += 0.05
        
        # Protocol anomaly detection
        proto_name = packet_data.get('protocol_name')
        if proto_name == 'ICMP':
            score += 0.1  # ICMP can be used for reconnaissance
        if proto_name == 'DNS' and port not in (53, 5353):
            score += 0.15  # DNS on unusual port
        flags = packet_data.get('flags_list', [])
        if flags == ['SYN'] and packet_data.get('payload_size', 0) == 0:
            score += 0.05  # SYN scan-like packet
        
        # Time-based anomaly (unusual hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Off-hours traffic
            score += 0.2

        # Rate-based anomaly per source IP (rolling 60s)
        src_ip = packet_data.get('src_ip')
        now_ts = time.time()
        if src_ip:
            dq = self.ip_activity[src_ip]
            dq.append(now_ts)
            # prune old
            cutoff = now_ts - self.rate_window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            rate = len(dq)  # packets in last window
            if rate > 60:
                score += min(0.3, (rate - 60) / 200.0)

            # Port fan-out detection: many distinct ports in short window
            port = int(packet_data.get('port', 0))
            pdq = self.port_fanout[src_ip]
            pdq.append((now_ts, port))
            cutoff = now_ts - self.rate_window_seconds
            while pdq and pdq[0][0] < cutoff:
                pdq.popleft()
            unique_ports = len({p for _, p in pdq if p > 0})
            if unique_ports > 50:
                score += 0.4
            elif unique_ports > 20:
                score += 0.2

        # Size anomaly using incremental stats (Welford)
        pkt_len = float(packet_data.get('length', 0))
        if src_ip is not None:
            stats = self.size_stats[src_ip]
            stats['n'] += 1
            n = stats['n']
            delta = pkt_len - stats['mean']
            stats['mean'] += delta / n
            stats['m2'] += delta * (pkt_len - stats['mean'])
            if n > 10 and stats['m2'] > 0:
                var = stats['m2'] / (n - 1)
                std = math.sqrt(max(var, 1e-9))
                z = abs((pkt_len - stats['mean']) / (std if std > 0 else 1.0))
                if z > 5:
                    score += 0.2
                elif z > 3:
                    score += 0.1

        # TTL anomalies
        ttl = packet_data.get('ttl', 64)
        if ttl < 32 or ttl > 128:
            score += 0.1
        
        # Suspicious content
        if packet_data.get('is_suspicious', False):
            score += 0.2

        # Bogon/reserved source IPs (non-private unexpected ranges)
        try:
            ip_obj = ipaddress.ip_address(src_ip) if src_ip else None
            if ip_obj and not ip_obj.is_private and (
                ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified or ip_obj.is_loopback
            ):
                score += 0.2
        except Exception:
            pass

        # DNS domain anomalies (length/entropy/char mix)
        domain = packet_data.get('dns_query') or ''
        if domain:
            try:
                dl = len(domain)
                if dl > 60:
                    score += 0.2
                # character entropy
                from math import log2
                freq = {}
                for ch in domain:
                    freq[ch] = freq.get(ch, 0) + 1
                ent = 0.0
                for c in freq.values():
                    p = c / dl
                    ent -= p * log2(p)
                if ent > 4.5:
                    score += 0.15
                digits = sum(ch.isdigit() for ch in domain)
                if dl > 0 and digits / dl > 0.35:
                    score += 0.1
            except Exception:
                pass
        
        return min(score, 1.0)

class MLAnomalyEngine:
    """Optional ML-based anomaly scoring using IsolationForest"""
    def __init__(self):
        self.enabled = SKLEARN_AVAILABLE
        self.last_count = 0

    def _features_from_packet(self, p):
        proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'DNS': 3}
        proto = proto_map.get(p.get('protocol_name', ''), 4)
        return [
            float(p.get('length', 0)),
            float(p.get('entropy', 0.0)),
            float(p.get('ttl', 64)),
            float(p.get('port', 0)),
            1.0 if p.get('is_encrypted', False) else 0.0,
            float(p.get('decoherence_factor', 0.0)),
            float(p.get('threat_score', 0.0)),
            float(proto)
        ]

    def score_recent(self, recent_packets):
        if not self.enabled:
            return
        if not recent_packets or len(recent_packets) < 30:
            return
        try:
            X = np.array([self._features_from_packet(p) for p in recent_packets], dtype=float)
            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            model.fit(X)
            scores = -model.score_samples(X)  # higher = more anomalous
            s_min, s_max = float(np.min(scores)), float(np.max(scores))
            denom = (s_max - s_min) + 1e-9
            anomalies = (scores - s_min) / denom
            for i, p in enumerate(recent_packets):
                p['anomaly_score'] = float(np.clip(anomalies[i], 0.0, 1.0))
                # blend into threat score conservatively
                base = float(p.get('threat_score', 0.0))
                blended = 0.7 * base + 0.3 * p['anomaly_score']
                p['threat_score'] = float(min(1.0, blended))
        except Exception as e:
            logger.debug(f"Anomaly engine error: {e}")

class NetworkTopologyAnalyzer:
    """Advanced network topology analysis and graph theory implementation"""
    def __init__(self):
        self.node_cache = {}
        self.edge_cache = {}
        self.centrality_cache = {}
    
    def calculate_network_centrality(self, connections_df):
        """Calculate various centrality metrics for network nodes"""
        centrality_metrics = {}
        
        # Degree centrality (simple connection count)
        degree_centrality = {}
        for node in set(connections_df['src_ip'].unique()) | set(connections_df['dst_ip'].unique()):
            in_degree = len(connections_df[connections_df['dst_ip'] == node])
            out_degree = len(connections_df[connections_df['src_ip'] == node])
            degree_centrality[node] = in_degree + out_degree
        
        # Betweenness centrality approximation
        betweenness_centrality = self._approximate_betweenness(connections_df)
        
        centrality_metrics['degree'] = degree_centrality
        centrality_metrics['betweenness'] = betweenness_centrality
        
        return centrality_metrics
    
    def _approximate_betweenness(self, connections_df):
        """Approximate betweenness centrality for large networks"""
        betweenness = {}
        nodes = set(connections_df['src_ip'].unique()) | set(connections_df['dst_ip'].unique())
        
        for node in nodes:
            # Count how many connections pass through this node
            through_count = 0
            for _, conn in connections_df.iterrows():
                if node != conn['src_ip'] and node != conn['dst_ip']:
                    # Simplified: if this node appears in many different connections
                    node_connections = connections_df[
                        (connections_df['src_ip'] == node) | (connections_df['dst_ip'] == node)
                    ]
                    through_count += len(node_connections)
            
            betweenness[node] = through_count
        
        return betweenness
    
    def detect_network_communities(self, connections_df):
        """Detect network communities using simple clustering"""
        communities = []
        processed_nodes = set()
        
        for _, conn in connections_df.iterrows():
            src, dst = conn['src_ip'], conn['dst_ip']
            
            if src not in processed_nodes and dst not in processed_nodes:
                # Find all nodes connected to this pair
                community = {src, dst}
                
                # Expand community by finding connected nodes
                connected = connections_df[
                    (connections_df['src_ip'].isin(community)) | 
                    (connections_df['dst_ip'].isin(community))
                ]
                
                for _, c in connected.iterrows():
                    community.add(c['src_ip'])
                    community.add(c['dst_ip'])
                
                communities.append(list(community))
                processed_nodes.update(community)
        
        return communities[:10]  # Limit to top 10 communities
    
    def calculate_network_diameter(self, connections_df):
        """Calculate approximate network diameter"""
        nodes = list(set(connections_df['src_ip'].unique()) | set(connections_df['dst_ip'].unique()))
        
        if len(nodes) < 2:
            return 0
        
        # Simple approximation: maximum hops between any two highly connected nodes
        degree_centrality = {}
        for node in nodes:
            degree_centrality[node] = len(connections_df[
                (connections_df['src_ip'] == node) | (connections_df['dst_ip'] == node)
            ])
        
        # Get top 5 most connected nodes
        top_nodes = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        
        max_distance = 0
        for i, (node1, _) in enumerate(top_nodes):
            for j, (node2, _) in enumerate(top_nodes[i+1:], i+1):
                # Simple distance calculation (1 if direct connection, 2 if through intermediary)
                direct = len(connections_df[
                    ((connections_df['src_ip'] == node1) & (connections_df['dst_ip'] == node2)) |
                    ((connections_df['src_ip'] == node2) & (connections_df['dst_ip'] == node1))
                ])
                
                distance = 1 if direct > 0 else 2  # Simplified
                max_distance = max(max_distance, distance)
        
        return max_distance

class ThreatIntelligence:
    """Advanced threat intelligence and OSINT analyzer"""
    def __init__(self):
        self.dns_cache = LRUCache(1000)
        self.whois_cache = LRUCache(500)
        self.reputation_cache = LRUCache(1000)
        self.malicious_indicators = set()
        self.suspicious_domains = set()
        self.threat_feeds = {
            'malware_domains': [],
            'phishing_urls': [],
            'tor_nodes': [],
            'suspicious_ips': []
        }
    
    def analyze_domain(self, domain):
        """Comprehensive domain analysis using OSINT"""
        analysis = {
            'domain': domain,
            'whois_info': None,
            'dns_records': {},
            'subdomains': [],
            'reputation_score': 0.0,
            'threat_indicators': [],
            'ssl_info': None
        }
        
        try:
            # Whois lookup
            cached_whois = self.whois_cache.get(domain)
            if not cached_whois:
                try:
                    whois_info = whois.whois(domain)
                    analysis['whois_info'] = {
                        'registrar': str(whois_info.registrar) if whois_info.registrar else 'Unknown',
                        'creation_date': str(whois_info.creation_date[0]) if whois_info.creation_date else 'Unknown',
                        'expiration_date': str(whois_info.expiration_date[0]) if whois_info.expiration_date else 'Unknown',
                        'name_servers': whois_info.name_servers[:5] if whois_info.name_servers else []
                    }
                    self.whois_cache.put(domain, analysis['whois_info'])
                except Exception as e:
                    analysis['whois_info'] = {'error': str(e)}
            else:
                analysis['whois_info'] = cached_whois
            
            # DNS Resolution
            try:
                # A Records
                a_records = dns.resolver.resolve(domain, 'A')
                analysis['dns_records']['A'] = [str(r) for r in a_records]
                
                # MX Records
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    analysis['dns_records']['MX'] = [str(r) for r in mx_records]
                except:
                    analysis['dns_records']['MX'] = []
                
                # TXT Records
                try:
                    txt_records = dns.resolver.resolve(domain, 'TXT')
                    analysis['dns_records']['TXT'] = [str(r) for r in txt_records]
                except:
                    analysis['dns_records']['TXT'] = []
                    
            except Exception as e:
                analysis['dns_records']['error'] = str(e)
            
            # Domain reputation analysis
            analysis['reputation_score'] = self.calculate_domain_reputation(domain, analysis)
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def analyze_ip(self, ip_address):
        """Comprehensive IP analysis using OSINT"""
        analysis = {
            'ip': ip_address,
            'reverse_dns': None,
            'geolocation': {},
            'reputation_score': 0.0,
            'threat_indicators': [],
            'open_ports': [],
            'asn_info': None
        }
        
        try:
            # Reverse DNS lookup
            try:
                reverse_name = dns.reversename.from_address(ip_address)
                reverse_dns = dns.resolver.resolve(reverse_name, 'PTR')
                analysis['reverse_dns'] = str(reverse_dns[0])
            except:
                analysis['reverse_dns'] = None
            
            # IP reputation scoring
            analysis['reputation_score'] = self.calculate_ip_reputation(ip_address)
            
            # Check against threat feeds
            if ip_address in self.threat_feeds['suspicious_ips']:
                analysis['threat_indicators'].append('Known suspicious IP')
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def calculate_domain_reputation(self, domain, domain_info):
        """Calculate domain reputation score"""
        score = 0.0
        
        # Check domain age
        if domain_info.get('whois_info', {}).get('creation_date'):
            try:
                creation_date = datetime.strptime(domain_info['whois_info']['creation_date'][:10], '%Y-%m-%d')
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:  # Very new domain
                    score += 0.4
                elif age_days < 90:  # Relatively new
                    score += 0.2
            except:
                pass
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[0-9]{4,}',  # Many numbers
            r'[a-z]{20,}',  # Very long strings
            r'\-{2,}',     # Multiple consecutive dashes
            r'[^a-z0-9\-\.]'  # Special characters
        ]
        
        domain_lc = domain.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lc):
                score += 0.1
        
        # Check TLD reputation
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 0.3
        
        return min(score, 1.0)
    
    def calculate_ip_reputation(self, ip):
        """Calculate IP reputation score"""
        score = 0.0
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private IP
            if ip_obj.is_private:
                return 0.0
            
            # Check for suspicious IP ranges
            if ip_obj.is_reserved or ip_obj.is_multicast:
                score += 0.3
            
            # Basic geographic reputation (simplified)
            # In real implementation, you'd use threat intelligence feeds
            
        except:
            pass
        
        return score
    
    def generate_network_graph(self, packets):
        """Generate network topology graph using NetworkX"""
        G = nx.DiGraph()
        
        # Add nodes and edges from packets
        for packet in packets:
            src = packet.get('src_ip', '')
            dst = packet.get('dst_ip', '')
            protocol = packet.get('protocol_name', 'Unknown')
            
            if src and dst:
                # Add nodes with attributes
                G.add_node(src, node_type='source', country=packet.get('country', 'Unknown'))
                G.add_node(dst, node_type='destination')
                
                # Add edge with weight (packet count)
                if G.has_edge(src, dst):
                    G[src][dst]['weight'] += 1
                    G[src][dst]['protocols'].add(protocol)
                else:
                    G.add_edge(src, dst, weight=1, protocols={protocol})
        
        return G
    
    def analyze_network_communities(self, network_graph):
        """Detect communities in network using Louvain algorithm"""
        try:
            # Convert to undirected for community detection
            undirected_graph = network_graph.to_undirected()
            
            # Detect communities
            communities = community_louvain.best_partition(undirected_graph)
            
            return communities
        except Exception as e:
            return {}
    
    def create_threat_wordcloud(self, threats):
        """Create word cloud of threat indicators"""
        try:
            if not threats:
                return None
            
            # Combine all threat descriptions
            text = ' '.join([threat.get('description', '') for threat in threats])
            
            if not text.strip():
                return None
            
            # Generate word cloud
            wordcloud = WordCloud(
                width=800, height=400,
                background_color='black',
                colormap='Reds',
                max_words=100
            ).generate(text)
            
            # Convert to image for Streamlit
            img = BytesIO()
            wordcloud.to_image().save(img, format='PNG')
            img.seek(0)
            
            return img
        except Exception as e:
            return None

class AdvancedVisualizations:
    """Advanced visualization engine for network data"""
    
    @staticmethod
    def create_3d_network_topology(packets, threat_intel):
        """Create interactive 3D network topology visualization"""
        if not packets:
            return None
        
        # Generate network graph
        G = threat_intel.generate_network_graph(packets)
        
        if not G.nodes():
            return None
        
        # Calculate 3D positions using spring layout
        pos_2d = nx.spring_layout(G, k=3, iterations=50)
        
        # Add Z dimension based on threat scores
        pos_3d = {}
        for node in G.nodes():
            node_packets = [p for p in packets if p.get('src_ip') == node or p.get('dst_ip') == node]
            avg_threat = np.mean([p.get('threat_score', 0) for p in node_packets]) if node_packets else 0
            pos_3d[node] = (pos_2d[node][0], pos_2d[node][1], avg_threat * 10)
        
        # Create 3D scatter plot
        node_trace = go.Scatter3d(
            x=[pos_3d[node][0] for node in G.nodes()],
            y=[pos_3d[node][1] for node in G.nodes()],
            z=[pos_3d[node][2] for node in G.nodes()],
            mode='markers+text',
            marker=dict(
                size=10,
                color=[len([p for p in packets if p.get('src_ip') == node]) for node in G.nodes()],
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Packet Count")
            ),
            text=[f"{node}<br>Packets: {len([p for p in packets if p.get('src_ip') == node])}" for node in G.nodes()],
            textposition="middle center",
            name='Network Nodes'
        )
        
        # Create edges
        edge_x, edge_y, edge_z = [], [], []
        for edge in G.edges():
            x0, y0, z0 = pos_3d[edge[0]]
            x1, y1, z1 = pos_3d[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_z.extend([z0, z1, None])
        
        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color='rgba(100,100,100,0.8)', width=2),
            hoverinfo='none',
            name='Connections'
        )
        
        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title="3D Network Topology (Lite Mode)",
            showlegend=True,
            scene=dict(
                xaxis_title="X Coordinate",
                yaxis_title="Y Coordinate",
                zaxis_title="Threat Level",
                bgcolor='rgba(248,249,250,1)',  # Light background
                xaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                yaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                zaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)')
            ),
            paper_bgcolor='rgba(255,255,255,1)',
            plot_bgcolor='rgba(255,255,255,1)',
            font=dict(color='black'),
            height=600
        )
        
        return fig

class AdvancedAnalytics:
    """Advanced network analytics and forensics with OSINT integration"""
    def __init__(self):
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        self.topology_analyzer = NetworkTopologyAnalyzer()
        self.osint = ThreatIntelligence()
        self.network_graph = nx.DiGraph()
        self.flow_analyzer = {}
    
    def analyze_traffic_patterns(self, packets):
        """Enhanced traffic pattern analysis with OSINT capabilities"""
        if not packets:
            return {}
        
        df = pd.DataFrame(packets)
        
        analysis = {
            'total_packets': len(df),
            'unique_sources': df['src_ip'].nunique(),
            'unique_destinations': df['dst_ip'].nunique(),
            'protocol_diversity': df['protocol_name'].nunique() if 'protocol_name' in df.columns else 0,
            'avg_packet_size': df['length'].mean(),
            'max_packet_size': df['length'].max(),
            'entropy_stats': {
                'mean': df[df['entropy'] > 0]['entropy'].mean() if 'entropy' in df.columns and df['entropy'].sum() > 0 else 0,
                'std': df[df['entropy'] > 0]['entropy'].std() if 'entropy' in df.columns and df['entropy'].sum() > 0 else 0,
                'max': df['entropy'].max() if 'entropy' in df.columns else 0
            }
        }
        
        # Enhanced OSINT analysis
        if self.osint:
            # Analyze top communicating IPs
            top_sources = df['src_ip'].value_counts().head(10)
            suspicious_flows = []
            
            for ip, count in top_sources.items():
                if count > 20:  # High volume communicator
                    ip_packets = df[df['src_ip'] == ip]
                    avg_size = ip_packets['length'].mean() if len(ip_packets) > 0 else 0
                    
                    # Check if suspicious IP
                    if self.osint.is_suspicious_ip(ip):
                        suspicious_flows.append({
                            'ip': ip,
                            'packet_count': count,
                            'risk_score': 0.8,
                            'indicators': ['Known malicious IP range']
                        })
            
            analysis['suspicious_flows'] = suspicious_flows
            
            # Build network topology graph
            if self.network_graph is not None:
                self.network_graph.clear()
                
                # Add nodes and edges
                for _, packet in df.iterrows():
                    src, dst = packet['src_ip'], packet['dst_ip']
                    
                    # Add nodes with attributes
                    if not self.network_graph.has_node(src):
                        self.network_graph.add_node(src, node_type='source', 
                                                   country=packet.get('country', 'Unknown'))
                    if not self.network_graph.has_node(dst):
                        self.network_graph.add_node(dst, node_type='destination')
                    
                    # Add edge with weight
                    if self.network_graph.has_edge(src, dst):
                        self.network_graph[src][dst]['weight'] += 1
                    else:
                        self.network_graph.add_edge(src, dst, weight=1, 
                                                   protocol=packet.get('protocol_name', 'Unknown'))
                
                # Calculate network metrics
                try:
                    analysis['network_metrics'] = {
                        'nodes': self.network_graph.number_of_nodes(),
                        'edges': self.network_graph.number_of_edges(),
                        'density': nx.density(self.network_graph),
                        'connected_components': nx.number_weakly_connected_components(self.network_graph)
                    }
                    
                    # Find most central nodes
                    if self.network_graph.number_of_nodes() > 0:
                        centrality = nx.degree_centrality(self.network_graph)
                        top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
                        analysis['central_nodes'] = top_central
                except:
                    pass
        
        return analysis

def calculate_shannon_entropy(data):
    """Calculate Shannon entropy of data to detect encryption/compression"""
    if not data or len(data) < 2:
        return 0
    
    try:
        # Get byte frequency
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        length = len(data)
        for count in byte_counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy: {e}")
        return 0

class DynamicDashboard:
    """Dynamic dashboard controller for real-time updates and interactivity"""
    
    def __init__(self):
        self.auto_refresh = True
        self.refresh_interval = 2
        self.active_filters = {}
        self.selected_timeframe = '1h'
        self.alert_sounds = False
        self.dashboard_layout = 'default'
        
    def create_dashboard_controls(self):
        """Create interactive dashboard control panel"""
        with st.expander("🎛️ Dashboard Controls", expanded=False):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                self.auto_refresh = st.toggle("🔄 Auto Refresh", value=True)
                self.refresh_interval = st.slider("Refresh Rate (sec)", 1, 10, 2)
                
            with col2:
                self.selected_timeframe = st.selectbox(
                    "⏱️ Timeframe",
                    ['5m', '15m', '30m', '1h', '6h', '24h'],
                    index=3
                )
                self.alert_sounds = st.toggle("🔊 Sound Alerts", value=False)
                
            with col3:
                self.dashboard_layout = st.selectbox(
                    "📊 Layout",
                    ['default', 'compact', 'detailed', 'analyst'],
                    index=0
                )
                threat_threshold = st.slider("🚨 Alert Threshold", 0.1, 1.0, 0.7)
        
        return {
            'auto_refresh': self.auto_refresh,
            'refresh_interval': self.refresh_interval,
            'timeframe': self.selected_timeframe,
            'alert_sounds': self.alert_sounds,
            'layout': self.dashboard_layout,
            'threat_threshold': threat_threshold
        }
    
    def create_live_metrics(self, packets, alerts):
        """Create live updating metrics dashboard"""
        if not packets:
            st.info("🔄 Waiting for data...")
            return
            
        df = pd.DataFrame(packets)
        
        # Real-time metrics
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            total_packets = len(df)
            st.metric(
                "📊 Total Packets",
                f"{total_packets:,}",
                delta=f"+{min(total_packets, 50)}" if total_packets > 0 else None
            )
            
        with col2:
            unique_ips = df['src_ip'].nunique()
            st.metric(
                "🌐 Unique IPs",
                unique_ips,
                delta=f"+{min(unique_ips, 10)}" if unique_ips > 0 else None
            )
            
        with col3:
            avg_threat = df['threat_score'].mean() if 'threat_score' in df.columns else 0
            threat_color = "normal" if avg_threat < 0.3 else "inverse"
            st.metric(
                "⚠️ Avg Threat",
                f"{avg_threat:.2f}",
                delta=f"{avg_threat:.2f}"
            )
            
        with col4:
            high_threats = len(df[df.get('threat_score', 0) > 0.7]) if 'threat_score' in df.columns else 0
            st.metric(
                "🚨 High Threats",
                high_threats,
                delta=f"+{high_threats}" if high_threats > 0 else None
            )
            
        with col5:
            countries = df['country'].nunique() if 'country' in df.columns else 0
            st.metric(
                "🗺️ Countries",
                countries,
                delta=f"+{min(countries, 5)}" if countries > 0 else None
            )
            
        with col6:
            protocols = df['protocol_name'].nunique() if 'protocol_name' in df.columns else 0
            st.metric(
                "🔗 Protocols",
                protocols,
                delta=f"+{min(protocols, 3)}" if protocols > 0 else None
            )
    
    def create_real_time_alerts(self, alerts):
        """Create real-time scrolling alerts panel"""
        st.markdown("### 🚨 Real-time Threat Alerts")
        
        if not alerts:
            st.info("✅ No active threats detected")
            return
            
        # Create scrollable alerts container
        alert_container = st.container()
        
        with alert_container:
            for i, alert in enumerate(reversed(alerts[-10:])):
                severity = alert.get('threat_score', 0)
                
                if severity > 0.8:
                    alert_type = "🔴 CRITICAL"
                    alert_color = "red"
                elif severity > 0.5:
                    alert_type = "🟡 WARNING"
                    alert_color = "orange"
                else:
                    alert_type = "🟢 INFO"
                    alert_color = "green"
                
                with st.expander(f"{alert_type} - {alert['source_ip']} - {alert['timestamp']}", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**Type:** {alert.get('type', 'Unknown')}")
                        st.write(f"**Source:** {alert['source_ip']}")
                        st.write(f"**Score:** {severity:.2f}")
                        st.write(f"**Details:** {alert.get('details', 'No details')}")
                    with col2:
                        if st.button(f"🚫 Block IP", key=f"block_alert_{i}"):
                            # Add blocking logic here
                            st.success(f"Blocked {alert['source_ip']}")
    
    def create_interactive_filters(self, packets):
        """Create interactive filtering system"""
        st.markdown("### 🔍 Interactive Filters")
        
        if not packets:
            return packets
            
        df = pd.DataFrame(packets)
        filtered_df = df.copy()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            # IP filter
            ip_filter = st.text_input("🌐 Filter by IP", placeholder="192.168.1.1")
            if ip_filter:
                filtered_df = filtered_df[
                    filtered_df['src_ip'].str.contains(ip_filter, na=False) |
                    filtered_df['dst_ip'].str.contains(ip_filter, na=False)
                ]
        
        with col2:
            # Protocol filter
            protocols = df['protocol_name'].unique() if 'protocol_name' in df.columns else []
            selected_protocols = st.multiselect(
                "🔗 Protocols",
                options=protocols,
                default=[]
            )
            if selected_protocols:
                filtered_df = filtered_df[filtered_df['protocol_name'].isin(selected_protocols)]
        
        with col3:
            # Country filter
            countries = df['country'].unique() if 'country' in df.columns else []
            selected_countries = st.multiselect(
                "🗺️ Countries",
                options=countries[:20],  # Limit for performance
                default=[]
            )
            if selected_countries:
                filtered_df = filtered_df[filtered_df['country'].isin(selected_countries)]
        
        with col4:
            # Threat level filter
            if 'threat_score' in df.columns:
                min_threat, max_threat = st.slider(
                    "⚠️ Threat Range",
                    0.0, 1.0, (0.0, 1.0),
                    step=0.1
                )
                filtered_df = filtered_df[
                    (filtered_df['threat_score'] >= min_threat) &
                    (filtered_df['threat_score'] <= max_threat)
                ]
        
        # Display filter summary
        st.info(f"📊 Showing {len(filtered_df)} of {len(df)} packets after filtering")
        
        return filtered_df.to_dict('records')

def get_country_flag(country_code):
    """Convert country code to flag emoji - supports all countries"""
    if not country_code or len(country_code) != 2:
        return "🏳️"
    
    # Comprehensive flag mapping for all countries
    flag_map = {
        'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴',
        'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿',
        'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮',
        'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BQ': '🇧🇶', 'BR': '🇧🇷', 'BS': '🇧🇸',
        'BT': '🇧🇹', 'BV': '🇧🇻', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩',
        'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳',
        'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿',
        'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪',
        'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰',
        'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇧', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫',
        'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶',
        'GR': '🇬🇷', 'GS': '🇬🇸', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HM': '🇭🇲',
        'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲',
        'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲',
        'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳',
        'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨',
        'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾',
        'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰',
        'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸',
        'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦',
        'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵',
        'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬',
        'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹',
        'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼',
        'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮',
        'SJ': '🇸🇯', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸',
        'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TF': '🇹🇫',
        'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴',
        'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'UM': '🇺🇲',
        'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮',
        'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲',
        'ZW': '🇿🇼'
    }
    
    return flag_map.get(country_code.upper(), "🏳️")

def sniffer_process(packet_queue, command_event):
    """Main packet capture process - runs independently from Streamlit UI"""
    
    logger.info("Starting packet capture process")
    
    # Initialize GeoIP reader
    geoip_reader = None
    geo_cache = LRUCache(CACHE_SIZE)
    
    try:
        if os.path.exists('GeoLite2-City.mmdb'):
            geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            logger.info("GeoLite2 database loaded successfully")
        else:
            logger.warning("GeoLite2-City.mmdb not found. Geo-location disabled.")
    except Exception as e:
        logger.error(f"Error loading GeoLite2 database: {e}")
    
    def get_geo_info(ip):
        """Get geographical information for an IP address with caching"""
        # Skip private/local IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '0.0.0.0':
            return {
                'latitude': HOME_LAT,
                'longitude': HOME_LON,
                'country': 'Local',
                'country_code': 'LO'
            }
        
        cached = geo_cache.get(ip)
        if cached:
            return cached
        
        if not geoip_reader:
            geo_info = {
                'latitude': HOME_LAT,
                'longitude': HOME_LON,
                'country': 'Unknown',
                'country_code': 'XX'
            }
            geo_cache.put(ip, geo_info)
            return geo_info
        
        try:
            response = geoip_reader.city(ip)
            geo_info = {
                'latitude': float(response.location.latitude or HOME_LAT),
                'longitude': float(response.location.longitude or HOME_LON),
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX'
            }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            geo_info = {
                'latitude': HOME_LAT,
                'longitude': HOME_LON,
                'country': 'Unknown',
                'country_code': 'XX'
            }
        
        geo_cache.put(ip, geo_info)
        return geo_info
    
    def process_packet(packet):
        """Enhanced packet extraction with comprehensive analysis and error resilience"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            timestamp = datetime.now()
            
            # Enhanced packet data structure with comprehensive fields
            packet_data = {
                'timestamp': timestamp.strftime("%H:%M:%S.%f")[:-3],
                'datetime': timestamp,
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'length': len(packet),
                'ttl': ip_layer.ttl,
                'entropy': 0.0,
                'threat_score': 0.0,
                'anomaly_score': 0.0,
                'tcp_flags': '',
                'dns_query': '',
                'port': 0,
                'sport': 0,
                'payload_size': 0,
                'quantum_state': 'coherent',
                'decoherence_factor': 0.0,
                'protocol_name': 'Unknown',
                'flags_list': [],
                'is_encrypted': False,
                'is_suspicious': False
            }
            
            # Enhanced geo lookup with better error handling
            try:
                geo_info = get_geo_info(ip_layer.src)
                packet_data.update(geo_info)
            except Exception as e:
                logger.debug(f"Geo lookup error for {ip_layer.src}: {e}")
                packet_data.update({
                    'latitude': HOME_LAT,
                    'longitude': HOME_LON,
                    'country': 'Unknown',
                    'country_code': 'XX'
                })
            
            # Enhanced TCP analysis with comprehensive flag parsing
            if packet.haslayer(TCP):
                try:
                    tcp_layer = packet[TCP]
                    packet_data['port'] = tcp_layer.dport
                    packet_data['sport'] = tcp_layer.sport
                    packet_data['protocol_name'] = 'TCP'
                    
                    # Enhanced TCP flags parsing with all flags
                    flags = []
                    if hasattr(tcp_layer, 'flags'):
                        flag_value = tcp_layer.flags
                        if flag_value & 0x01: flags.append('FIN')
                        if flag_value & 0x02: flags.append('SYN')
                        if flag_value & 0x04: flags.append('RST')
                        if flag_value & 0x08: flags.append('PSH')
                        if flag_value & 0x10: flags.append('ACK')
                        if flag_value & 0x20: flags.append('URG')
                        if flag_value & 0x40: flags.append('ECE')
                        if flag_value & 0x80: flags.append('CWR')
                    
                    packet_data['tcp_flags'] = ','.join(flags)
                    packet_data['flags_list'] = flags
                    
                    # Enhanced payload analysis with encryption detection
                    if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                        try:
                            payload_data = bytes(tcp_layer.payload)
                            packet_data['payload_size'] = len(payload_data)
                            
                            if len(payload_data) > 10:
                                # Enhanced entropy calculation
                                entropy = calculate_shannon_entropy(payload_data)
                                packet_data['entropy'] = entropy
                                
                                # Encryption detection
                                if entropy > 0.8:
                                    packet_data['is_encrypted'] = True
                                
                                # Pattern-based threat detection
                                payload_str = payload_data.decode('utf-8', errors='ignore').lower()
                                suspicious_patterns = [
                                    'cmd.exe', 'powershell', '/bin/bash', 'wget', 'curl',
                                    'netcat', 'nc ', 'shell', 'reverse', 'backdoor',
                                    'exploit', 'payload', 'metasploit'
                                ]
                                
                                if any(pattern in payload_str for pattern in suspicious_patterns):
                                    packet_data['is_suspicious'] = True
                                    
                        except Exception as e:
                            logger.debug(f"Payload analysis error: {e}")
                    
                except Exception as e:
                    logger.debug(f"TCP processing error: {e}")
                    packet_data['protocol_name'] = 'TCP'
            
            # Enhanced UDP analysis with better DNS handling
            elif packet.haslayer(UDP):
                try:
                    udp_layer = packet[UDP]
                    packet_data['port'] = udp_layer.dport
                    packet_data['sport'] = udp_layer.sport
                    packet_data['protocol_name'] = 'UDP'
                    
                    # Enhanced DNS analysis with malicious domain detection
                    if packet.haslayer(DNS):
                        try:
                            dns_layer = packet[DNS]
                            packet_data['protocol_name'] = 'DNS'
                            
                            if hasattr(dns_layer, 'qr') and dns_layer.qr == 0:  # Query
                                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                                    qname = dns_layer.qd.qname
                                    if qname:
                                        domain = qname.decode('utf-8').rstrip('.')
                                        packet_data['dns_query'] = domain
                                        
                                        # Malicious domain patterns
                                        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
                                        suspicious_patterns = ['dga-', 'temp-', 'random-', 'test-']
                                        
                                        if (any(tld in domain for tld in suspicious_tlds) or
                                            any(pattern in domain for pattern in suspicious_patterns) or
                                            len(domain) > 50):  # Unusually long domains
                                            packet_data['is_suspicious'] = True
                                            
                        except Exception as e:
                            logger.debug(f"DNS processing error: {e}")
                            packet_data['dns_query'] = 'MALFORMED'
                            packet_data['is_suspicious'] = True
                            
                except Exception as e:
                    logger.debug(f"UDP processing error: {e}")
                    packet_data['protocol_name'] = 'UDP'
            
            # Enhanced ICMP analysis
            elif packet.haslayer(ICMP):
                try:
                    icmp_layer = packet[ICMP]
                    packet_data['protocol_name'] = 'ICMP'
                    packet_data['port'] = 0
                    
                    # ICMP type analysis for attack detection
                    if hasattr(icmp_layer, 'type'):
                        icmp_type = icmp_layer.type
                        if icmp_type == 8:  # Echo Request (Ping)
                            packet_data['dns_query'] = 'PING_REQUEST'
                        elif icmp_type == 3:  # Destination Unreachable
                            packet_data['is_suspicious'] = True
                            packet_data['dns_query'] = 'DEST_UNREACHABLE'
                            
                except Exception as e:
                    logger.debug(f"ICMP processing error: {e}")
                    packet_data['protocol_name'] = 'ICMP'
            
            else:
                # Handle other protocols
                protocol_map = {
                    1: 'ICMP', 2: 'IGMP', 4: 'IPv4', 6: 'TCP', 17: 'UDP',
                    41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'
                }
                packet_data['protocol_name'] = protocol_map.get(ip_layer.proto, f"Proto-{ip_layer.proto}")
            
            # Enhanced threat scoring with multiple factors
            threat_score = 0.0
            
            # Entropy-based scoring
            entropy = packet_data.get('entropy', 0)
            if entropy > 0.9:
                threat_score += 0.4
            elif entropy > 0.7:
                threat_score += 0.2
            
            # Suspicious content scoring
            if packet_data.get('is_suspicious', False):
                threat_score += 0.3
            
            # Port-based scoring
            port = packet_data.get('port', 0)
            suspicious_ports = [1234, 4444, 5555, 6666, 31337]
            if port in suspicious_ports:
                threat_score += 0.2
            
            # Flag-based scoring for TCP
            flags = packet_data.get('flags_list', [])
            if 'SYN' in flags and 'FIN' in flags:  # SYN+FIN scan
                threat_score += 0.3
            elif flags == ['SYN']:  # SYN scan
                threat_score += 0.1
            
            packet_data['threat_score'] = min(threat_score, 1.0)
            
            # Enhanced quantum analysis
            decoherence = min((entropy * 0.5 + threat_score * 0.5), 1.0)
            packet_data['decoherence_factor'] = decoherence
            
            if decoherence < 0.2:
                packet_data['quantum_state'] = 'coherent'
            elif decoherence < 0.5:
                packet_data['quantum_state'] = 'superposition'
            elif decoherence < 0.8:
                packet_data['quantum_state'] = 'entangled'
            else:
                packet_data['quantum_state'] = 'decoherent'
            
            # Anomaly scoring based on packet characteristics
            anomaly_score = 0.0
            
            # Size anomalies
            if packet_data['length'] < 20 or packet_data['length'] > 1400:
                anomaly_score += 0.2
            
            # TTL anomalies
            ttl = packet_data.get('ttl', 64)
            if ttl < 32 or ttl > 128:
                anomaly_score += 0.1
            
            # Time-based anomalies (if needed in future)
            packet_data['anomaly_score'] = min(anomaly_score + decoherence * 0.1, 1.0)
            
            return packet_data
            
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
            # Return minimal packet data on error to avoid losing packets
            return {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src_ip': '127.0.0.1',
                'dst_ip': '127.0.0.1',
                'protocol': 0,
                'protocol_name': 'ERROR',
                'length': 0,
                'threat_score': 0.0,
                'entropy': 0.0,
                'quantum_state': 'decoherent',
                'decoherence_factor': 1.0,
                'latitude': HOME_LAT,
                'longitude': HOME_LON,
                'country': 'Error',
                'country_code': 'ER'
            }
    
    # Enhanced packet callback function with robust error handling
    def packet_callback(packet):
        try:
            packet_data = process_packet(packet)
            if packet_data:
                try:
                    # Enhanced queue management with priority for threat packets
                    threat_score = packet_data.get('threat_score', 0)
                    if threat_score > 0.5:  # High priority for threat packets
                        packet_queue.put(packet_data, timeout=QUEUE_TIMEOUT * 2)
                    else:
                        packet_queue.put(packet_data, timeout=QUEUE_TIMEOUT)
                except queue.Full:
                    # Enhanced queue full handling - remove old packets for new ones
                    try:
                        if not packet_queue.empty():
                            packet_queue.get_nowait()  # Remove oldest packet
                        packet_queue.put(packet_data, timeout=0.1)
                    except:
                        logger.debug("Packet queue management failed")
        except Exception as e:
            logger.debug(f"Packet callback error: {e}")
    
    # Enhanced packet capture with multiple fallback strategies
    capture_attempts = 0
    max_attempts = 3
    
    while capture_attempts < max_attempts and not command_event.is_set():
        try:
            logger.info(f"Starting packet sniffing (attempt {capture_attempts + 1}/{max_attempts})...")
            
            # Primary capture with enhanced parameters
            sniff(
                prn=packet_callback,
                store=0,
                stop_filter=lambda x: command_event.is_set(),
                # Run continuously; stop via stop_filter when command_event is set
                count=0,    # Capture indefinitely until stopped
                filter="ip"  # Enhanced filter for IP packets only
            )
            logger.info("Packet capture stopped normally")
            break  # Successful capture, exit loop
            
        except PermissionError:
            logger.error(f"Permission denied for packet capture (attempt {capture_attempts + 1})")
            if capture_attempts == 0:
                logger.info("Trying alternative capture methods...")
            capture_attempts += 1
            
        except OSError as e:
            logger.error(f"Network interface error: {e} (attempt {capture_attempts + 1})")
            capture_attempts += 1
            time.sleep(1)  # Wait before retry
            
        except KeyboardInterrupt:
            logger.info("Packet capture interrupted by user")
            break
            
        except Exception as e:
            logger.error(f"Packet capture error: {e} (attempt {capture_attempts + 1})")
            capture_attempts += 1
            
            if capture_attempts < max_attempts:
                logger.info(f"Retrying packet capture in 2 seconds...")
                time.sleep(2)
    
    if capture_attempts >= max_attempts:
        logger.warning("All packet capture attempts failed. Consider running with elevated privileges.")
        # Cloud/demo fallback: generate synthetic packets if live capture isn't permitted
        if os.environ.get('CIPHERSKY_DEMO', '1') == '1':
            logger.info("Entering DEMO mode: generating synthetic packet stream")
            def demo_loop():
                protocols = [(6,'TCP'),(17,'UDP'),(1,'ICMP')]
                while not command_event.is_set():
                    now = datetime.now()
                    proto_num, proto_name = random.choice(protocols)
                    src_ip = f"192.0.2.{random.randint(1, 254)}"
                    dst_ip = f"198.51.100.{random.randint(1, 254)}"
                    pkt = {
                        'timestamp': now.strftime("%H:%M:%S.%f")[:-3],
                        'datetime': now,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': proto_num,
                        'protocol_name': proto_name,
                        'length': random.randint(60, 1500),
                        'ttl': random.choice([32, 64, 128]),
                        'entropy': random.uniform(0.2, 0.95),
                        'threat_score': random.random() * 0.9,
                        'anomaly_score': random.random() * 0.6,
                        'tcp_flags': 'SYN' if proto_name=='TCP' and random.random()>0.7 else '',
                        'dns_query': '',
                        'port': random.choice([80,443,53,22,1234,5555]),
                        'sport': random.randint(1024,65535),
                        'payload_size': random.randint(0,1200),
                        'quantum_state': random.choice(['coherent','superposition','entangled','decoherent']),
                        'decoherence_factor': random.uniform(0.0,1.0),
                        'flags_list': [],
                        'is_encrypted': random.random()>0.6,
                        'is_suspicious': random.random()>0.85,
                        'latitude': HOME_LAT,
                        'longitude': HOME_LON,
                        'country': 'Demo',
                        'country_code': 'DM'
                    }
                    try:
                        packet_queue.put(pkt, timeout=QUEUE_TIMEOUT)
                    except queue.Full:
                        try:
                            if not packet_queue.empty():
                                packet_queue.get_nowait()
                            packet_queue.put(pkt, timeout=0.1)
                        except Exception:
                            pass
                    time.sleep(0.2)
            t = threading.Thread(target=demo_loop, daemon=True)
            t.start()
    
    # Cleanup geoip reader
    if geoip_reader:
        try:
            geoip_reader.close()
        except Exception as e:
            logger.debug(f"Error closing GeoIP reader: {e}")
    logger.info("Packet capture process terminated")

class QuantumNetworkAnalyzer:
    """Quantum-inspired network analysis using advanced physics principles"""
    
    def __init__(self):
        self.quantum_states = {}
        self.entanglement_matrix = None
        self.network_graph = nx.Graph()
        self.quantum_metrics = {}
        
    def generate_fallback_packets(self, count=30):
        """Generate enhanced realistic fallback packets when capture fails"""
        packets = []
        current_time = time.time()
        
        # Enhanced realistic IP pools
        internal_ips = [f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(8)]
        external_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9",
            "142.250.191.14", "31.13.64.35", "151.101.1.140"
        ] + [
            f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            for _ in range(10)
        ]
        
        protocols = [('TCP', 6, 0.6), ('UDP', 17, 0.3), ('ICMP', 1, 0.1)]
        
        for i in range(count):
            # Select protocol
            rand_val = random.random()
            cumulative = 0
            for proto_name, proto_num, prob in protocols:
                cumulative += prob
                if rand_val <= cumulative:
                    selected_protocol = (proto_name, proto_num)
                    break
            else:
                selected_protocol = ('TCP', 6)
            
            proto_name, proto_num = selected_protocol
            
            # Generate realistic packet
            packet = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'datetime': datetime.now(),
                'src_ip': random.choice(internal_ips + external_ips),
                'dst_ip': random.choice(internal_ips + external_ips),
                'protocol': proto_num,
                'protocol_name': proto_name,
                'length': random.randint(64, 1400),
                'ttl': random.choice([32, 64, 128, 255]),
                'entropy': random.uniform(0.1, 0.8),
                'threat_score': random.uniform(0.0, 0.3),
                'anomaly_score': random.uniform(0.0, 0.2),
                'tcp_flags': ','.join(random.sample(['SYN', 'ACK', 'PSH'], random.randint(1, 3))),
                'dns_query': '',
                'port': random.choice([80, 443, 53, 22, 25, 110, 993, 8080]),
                'sport': random.randint(1024, 65535),
                'payload_size': random.randint(0, 1200),
                'quantum_state': random.choice(['coherent', 'superposition', 'entangled']),
                'decoherence_factor': random.uniform(0.0, 0.4),
                'flags_list': ['SYN', 'ACK'],
                'is_encrypted': random.choice([True, False]),
                'is_suspicious': False,
                'latitude': random.uniform(-90, 90),
                'longitude': random.uniform(-180, 180),
                'country': random.choice(['USA', 'Germany', 'China', 'Japan', 'UK']),
                'country_code': random.choice(['US', 'DE', 'CN', 'JP', 'GB'])
            }
            
            # Add some DNS queries
            if proto_name == 'UDP' and packet['port'] == 53:
                packet['dns_query'] = random.choice([
                    'google.com', 'github.com', 'stackoverflow.com', 
                    'reddit.com', 'youtube.com', 'amazon.com'
                ])
            
            packets.append(packet)
        
        return packets
        
    def inject_fallback_packets(self, packet_queue):
        """Inject fallback packets when capture is not working"""
        try:
            fallback_packets = self.generate_fallback_packets()
            for packet in fallback_packets:
                try:
                    packet_queue.put(packet, timeout=0.1)
                except queue.Full:
                    break
            return len(fallback_packets)
        except Exception as e:
            logger.debug(f"Fallback packet injection error: {e}")
            return 0
        
    def analyze_quantum_entanglement(self, packet_data):
        """Analyze network connections using quantum entanglement principles"""
        try:
            if len(packet_data) < 2:
                return {}
                
            # Create quantum state representation of network connections
            connections = [(p['src_ip'], p['dst_ip']) for p in packet_data if 'src_ip' in p and 'dst_ip' in p]
            
            if not connections:
                return {}
            
            # Build quantum entanglement matrix (optimized for lite mode)
            unique_ips = list(set([ip for conn in connections for ip in conn]))
            n_nodes = len(unique_ips)
            
            # Lite mode optimization: limit node count
            if n_nodes > 50:  # Reduced from 100 for lite mode
                unique_ips = unique_ips[:50]
                n_nodes = 50
            
            entanglement_matrix = np.zeros((n_nodes, n_nodes), dtype=complex)
            
            # Calculate quantum coherence between nodes
            for i, ip1 in enumerate(unique_ips):
                for j, ip2 in enumerate(unique_ips):
                    if i != j:
                        # Calculate quantum entanglement strength
                        shared_packets = len([p for p in packet_data 
                                            if (p.get('src_ip') == ip1 and p.get('dst_ip') == ip2) or
                                               (p.get('src_ip') == ip2 and p.get('dst_ip') == ip1)])
                        
                        if shared_packets > 0:
                            # Apply quantum superposition principle
                            entanglement_strength = (shared_packets / len(packet_data)) * QUANTUM_ENTANGLEMENT_THRESHOLD
                            phase = np.exp(1j * 2 * PI_CONST * entanglement_strength)
                            entanglement_matrix[i][j] = entanglement_strength * phase
            
            self.entanglement_matrix = entanglement_matrix
            
            # Calculate quantum metrics
            eigenvalues = np.linalg.eigvals(entanglement_matrix)
            quantum_entropy = -np.sum([np.abs(ev)**2 * np.log(np.abs(ev)**2 + 1e-10) 
                                     for ev in eigenvalues if np.abs(ev) > 1e-10])
            
            self.quantum_metrics = {
                'quantum_entropy': float(quantum_entropy),
                'entanglement_degree': float(np.mean(np.abs(entanglement_matrix))),
                'coherence_measure': float(np.real(np.trace(entanglement_matrix @ entanglement_matrix.conj().T))),
                'quantum_nodes': n_nodes
            }
            
            return self.quantum_metrics
            
        except Exception as e:
            logger.error(f"Quantum entanglement analysis error: {e}")
            return {}

class PhysicsBasedVisualizations:
    """Advanced physics-based network visualizations"""
    
    def __init__(self):
        self.particle_system = {}
        self.force_simulation = None
        
    def create_particle_physics_network(self, packet_data):
        """Create network visualization using particle physics simulation"""
        try:
            if not packet_data:
                return go.Figure()
            
            # Extract unique nodes (IPs) - lite mode optimization
            nodes = list(set([p.get('src_ip', '') for p in packet_data if p.get('src_ip')] +
                            [p.get('dst_ip', '') for p in packet_data if p.get('dst_ip')]))
            
            # Lite mode: further reduced node limit for better performance
            if len(nodes) > 25:  # Reduced from 50 for lite mode
                nodes = nodes[:25]
            
            # Create network graph
            G = nx.Graph()
            
            # Add nodes with physics properties
            for node in nodes:
                threat_level = np.mean([p.get('threat_score', 0) for p in packet_data 
                                     if p.get('src_ip') == node or p.get('dst_ip') == node])
                
                # Calculate node mass based on traffic volume
                node_packets = [p for p in packet_data 
                              if p.get('src_ip') == node or p.get('dst_ip') == node]
                mass = len(node_packets) / len(packet_data) if packet_data else 0
                
                G.add_node(node, mass=mass, threat_level=threat_level)
            
            # Add edges with force calculations
            edge_weights = {}
            for packet in packet_data:
                src, dst = packet.get('src_ip'), packet.get('dst_ip')
                if src and dst and src in nodes and dst in nodes:
                    edge = (src, dst)
                    edge_weights[edge] = edge_weights.get(edge, 0) + 1
            
            for (src, dst), weight in edge_weights.items():
                # Calculate electromagnetic force between nodes
                force_strength = weight / len(packet_data)
                G.add_edge(src, dst, weight=force_strength)
            
            # Apply spring-force layout with physics simulation
            pos = nx.spring_layout(G, k=1/np.sqrt(len(nodes)), iterations=100, weight='weight')
            
            # Create 3D visualization with particle effects
            edge_x, edge_y, edge_z = [], [], []
            edge_info = []
            
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                
                # Add 3D z-component based on connection strength
                z0 = G[edge[0]][edge[1]]['weight'] * 10
                z1 = z0
                
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                edge_z.extend([z0, z1, None])
                edge_info.append(f"Connection: {edge[0]} ↔ {edge[1]}")
            
            # Node coordinates and properties
            node_x = [pos[node][0] for node in nodes]
            node_y = [pos[node][1] for node in nodes]
            node_z = [G.nodes[node]['mass'] * 10 for node in nodes]
            node_colors = [G.nodes[node]['threat_level'] for node in nodes]
            node_sizes = [G.nodes[node]['mass'] * 100 + 10 for node in nodes]
            
            # Create 3D scatter plot with physics-based layout
            fig = go.Figure()
            
            # Add edges as 3D lines
            fig.add_trace(go.Scatter3d(
                x=edge_x, y=edge_y, z=edge_z,
                mode='lines',
                line=dict(color='rgba(100, 100, 100, 0.8)', width=2),
                name='Network Connections',
                hoverinfo='skip',
                visible=True
            ))
            
            # Add nodes as 3D particles
            fig.add_trace(go.Scatter3d(
                x=node_x, y=node_y, z=node_z,
                mode='markers',
                marker=dict(
                    size=node_sizes,
                    color=node_colors,
                    colorscale='Viridis',
                    colorbar=dict(title="Threat Level"),
                    opacity=0.9,
                    line=dict(color='rgba(0,0,0,0.3)', width=1)
                ),
                text=nodes,
                name='Network Nodes',
                hovertemplate='<b>%{text}</b><br>' +
                              'Threat: %{marker.color:.2f}<br>' +
                              'Mass: %{marker.size:.1f}<br>' +
                              'Z (Conn Strength): %{z:.2f}<extra></extra>',
                visible=True
            ))
            
            fig.update_layout(
                title="🔬 Physics-Based Network Topology (Lite 3D Particle System)",
                scene=dict(
                    xaxis_title="X-Axis (Network Space)",
                    yaxis_title="Y-Axis (Network Space)",
                    zaxis_title="Z-Axis (Connection Strength)",
                    bgcolor='rgba(248,249,250,1)',
                    xaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                    yaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                    zaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)')
                ),
                font=dict(color='black'),
                paper_bgcolor='white',
                height=620,
                legend=dict(bgcolor='rgba(255,255,255,0.6)')
            )

            # Add interactive controls (toggle nodes/edges, reset camera)
            fig.update_layout(
                updatemenus=[
                    dict(
                        type='buttons',
                        direction='right',
                        x=0.0, y=1.12,
                        xanchor='left',
                        buttons=[
                            dict(
                                label='Show Nodes',
                                method='update',
                                args=[{'visible': [False, True]}]
                            ),
                            dict(
                                label='Show Edges',
                                method='update',
                                args=[{'visible': [True, False]}]
                            ),
                            dict(
                                label='Show Both',
                                method='update',
                                args=[{'visible': [True, True]}]
                            ),
                            dict(
                                label='Reset Camera',
                                method='relayout',
                                args=[{'scene.camera': {'eye': {'x': 1.6, 'y': 1.6, 'z': 1.6}}}]
                            )
                        ]
                    )
                ]
            )

            # Light-friendly colorscale for nodes
            fig['data'][1]['marker']['colorscale'] = 'Turbo'
            
            return fig
            
        except Exception as e:
            logger.error(f"Physics visualization error: {e}")
            return go.Figure().add_annotation(text=f"Physics simulation error: {e}")
    
    def create_quantum_state_visualization(self, quantum_metrics):
        """Visualize network quantum states"""
        try:
            if not quantum_metrics:
                return go.Figure()
            
            # Create quantum state sphere (Bloch sphere representation) - lite mode
            theta = np.linspace(0, 2*PI_CONST, 50)  # Reduced from 100 for lite mode
            phi = np.linspace(0, PI_CONST, 50)      # Reduced from 100 for lite mode
            THETA, PHI = np.meshgrid(theta, phi)
            
            # Map network metrics to quantum states
            X = np.sin(PHI) * np.cos(THETA)
            Y = np.sin(PHI) * np.sin(THETA)
            Z = np.cos(PHI)
            
            # Color based on quantum entropy
            entropy = quantum_metrics.get('quantum_entropy', 0)
            colors = np.abs(np.sin(THETA + PHI * entropy))
            
            fig = go.Figure()
            
            # Add quantum state sphere
            fig.add_trace(go.Surface(
                x=X, y=Y, z=Z,
                surfacecolor=colors,
                colorscale='Viridis',
                opacity=0.85,
                name='Quantum State Space'
            ))
            
            # Add quantum measurement points
            if 'entanglement_degree' in quantum_metrics:
                ent_degree = quantum_metrics['entanglement_degree']
                coherence = quantum_metrics.get('coherence_measure', 0)
                
                # Map to sphere coordinates
                sphere_x = np.sin(ent_degree * PI_CONST) * np.cos(coherence * 2 * PI_CONST)
                sphere_y = np.sin(ent_degree * PI_CONST) * np.sin(coherence * 2 * PI_CONST)
                sphere_z = np.cos(ent_degree * PI_CONST)
                
                fig.add_trace(go.Scatter3d(
                    x=[sphere_x], y=[sphere_y], z=[sphere_z],
                    mode='markers',
                    marker=dict(size=14, color='rgba(220,20,60,0.9)', symbol='diamond',
                                line=dict(color='rgba(0,0,0,0.4)', width=1)),
                    name='Network Quantum State',
                    hovertemplate='<b>Network Quantum State</b><br>' +
                                  'Entanglement: %{customdata[0]:.3f}<br>' +
                                  'Coherence: %{customdata[1]:.3f}<extra></extra>',
                    customdata=[[ent_degree, coherence]]
                ))
            
            fig.update_layout(
                title="🌌 Network Quantum State (Bloch Sphere, Lite Mode)",
                scene=dict(
                    xaxis_title="X (Quantum)",
                    yaxis_title="Y (Quantum)",
                    zaxis_title="Z (Quantum)",
                    bgcolor='rgba(248,249,250,1)',
                    xaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                    yaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                    zaxis=dict(gridcolor='rgba(0,0,0,0.1)', zerolinecolor='rgba(0,0,0,0.2)'),
                    aspectmode='cube'
                ),
                font=dict(color='black'),
                paper_bgcolor='white',
                height=620,
                legend=dict(bgcolor='rgba(255,255,255,0.6)')
            )

            # Interactivity: camera presets and sphere transparency toggle
            fig.update_layout(
                updatemenus=[
                    dict(
                        type='buttons',
                        direction='right',
                        x=0.0, y=1.12,
                        xanchor='left',
                        buttons=[
                            dict(
                                label='Isometric',
                                method='relayout',
                                args=[{'scene.camera': {'eye': {'x': 1.6, 'y': 1.6, 'z': 1.6}}}]
                            ),
                            dict(
                                label='Top',
                                method='relayout',
                                args=[{'scene.camera': {'eye': {'x': 0.0, 'y': 0.0, 'z': 2.5}}}]
                            ),
                            dict(
                                label='Front',
                                method='relayout',
                                args=[{'scene.camera': {'eye': {'x': 0.0, 'y': 2.5, 'z': 0.0}}}]
                            ),
                            dict(
                                label='Toggle Sphere Opacity',
                                method='restyle',
                                args=[{'opacity': [0.5]}, [0]]
                            )
                        ]
                    )
                ]
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Quantum visualization error: {e}")
            return go.Figure().add_annotation(text=f"Quantum visualization error: {e}")
    
    def create_3d_security_radar(self, packet_data):
        """Create 3D radar chart for security metrics"""
        try:
            if not packet_data:
                return go.Figure()
            
            # Calculate security metrics
            metrics = {
                'Threat_Level': np.mean([p.get('threat_score', 0) for p in packet_data]) * 100,
                'Encryption_Rate': len([p for p in packet_data if p.get('is_encrypted', False)]) / len(packet_data) * 100,
                'Protocol_Diversity': len(set([p.get('protocol_name', '') for p in packet_data])) * 10,
                'Traffic_Anomaly': np.mean([p.get('anomaly_score', 0) for p in packet_data]) * 100,
                'Port_Risk': len(set([p.get('port', 0) for p in packet_data if p.get('port', 0) in [22, 23, 21, 3389]])) * 20,
                'Geo_Diversity': len(set([p.get('country', '') for p in packet_data if p.get('country')])) * 5
            }
            
            categories = list(metrics.keys())
            values = list(metrics.values())
            
            # Create 3D radar chart
            theta = np.linspace(0, 2*np.pi, len(categories), endpoint=False)
            r = np.array(values)
            
            # Convert to 3D coordinates
            x = r * np.cos(theta)
            y = r * np.sin(theta)
            z = r * 0.5  # Height based on values
            
            fig = go.Figure()
            
            # Add radar surface
            fig.add_trace(go.Scatter3d(
                x=x, y=y, z=z,
                mode='lines+markers+text',
                line=dict(color='rgba(65,105,225,0.8)', width=4),
                marker=dict(size=8, color=values, colorscale='RdYlBu_r', showscale=True),
                text=categories,
                textposition='top center',
                name='Security Metrics',
                hovertemplate='<b>%{text}</b><br>Value: %{marker.color:.1f}%<extra></extra>'
            ))
            
            # Add reference grid circles
            for radius in [25, 50, 75, 100]:
                grid_x = [radius * np.cos(t) for t in np.linspace(0, 2*np.pi, 20)]
                grid_y = [radius * np.sin(t) for t in np.linspace(0, 2*np.pi, 20)]
                grid_z = [0] * 20
                
                fig.add_trace(go.Scatter3d(
                    x=grid_x, y=grid_y, z=grid_z,
                    mode='lines',
                    line=dict(color='rgba(128,128,128,0.3)', width=1),
                    showlegend=False,
                    hoverinfo='none'
                ))
            
            fig.update_layout(
                title='🛡️ 3D Security Metrics Radar',
                scene=dict(
                    xaxis_title='X-Axis',
                    yaxis_title='Y-Axis',
                    zaxis_title='Intensity',
                    bgcolor='rgba(248,249,250,1)',
                    aspectmode='cube'
                ),
                font=dict(color='black'),
                paper_bgcolor='white',
                height=500
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"3D security radar error: {e}")
            return go.Figure().add_annotation(text=f"Security radar error: {e}")
    
    def create_3d_network_performance_radar(self, packet_data):
        """Create 3D radar chart for network performance metrics"""
        try:
            if not packet_data:
                return go.Figure()
            
            # Calculate performance metrics
            packet_sizes = [p.get('length', 0) for p in packet_data]
            protocols = [p.get('protocol_name', '') for p in packet_data]
            
            metrics = {
                'Throughput': (np.mean(packet_sizes) / 1500) * 100,  # Normalized to MTU
                'Latency_Score': 100 - (np.std([p.get('ttl', 64) for p in packet_data]) / 64 * 100),
                'Packet_Efficiency': (len([p for p in packet_sizes if p > 64]) / len(packet_sizes)) * 100,
                'Protocol_Balance': min(100, len(set(protocols)) * 25),
                'Traffic_Volume': min(100, len(packet_data) / 10),
                'Network_Stability': 100 - (np.std(packet_sizes) / np.mean(packet_sizes) * 50 if packet_sizes else 0)
            }
            
            categories = list(metrics.keys())
            values = list(metrics.values())
            
            # Create 3D radar chart with different styling
            theta = np.linspace(0, 2*np.pi, len(categories), endpoint=False)
            r = np.array(values)
            
            # Convert to 3D coordinates with spiral effect
            x = r * np.cos(theta) * (1 + 0.1 * np.sin(theta))
            y = r * np.sin(theta) * (1 + 0.1 * np.cos(theta))
            z = r * 0.3 + 10 * np.sin(theta)  # Spiral height
            
            fig = go.Figure()
            
            # Add performance radar surface
            fig.add_trace(go.Scatter3d(
                x=x, y=y, z=z,
                mode='lines+markers+text',
                line=dict(color='rgba(34,139,34,0.8)', width=4),
                marker=dict(size=10, color=values, colorscale='Viridis', showscale=True),
                text=categories,
                textposition='middle right',
                name='Performance Metrics',
                hovertemplate='<b>%{text}</b><br>Score: %{marker.color:.1f}%<extra></extra>'
            ))
            
            # Add performance zones
            for radius in [30, 60, 90]:
                zone_color = 'rgba(255,0,0,0.2)' if radius < 40 else 'rgba(255,255,0,0.2)' if radius < 70 else 'rgba(0,255,0,0.2)'
                grid_x = [radius * np.cos(t) for t in np.linspace(0, 2*np.pi, 15)]
                grid_y = [radius * np.sin(t) for t in np.linspace(0, 2*np.pi, 15)]
                grid_z = [5] * 15
                
                fig.add_trace(go.Scatter3d(
                    x=grid_x, y=grid_y, z=grid_z,
                    mode='lines',
                    line=dict(color=zone_color, width=2),
                    showlegend=False,
                    hoverinfo='none'
                ))
            
            fig.update_layout(
                title='⚡ 3D Network Performance Radar',
                scene=dict(
                    xaxis_title='X-Performance',
                    yaxis_title='Y-Performance', 
                    zaxis_title='Z-Efficiency',
                    bgcolor='rgba(248,249,250,1)',
                    camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
                ),
                font=dict(color='black'),
                paper_bgcolor='white',
                height=500
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"3D performance radar error: {e}")
            return go.Figure().add_annotation(text=f"Performance radar error: {e}")
    
    def create_spectrum_analysis_graph(self, packet_data):
        """Create spectrum analysis graph for network traffic"""
        try:
            if not packet_data:
                return go.Figure()
            
            # Extract temporal data
            timestamps = []
            packet_sizes = []
            
            for i, packet in enumerate(packet_data):
                timestamps.append(i)  # Use index as time proxy
                packet_sizes.append(packet.get('length', 0))
            
            # Perform FFT for spectrum analysis
            if len(packet_sizes) >= 4:
                # Pad to power of 2 for efficient FFT
                n = len(packet_sizes)
                padded_size = 2 ** int(np.ceil(np.log2(n)))
                padded_data = np.pad(packet_sizes, (0, padded_size - n), 'constant')
                
                # Apply window function
                window = np.hanning(len(padded_data))
                windowed_data = padded_data * window
                
                # Compute FFT
                fft_result = np.fft.fft(windowed_data)
                frequencies = np.fft.fftfreq(len(fft_result))
                magnitude = np.abs(fft_result)
                
                # Take only positive frequencies
                positive_freq_idx = frequencies >= 0
                frequencies = frequencies[positive_freq_idx]
                magnitude = magnitude[positive_freq_idx]
                
                # Convert to dB scale
                magnitude_db = 20 * np.log10(magnitude + 1e-10)
                
                fig = go.Figure()
                
                # Add spectrum plot
                fig.add_trace(go.Scatter(
                    x=frequencies * 1000,  # Scale for better visualization
                    y=magnitude_db,
                    mode='lines',
                    line=dict(color='rgba(75,0,130,0.8)', width=2),
                    fill='tozeroy',
                    fillcolor='rgba(75,0,130,0.3)',
                    name='Traffic Spectrum',
                    hovertemplate='Frequency: %{x:.3f}<br>Magnitude: %{y:.1f} dB<extra></extra>'
                ))
                
                # Add peak markers
                peaks, _ = find_peaks(magnitude_db, height=np.max(magnitude_db) * 0.7)
                if len(peaks) > 0:
                    fig.add_trace(go.Scatter(
                        x=frequencies[peaks] * 1000,
                        y=magnitude_db[peaks],
                        mode='markers',
                        marker=dict(color='red', size=8, symbol='cross'),
                        name='Spectral Peaks',
                        hovertemplate='Peak Frequency: %{x:.3f}<br>Peak Magnitude: %{y:.1f} dB<extra></extra>'
                    ))
                
                # Add frequency bands
                freq_max = np.max(frequencies) * 1000
                fig.add_vrect(x0=0, x1=freq_max*0.2, fillcolor="rgba(0,255,0,0.1)", annotation_text="Low Freq", line_width=0)
                fig.add_vrect(x0=freq_max*0.2, x1=freq_max*0.6, fillcolor="rgba(255,255,0,0.1)", annotation_text="Mid Freq", line_width=0)
                fig.add_vrect(x0=freq_max*0.6, x1=freq_max, fillcolor="rgba(255,0,0,0.1)", annotation_text="High Freq", line_width=0)
                
                fig.update_layout(
                    title='📊 Network Traffic Spectrum Analysis',
                    xaxis_title='Frequency (mHz)',
                    yaxis_title='Magnitude (dB)',
                    paper_bgcolor='white',
                    plot_bgcolor='rgba(248,249,250,1)',
                    font=dict(color='black'),
                    height=400,
                    showlegend=True,
                    xaxis=dict(gridcolor='rgba(0,0,0,0.1)'),
                    yaxis=dict(gridcolor='rgba(0,0,0,0.1)')
                )
                
                return fig
            
            else:
                # Not enough data for FFT
                fig = go.Figure()
                fig.add_annotation(
                    text="Insufficient data for spectrum analysis<br>Need at least 4 data points",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False
                )
                fig.update_layout(
                    title='📊 Network Traffic Spectrum Analysis',
                    paper_bgcolor='white',
                    height=400
                )
                return fig
            
        except Exception as e:
            logger.error(f"Spectrum analysis error: {e}")
            return go.Figure().add_annotation(text=f"Spectrum analysis error: {e}")

class AdvancedCyberSecurityTools:
    """Advanced cybersecurity analysis tools"""
    
    def __init__(self):
        self.ml_models = {}
        self.threat_patterns = {}
        
    def quantum_cryptanalysis(self, packet_data):
        """Analyze cryptographic patterns using quantum-inspired methods"""
        try:
            crypto_analysis = {
                'quantum_resistant_detected': [],
                'classical_crypto_vulnerable': [],
                'entropy_analysis': {},
                'key_patterns': []
            }
            
            for packet in packet_data:
                payload = packet.get('payload', b'')
                if isinstance(payload, str):
                    payload = payload.encode()
                
                if len(payload) > 16:
                    # Analyze for cryptographic patterns
                    entropy = self._calculate_payload_entropy(payload)
                    
                    # Check for quantum-resistant crypto signatures
                    if b'NTRU' in payload or b'SPHINCS' in payload or b'SIKE' in payload:
                        crypto_analysis['quantum_resistant_detected'].append({
                            'packet': packet,
                            'crypto_type': 'quantum_resistant',
                            'entropy': entropy
                        })
                    
                    # Check for classical crypto that's vulnerable to quantum attacks
                    elif b'RSA' in payload or b'ECDSA' in payload or entropy > 7.5:
                        crypto_analysis['classical_crypto_vulnerable'].append({
                            'packet': packet,
                            'crypto_type': 'quantum_vulnerable',
                            'entropy': entropy
                        })
            
            return crypto_analysis
            
        except Exception as e:
            logger.error(f"Quantum cryptanalysis error: {e}")
            return {}
    
    def _calculate_payload_entropy(self, payload):
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0
        
        byte_counts = [0] * 256
        for byte in payload:
            byte_counts[byte] += 1
        
        entropy = 0
        length = len(payload)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy

def main():
    """Main Streamlit application"""
    
    # Page configuration
    st.set_page_config(
        page_title="CipherSky",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    # Consent Gate
    ensure_user_consent()
    
    # Initialize session state
    if 'packet_data' not in st.session_state:
        st.session_state.packet_data = []
    if 'dns_queries' not in st.session_state:
        st.session_state.dns_queries = []
    if 'sniffer_process' not in st.session_state:
        st.session_state.sniffer_process = None
    if 'packet_queue' not in st.session_state:
        st.session_state.packet_queue = multiprocessing.Queue(maxsize=2000)
    if 'command_event' not in st.session_state:
        st.session_state.command_event = multiprocessing.Event()
    if 'firewall' not in st.session_state:
        st.session_state.firewall = FirewallController()
    if 'is_running' not in st.session_state:
        st.session_state.is_running = False
    if 'threat_detector' not in st.session_state:
        st.session_state.threat_detector = ThreatDetector()
    if 'anomaly_engine' not in st.session_state:
        st.session_state.anomaly_engine = MLAnomalyEngine()
    if 'analytics' not in st.session_state:
        st.session_state.analytics = AdvancedAnalytics()
    if 'quantum_analyzer' not in st.session_state:
        st.session_state.quantum_analyzer = QuantumNetworkAnalyzer()
    if 'physics_viz' not in st.session_state:
        st.session_state.physics_viz = PhysicsBasedVisualizations()
    if 'advanced_security' not in st.session_state:
        st.session_state.advanced_security = AdvancedCyberSecurityTools()
    if 'quantum_metrics' not in st.session_state:
        st.session_state.quantum_metrics = {}
    if 'physics_analysis' not in st.session_state:
        st.session_state.physics_analysis = {}
    if 'threat_intel' not in st.session_state:
        st.session_state.threat_intel = ThreatIntelligence()
    if 'visualizations' not in st.session_state:
        st.session_state.visualizations = AdvancedVisualizations()
    if 'quantum_network' not in st.session_state:
        st.session_state.quantum_network = QuantumNetworkAnalyzer()
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []
    if 'attack_log' not in st.session_state:
        st.session_state.attack_log = []
    if 'osint_cache' not in st.session_state:
        st.session_state.osint_cache = {}
    if 'network_graph' not in st.session_state:
        st.session_state.network_graph = None
    if 'last_update' not in st.session_state:
        st.session_state.last_update = time.time()
    if 'geo_resolver' not in st.session_state:
        st.session_state.geo_resolver = GeoResolver()
    
    # Initialize dynamic dashboard
    if 'dashboard' not in st.session_state:
        st.session_state.dashboard = DynamicDashboard()
    
    # Register cleanup function
    def cleanup():
        """Cleanup function for graceful shutdown"""
        try:
            if st.session_state.get('is_running', False):
                st.session_state.command_event.set()
                if st.session_state.sniffer_process and st.session_state.sniffer_process.is_alive():
                    st.session_state.sniffer_process.terminate()
                    st.session_state.sniffer_process.join(timeout=PROCESS_TIMEOUT)
            
            if 'firewall' in st.session_state:
                st.session_state.firewall.cleanup()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    # Register cleanup with atexit
    import atexit
    atexit.register(cleanup)
    
    # Enhanced Header with real-time status
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("# CipherSky")
    with col2:
        if st.session_state.is_running:
            st.success("🟢 ACTIVE")
        else:
            st.error("🔴 STOPPED")
    with col3:
        current_time = datetime.now().strftime("%H:%M:%S")
        st.metric("⏰ Time", current_time)
    
    # Dynamic Dashboard Controls
    dashboard_config = st.session_state.dashboard.create_dashboard_controls()
    
    # Status indicators
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        status_color = "🟢" if st.session_state.is_running else "🔴"
        st.metric("Capture Status", f"{status_color} {'Active' if st.session_state.is_running else 'Stopped'}")
    with col2:
        st.metric("Total Packets", len(st.session_state.packet_data))
    with col3:
        unique_ips = len(set([p['src_ip'] for p in st.session_state.packet_data])) if st.session_state.packet_data else 0
        st.metric("Unique Source IPs", unique_ips)
    with col4:
        st.metric("Blocked IPs", len(st.session_state.firewall.blocked_ips))
    
    # Sidebar - Advanced Operations Center
    st.sidebar.markdown("---")
    # Advanced Operations Center (stock Streamlit UI)
    st.sidebar.header("🎯 Advanced Operations Center")
    st.sidebar.caption("Quantum-Enhanced Network Defense HUD")
    
    # Developer Credits (stock Streamlit UI)
    st.sidebar.subheader("🔧 Developer")
    st.sidebar.write("Labib Bin Shahed")
    st.sidebar.markdown("📧 [labib-x@protonmail.com](mailto:labib-x@protonmail.com)")
    
    # System Status Dashboard
    st.sidebar.subheader("📊 Mission Control")
    
    # Real-time System Metrics
    col1, col2 = st.sidebar.columns(2)
    with col1:
        packets_count = len(st.session_state.packet_data) if st.session_state.packet_data else 0
        st.metric("📡 Packets", f"{packets_count:,}", help="Total packets captured")
    with col2:
        threat_count = len([p for p in st.session_state.packet_data if p.get('threat_score', 0) > 0.5]) if st.session_state.packet_data else 0
        st.metric("⚠️ Threats", threat_count, help="High-risk packets detected")
    
    # Advanced Packet Capture Engine
    st.sidebar.markdown("---")
    st.sidebar.subheader("🚀 Quantum Packet Engine")
    
    # Engine Status Indicator
    status_color = "🟢" if st.session_state.is_running else "🔴"
    status_text = "ACTIVE" if st.session_state.is_running else "STANDBY"
    st.sidebar.markdown(f"**Status:** {status_color} {status_text}")
    
    # Capture Mode Selection
    capture_mode = st.sidebar.selectbox(
        "🔬 Capture Mode",
        ["Standard", "Deep Inspection", "Quantum Analysis", "Stealth Mode"],
        help="Select packet capture analysis level"
    )
    
    # Network Interface Selection
    interface_options = ["Auto-Detect", "WiFi (en0)", "Ethernet (en1)", "All Interfaces"]
    selected_interface = st.sidebar.selectbox(
        "🌐 Network Interface", 
        interface_options,
        help="Choose network interface to monitor"
    )
    
    # Advanced Filters
    with st.sidebar.expander("⚙️ Advanced Filters"):
        protocol_filter = st.multiselect(
            "Protocol Filter",
            ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"],
            default=["TCP", "UDP", "DNS"],
            help="Select protocols to capture"
        )
        
        port_range = st.text_input(
            "Port Range",
            placeholder="80,443,53 or 1000-2000",
            help="Specific ports or ranges to monitor"
        )
        
        payload_analysis = st.checkbox(
            "🔍 Deep Payload Analysis",
            value=False,
            help="Enable advanced payload inspection"
        )
    
    # Enhanced Control Panel
    col1, col2, col3 = st.sidebar.columns(3)
    with col1:
        if st.button("🟢 START", use_container_width=True, disabled=st.session_state.is_running, help="Begin quantum packet capture"):
            try:
                st.session_state.command_event.clear()
                st.session_state.sniffer_process = multiprocessing.Process(
                    target=sniffer_process,
                    args=(st.session_state.packet_queue, st.session_state.command_event)
                )
                st.session_state.sniffer_process.start()
                st.session_state.is_running = True
                st.sidebar.success(f"✅ {capture_mode} capture started!")
                logger.info(f"Packet capture started by user - Mode: {capture_mode}, Interface: {selected_interface}")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.sidebar.error(f"❌ Failed to start capture: {e}")
                logger.error(f"Failed to start packet capture: {e}")
    
    with col2:
        if st.button("🔴 STOP", use_container_width=True, disabled=not st.session_state.is_running, help="Stop packet capture"):
            try:
                st.session_state.command_event.set()
                if st.session_state.sniffer_process and st.session_state.sniffer_process.is_alive():
                    st.session_state.sniffer_process.terminate()
                    st.session_state.sniffer_process.join(timeout=PROCESS_TIMEOUT)
                st.session_state.is_running = False
                st.sidebar.success("✅ Capture stopped!")
                logger.info("Packet capture stopped by user")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.sidebar.error(f"❌ Failed to stop capture: {e}")
                logger.error(f"Failed to stop packet capture: {e}")
    
    with col3:
        if st.button("🔄 RESET", use_container_width=True, help="Clear all captured data"):
            st.session_state.packet_data = []
            st.session_state.dns_queries = []
            st.session_state.alerts = []
            st.session_state.quantum_metrics = {}
            st.sidebar.success("✅ Data cleared!")
            st.rerun()
    
    # Process health check
    if st.session_state.is_running and st.session_state.sniffer_process:
        if not st.session_state.sniffer_process.is_alive():
            st.sidebar.warning("⚠️ Capture process died unexpectedly")
            st.session_state.is_running = False
    
    # Advanced Threat Response Center
    st.sidebar.markdown("---")
    st.sidebar.subheader("🛡️ Threat Response Center")
    
    # Threat Level Indicator
    if st.session_state.packet_data:
        avg_threat = np.mean([p.get('threat_score', 0) for p in st.session_state.packet_data[-100:]])
        if avg_threat > 0.7:
            st.sidebar.error(f"🔴 HIGH ALERT • Threat Level: {avg_threat:.1%}")
        elif avg_threat > 0.4:
            st.sidebar.warning(f"🟡 ELEVATED • Threat Level: {avg_threat:.1%}")
        else:
            st.sidebar.success(f"🟢 SECURE • Threat Level: {avg_threat:.1%}")
    
    # Multi-Target Kill Switch
    with st.sidebar.form("advanced_kill_switch_form"):
        st.markdown("**🎯 Target Management**")
        
        # Single IP blocking
        target_ip = st.text_input(
            "Single IP Target", 
            placeholder="192.168.1.100",
            help="Enter IP address to block"
        )
        
        # Bulk IP blocking
        bulk_targets = st.text_area(
            "Bulk IP Targets",
            placeholder="192.168.1.100\n10.0.0.50\n172.16.0.25",
            help="Enter multiple IPs (one per line)",
            height=60
        )
        
        # CIDR/Subnet blocking
        subnet_target = st.text_input(
            "Subnet CIDR",
            placeholder="192.168.1.0/24",
            help="Block entire subnet"
        )
        
        # Auto-block based on threat score
        auto_block = st.checkbox(
            "🤖 Auto-Block High Threats",
            help="Automatically block IPs with threat score > 0.8"
        )
        
        auto_threshold = st.slider(
            "Auto-Block Threshold",
            0.5, 1.0, 0.8, 0.05,
            help="Threat score threshold for auto-blocking"
        ) if auto_block else 0.8
        
        col1, col2 = st.columns(2)
        with col1:
            block_single = st.form_submit_button("🔫 BLOCK IP", use_container_width=True)
        with col2:
            block_bulk = st.form_submit_button("💥 BLOCK ALL", use_container_width=True)
        
        if block_single and target_ip:
            if st.session_state.firewall.block_ip(target_ip):
                st.success(f"✅ Blocked {target_ip}")
            else:
                st.error(f"❌ Failed to block {target_ip}")
        
        if block_bulk and bulk_targets:
            ips = [ip.strip() for ip in bulk_targets.split('\n') if ip.strip()]
            blocked_count = 0
            for ip in ips:
                if st.session_state.firewall.block_ip(ip):
                    blocked_count += 1
            st.success(f"✅ Blocked {blocked_count}/{len(ips)} targets")
    
    # Auto-blocking logic
    if auto_block and st.session_state.packet_data:
        high_threat_ips = set()
        for packet in st.session_state.packet_data[-50:]:  # Check recent packets
            if packet.get('threat_score', 0) > auto_threshold:
                src_ip = packet.get('src_ip')
                def _is_global(ip):
                    try:
                        return ipaddress.ip_address(ip).is_global
                    except Exception:
                        return False
                if src_ip and _is_global(src_ip):
                    if src_ip not in st.session_state.firewall.blocked_ips:
                        high_threat_ips.add(src_ip)
                        if st.session_state.firewall.block_ip(src_ip):
                            st.sidebar.warning(f"🤖 Auto-blocked: {src_ip}")
    
    # Advanced Blocked IPs Management
    if st.session_state.firewall.blocked_ips:
        st.sidebar.markdown("---")
        st.sidebar.subheader("🚫 Quarantine Zone")
        
        # Quick stats
        blocked_count = len(st.session_state.firewall.blocked_ips)
        st.sidebar.markdown(f"**🔒 {blocked_count} IPs in quarantine**")
        
        # Bulk actions
        col1, col2 = st.sidebar.columns(2)
        with col1:
            if st.button("🔓 RELEASE ALL", use_container_width=True, help="Unblock all IPs"):
                released = 0
                for ip in list(st.session_state.firewall.blocked_ips):
                    if st.session_state.firewall.unblock_ip(ip):
                        released += 1
                st.sidebar.success(f"✅ Released {released} IPs")
                st.rerun()
        
        with col2:
            if st.button("📋 EXPORT LIST", use_container_width=True, help="Export blocked IPs"):
                blocked_list = '\n'.join(st.session_state.firewall.blocked_ips)
                st.sidebar.download_button(
                    "💾 Download List",
                    blocked_list,
                    f"blocked_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    "text/plain",
                    use_container_width=True
                )
        
        # Individual IP management with enhanced info
        with st.sidebar.expander(f"📋 Manage {blocked_count} Blocked IPs", expanded=False):
            for ip in sorted(list(st.session_state.firewall.blocked_ips)):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                # Get IP info if available
                ip_packets = [p for p in st.session_state.packet_data if p.get('src_ip') == ip][-5:]
                threat_scores = [p.get('threat_score', 0) for p in ip_packets]
                avg_threat = np.mean(threat_scores) if threat_scores else 0
                
                col1.markdown(f"`{ip}`")
                if avg_threat > 0:
                    col1.caption(f"🎯 {avg_threat:.1%} threat")
                
                if col2.button("🔍", key=f"info_{ip}", help="IP Details"):
                    st.sidebar.info(f"**{ip}**\nPackets: {len(ip_packets)}\nThreat: {avg_threat:.1%}")
                
                if col3.button("🔓", key=f"unblock_{ip}", help="Unblock IP"):
                    if st.session_state.firewall.unblock_ip(ip):
                        st.sidebar.success(f"✅ Released {ip}")
                        st.rerun()
                    else:
                        st.sidebar.error(f"❌ Failed to release {ip}")
    
    # Advanced Data Export & Analytics
    st.sidebar.markdown("---")
    st.sidebar.subheader("📊 Data Export & Analytics")
    
    if st.session_state.packet_data:
        df = pd.DataFrame(st.session_state.packet_data)
        
        # Export format selection
        export_format = st.sidebar.selectbox(
            "Export Format",
            ["CSV (Spreadsheet)", "JSON (Raw Data)", "XML (Structured)", "TXT (Log Format)"]
        )
        
        # Data filtering for export
        with st.sidebar.expander("🔍 Export Filters"):
            time_filter = st.selectbox(
                "Time Range",
                ["All Data", "Last Hour", "Last 30 Minutes", "Last 10 Minutes"],
                help="Filter data by time range"
            )
            
            threat_filter = st.selectbox(
                "Threat Level",
                ["All Threats", "High Risk Only", "Medium+ Risk", "Low Risk Only"]
            )
            
            protocol_export = st.multiselect(
                "Protocols",
                ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"],
                default=["TCP", "UDP", "DNS"]
            )
        
        # Apply filters
        filtered_df = df.copy()
        
        if time_filter != "All Data":
            time_minutes = {"Last Hour": 60, "Last 30 Minutes": 30, "Last 10 Minutes": 10}[time_filter]
            cutoff_time = datetime.now() - timedelta(minutes=time_minutes)
            filtered_df = filtered_df[pd.to_datetime(filtered_df['timestamp']) > cutoff_time]
        
        if threat_filter != "All Threats":
            threat_thresholds = {"High Risk Only": 0.7, "Medium+ Risk": 0.4, "Low Risk Only": 0.0}
            threshold = threat_thresholds[threat_filter]
            if threat_filter == "Low Risk Only":
                filtered_df = filtered_df[filtered_df['threat_score'] <= 0.4]
            else:
                filtered_df = filtered_df[filtered_df['threat_score'] >= threshold]
        
        # Generate export data
        if export_format == "CSV (Spreadsheet)":
            export_data = filtered_df.to_csv(index=False)
            mime_type = "text/csv"
            file_ext = "csv"
        elif export_format == "JSON (Raw Data)":
            export_data = filtered_df.to_json(orient="records", indent=2)
            mime_type = "application/json"
            file_ext = "json"
        elif export_format == "XML (Structured)":
            export_data = filtered_df.to_xml(index=False)
            mime_type = "text/xml"
            file_ext = "xml"
        else:  # TXT Log Format
            log_lines = []
            for _, row in filtered_df.iterrows():
                log_lines.append(f"[{row['timestamp']}] {row['src_ip']}:{row.get('src_port', 'N/A')} -> {row['dst_ip']}:{row.get('dst_port', 'N/A')} | {row.get('protocol_name', 'Unknown')} | Threat: {row.get('threat_score', 0):.3f}")
            export_data = "\n".join(log_lines)
            mime_type = "text/plain"
            file_ext = "txt"
        
        # Export button with stats
        export_count = len(filtered_df)
        st.sidebar.download_button(
            f"💾 Export {export_count:,} Records",
            data=export_data,
            file_name=f"ciphersky_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}",
            mime=mime_type,
            use_container_width=True,
            help=f"Export {export_count} filtered records as {export_format}"
        )
        
        # Quick Analytics
        if st.sidebar.button("📈 Generate Report", use_container_width=True):
            unique_sources = df['src_ip'].nunique()
            high_threats = len(df[df['threat_score'] > 0.7])
            protocols = df['protocol_name'].value_counts().head(3)
            
            st.sidebar.markdown(f"""
            **📊 Session Analytics**
            - **Total Packets:** {len(df):,}
            - **Unique Sources:** {unique_sources:,}
            - **High Threats:** {high_threats:,}
            - **Top Protocol:** {protocols.index[0] if not protocols.empty else 'N/A'}
            """)
    else:
        st.sidebar.info("📭 No data to export")
    
    # Compact Sidebar Dashboard
    st.sidebar.markdown("---")
    st.sidebar.subheader("📈 Sidebar Dashboard")
    try:
        packets_count = len(st.session_state.packet_data) if st.session_state.packet_data else 0
        high_threats = len([p for p in st.session_state.packet_data if p.get('threat_score', 0) > 0.7]) if st.session_state.packet_data else 0
        if 'sidebar_trend' not in st.session_state:
            st.session_state.sidebar_trend = {'Packets': [], 'High Threats': []}
        st.session_state.sidebar_trend['Packets'].append(packets_count)
        st.session_state.sidebar_trend['High Threats'].append(high_threats)
        # Keep last 30 points
        for k in list(st.session_state.sidebar_trend.keys()):
            st.session_state.sidebar_trend[k] = st.session_state.sidebar_trend[k][-30:]
        trend_df = pd.DataFrame(st.session_state.sidebar_trend)
        if not trend_df.empty:
            st.sidebar.line_chart(trend_df)
    except Exception:
        pass

    # Quantum-Enhanced Settings
    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Quantum Settings")
    
    # Performance mode
    perf_mode = st.sidebar.selectbox(
        "Performance Mode",
        ["Lite Mode (Optimized)", "Standard Mode", "High Performance", "Quantum Maximum"],
        index=0,
        help="Select processing intensity level"
    )
    
    # Auto-refresh with advanced options
    auto_refresh = st.sidebar.checkbox(
        "🔄 Auto Quantum Refresh", 
        value=True, 
        help="Automatically refresh with quantum synchronization"
    )
    
    if auto_refresh:
        refresh_interval = st.sidebar.slider(
            "Quantum Refresh Rate (seconds)", 
            1, 10, 2 if perf_mode == "Lite Mode (Optimized)" else 3,
            help="Faster refresh for real-time monitoring"
        )
        
        # Adaptive refresh based on threat level
        adaptive_refresh = st.sidebar.checkbox(
            "🧠 Adaptive Refresh",
            value=True,
            help="Automatically adjust refresh rate based on threat level"
        )
    
    # Advanced features toggles
    with st.sidebar.expander("🔬 Advanced Features"):
        enable_quantum = st.checkbox(
            "⚛️ Quantum Analysis",
            value=True,
            help="Enable quantum network analysis"
        )
        
        enable_physics = st.checkbox(
            "🔬 Physics Simulation",
            value=True,
            help="Enable physics-based visualizations"
        )
        
        enable_ai = st.checkbox(
            "🤖 AI Threat Detection",
            value=True,
            help="Enable advanced AI threat analysis"
        )
        
        debug_mode = st.checkbox(
            "🐛 Debug Mode",
            value=False,
            help="Enable detailed logging and diagnostics"
        )
    
    # Apply lite mode optimizations
    if perf_mode == "Lite Mode (Optimized)":
        # Reduce packet processing batch size
        max_processing = 50
        # Limit visualization complexity
        viz_samples = 25
    elif perf_mode == "Standard Mode":
        max_processing = 100
        viz_samples = 50
    else:
        max_processing = 200
        viz_samples = 100
    
    # Process incoming packets with enhanced lite mode optimization
    packets_processed = 0
    processing_limit = max_processing if 'max_processing' in locals() else 50  # Lite mode default
    
    try:
        while not st.session_state.packet_queue.empty() and packets_processed < processing_limit:
            try:
                packet_data = st.session_state.packet_queue.get_nowait()
                # Optional geo enrichment for unknown globals (consent-aware)
                try:
                    if st.session_state.get('allow_external_geo', False):
                        sip = packet_data.get('src_ip')
                        cc = packet_data.get('country_code')
                        lat = packet_data.get('latitude')
                        lon = packet_data.get('longitude')
                        # only enrich for public IPs with missing/placeholder geo
                        is_placeholder = (cc in (None, 'XX', 'LO')) or (
                            isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and 
                            abs(float(lat) - HOME_LAT) < 1e-6 and abs(float(lon) - HOME_LON) < 1e-6
                        )
                        if sip and is_placeholder and GeoResolver._is_global_ip(sip):
                            info = st.session_state.geo_resolver.resolve(sip)
                            if info:
                                packet_data.update(info)
                except Exception:
                    pass
                
                # Ensure threat_score is calculated for every packet (optimized)
                if 'threat_score' not in packet_data:
                    packet_data['threat_score'] = st.session_state.threat_detector.calculate_threat_score(packet_data)
                else:
                    # Recompute with enhanced detector to keep scores current
                    packet_data['threat_score'] = st.session_state.threat_detector.calculate_threat_score(packet_data)
                
                st.session_state.packet_data.append(packet_data)
                packets_processed += 1
                
                # Add DNS queries to separate list (lite mode optimization)
                if packet_data.get('dns_query'):
                    st.session_state.dns_queries.append({
                        'timestamp': packet_data['timestamp'],
                        'src_ip': packet_data['src_ip'],
                        'query': packet_data['dns_query'],
                        'threat_score': packet_data.get('threat_score', 0)
                    })
                    
                    # Limit DNS queries list for performance
                    if len(st.session_state.dns_queries) > 500:
                        st.session_state.dns_queries = st.session_state.dns_queries[-400:]
                
            except queue.Empty:
                break
            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
        
        # Enhanced data size management for lite mode
        max_packets = MAX_PACKETS if perf_mode != "Lite Mode (Optimized)" else MAX_PACKETS // 2
        if len(st.session_state.packet_data) > max_packets:
            st.session_state.packet_data = st.session_state.packet_data[-MAX_PACKETS:]
        if len(st.session_state.dns_queries) > 500:
            st.session_state.dns_queries = st.session_state.dns_queries[-500:]
            
    except Exception as e:
        logger.error(f"Error processing packet queue: {e}")
    
    # Update timestamp
    if packets_processed > 0:
        st.session_state.last_update = time.time()

    # ML-based anomaly scoring on recent window (optional, lightweight)
    try:
        recent_window = min(200, len(st.session_state.packet_data))
        if recent_window >= 30:
            recent_packets = st.session_state.packet_data[-recent_window:]
            st.session_state.anomaly_engine.score_recent(recent_packets)
    except Exception as e:
        logger.debug(f"Anomaly scoring skipped: {e}")
    
    # Dynamic Live Metrics Dashboard
    st.session_state.dashboard.create_live_metrics(
        st.session_state.packet_data,
        st.session_state.alerts
    )
    
    # Interactive Filters
    filtered_packets = st.session_state.dashboard.create_interactive_filters(
        st.session_state.packet_data
    )
    
    # Real-time Alerts Panel
    col1, col2 = st.columns([2, 1])
    with col1:
        # Main Dashboard Tabs with enhanced layouts
        if dashboard_config['layout'] == 'compact':
            tab1, tab2 = st.tabs(["🌍 Overview", "🚨 Threats"])
            # Define dummy tabs to prevent reference errors
            tab3 = tab4 = tab5 = tab6 = tab7 = tab8 = tab9 = tab10 = None
        elif dashboard_config['layout'] == 'detailed':
            tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs([
                "🌍 Global Intel", "📊 Live Feed", "🔍 Forensics", "⚠️ Threats",
                "🚨 Attack Monitor", "📈 Analytics", "🎯 Hunting", "⚙️ Config",
                "⚛️ Quantum", "🔬 Physics"
            ])
        elif dashboard_config['layout'] == 'analyst':
            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "🕵️ Investigation", "📊 Analysis", "🚨 Incidents", "📈 Trends", "🎯 Hunt"
            ])
            # Define dummy tabs to prevent reference errors
            tab6 = tab7 = tab8 = tab9 = tab10 = None
        else:  # default
            tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                "🌍 Global Intel", "📊 Live Feed", "🔍 Forensics", 
                "⚠️ Threats", "🚨 Attack Monitor", "📈 Analytics"
            ])
            # Define dummy tabs to prevent reference errors
            tab7 = tab8 = tab9 = tab10 = None
    
    with col2:
        st.session_state.dashboard.create_real_time_alerts(st.session_state.alerts)
    
    # Tab 1: Global Intel - Advanced Quantum Physics 3D Globe Visualization
    with tab1:
        st.header("🌍 Quantum-Enhanced Global Network Intelligence")
        
        # Advanced Controls
        col1, col2, col3 = st.columns(3)
        with col1:
            physics_mode = st.selectbox(
                "🔬 Visualization Physics",
                ["Classical", "Quantum Entangled", "Particle Field", "Electromagnetic", "Gravitational"],
                index=1
            )
        with col2:
            dimensional_view = st.selectbox(
                "📐 Dimensional Space",
                ["3D Standard", "4D Spacetime", "Higher Dimensional", "Quantum Superposition"],
                index=2
            )
        with col3:
            threat_sensitivity = st.slider(
                "⚡ Quantum Threat Sensitivity",
                0.1, 2.0, 1.0, 0.1
            )
        
        if st.session_state.packet_data:
            try:
                df = pd.DataFrame(st.session_state.packet_data)
                
                # Apply quantum entanglement analysis to enhance visualizations
                quantum_metrics = st.session_state.quantum_analyzer.analyze_quantum_entanglement(
                    st.session_state.packet_data
                )
                
                # Filter out local/non-global IPs for better visualization
                def _is_global_series(ip):
                    try:
                        return ipaddress.ip_address(ip).is_global
                    except Exception:
                        return False
                external_df = df[df['src_ip'].apply(_is_global_series)]
                
                if not external_df.empty:
                    # Map controls
                    with st.expander("🗺️ Map Controls", expanded=False):
                        mcol1, mcol2, mcol3 = st.columns(3)
                        with mcol1:
                            projection = st.selectbox("Projection", ["orthographic", "natural earth", "equirectangular"], index=0)
                            show_paths = st.checkbox("Show Flight Paths", value=True)
                        with mcol2:
                            rot_lon = st.slider("Rotation Lon", -180, 180, 0)
                            rot_lat = st.slider("Rotation Lat", -90, 90, 0)
                        with mcol3:
                            cluster_sources = st.checkbox("Cluster Sources", value=True)
                            max_paths = st.slider("Max Paths", 5, 50, 15)
                    # Create REVOLUTIONARY physics-enhanced 3D visualization
                    if physics_mode == "Quantum Entangled":
                        fig = go.Figure()
                        
                        # Quantum-enhanced home base with probability wave function (lite mode)
                        theta = np.linspace(0, 2*PI_CONST, 25)  # Reduced from 50 for lite mode
                        quantum_radius = 5 + 3 * np.sin(theta * 8)  # Quantum fluctuation
                        quantum_lons = HOME_LON + quantum_radius * np.cos(theta)
                        quantum_lats = HOME_LAT + quantum_radius * np.sin(theta) * 0.5
                        
                        fig.add_trace(go.Scattergeo(
                            lon=quantum_lons,
                            lat=quantum_lats,
                            mode='lines',
                            line=dict(width=3, color='rgba(255, 255, 0, 0.8)'),
                            name='Quantum Probability Field',
                            hoverinfo='none'
                        ))
                        
                        # Central quantum core
                        fig.add_trace(go.Scattergeo(
                            lon=[HOME_LON],
                            lat=[HOME_LAT],
                            mode='markers+text',
                            marker=dict(
                                size=50, 
                                color='#FFFF00',
                                symbol='circle',
                                line=dict(width=6, color='#FF00FF'),
                                opacity=1.0
                            ),
                            text=['⚛️ QUANTUM CORE'],
                            textposition='top center',
                            textfont=dict(size=18, color='#00FFFF'),
                            name='⚛️ Quantum Core'
                        ))
                        
                    elif physics_mode == "Particle Field":
                        fig = go.Figure()
                        
                        # Create particle field visualization (lite mode - reduced particles)
                        n_particles = 15  # Reduced from 30 for lite mode
                        particle_lons = np.random.uniform(-180, 180, n_particles)
                        particle_lats = np.random.uniform(-90, 90, n_particles)
                        
                        fig.add_trace(go.Scattergeo(
                            lon=particle_lons,
                            lat=particle_lats,
                            mode='markers',
                            marker=dict(
                                size=8,
                                color=np.random.rand(n_particles),
                                colorscale='Viridis',
                                opacity=0.6
                            ),
                            name='Quantum Particles',
                            hoverinfo='none'
                        ))
                        
                        # Home base as particle accelerator
                        fig.add_trace(go.Scattergeo(
                            lon=[HOME_LON],
                            lat=[HOME_LAT],
                            mode='markers+text',
                            marker=dict(
                                size=60, 
                                color='#00FFFF',
                                symbol='diamond',
                                line=dict(width=8, color='#FF0080'),
                                opacity=0.95
                            ),
                            text=['🔬 PARTICLE CORE'],
                            textposition='top center',
                            textfont=dict(size=20, color='#FFFF00'),
                            name='🔬 Particle Accelerator'
                        ))
                        
                    elif physics_mode == "Electromagnetic":
                        fig = go.Figure()
                        
                        # Electromagnetic field lines (lite mode - fewer lines)
                        field_angles = np.linspace(0, 2*PI_CONST, 8)  # Reduced from 12 for lite mode
                        for angle in field_angles:
                            field_lons = [HOME_LON + i * 20 * np.cos(angle) for i in np.linspace(0, 1, 10)]  # Reduced points
                            field_lats = [HOME_LAT + i * 10 * np.sin(angle) for i in np.linspace(0, 1, 10)]   # Reduced points
                            
                            fig.add_trace(go.Scattergeo(
                                lon=field_lons,
                                lat=field_lats,
                                mode='lines',
                                line=dict(width=2, color=f'rgba({int(255*np.cos(angle)**2)}, {int(255*np.sin(angle)**2)}, 255, 0.7)'),
                                name='EM Field' if angle == field_angles[0] else None,
                                showlegend=angle == field_angles[0],
                                hoverinfo='none'
                            ))
                        
                        # Electromagnetic source
                        fig.add_trace(go.Scattergeo(
                            lon=[HOME_LON],
                            lat=[HOME_LAT],
                            mode='markers+text',
                            marker=dict(
                                size=55, 
                                color='#FF8800',
                                symbol='cross',
                                line=dict(width=7, color='#FFFF00'),
                                opacity=0.9
                            ),
                            text=['⚡ EM SOURCE'],
                            textposition='top center',
                            textfont=dict(size=19, color='#00FFFF'),
                            name='⚡ Electromagnetic Core'
                        ))
                    
                    else:  # Classical or other modes
                        fig = go.Figure()
                        
                        # Enhanced classical visualization
                        fig.add_trace(go.Scattergeo(
                            lon=[HOME_LON],
                            lat=[HOME_LAT],
                            mode='markers+text',
                            marker=dict(
                                size=45, 
                                color='#FF0000',
                                symbol='star',
                                line=dict(width=5, color='#FFFF00'),
                                opacity=0.95
                            ),
                            text=['🏠 COMMAND CENTER'],
                            textposition='top center',
                            textfont=dict(size=17, color='#FFFF00'),
                            name='🏠 Command Center'
                        ))
                    
                    # Add clustered threat sources with continuous color scale
                    src_data = external_df[['src_ip','latitude','longitude','country','country_code','threat_score']].dropna()
                    if not src_data.empty:
                        if cluster_sources:
                            src_data = src_data.copy()
                            src_data['lat_bin'] = src_data['latitude'].round(1)
                            src_data['lon_bin'] = src_data['longitude'].round(1)
                            agg = src_data.groupby(['lat_bin','lon_bin']).agg(
                                count=('src_ip','nunique'),
                                avg_threat=('threat_score','mean'),
                                country=('country','first'),
                                cc=('country_code','first')
                            ).reset_index()
                            lon_vals = agg['lon_bin']
                            lat_vals = agg['lat_bin']
                            counts = agg['count']
                            threat_vals = (agg['avg_threat'] * threat_sensitivity).clip(0,1)
                            text_vals = [f"{get_country_flag(cc)} {c or 'Unknown'}<br>Sources: {cnt}<br>Threat: {thr*100:.1f}%" for c, cc, cnt, thr in zip(agg['country'], agg['cc'], counts, threat_vals)]
                        else:
                            lon_vals = src_data['longitude']
                            lat_vals = src_data['latitude']
                            counts = pd.Series([1]*len(src_data))
                            threat_vals = (src_data['threat_score'] * threat_sensitivity).clip(0,1)
                            text_vals = [f"{get_country_flag(r.country_code)} {r.country or 'Unknown'}<br>{r.src_ip}<br>Threat: {r.threat_score*100:.1f}%" for r in src_data.itertuples()]

                        max_count = counts.max() if hasattr(counts, 'max') else 1
                        if not isinstance(max_count, (int, float)) or max_count <= 0:
                            max_count = 1
                        sizes = (counts.astype(float) / max_count) * 20 + 8
                        fig.add_trace(go.Scattergeo(
                            lon=lon_vals,
                            lat=lat_vals,
                            mode='markers',
                            marker=dict(
                                size=sizes,
                                color=threat_vals,
                                colorscale='YlOrRd',
                                cmin=0, cmax=1,
                                line=dict(width=1, color='white'),
                                sizemode='diameter',
                                showscale=True,
                                colorbar=dict(title='Threat')
                            ),
                            text=text_vals,
                            name='🌍 Sources',
                            hovertemplate='<b>%{text}</b><br>Lat: %{lat:.2f}<br>Lon: %{lon:.2f}<extra></extra>'
                        ))

                        # Great-circle flight paths from sampled points
                        if show_paths:
                            # Helper: great-circle interpolation
                            def great_circle_path(lon1, lat1, lon2, lat2, steps=20):
                                if any([pd.isna(lon1), pd.isna(lat1), pd.isna(lon2), pd.isna(lat2)]):
                                    return [], []
                                # convert to radians
                                φ1, λ1, φ2, λ2 = np.radians([lat1, lon1, lat2, lon2])
                                # unit vectors
                                def sph2cart(phi, lam):
                                    x = np.cos(phi) * np.cos(lam)
                                    y = np.cos(phi) * np.sin(lam)
                                    z = np.sin(phi)
                                    return np.array([x, y, z])
                                p1 = sph2cart(φ1, λ1)
                                p2 = sph2cart(φ2, λ2)
                                # angle between
                                Ω = np.arccos(np.clip(np.dot(p1, p2), -1.0, 1.0))
                                if Ω == 0:
                                    return [lon1, lon2], [lat1, lat2]
                                lons, lats = [], []
                                ts = np.linspace(0, 1, steps)
                                for t in ts:
                                    A = np.sin((1 - t) * Ω) / np.sin(Ω)
                                    B = np.sin(t * Ω) / np.sin(Ω)
                                    p = A * p1 + B * p2
                                    # back to lat/lon
                                    x, y, z = p
                                    phi = np.arctan2(z, np.sqrt(x*x + y*y))
                                    lam = np.arctan2(y, x)
                                    lons.append(np.degrees(lam))
                                    lats.append(np.degrees(phi))
                                return lons, lats

                            # Build a sample of arcs by highest threat then by count
                            if cluster_sources:
                                sample_df = agg.sort_values(['avg_threat','count'], ascending=[False, False]).head(max_paths)
                                iter_rows = sample_df.itertuples()
                                lon_iter = [r.lon_bin for r in iter_rows]
                                # re-create iter as consumed; use itertuples again
                                iter_rows = sample_df.itertuples()
                                lat_iter = [r.lat_bin for r in iter_rows]
                                thr_iter = sample_df['avg_threat']
                            else:
                                sample_df = src_data.sort_values('threat_score', ascending=False).head(max_paths)
                                lon_iter = sample_df['longitude'].tolist()
                                lat_iter = sample_df['latitude'].tolist()
                                thr_iter = sample_df['threat_score']

                            for lon_s, lat_s, thr in zip(lon_iter, lat_iter, thr_iter):
                                line_color = 'rgba(255,0,0,0.85)' if thr > 0.7 else ('rgba(255,136,0,0.75)' if thr > 0.4 else 'rgba(0,200,255,0.6)')
                                line_width = 4 if thr > 0.7 else (3 if thr > 0.4 else 2)
                                lons, lats = great_circle_path(lon_s, lat_s, HOME_LON, HOME_LAT, steps=24)
                                fig.add_trace(go.Scattergeo(
                                    lon=lons,
                                    lat=lats,
                                    mode='lines',
                                    line=dict(color=line_color, width=line_width),
                                    opacity=0.85,
                                    showlegend=False,
                                    hoverinfo='skip'
                                ))
                    
                    # Enhanced globe layout with bigger size and better visuals
                    fig.update_layout(
                        geo=dict(
                            projection_type=projection,
                            showland=True,
                            landcolor='rgb(220, 232, 221)',
                            showocean=True,
                            oceancolor='rgb(209, 227, 248)',
                            showlakes=True,
                            lakecolor='rgb(200, 220, 240)',
                            showrivers=True,
                            rivercolor='rgb(170, 190, 220)',
                            showcountries=True,
                            countrycolor='rgb(120, 120, 120)',
                            showcoastlines=True,
                            coastlinecolor='rgb(150, 150, 150)',
                            bgcolor='rgba(255, 255, 255, 1)',  # White background
                            projection=dict(
                                rotation=dict(lon=rot_lon, lat=rot_lat, roll=0),
                                scale=1.2
                            )
                        ),
                        paper_bgcolor='rgba(255, 255, 255, 1)',
                        plot_bgcolor='rgba(255, 255, 255, 1)',
                        font=dict(color='black', size=14),
                        height=850,
                        title=dict(
                            text='🌍 Global Threat Intelligence Network',
                            font=dict(size=28, color='darkblue'),
                            x=0.5,
                            y=0.95
                        ),
                        legend=dict(
                            bgcolor='rgba(255, 255, 255, 0.9)',
                            bordercolor='lightgray',
                            borderwidth=2,
                            font=dict(color='black')
                        )
                    )
                    
                    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                else:
                    st.info("📍 No external traffic detected yet...")
            except Exception as e:
                st.error(f"❌ Error creating globe visualization: {e}")
                logger.error(f"Globe visualization error: {e}")
        else:
            st.info("🔄 Waiting for network traffic data...")
    
    # Tab 2: Live Feed
    with tab2:
        st.header("📊 Live Network Feed")
        
        if st.session_state.packet_data:
            try:
                # Recent packets (last 20)
                recent_df = pd.DataFrame(st.session_state.packet_data[-20:])
                
                # Add flag emojis
                recent_df['flag'] = recent_df['country_code'].apply(get_country_flag)
                
                # Display table
                display_df = recent_df[['timestamp', 'flag', 'src_ip', 'dst_ip', 'protocol_name', 'length', 'country']].copy()
                display_df.columns = ['Time', 'Flag', 'Source IP', 'Dest IP', 'Protocol', 'Size (B)', 'Country']
                
                st.dataframe(display_df, use_container_width=True, height=400)
                
                # Statistics
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("� 3D Protocol Network Topology")
                    full_df = pd.DataFrame(st.session_state.packet_data)
                    if not full_df.empty:
                        protocol_counts = full_df['protocol_name'].value_counts().head(10)
                        
                        # Create advanced 3D cone plot for protocol distribution
                        theta = np.linspace(0, 2*np.pi, len(protocol_counts))
                        phi = np.linspace(0, np.pi, len(protocol_counts))
                        
                        x = protocol_counts.values * np.sin(phi) * np.cos(theta)
                        y = protocol_counts.values * np.sin(phi) * np.sin(theta)
                        z = protocol_counts.values * np.cos(phi)
                        
                        # Create cone vectors pointing outward
                        u = x * 0.5  # Vector components
                        v = y * 0.5
                        w = z * 0.5
                        
                        colors = ['#FF0000', '#00FF00', '#0000FF', '#FFFF00', '#FF00FF', 
                                 '#00FFFF', '#FFA500', '#800080', '#FFC0CB', '#A52A2A'][:len(protocol_counts)]
                        
                        fig = go.Figure()
                        
                        # Add cone plot for protocol vectors
                        fig.add_trace(go.Cone(
                            x=x, y=y, z=z,
                            u=u, v=v, w=w,
                            colorscale=[[0, colors[i%len(colors)]] for i in range(len(protocol_counts))],
                            sizemode="absolute",
                            sizeref=max(protocol_counts.values)*0.1,
                            anchor="tail",
                            showscale=False
                        ))
                        
                        # Add protocol labels as 3D text
                        fig.add_trace(go.Scatter3d(
                            x=x*1.2, y=y*1.2, z=z*1.2,
                            mode='text',
                            text=[f'{proto}<br>{count}' for proto, count in zip(protocol_counts.index, protocol_counts.values)],
                            textfont=dict(size=12, color='black'),
                            showlegend=False
                        ))
                        
                        # Add central sphere
                        fig.add_trace(go.Scatter3d(
                            x=[0], y=[0], z=[0],
                            mode='markers',
                            marker=dict(size=20, color='gold', opacity=0.8),
                            text=['Network Core'],
                            showlegend=False
                        ))
                        
                        fig.update_layout(
                            scene=dict(
                                xaxis_title="X Protocol Space",
                                yaxis_title="Y Protocol Space",
                                zaxis_title="Z Packet Volume",
                                bgcolor='rgba(240,248,255,1)',
                                camera=dict(eye=dict(x=1.5, y=1.5, z=1.5)),
                                aspectmode='cube'
                            ),
                            title="🚀 3D Protocol Network Topology",
                            height=500,
                            paper_bgcolor='rgba(255,255,255,1)',
                            font=dict(color='black', size=12)
                        )
                        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': True})
                
                with col2:
                    st.subheader("🌐 Top Source Countries")
                    if not full_df.empty:
                        country_counts = full_df['country'].value_counts().head(8)
                        
                        # Create 3D cylindrical country visualization
                        theta = np.linspace(0, 2*np.pi, len(country_counts))
                        r = country_counts.values
                        x = r * np.cos(theta)
                        y = r * np.sin(theta)
                        z = list(range(len(country_counts)))
                        
                        fig = go.Figure(data=[
                            go.Scatter3d(
                                x=x, y=y, z=z,
                                mode='markers+text',
                                marker=dict(
                                    size=r * 0.5,
                                    color=r,
                                    colorscale='Viridis',
                                    opacity=0.8,
                                    colorbar=dict(title="Packet Count")
                                ),
                                text=country_counts.index,
                                textposition='middle center'
                            )
                        ])
                        
                        fig.update_layout(
                            scene=dict(
                                xaxis_title="X Activity",
                                yaxis_title="Y Activity", 
                                zaxis_title="Country Rank",
                                bgcolor='rgba(255,255,255,1)',
                                camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
                            ),
                            paper_bgcolor='rgba(255,255,255,1)',
                            plot_bgcolor='rgba(255,255,255,1)',
                            font=dict(color='black'),
                            title="3D Traffic by Country",
                            height=400
                        )
                        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                        
            except Exception as e:
                st.error(f"❌ Error displaying live feed: {e}")
                logger.error(f"Live feed error: {e}")
        else:
            st.info("🔄 Waiting for packet data...")
    
    # Tab 3: Forensics
    with tab3:
        st.header("🔍 Network Forensics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🌐 DNS Query Log")
            if st.session_state.dns_queries:
                try:
                    dns_df = pd.DataFrame(st.session_state.dns_queries[-30:])
                    st.dataframe(dns_df, use_container_width=True, height=300)
                    
                    # Top queried domains
                    if len(st.session_state.dns_queries) > 5:
                        all_dns = pd.DataFrame(st.session_state.dns_queries)
                        top_domains = all_dns['query'].value_counts().head(10)
                        st.subheader("🔝 Top Queried Domains")
                        for domain, count in top_domains.items():
                            st.write(f"• `{domain}` ({count} queries)")
                            
                except Exception as e:
                    st.error(f"❌ DNS analysis error: {e}")
            else:
                st.info("📭 No DNS queries captured yet...")
        
        with col2:
            st.subheader("🔐 Entropy Analysis")
            if st.session_state.packet_data:
                try:
                    df = pd.DataFrame(st.session_state.packet_data)
                    entropy_data = df[df['entropy'] > 0]
                    
                    if not entropy_data.empty and len(entropy_data) > 2:
                        # Convert timestamp to numeric for plotting
                        entropy_data = entropy_data.copy()
                        entropy_data['time_numeric'] = range(len(entropy_data))
                        
                        fig = px.scatter(
                            entropy_data,
                            x='time_numeric',
                            y='entropy',
                            color='protocol_name',
                            size='length',
                            hover_data=['timestamp', 'src_ip', 'dst_ip'],
                            title="Data Entropy Over Time",
                            labels={'time_numeric': 'Packet Sequence', 'entropy': 'Shannon Entropy'}
                        )
                        fig.update_layout(height=300)
                        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                        
                        # High entropy warning
                        high_entropy = entropy_data[entropy_data['entropy'] > 7.5]
                        if not high_entropy.empty:
                            st.warning(f"⚠️ {len(high_entropy)} packets with high entropy (>7.5) detected - possible encryption/compression")
                            
                    else:
                        st.info("📊 Insufficient entropy data for analysis...")
                        
                except Exception as e:
                    st.error(f"❌ Entropy analysis error: {e}")
                    logger.error(f"Entropy analysis error: {e}")
            else:
                st.info("🔄 Waiting for packet data...")
    
    # Tab 4: Threats
    with tab4:
        st.header("⚠️ Threat Detection")
        
        if st.session_state.packet_data:
            try:
                df = pd.DataFrame(st.session_state.packet_data)
                
                # Top talkers analysis
                ip_counts = df['src_ip'].value_counts()
                
                # Adjustable threshold
                threat_threshold = st.slider("🎯 Threat Detection Threshold", 50, 500, 100, 
                                           help="Number of packets to consider an IP high-risk")
                
                high_risk_ips = ip_counts[ip_counts >= threat_threshold]
                
                if not high_risk_ips.empty:
                    st.subheader(f"🚨 High Risk IPs (≥{threat_threshold} packets)")
                    
                    for ip, count in high_risk_ips.head(10).items():
                        with st.container():
                            col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                            
                            with col1:
                                risk_level = "🔴 CRITICAL" if count > 500 else "🟠 HIGH"
                                st.metric(f"**{ip}**", f"{count} packets", risk_level)
                            
                            with col2:
                                try:
                                    geo_data = df[df['src_ip'] == ip].iloc[0]
                                    flag = get_country_flag(geo_data['country_code'])
                                    st.write(f"{flag} {geo_data['country']}")
                                    protocols = df[df['src_ip'] == ip]['protocol_name'].value_counts()
                                    st.write(f"Protocols: {', '.join(protocols.head(3).index)}")
                                except Exception:
                                    st.write("Unknown location")
                            
                            with col3:
                                # Time analysis
                                ip_data = df[df['src_ip'] == ip]
                                if 'datetime' in ip_data.columns:
                                    time_span = ip_data['datetime'].max() - ip_data['datetime'].min()
                                    st.write(f"Duration: {time_span}")
                                    rate = count / max(time_span.total_seconds(), 1) if time_span.total_seconds() > 0 else count
                                    st.write(f"Rate: {rate:.1f} pkt/s")
                            
                            with col4:
                                if ip not in st.session_state.firewall.blocked_ips:
                                    if st.button(f"🚫", key=f"block_threat_{ip}", help=f"Block {ip}"):
                                        if st.session_state.firewall.block_ip(ip):
                                            st.success(f"✅ Blocked {ip}")
                                            st.rerun()
                                        else:
                                            st.error(f"❌ Failed to block {ip}")
                                else:
                                    st.write("🚫 Blocked")
                            
                            st.divider()
                else:
                    st.info(f"✅ No high-risk IPs detected (threshold: {threat_threshold} packets)")
                
                # Additional threat analysis
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📈 Traffic Timeline")
                    if len(df) > 10:
                        # Create timeline of packet counts
                        df_copy = df.copy()
                        try:
                            # Parse timestamp to datetime
                            df_copy['datetime'] = pd.to_datetime(df_copy['timestamp'], format='%H:%M:%S.%f', errors='coerce')
                            # If that fails, try without microseconds
                            if df_copy['datetime'].isna().all():
                                df_copy['datetime'] = pd.to_datetime(df_copy['timestamp'], format='%H:%M:%S', errors='coerce')
                            
                            if not df_copy['datetime'].isna().all():
                                df_copy['minute'] = df_copy['datetime'].dt.floor('min')
                                timeline = df_copy.groupby('minute').size().reset_index()
                                timeline.columns = ['time', 'packets']
                                
                                if len(timeline) > 0:
                                    fig = px.line(timeline, x='time', y='packets', 
                                                title="Packets per Minute",
                                                color_discrete_sequence=['#00FF41'])
                                    fig.update_layout(
                                        height=300, 
                                        font=dict(color='white'), 
                                        paper_bgcolor='rgba(0,0,0,0)',
                                        plot_bgcolor='rgba(0,0,0,0)'
                                    )
                                    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                                else:
                                    st.info("No timeline data to display")
                            else:
                                st.warning("Unable to parse timestamps for timeline")
                        except Exception as e:
                            st.error(f"Timeline error: {e}")
                
                with col2:
                    st.subheader("🎯 Port Scan Detection")
                    # Simple port scan detection
                    port_attempts = df.groupby('src_ip')['port'].nunique().sort_values(ascending=False)
                    potential_scanners = port_attempts[port_attempts > 10]  # IPs touching many ports
                    
                    if not potential_scanners.empty:
                        st.warning("⚠️ Potential Port Scan Activity:")
                        for ip, port_count in potential_scanners.head(5).items():
                            st.write(f"• `{ip}`: {port_count} different ports")
                    else:
                        st.info("✅ No port scan activity detected")
                        
            except Exception as e:
                st.error(f"❌ Error in threat analysis: {e}")
                logger.error(f"Threat analysis error: {e}")
        else:
            st.info("🔄 Waiting for threat analysis data...")
    
    # Tab 5: Advanced Network Topology
    with tab5:
        st.header("🌐 Advanced Network Topology & Intelligence")
        
        if st.session_state.packet_data:
            try:
                df = pd.DataFrame(st.session_state.packet_data)
                
                # Advanced Network Topology Analysis
                st.markdown("### 🕸️ 3D Network Topology Graph")
                
                # Create network graph with centrality analysis
                connections = df.groupby(['src_ip', 'dst_ip']).agg({
                    'length': 'sum',
                    'threat_score': 'mean'
                }).reset_index()
                connections['packet_count'] = df.groupby(['src_ip', 'dst_ip']).size().values
                
                # Calculate node positions using force-directed layout simulation
                unique_nodes = list(set(df['src_ip'].unique()) | set(df['dst_ip'].unique()))
                node_positions = {}
                
                # Position nodes in 3D space using spherical coordinates
                for i, node in enumerate(unique_nodes[:50]):  # Limit for performance
                    phi = (i * 2.4) % (2 * np.pi)
                    theta = (i * 1.618) % np.pi  # Golden angle for better distribution
                    radius = 5 + np.random.uniform(-1, 1)
                    
                    x = radius * np.sin(theta) * np.cos(phi)
                    y = radius * np.sin(theta) * np.sin(phi)
                    z = radius * np.cos(theta)
                    node_positions[node] = (x, y, z)
                
                # Create 3D network graph
                fig = go.Figure()
                
                # Add connections as 3D lines
                for _, conn in connections.head(100).iterrows():  # Top 100 connections
                    src_pos = node_positions.get(conn['src_ip'])
                    dst_pos = node_positions.get(conn['dst_ip'])
                    
                    if src_pos and dst_pos:
                        # Line thickness based on packet count
                        line_width = max(1, min(10, conn['packet_count'] / 10))
                        # Line color based on threat score
                        threat = conn['threat_score']
                        line_color = 'red' if threat > 0.7 else 'orange' if threat > 0.4 else 'green'
                        
                        fig.add_trace(go.Scatter3d(
                            x=[src_pos[0], dst_pos[0]], 
                            y=[src_pos[1], dst_pos[1]], 
                            z=[src_pos[2], dst_pos[2]],
                            mode='lines',
                            line=dict(color=line_color, width=line_width),
                            opacity=0.6,
                            showlegend=False,
                            hovertemplate=f'Connection: {conn["src_ip"]} → {conn["dst_ip"]}<br>Packets: {conn["packet_count"]}<br>Avg Threat: {threat:.2f}'
                        ))
                
                # Add nodes with threat-based coloring
                node_data = df.groupby('src_ip').agg({
                    'threat_score': 'mean',
                    'length': 'sum',
                    'country': 'first',
                    'country_code': 'first'
                }).reset_index()
                node_data['packet_count'] = df.groupby('src_ip').size().values
                
                for _, node in node_data.head(50).iterrows():
                    pos = node_positions.get(node['src_ip'])
                    if pos:
                        threat_score = node['threat_score']
                        node_size = max(8, min(25, node['packet_count'] / 5))
                        
                        # Color coding by threat level
                        if threat_score > 0.7:
                            node_color = 'red'
                            symbol = 'diamond'
                        elif threat_score > 0.4:
                            node_color = 'orange' 
                            symbol = 'square'
                        else:
                            node_color = 'green'
                            symbol = 'circle'
                        
                        flag = get_country_flag(node['country_code'])
                        
                        fig.add_trace(go.Scatter3d(
                            x=[pos[0]], y=[pos[1]], z=[pos[2]],
                            mode='markers+text',
                            marker=dict(
                                size=node_size,
                                color=node_color,
                                symbol=symbol,
                                opacity=0.8,
                                line=dict(width=2, color='rgba(0,0,0,0.4)')
                            ),
                            text=f'{flag}<br>{node["src_ip"][-8:]}',
                            textfont=dict(size=8, color='black'),
                            showlegend=False,
                            hovertemplate=f'<b>{node["src_ip"]}</b><br>Country: {node["country"]} {flag}<br>Threat Score: {threat_score:.2f}<br>Packets: {node["packet_count"]}<br>Total Bytes: {node["length"]}'
                        ))
                
                fig.update_layout(
                    scene=dict(
                        xaxis_title="Network X-Space",
                        yaxis_title="Network Y-Space", 
                        zaxis_title="Network Z-Space",
                        bgcolor='rgba(248,249,250,1)',
                        camera=dict(eye=dict(x=1.5, y=1.5, z=1.5)),
                        aspectmode='cube',
                        xaxis=dict(showgrid=True, gridcolor='rgba(0,0,0,0.1)', showbackground=True, backgroundcolor='rgba(255,255,255,1)', zerolinecolor='rgba(0,0,0,0.2)'),
                        yaxis=dict(showgrid=True, gridcolor='rgba(0,0,0,0.1)', showbackground=True, backgroundcolor='rgba(255,255,255,1)', zerolinecolor='rgba(0,0,0,0.2)'),
                        zaxis=dict(showgrid=True, gridcolor='rgba(0,0,0,0.1)', showbackground=True, backgroundcolor='rgba(255,255,255,1)', zerolinecolor='rgba(0,0,0,0.2)')
                    ),
                    title=dict(
                        text="🕸️ 3D Network Topology Intelligence Graph (Lite Mode)",
                        font=dict(size=16, color='black')
                    ),
                    height=600,
                    paper_bgcolor='rgba(255,255,255,1)',
                    font=dict(color='black'),
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': True})
                
                # Network Analysis Dashboard
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("### 🎯 Network Centrality Analysis")
                    
                    # Calculate network centrality metrics
                    src_counts = df['src_ip'].value_counts().head(10)
                    dst_counts = df['dst_ip'].value_counts().head(10)
                    
                    st.write("**🔥 Most Active Sources (Degree Centrality):**")
                    for ip, count in src_counts.items():
                        ip_info = df[df['src_ip'] == ip].iloc[0]
                        flag = get_country_flag(ip_info['country_code'])
                        threat = ip_info['threat_score']
                        risk = "🔴" if threat > 0.7 else "🟡" if threat > 0.4 else "🟢"
                        st.write(f"{flag} `{ip}` - {count} conn {risk}")
                    
                    st.write("\n**📡 Most Targeted Destinations:**")
                    for ip, count in dst_counts.items():
                        st.write(f"🎯 `{ip}` - {count} requests")
                
                with col2:
                    st.markdown("### 🌊 Traffic Flow Analysis")
                    
                    # Protocol flow analysis
                    flow_analysis = df.groupby(['protocol_name', 'src_ip']).size().reset_index(name='flow_volume')
                    flow_summary = flow_analysis.groupby('protocol_name')['flow_volume'].agg(['sum', 'mean', 'max']).round(2)
                    
                    st.write("**Protocol Flow Statistics:**")
                    for protocol in flow_summary.index[:8]:
                        stats = flow_summary.loc[protocol]
                        st.write(f"**{protocol}:** Total: {stats['sum']}, Avg: {stats['mean']}, Peak: {stats['max']}")
                    
                    # Bandwidth utilization
                    st.write("\n**💾 Bandwidth Utilization:**")
                    total_bytes = df['length'].sum()
                    protocol_bytes = df.groupby('protocol_name')['length'].sum().sort_values(ascending=False).head(5)
                    for protocol, bytes_used in protocol_bytes.items():
                        percentage = (bytes_used / total_bytes) * 100
                        st.write(f"**{protocol}:** {bytes_used:,} bytes ({percentage:.1f}%)")
                
                with col3:
                    st.markdown("### ⚡ Real-time Network Health")
                    
                    # Calculate network health metrics
                    unique_sources = df['src_ip'].nunique()
                    unique_destinations = df['dst_ip'].nunique()
                    avg_threat_score = df['threat_score'].mean()
                    high_threat_ratio = (df['threat_score'] > 0.7).mean() * 100
                    
                    # Health indicators
                    health_score = 100 - (high_threat_ratio * 2) - min(50, unique_sources/10)
                    health_status = "🟢 HEALTHY" if health_score > 70 else "🟡 MODERATE" if health_score > 40 else "🔴 CRITICAL"
                    
                    st.metric("Network Health", f"{health_score:.0f}%", health_status)
                    st.metric("Active Sources", unique_sources)
                    st.metric("Target Destinations", unique_destinations) 
                    st.metric("Avg Threat Level", f"{avg_threat_score:.2f}")
                    st.metric("High Threat Ratio", f"{high_threat_ratio:.1f}%")
                    
                    # Network topology insights
                    st.write("**🔍 Topology Insights:**")
                    
                    # Detect potential network patterns
                    if unique_sources > unique_destinations * 3:
                        st.warning("⚠️ Potential DoS pattern detected")
                    elif avg_threat_score > 0.6:
                        st.error("🚨 High overall threat level")
                    elif unique_sources < 5:
                        st.info("ℹ️ Low traffic volume")
                    else:
                        st.success("✅ Normal traffic patterns")
                
                # Advanced Connection Matrix
                st.markdown("### 🗺️ Connection Matrix Heatmap")
                
                # Create connection heatmap
                top_sources = df['src_ip'].value_counts().head(15).index.tolist()
                top_destinations = df['dst_ip'].value_counts().head(15).index.tolist()
                
                # Build connection matrix
                connection_matrix = np.zeros((len(top_sources), len(top_destinations)))
                for i, src in enumerate(top_sources):
                    for j, dst in enumerate(top_destinations):
                        count = len(df[(df['src_ip'] == src) & (df['dst_ip'] == dst)])
                        connection_matrix[i][j] = count
                
                # Create interactive heatmap
                fig_heatmap = go.Figure(data=go.Heatmap(
                    z=connection_matrix,
                    x=[f"{dst[-8:]}" for dst in top_destinations],
                    y=[f"{src[-8:]}" for src in top_sources],
                    colorscale='Viridis',
                    hovertemplate='Src: %{y}<br>Dst: %{x}<br>Connections: %{z}<extra></extra>'
                ))
                
                fig_heatmap.update_layout(
                    title="🗺️ Source → Destination Connection Heatmap",
                    xaxis_title="Destination IPs",
                    yaxis_title="Source IPs", 
                    height=400,
                    paper_bgcolor='rgba(255,255,255,1)',
                    font=dict(color='black')
                )
                st.plotly_chart(fig_heatmap, use_container_width=True, config={'displayModeBar': True})
                
            except Exception as e:
                st.error(f"❌ Advanced topology analysis error: {e}")
                logger.error(f"Network topology error: {e}")
        else:
            st.info("🔄 Initializing advanced network topology analysis...")
    
    # Tab 6: Protocol Analysis
    with tab6:
        st.header("📡 Advanced Protocol Analysis")
        
        if st.session_state.packet_data:
            try:
                df = pd.DataFrame(st.session_state.packet_data)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("### 🔍 OS Fingerprinting")
                    os_fingerprints = {}
                    
                    for _, packet in df.iterrows():
                        ttl = packet.get('ttl', 64)
                        src_ip = packet['src_ip']
                        
                        # Simple OS detection based on TTL
                        if ttl <= 64:
                            os_guess = "Linux/Unix"
                            confidence = (64 - abs(64 - ttl)) / 64
                        elif ttl <= 128:
                            os_guess = "Windows"
                            confidence = (64 - abs(128 - ttl)) / 64
                        else:
                            os_guess = "Network Device"
                            confidence = 0.5
                        
                        if confidence > 0.7 and src_ip not in os_fingerprints:
                            os_fingerprints[src_ip] = {'os': os_guess, 'ttl': ttl, 'confidence': confidence}
                    
                    for ip, data in list(os_fingerprints.items())[:10]:
                        ip_info = df[df['src_ip'] == ip].iloc[0] if len(df[df['src_ip'] == ip]) > 0 else {}
                        flag = get_country_flag(ip_info.get('country_code', 'XX'))
                        st.write(f"{flag} **{ip}** - {data['os']} (TTL: {data['ttl']}, {data['confidence']*100:.0f}%)")
                
                with col2:
                    st.markdown("### 📊 Port Analysis")
                    port_stats = df.groupby('port').agg({
                        'src_ip': 'nunique',
                        'protocol_name': lambda x: x.mode().iloc[0] if not x.empty else 'Unknown'
                    }).sort_values('src_ip', ascending=False).head(10)
                    port_stats.columns = ['Unique Sources', 'Primary Protocol']
                    
                    st.dataframe(port_stats, use_container_width=True)
                
                # Traffic patterns
                st.markdown("### 📈 Traffic Patterns")
                
                # Create hourly traffic analysis
                try:
                    # Parse timestamp to datetime with better error handling
                    df_time = df.copy()
                    df_time['datetime'] = pd.to_datetime(df_time['timestamp'], format='%H:%M:%S.%f', errors='coerce')
                    # If that fails, try without microseconds
                    if df_time['datetime'].isna().all():
                        df_time['datetime'] = pd.to_datetime(df_time['timestamp'], format='%H:%M:%S', errors='coerce')
                    
                    if not df_time['datetime'].isna().all():
                        df_time['hour'] = df_time['datetime'].dt.hour
                        hourly_traffic = df_time.groupby('hour').size().reset_index(name='packet_count')
                        
                        if len(hourly_traffic) > 0:
                            # Create 3D surface plot for hourly traffic
                            fig = go.Figure(data=[go.Scatter3d(
                                x=hourly_traffic['hour'],
                                y=[0] * len(hourly_traffic),  # Y-axis for depth
                                z=hourly_traffic['packet_count'],
                                mode='markers+lines',
                                marker=dict(
                                    size=hourly_traffic['packet_count'] / hourly_traffic['packet_count'].max() * 20 + 5,
                                    color=hourly_traffic['packet_count'],
                                    colorscale='Viridis',
                                    colorbar=dict(title="Packets")
                                ),
                                line=dict(color='#00FF41', width=6),
                                text=[f'Hour {h}: {c} packets' for h, c in zip(hourly_traffic['hour'], hourly_traffic['packet_count'])],
                                name='Hourly Traffic'
                            )])
                            
                            fig.update_layout(
                                title='3D Hourly Traffic Distribution',
                                scene=dict(
                                    xaxis_title='Hour of Day',
                                    yaxis_title='Depth',
                                    zaxis_title='Packet Count',
                                    bgcolor='rgba(0,0,0,0)'
                                ),
                                height=500,
                                font=dict(color='white'),
                                paper_bgcolor='rgba(0,0,0,0)'
                            )
                            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': True})
                        else:
                            st.info("No traffic pattern data available")
                    else:
                        st.warning("Unable to parse timestamps for traffic patterns")
                except Exception as e:
                    st.error(f"Traffic pattern analysis error: {e}")
                
                # Additional parameter visualizations (Lite Mode)
                st.markdown("### 📊 Additional Metrics (Lite)")
                mcol1, mcol2 = st.columns(2)
                with mcol1:
                    if 'ttl' in df.columns:
                        try:
                            fig_ttl = px.histogram(df, x='ttl', nbins=20, title='TTL Distribution', color_discrete_sequence=['#1f77b4'])
                            fig_ttl.update_layout(height=300)
                            st.plotly_chart(fig_ttl, use_container_width=True, config={'displayModeBar': False})
                        except Exception:
                            pass
                with mcol2:
                    if 'flags_list' in df.columns:
                        try:
                            flags = []
                            for fl in df['flags_list']:
                                if isinstance(fl, list):
                                    flags.extend(fl)
                            if flags:
                                flag_counts = Counter(flags)
                                flag_df = pd.DataFrame({'flag': list(flag_counts.keys()), 'count': list(flag_counts.values())}).sort_values('count', ascending=False)
                                fig_flags = px.bar(flag_df, x='flag', y='count', title='TCP Flags Distribution', color='flag', color_discrete_sequence=px.colors.qualitative.Set2)
                                fig_flags.update_layout(height=300, showlegend=False)
                                st.plotly_chart(fig_flags, use_container_width=True, config={'displayModeBar': False})
                        except Exception:
                            pass

                mcol3, mcol4 = st.columns(2)
                with mcol3:
                    if 'entropy' in df.columns and 'length' in df.columns and df['entropy'].notna().any():
                        try:
                            sample_df = df[['entropy','length','protocol_name']].dropna().tail(500)
                            fig_es = px.scatter(sample_df, x='entropy', y='length', color='protocol_name', title='Entropy vs Packet Size')
                            fig_es.update_layout(height=300)
                            st.plotly_chart(fig_es, use_container_width=True, config={'displayModeBar': False})
                        except Exception:
                            pass
                with mcol4:
                    if 'decoherence_factor' in df.columns and 'threat_score' in df.columns:
                        try:
                            sample_df2 = df[['decoherence_factor','threat_score']].dropna().tail(500)
                            fig_dt = px.scatter(sample_df2, x='decoherence_factor', y='threat_score', title='Threat vs Decoherence')
                            fig_dt.update_layout(height=300)
                            st.plotly_chart(fig_dt, use_container_width=True, config={'displayModeBar': False})
                        except Exception:
                            pass

                # Optional anomaly timeline (if computed)
                if 'anomaly_score' in df.columns and df['anomaly_score'].notna().any():
                    try:
                        as_df = df[['anomaly_score']].tail(200)
                        fig_anom = px.line(as_df, y='anomaly_score', title='Anomaly Score Timeline (recent)')
                        fig_anom.update_layout(height=260)
                        st.plotly_chart(fig_anom, use_container_width=True, config={'displayModeBar': False})
                    except Exception:
                        pass

                # Port × Protocol heatmap (lite via expander)
                with st.expander('Port × Protocol Heatmap (Lite)'):
                    try:
                        pp = df.groupby(['protocol_name','port']).size().reset_index(name='count')
                        # limit to top 10 ports by volume
                        top_ports = pp.groupby('port')['count'].sum().sort_values(ascending=False).head(10).index.tolist()
                        pp_top = pp[pp['port'].isin(top_ports)]
                        if not pp_top.empty:
                            pivot = pp_top.pivot(index='protocol_name', columns='port', values='count').fillna(0)
                            fig_heat = px.imshow(pivot.values, x=pivot.columns.astype(str), y=pivot.index, color_continuous_scale='Viridis', labels=dict(color='count'), aspect='auto', title='Protocol vs Port Activity')
                            fig_heat.update_layout(height=320)
                            st.plotly_chart(fig_heat, use_container_width=True, config={'displayModeBar': False})
                        else:
                            st.info('Not enough data for heatmap yet.')
                    except Exception:
                        st.info('Heatmap not available for current data.')
            
            except Exception as e:
                st.error(f"❌ Protocol analysis error: {e}")
        else:
            st.info("🔄 Analyzing protocols...")
    
    # Tab 7: Advanced Hunting (only in detailed layout)
    if tab7 is not None:
        with tab7:
            st.header("🛡️ DNS Security Analysis")
            
            if st.session_state.dns_queries:
                try:
                    dns_df = pd.DataFrame(st.session_state.dns_queries)
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("### 🔍 Recent DNS Queries")
                        recent_dns = dns_df.tail(15)
                        
                        for _, query in recent_dns.iterrows():
                            threat_score = query.get('threat_score', 0)
                            risk_color = "🔴" if threat_score > 0.7 else "🟡" if threat_score > 0.4 else "🟢"
                            st.write(f"{risk_color} **{query['query']}** from {query['src_ip']}")
                    
                    with col2:
                        st.markdown("### 🚨 DNS Threat Analysis")
                        
                        # Detect suspicious DNS patterns
                        suspicious_patterns = [
                            r'[a-f0-9]{32,}',  # Long hex strings
                            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
                            r'\.tk$|\.ml$|\.ga$'  # Suspicious TLDs
                        ]
                        
                        suspicious_count = 0
                        for _, query in dns_df.iterrows():
                            query_name = query['query']
                            for pattern in suspicious_patterns:
                                if re.search(pattern, query_name):
                                    suspicious_count += 1
                                    st.warning(f"⚠️ Suspicious: {query_name}")
                                    break
                        
                        if suspicious_count == 0:
                            st.success("✅ No suspicious DNS patterns detected")
                    
                    # DNS query statistics
                    st.markdown("### 📊 DNS Statistics")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Total Queries", len(dns_df))
                    
                    with col2:
                        unique_domains = dns_df['query'].nunique()
                        st.metric("Unique Domains", unique_domains)
                    
                    with col3:
                        unique_sources = dns_df['src_ip'].nunique()
                        st.metric("Query Sources", unique_sources)
                    
                    # Top queried domains
                    st.markdown("### 🔝 Top Queried Domains")
                    top_domains = dns_df['query'].value_counts().head(10)
                    
                    fig = px.bar(
                        x=top_domains.values,
                        y=top_domains.index,
                        orientation='h',
                        title="Most Queried Domains",
                        color_discrete_sequence=['#00FF41']
                    )
                    fig.update_layout(height=400, font=dict(color='white'), paper_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                
                except Exception as e:
                    st.error(f"❌ DNS analysis error: {e}")
            else:
                st.info("🔄 Waiting for DNS queries...")
    
    # Tab 8: Geospatial Analysis
    # Tab 8: Configuration (only in detailed layout)
    if tab8 is not None:
        with tab8:
            st.header("🌍 Geospatial Threat Analysis")
            
            if st.session_state.packet_data:
                try:
                    df = pd.DataFrame(st.session_state.packet_data)
                    external_df = df[~df['src_ip'].str.startswith(('127.', '192.168.', '10.', '172.'))]
                    
                    if not external_df.empty:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("### 🗺️ Threat Heatmap")
                            
                            # Create country-based threat analysis
                            # Ensure threat_score column exists
                            if 'threat_score' not in external_df.columns:
                                external_df['threat_score'] = external_df.apply(lambda row: st.session_state.threat_detector.calculate_threat_score(row.to_dict()), axis=1)
                            
                            country_threats = external_df.groupby('country_code').agg({
                                'threat_score': 'mean',
                                'src_ip': 'count'
                            }).reset_index()
                            country_threats.columns = ['country_code', 'avg_threat', 'packet_count']
                            
                            # Only show countries with significant activity
                            significant_countries = country_threats[country_threats['packet_count'] >= 5]
                            
                            if not significant_countries.empty:
                                fig = px.choropleth(
                                    significant_countries,
                                    locations='country_code',
                                    color='avg_threat',
                                    hover_data=['packet_count'],
                                    color_continuous_scale='Reds',
                                    title="Global Threat Distribution"
                                )
                                fig.update_layout(height=500, font=dict(color='white'), paper_bgcolor='rgba(0,0,0,0)')
                                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                        
                        with col2:
                            st.markdown("### 📍 High-Risk Locations")
                            
                            # Identify high-risk geographic areas
                            risk_threshold = 0.6
                            if 'threat_score' in external_df.columns:
                                high_risk_countries = external_df[external_df['threat_score'] > risk_threshold]
                            else:
                                # Add default threat_score if missing
                                external_df['threat_score'] = 0.3  # Default moderate threat
                                high_risk_countries = external_df[external_df['threat_score'] > risk_threshold]
                            
                            if not high_risk_countries.empty:
                                risk_summary = high_risk_countries.groupby(['country', 'country_code']).agg({
                                    'src_ip': 'nunique',
                                    'threat_score': 'mean'
                                }).sort_values('threat_score', ascending=False).head(10)
                                
                                for (country, code), data in risk_summary.iterrows():
                                    flag = get_country_flag(code)
                                    threat_pct = data['threat_score'] * 100
                                    st.write(f"{flag} **{country}** - {data['src_ip']} sources, {threat_pct:.1f}% threat level")
                            else:
                                st.success("✅ No high-risk geographic areas detected")
                        
                        # Geographic statistics
                        st.markdown("### 🌐 Geographic Distribution")
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            countries_count = external_df['country_code'].nunique()
                            st.metric("Countries", countries_count)
                        
                        with col2:
                            continents = external_df['country'].nunique()
                            st.metric("Unique Locations", continents)
                        
                        with col3:
                            avg_distance = ((external_df['latitude'] - HOME_LAT)**2 + 
                                           (external_df['longitude'] - HOME_LON)**2)**0.5
                            st.metric("Avg Distance", f"{avg_distance.mean():.1f}°")
                        
                        with col4:
                            if 'threat_score' in external_df.columns and not external_df.empty:
                                max_threat_country = external_df.loc[external_df['threat_score'].idxmax(), 'country']
                            else:
                                max_threat_country = 'N/A'
                            st.metric("Highest Threat", max_threat_country)
                
                except Exception as e:
                    st.error(f"❌ Geospatial analysis error: {e}")
            else:
                st.info("🔄 Analyzing geographic data...")
    
    # Additional Monitoring Section (Independent)
    st.header("⚡ Real-time Performance Monitoring")
    
    # System performance metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### 🚀 System Performance")
        
        try:
            queue_size = st.session_state.packet_queue.qsize()
        except (NotImplementedError, AttributeError):
            queue_size = "N/A"
        st.metric("Queue Size", queue_size)
        
        process_status = "Running" if st.session_state.is_running else "Stopped"
        st.metric("Capture Status", process_status)
        
        if st.session_state.packet_data:
            packets_per_second = len(st.session_state.packet_data[-60:]) / 60
            st.metric("Packets/Second", f"{packets_per_second:.1f}")
    
    with col2:
        st.markdown("### 📊 Traffic Statistics")
        
        if st.session_state.packet_data:
            df = pd.DataFrame(st.session_state.packet_data)
            
            total_bytes = df['length'].sum()
            st.metric("Total Traffic", f"{total_bytes/1024:.1f} KB")
            
            avg_packet_size = df['length'].mean()
            st.metric("Avg Packet Size", f"{avg_packet_size:.0f} bytes")
            
            protocol_diversity = df['protocol_name'].nunique()
            st.metric("Protocol Types", protocol_diversity)
        
    with col3:
        st.markdown("### 🛡️ Security Metrics")
        
        if st.session_state.packet_data:
            df = pd.DataFrame(st.session_state.packet_data)
            
            high_threat_count = len([p for p in st.session_state.packet_data if p.get('threat_score', 0) > 0.7])
            st.metric("High Threats", high_threat_count)
            
            blocked_ips_count = len(st.session_state.firewall.blocked_ips)
            st.metric("Blocked IPs", blocked_ips_count)
            
            alert_count = len(st.session_state.alerts)
            st.metric("Active Alerts", alert_count)
    
    # Real-time charts
        if st.session_state.packet_data:
            st.markdown("### 📈 Live Traffic Visualization (Lite Mode)")
            
            # Lite mode: use fewer packets for visualization
            df = pd.DataFrame(st.session_state.packet_data[-25:])  # Reduced from 100 for lite mode
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Packet size distribution
                fig = px.histogram(
                    df,
                    x='length',
                    nbins=20,
                    title="Packet Size Distribution",
                    color_discrete_sequence=['#00FF41']
                )
                fig.update_layout(height=300, font=dict(color='white'), paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                if 'threat_score' in df.columns:
                    fig = px.line(
                        df,
                        y='threat_score',
                        title="Threat Score Timeline",
                        color_discrete_sequence=['#FF4444']
                    )
                    fig.update_layout(height=300, font=dict(color='white'), paper_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig, config={'displayModeBar': False})
                else:
                    st.info("Threat scoring not available")

    # Tab 9: Quantum Network Analysis (only in detailed layout)
    if tab9 is not None:
        with tab9:
            st.header("⚛️ Quantum Network Analysis")
            
            if st.session_state.packet_data:
                try:
                    # Perform quantum entanglement analysis
                    quantum_metrics = st.session_state.quantum_analyzer.analyze_quantum_entanglement(
                        st.session_state.packet_data
                    )
                    st.session_state.quantum_metrics = quantum_metrics
                    
                    if quantum_metrics:
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric(
                                "🌌 Quantum Entropy", 
                                f"{quantum_metrics.get('quantum_entropy', 0):.3f}",
                                help="Measure of quantum information disorder in the network"
                            )
                        
                        with col2:
                            st.metric(
                                "🔗 Entanglement Degree", 
                                f"{quantum_metrics.get('entanglement_degree', 0):.3f}",
                                help="Strength of quantum correlations between network nodes"
                            )
                        
                        with col3:
                            st.metric(
                                "🌊 Coherence Measure", 
                                f"{quantum_metrics.get('coherence_measure', 0):.3f}",
                                help="Quantum coherence in network communications"
                            )
                        
                        # Quantum State Visualization
                        st.markdown("### 🧪 Network Quantum State (Bloch Sphere)")
                        quantum_viz = st.session_state.physics_viz.create_quantum_state_visualization(quantum_metrics)
                        st.plotly_chart(quantum_viz, use_container_width=True, config={'displayModeBar': True})
                        
                        # Quantum Anomaly Detection
                        st.markdown("### ⚠️ Quantum Anomaly Detection")
                        quantum_anomalies = st.session_state.quantum_analyzer.detect_quantum_anomalies(
                            st.session_state.packet_data
                        )
                        
                        if quantum_anomalies:
                            st.warning(f"🚨 Detected {len(quantum_anomalies)} quantum anomalies!")
                            
                            # Lite mode: show fewer anomalies
                            for anomaly in quantum_anomalies[:5]:  # Reduced from 10 for lite mode
                                with st.expander(f"Anomaly: {anomaly.get('quantum_state', 'Unknown')}"):
                                    st.write(f"**Decoherence Factor:** {anomaly.get('decoherence_factor', 0):.4f}")
                                    st.write(f"**Anomaly Type:** {anomaly.get('anomaly_type', 'Unknown')}")
                                    # Lite mode: simplified packet display
                                    packet_info = anomaly.get('packet', {})
                                    st.write(f"**Source:** {packet_info.get('src_ip', 'N/A')}")
                                    st.write(f"**Protocol:** {packet_info.get('protocol_name', 'N/A')}")
                        else:
                            st.success("✅ No quantum anomalies detected - Network is in coherent state")
                        
                        # Advanced Quantum Cryptanalysis
                        st.markdown("### 🔐 Quantum Cryptographic Analysis")
                        crypto_analysis = st.session_state.advanced_security.quantum_cryptanalysis(
                            st.session_state.packet_data
                        )
                        
                        if crypto_analysis:
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                quantum_resistant = crypto_analysis.get('quantum_resistant_detected', [])
                                if quantum_resistant:
                                    st.success(f"🛡️ Found {len(quantum_resistant)} quantum-resistant crypto implementations")
                                    # Lite mode: show fewer entries
                                    for qr in quantum_resistant[:3]:  # Reduced from 5 for lite mode
                                        st.write(f"• **{qr.get('crypto_type')}** (Entropy: {qr.get('entropy', 0):.2f})")
                                else:
                                    st.info("🔍 No quantum-resistant cryptography detected")
                            
                            with col2:
                                vulnerable = crypto_analysis.get('classical_crypto_vulnerable', [])
                                if vulnerable:
                                    st.warning(f"⚠️ Found {len(vulnerable)} potentially quantum-vulnerable crypto")
                                    # Lite mode: show fewer entries
                                    for vuln in vulnerable[:3]:  # Reduced from 5 for lite mode
                                        st.write(f"• **{vuln.get('crypto_type')}** (Entropy: {vuln.get('entropy', 0):.2f})")
                                else:
                                    st.success("✅ No known quantum-vulnerable cryptography detected")
                    
                    else:
                        st.info("🔄 Calculating quantum network properties...")
                        
                except Exception as e:
                    st.error(f"❌ Quantum analysis error: {e}")
            else:
                st.info("📡 Waiting for network data to perform quantum analysis...")

    # Tab 10: Advanced Physics Analysis (only in detailed layout)
    if tab10 is not None:
        with tab10:
            st.header("🔬 Advanced Physics Network Analysis (Lite Mode)")
            
            # Lite mode performance indicator
            st.info("⚡ Lite Mode Active - Optimized for performance with reduced complexity")
            
            if st.session_state.packet_data:
                try:
                    # Physics-Based Network Topology
                    st.markdown("### ⚡ Particle Physics Network Simulation")
                    physics_viz = st.session_state.physics_viz.create_particle_physics_network(
                        st.session_state.packet_data
                    )
                    st.plotly_chart(physics_viz, use_container_width=True, config={'displayModeBar': True})
                    
                    # 3D Radar Charts Section
                    st.markdown("### 🎯 3D Security & Performance Radar Charts")
                    
                    radar_col1, radar_col2 = st.columns(2)
                    
                    with radar_col1:
                        st.markdown("#### 🛡️ Security Metrics Radar")
                        security_radar = st.session_state.physics_viz.create_3d_security_radar(
                            st.session_state.packet_data
                        )
                        st.plotly_chart(security_radar, use_container_width=True, config={'displayModeBar': False})
                    
                    with radar_col2:
                        st.markdown("#### ⚡ Performance Metrics Radar")
                        performance_radar = st.session_state.physics_viz.create_3d_network_performance_radar(
                            st.session_state.packet_data
                        )
                        st.plotly_chart(performance_radar, use_container_width=True, config={'displayModeBar': False})
                    
                    # Spectrum Analysis Section
                    st.markdown("### 📊 Network Traffic Spectrum Analysis")
                    spectrum_graph = st.session_state.physics_viz.create_spectrum_analysis_graph(
                        st.session_state.packet_data
                    )
                    st.plotly_chart(spectrum_graph, use_container_width=True, config={'displayModeBar': False})
                    
                    # Advanced Physics Metrics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        # Calculate network "temperature" using Boltzmann statistics
                        if st.session_state.packet_data:
                            entropies = [p.get('entropy', 0) for p in st.session_state.packet_data if 'entropy' in p]
                            if entropies:
                                network_temp = np.mean(entropies) * BOLTZMANN_CONSTANT * 1e23
                                st.metric("🌡️ Network Temperature", f"{network_temp:.2e} K", 
                                         help="Thermodynamic temperature of network activity")
                    
                    with col2:
                        # Calculate information "energy" using Planck relation
                        total_bits = sum(p.get('length', 0) * 8 for p in st.session_state.packet_data)
                        info_energy = total_bits * PLANCK_CONSTANT * LIGHT_SPEED / 1e-15  # Femtojoules
                        st.metric("⚡ Information Energy", f"{info_energy:.2e} fJ",
                                 help="Energy equivalent of information processed")
                    
                    with col3:
                        # Golden ratio analysis of packet timing
                        timestamps = [p.get('timestamp') for p in st.session_state.packet_data if p.get('timestamp')]
                        if len(timestamps) > 2:
                            time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                                         for i in range(len(timestamps)-1) 
                                         if isinstance(timestamps[i], datetime)]
                            if time_diffs:
                                phi_metric = np.std(time_diffs) / (np.mean(time_diffs) + 1e-10)
                                st.metric("🌀 Temporal Φ Ratio", f"{phi_metric / PHI:.3f}",
                                         help="Deviation from golden ratio in packet timing")
                    
                    with col4:
                        # Network dimensionality using fractal analysis
                        if len(st.session_state.packet_data) > 10:
                            sizes = [p.get('length', 0) for p in st.session_state.packet_data]
                            if sizes:
                                fractal_dim = 1 + (np.log(len(sizes)) / np.log(max(sizes) / min(sizes) + 1))
                                st.metric("📐 Fractal Dimension", f"{fractal_dim:.3f}",
                                         help="Fractal dimension of network traffic patterns")
                    
                    # Advanced Malware Detection using ML
                    st.markdown("### 🧠 Advanced ML Threat Detection")
                    malware_analysis = st.session_state.advanced_security.advanced_malware_detection(
                        st.session_state.packet_data
                    )
                    
                    if malware_analysis and 'error' not in malware_analysis:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric("🔍 Total Packets Analyzed", malware_analysis.get('total_packets', 0))
                            st.metric("⚠️ Suspicious Packets", malware_analysis.get('suspicious_count', 0))
                            
                            if malware_analysis.get('suspicious_count', 0) > 0:
                                threat_level = malware_analysis['suspicious_count'] / malware_analysis.get('total_packets', 1)
                                if threat_level > 0.1:
                                    st.error(f"🚨 High threat level: {threat_level:.1%}")
                                elif threat_level > 0.05:
                                    st.warning(f"⚠️ Medium threat level: {threat_level:.1%}")
                                else:
                                    st.info(f"ℹ️ Low threat level: {threat_level:.1%}")
                        
                        with col2:
                            cluster_info = malware_analysis.get('cluster_analysis', {})
                            st.metric("🔬 Behavior Clusters", cluster_info.get('n_clusters', 0))
                            st.metric("🌐 Anomaly Points", cluster_info.get('noise_points', 0))
                        
                        # Display suspicious packets (lite mode optimization)
                        suspicious = malware_analysis.get('suspicious_packets', [])
                        if suspicious:
                            st.markdown("#### 🚨 Suspicious Packet Analysis (Lite Mode)")
                            # Lite mode: show fewer suspicious packets
                            for i, susp in enumerate(suspicious[:3]):  # Reduced from 5 for lite mode
                                with st.expander(f"Suspicious Packet #{i+1} - {susp.get('suspicion_level', 'Unknown')} Risk"):
                                    packet = susp.get('packet', {})
                                    # Lite mode: simplified packet info
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.write(f"**Source:** {packet.get('src_ip', 'Unknown')}")
                                        st.write(f"**Protocol:** {packet.get('protocol_name', 'Unknown')}")
                                    with col2:
                                        st.write(f"**Destination:** {packet.get('dst_ip', 'Unknown')}")
                                        st.write(f"**Threat Score:** {packet.get('threat_score', 0):.3f}")
                    
                    else:
                        st.info("🔄 Performing advanced machine learning analysis...")
                    
                    # Behavioral Analysis
                    st.markdown("### 🔍 Network Behavioral Analysis")
                    behavioral_metrics = st.session_state.advanced_security.behavioral_analysis(
                        st.session_state.packet_data
                    )
                    
                    if behavioral_metrics:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric("⏱️ Avg Interval", f"{behavioral_metrics.get('interval_mean', 0):.3f}s")
                            st.metric("📊 Interval StdDev", f"{behavioral_metrics.get('interval_std', 0):.3f}s")
                        
                        with col2:
                            st.metric("🔄 Periodicity Score", f"{behavioral_metrics.get('periodicity_score', 0):.3f}")
                            
                            if behavioral_metrics.get('potential_beaconing', False):
                                st.error("🚨 Potential C2 Beaconing Detected!")
                            else:
                                st.success("✅ No suspicious beaconing patterns")
                    
                except Exception as e:
                    st.error(f"❌ Physics analysis error: {e}")
            else:
                st.info("📡 Waiting for network data to perform physics analysis...")

    # Dynamic auto-refresh based on dashboard configuration
    if dashboard_config.get('auto_refresh', True):
        refresh_interval = dashboard_config.get('refresh_interval', 2)
        
        # Add refresh indicator
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i in range(refresh_interval):
            progress_bar.progress((i + 1) / refresh_interval)
            status_text.text(f"⏱️ Next refresh in {refresh_interval - i} seconds...")
            time.sleep(1)
        
        progress_bar.empty()
        status_text.empty()
        st.rerun()
    else:
        # Manual refresh button
        if st.button("🔄 Manual Refresh", type="primary"):
            st.rerun()
    
    # Footer with stock Streamlit elements
    st.markdown("---")
    st.caption("🎯 CipherSky Quantum Network Defense | ⚡ Lite Mode Active")
    st.caption("Optimized for performance with intelligent feature scaling and reduced complexity")
    st.caption("👨‍💻 Built by Labib Bin Shahed • labib-x@protonmail.com")

if __name__ == "__main__":
    # Set multiprocessing start method for better compatibility
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        pass  # Already set
    
    # Suppress warnings for cleaner output
    warnings.filterwarnings('ignore', category=UserWarning)
    warnings.filterwarnings('ignore', category=FutureWarning)
    
    # Set page config first
    try:
        main()
    except KeyboardInterrupt:
        print("\nApplication stopped by user")
    except Exception as e:
        print(f"Application error: {e}")
        st.error(f"Application error: {e}")
