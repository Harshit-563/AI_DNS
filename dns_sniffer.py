"""
DNS Threat Sniffer Dashboard
Real-time DNS packet capture with API-backed classification and a Tkinter UI.
"""

import json
import logging
import math
import os
import queue
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

try:
    from google import genai
except ImportError:
    genai = None

try:
    from ipwhois.asn import IPASN
    from ipwhois.net import Net
except ImportError:
    IPASN = None
    Net = None

try:
    from scapy.all import DNS, IP, UDP, sniff
except ImportError:
    raise SystemExit("ERROR: Scapy not installed. Install with: pip install scapy")

from core.fastflux_integration import IntegratedThreatClassifier


load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


BG_DARK = "#0d1117"
BG_PANEL = "#161b22"
BG_ACCENT = "#1c2128"
ACCENT_BLUE = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED = "#f85149"
ACCENT_AMBER = "#ffa500"
TEXT_MAIN = "#e6edf3"
TEXT_MUTED = "#8b949e"
DETAIL_BLUE = "#79c0ff"
DETAIL_BG = "#0d1117"
BORDER_COLOR = "#30363d"
MAX_ROWS = 100
FAST_FLUX_WINDOW = 60
WHITELIST_FILE = "dns_whitelist.txt"
FEATURE_NAMES = [
    "domain_length",
    "entropy",
    "digit_ratio",
    "subdomain_depth",
    "ttl",
    "unique_ip_count",
    "query_rate",
]


def shannon_entropy(domain):
    """Calculate Shannon entropy for a domain string."""
    if not domain:
        return 0.0
    clean = domain.replace(".", "").lower()
    if not clean:
        return 0.0

    freq = {char: clean.count(char) for char in set(clean)}
    entropy = 0.0
    for count in freq.values():
        probability = count / len(clean)
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE, "r", encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


class DNSThreatDashboard:
    """Tkinter DNS sniffer modeled after the requested threat analyzer UI."""

    def __init__(self, root):
        self.root = root
        self.root.title("DOMAIN_WATCH THE THREAT ANALYZER")
        self.root.geometry("1200x950")
        self.root.configure(bg=BG_DARK)

        model_path = Path("models") / "dns_best_model.pkl"
        self.classifier = IntegratedThreatClassifier(
            model_path=str(model_path) if model_path.exists() else None
        )
        self.interface = None

        self.is_sniffing = False
        self.packet_queue = queue.Queue()
        self.domain_cache = defaultdict(
            lambda: {"ips": set(), "timestamps": deque(maxlen=50)}
        )
        self.packet_details = {}
        self.session_packet_details = []
        self.asn_cache = {}
        self.whitelist = load_whitelist()
        self.stats = {"Benign": 0, "Suspicious": 0, "DGA": 0, "fast_flux": 0}

        self.build_ui()
        self.root.after(150, self.process_ui_queue)

        self.sniffer_thread = threading.Thread(target=self.start_capture_loop, daemon=True)
        self.sniffer_thread.start()

    def build_ui(self):
        # ===== HEADER =====
        header = tk.Frame(self.root, bg=BG_DARK, pady=12)
        header.pack(fill="x", padx=0)
        
        # Logo/Title area
        title_frame = tk.Frame(header, bg=BG_DARK)
        title_frame.pack(side="left", padx=15, pady=5)
        tk.Label(
            title_frame,
            text="🛡️  DNS THREAT ANALYZER",
            font=("Segoe UI", 18, "bold"),
            fg=ACCENT_BLUE,
            bg=BG_DARK,
        ).pack(side="left")
        tk.Label(
            title_frame,
            text="Real-Time Security Monitoring",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_DARK,
        ).pack(side="left", padx=(10, 0))
        
        # Status indicator
        self.status_lbl = tk.Label(
            header,
            text="● PAUSED",
            font=("Segoe UI", 10, "bold"),
            fg=ACCENT_AMBER,
            bg=BG_DARK,
        )
        self.status_lbl.pack(side="right", padx=15)

        # ===== TOOLBAR =====
        toolbar = tk.Frame(self.root, bg=BG_PANEL, height=60)
        toolbar.pack(fill="x", padx=0, pady=(5, 0))
        
        # Left button group
        left_group = tk.Frame(toolbar, bg=BG_PANEL)
        left_group.pack(side="left", padx=10, pady=8)
        
        self.btn_start = tk.Button(
            left_group,
            text="▶  START SNIFFER",
            bg=ACCENT_GREEN,
            fg="#0d1117",
            font=("Segoe UI", 9, "bold"),
            command=self.toggle_sniffing,
            width=18,
            relief=tk.FLAT,
            activebackground="#34d399",
        )
        self.btn_start.pack(side="left", padx=4)

        tk.Button(
            left_group,
            text="📊  STATISTICS",
            bg=ACCENT_AMBER,
            fg="#0d1117",
            font=("Segoe UI", 9, "bold"),
            command=self.analyze_stats,
            width=12,
            relief=tk.FLAT,
            activebackground="#ffd166",
        ).pack(side="left", padx=4)

        tk.Button(
            left_group,
            text="💾  EXPORT",
            bg=BORDER_COLOR,
            fg=TEXT_MAIN,
            font=("Segoe UI", 9, "bold"),
            command=self.download_logs,
            width=10,
            relief=tk.FLAT,
            activebackground="#444d56",
        ).pack(side="left", padx=4)

        # Right button group
        right_group = tk.Frame(toolbar, bg=BG_PANEL)
        right_group.pack(side="right", padx=10, pady=8)
        
        tk.Button(
            right_group,
            text="🧠  AI ANALYSIS",
            bg=ACCENT_BLUE,
            fg="#0d1117",
            font=("Segoe UI", 9, "bold"),
            command=self.trigger_llm,
            width=14,
            relief=tk.FLAT,
            activebackground="#79c0ff",
        ).pack(side="left", padx=4)

        tk.Button(
            right_group,
            text="🗑️  CLEAR WHITELIST",
            bg="#444d56",
            fg=TEXT_MAIN,
            font=("Segoe UI", 9),
            command=self.clear_full_whitelist,
            width=14,
            relief=tk.FLAT,
            activebackground="#555d66",
        ).pack(side="left", padx=4)

        # ===== TABLE SECTION =====
        table_label = tk.Label(
            self.root,
            text="📡 DNS Query Log",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_MAIN,
            bg=BG_DARK,
        )
        table_label.pack(anchor="w", padx=10, pady=(10, 5))

        tree_frame = tk.Frame(self.root, bg=BG_DARK)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # Create scrollbar
        scrollbar = tk.Scrollbar(tree_frame, bg=BG_PANEL, troughcolor=BG_DARK)
        scrollbar.pack(side="right", fill="y")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=BG_PANEL,
            foreground=TEXT_MAIN,
            fieldbackground=BG_PANEL,
            rowheight=26,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", ACCENT_BLUE)],
            foreground=[("selected", "#0d1117")],
        )
        style.configure(
            "Treeview.Heading",
            background=BG_ACCENT,
            foreground=ACCENT_BLUE,
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map("Treeview.Heading", background=[("active", BG_PANEL)])

        cols = ("src", "dst", "query", "ttl", "conf", "status")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", yscrollcommand=scrollbar.set, height=15)
        scrollbar.config(command=self.tree.yview)
        
        col_config = {
            "src": ("SRC IP", 100),
            "dst": ("DST IP", 100),
            "query": ("DNS QUERY", 400),
            "ttl": ("TTL", 60),
            "conf": ("CONFIDENCE", 100),
            "status": ("STATUS", 120),
        }
        
        for key, (title, width) in col_config.items():
            self.tree.heading(key, text=title)
            self.tree.column(key, anchor="w" if key == "query" else "center", width=width)
        
        self.tree.pack(fill="both", expand=True)

        # Tag configuration for row colors
        self.tree.tag_configure("benign", background=BG_PANEL, foreground=ACCENT_GREEN)
        self.tree.tag_configure("benign_alt", background=BG_ACCENT, foreground=ACCENT_GREEN)
        self.tree.tag_configure("suspicious", background=BG_PANEL, foreground=ACCENT_AMBER)
        self.tree.tag_configure("suspicious_alt", background=BG_ACCENT, foreground=ACCENT_AMBER)
        self.tree.tag_configure("malicious", background="#3e1a19", foreground=ACCENT_RED)
        self.tree.tag_configure("malicious_alt", background="#4a1f21", foreground=ACCENT_RED)

        # ===== DETAILS PANEL =====
        details_label = tk.Label(
            self.root,
            text="🔍 Detailed Analysis",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_MAIN,
            bg=BG_DARK,
        )
        details_label.pack(anchor="w", padx=10, pady=(10, 5))

        detail_frame = tk.Frame(self.root, bg=BG_DARK)
        detail_frame.pack(fill="both", padx=10, pady=(0, 10), expand=False)

        # Create scrollbar for detail box
        detail_scrollbar = tk.Scrollbar(detail_frame, bg=BG_PANEL, troughcolor=BG_DARK)
        detail_scrollbar.pack(side="right", fill="y")

        self.detail_box = tk.Text(
            detail_frame,
            height=10,
            bg=DETAIL_BG,
            fg=DETAIL_BLUE,
            font=("Consolas", 9),
            borderwidth=1,
            border=1,
            relief=tk.SUNKEN,
            padx=10,
            pady=8,
            yscrollcommand=detail_scrollbar.set,
        )
        detail_scrollbar.config(command=self.detail_box.yview)
        self.detail_box.pack(fill="both", expand=True)

        # Context menu
        self.popup_menu = tk.Menu(
            self.root,
            tearoff=0,
            bg=BG_PANEL,
            fg=TEXT_MAIN,
            font=("Segoe UI", 9),
            activebackground=ACCENT_BLUE,
            activeforeground="#0d1117",
        )
        self.popup_menu.add_command(
            label="✓ Mark as False Positive (Whitelist)",
            command=self.mark_false_positive,
        )
        self.popup_menu.add_command(
            label="🗑️ Remove from Whitelist",
            command=self.unwhitelist_selected,
        )

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def toggle_sniffing(self):
        self.is_sniffing = not self.is_sniffing
        if self.is_sniffing:
            self.btn_start.config(text="⏹  STOP SNIFFER", bg=ACCENT_RED)
            self.status_lbl.config(text="● ACTIVE", fg=ACCENT_GREEN)
            self.write_detail("\n[▶ SYSTEM] Sniffer activated. Monitoring DNS traffic...\n" + "="*70 + "\n\n")
        else:
            self.btn_start.config(text="▶  START SNIFFER", bg=ACCENT_GREEN)
            self.status_lbl.config(text="● PAUSED", fg=ACCENT_AMBER)
            self.write_detail("\n[⏸ SYSTEM] Sniffer paused. No new queries captured.\n" + "="*70 + "\n\n")

    def analyze_stats(self):
        stats = {"Benign": 0, "Suspicious": 0, "DGA": 0, "fast_flux": 0}
        for item in self.session_packet_details:
            status = item.get("status", "Benign")
            if status == "fast_flux" or "Fast-Flux" in status or "FAST-FLUX" in status:
                stats["fast_flux"] += 1
            elif "DGA" in status:
                stats["DGA"] += 1
            elif "SUSPICIOUS" in status or "Suspicious" in status:
                stats["Suspicious"] += 1
            else:
                stats["Benign"] += 1

        self.stats = stats
        top = tk.Toplevel(self.root)
        top.title("📊 Session Statistics")
        top.geometry("400x300")
        top.configure(bg=BG_PANEL)
        top.resizable(False, False)
        
        # Title
        tk.Label(
            top,
            text="📊 LIVE STATISTICS",
            font=("Segoe UI", 14, "bold"),
            bg=BG_PANEL,
            fg=ACCENT_BLUE,
        ).pack(pady=(15, 20))
        
        total = sum(stats.values())
        tk.Label(
            top,
            text=f"Total Queries: {total}",
            font=("Segoe UI", 11, "bold"),
            bg=BG_PANEL,
            fg=TEXT_MAIN,
        ).pack(pady=5)
        
        # Stats with color coding
        for label, value in [
            ("✓ Benign", stats["Benign"]),
            ("⚠ Suspicious", stats["Suspicious"]),
            ("🔴 DGA", stats["DGA"]),
            ("🔴 Fast-Flux", stats["fast_flux"]),
        ]:
            pct = (value / max(total, 1)) * 100
            
            # Determine color
            if "Benign" in label:
                color = ACCENT_GREEN
            elif "Suspicious" in label:
                color = ACCENT_AMBER
            else:
                color = ACCENT_RED
            
            tk.Label(
                top,
                text=f"{label}: {value:>5} ({pct:>5.1f}%)",
                font=("Segoe UI", 10),
                bg=BG_PANEL,
                fg=color,
            ).pack(pady=4)
        
        # Close button
        tk.Button(
            top,
            text="Close",
            bg=ACCENT_BLUE,
            fg="#0d1117",
            font=("Segoe UI", 9, "bold"),
            command=top.destroy,
            width=15,
        ).pack(pady=(20, 10))

    def download_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
        )
        if not filename:
            return

        data_to_save = self.session_packet_details
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(data_to_save, handle, indent=4)
        messagebox.showinfo("Success", f"Logs saved to {os.path.basename(filename)}")

    def clear_full_whitelist(self):
        self.whitelist = set()
        if os.path.exists(WHITELIST_FILE):
            os.remove(WHITELIST_FILE)
        self.write_detail("\n[SYSTEM] GLOBAL WHITELIST PURGED.\n")

    def trigger_llm(self):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        packet_data = self.packet_details[item_id]
        self.write_detail("\n[SYSTEM] FETCHING CLOUD FORENSICS...\n")
        self.write_detail(self.analyze_threat_with_llm(packet_data) + "\n")

    def write_detail(self, text):
        self.detail_box.insert(tk.END, text)
        self.detail_box.see(tk.END)

    def add_to_whitelist(self, domain):
        if domain in self.whitelist:
            return
        self.whitelist.add(domain)
        with open(WHITELIST_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"{domain}\n")

    def remove_from_whitelist(self, domain):
        if domain not in self.whitelist:
            return False
        self.whitelist.remove(domain)
        with open(WHITELIST_FILE, "w", encoding="utf-8") as handle:
            for entry in sorted(self.whitelist):
                handle.write(f"{entry}\n")
        return True

    def mark_false_positive(self):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        domain = self.packet_details[item_id]["query_info"]["domain"]
        self.add_to_whitelist(domain)
        self.tree.item(item_id, tags=("benign",))
        self.tree.set(item_id, column="status", value="WHITELISTED")
        self.packet_details[item_id]["status"] = "WHITELISTED"

    def unwhitelist_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        domain = self.packet_details[item_id]["query_info"]["domain"]
        if self.remove_from_whitelist(domain):
            self.tree.set(item_id, column="status", value="RE-EVALUATED")
            self.packet_details[item_id]["status"] = "RE-EVALUATED"

    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        self.tree.selection_set(item_id)
        self.popup_menu.tk_popup(event.x_root, event.y_root)

    def on_tree_select(self, _event):
        selected = self.tree.selection()
        if not selected:
            return
        packet = self.packet_details[selected[0]]
        self.detail_box.delete("1.0", tk.END)
        
        # Extract all available data
        q = packet.get('query_info', {})
        n = packet.get('network_context', {})
        ai = packet.get('ai_analysis', {})
        rf = packet.get('raw_features', {})
        ff = ai.get('fastflux_analysis', {}) if isinstance(ai.get('fastflux_analysis'), dict) else {}
        ff_score = ai.get('ff_score')
        if ff_score is None:
            ff_score = ff.get('fastflux_score', 0)
        try:
            ff_score = float(ff_score)
        except (TypeError, ValueError):
            ff_score = 0.0
        data = {'status': packet.get('status', 'Unknown')}
        
        # Build threat signals text
        signals = []
        if ai.get('explanation'):
            signals.append(ai['explanation'])
        signals_text = " | ".join(signals) if signals else "No anomalies detected"
        
        # Build probabilities text
        probs = ai.get('probabilities', {})
        if probs and isinstance(probs, dict):
            probabilities_text = f"Base: {probs.get('base_class', 'N/A')} ({probs.get('base_confidence', 0):.1%}) → Final: {probs.get('final_class', 'N/A')}"
        else:
            probabilities_text = "N/A"
        
        # Build detector details
        detector_text = ""
        if ai.get('label') == 'fast_flux' or ai.get('is_fastflux'):
            detector_text = f"Fast-Flux Detector Triggered:\n"
            detector_text += f"  • Score: {ff_score:.3f}\n"
            detector_text += f"  • Domain Lexical Score: {ff.get('domain_lexical_score', 0):.3f}\n"
            detector_text += f"  • Subdomain Complexity Score: {ff.get('subdomain_complexity_score', 0):.3f}\n"
            detector_text += f"  • Domain Age Score: {ff.get('domain_age_score', 0):.3f}\n"
        else:
            detector_text = f"Standard Classification Engine:\n"
            detector_text += f"  • Base Prediction: {probs.get('base_prediction', 'N/A')}\n"
            detector_text += f"  • Confidence: {probs.get('base_confidence', 0):.1%}\n"
        
        # Build reasons text
        reasons = []
        if ai.get('confidence', 0) >= 0.8:
            reasons.append("High confidence prediction")
        if ai.get('is_fastflux'):
            reasons.append("Fast-Flux network pattern detected")
        if rf.get('entropy', 0) > 4.5:
            reasons.append("High domain entropy (randomization)")
        if rf.get('digit_ratio', 0) > 0.3:
            reasons.append("Excessive digit percentage")
        if rf.get('subdomain_depth', 0) > 3:
            reasons.append("Deep subdomain structure")
        if n.get('query_rate', 0) > 100:
            reasons.append("High query rate detected")
        if n.get('asn_diversity', 0) > 0.5:
            reasons.append("Multiple ASN sources (IP churn)")
        
        reasons_text = "\n  • ".join(reasons) if reasons else "  • No specific indicators"
        if reasons:
            reasons_text = "  • " + reasons_text
        
        # Build comprehensive inspection output
        inspection = f"""
{'='*80}
                        🔍 DETAILED PACKET INSPECTION
{'='*80}

DOMAIN INFO
  → Domain              : {q.get('domain', 'N/A')}
  → TTL                 : {q.get('ttl', 'N/A')} seconds
  → IP Count            : {q.get('ip_count', 'N/A')}
  → Record Type         : {q.get('record_type', 'A')}
  → Response Code       : {q.get('response_code', '0')}

RESOLUTION
  → IP Addresses        : {', '.join(q.get('ips', [])) if q.get('ips') else 'N/A'}
  → Resolution Count    : {len(q.get('ips', []))}

NETWORK FLOW
  → Source Port         : {q.get('source_port', 'Unknown')}
  → Destination Port    : 53 (DNS)
  → Protocol            : UDP

NETWORK CONTEXT
  → ASN Diversity       : {round(n.get('asn_diversity', 0), 3)}
  → Query Rate          : {n.get('query_rate', 0)} queries/period
  → Domain Reputation   : Not Checked

THREAT ENGINE
  → Classification      : {data.get('status', 'UNKNOWN')}
  → Confidence          : {round(ai.get('confidence', 0) * 100)}%
  → Signals             : {signals_text}

ML ANALYSIS
  → Prediction          : {ai.get('label', 'Unknown')}
  → Confidence          : {round(ai.get('confidence', 0) * 100)}%
  → Recommendation      : {ai.get('recommendation', 'REVIEW')}
  → Probabilities       : {probabilities_text}

FAST-FLUX ANALYSIS
  → Score               : {round(ff_score, 3)}
  → Detected            : {'🔴 YES' if ai.get('is_fastflux') else '✓ NO'}
  → TTL Risk            : {round(ff.get('ttl_score', 0), 3)}
  → IP Diversity Risk   : {round(ff.get('ip_diversity_score', 0), 3)}
  → Query Rate Risk     : {round(ff.get('query_rate_score', 0), 3)}

RAW FEATURES
  → Domain Length       : {rf.get('domain_length', 'N/A')}
  → Entropy             : {round(rf.get('entropy', 0), 3)}
  → Digit Ratio         : {round(rf.get('digit_ratio', 0), 3)}
  → Subdomain Depth     : {rf.get('subdomain_depth', 'N/A')}
  → TTL Value           : {rf.get('ttl', 'N/A')}
  → Unique IP Count     : {rf.get('unique_ip_count', 'N/A')}
  → Query Rate          : {rf.get('query_rate', 'N/A')}

DETECTOR DETAILS
{detector_text}

DETECTION REASONS
{reasons_text}

FINAL STATUS
  → Result              : {data.get('status', 'UNKNOWN')}
  → Captured At         : {packet.get('captured_at', 'N/A')}
  → Whitelist Status    : {'🔒 WHITELISTED' if q.get('domain', '') in self.whitelist else '◯ NOT WHITELISTED'}

{'='*80}
"""
        
        self.write_detail(inspection)

    def start_capture_loop(self):
        try:
            sniff(
                filter="udp port 53",
                prn=self.parse_dns,
                store=False,
                
            )
        except PermissionError:
            logger.error("Elevated privileges required for packet capture.")
            self.packet_queue.put(
                {
                    "type": "detail",
                    "message": "[SYSTEM] ERROR: Run this program as Administrator.\n",
                }
            )
        except Exception as exc:
            logger.exception("Sniffer failed")
            self.packet_queue.put(
                {"type": "detail", "message": f"[SYSTEM] SNIFFER ERROR: {exc}\n"}
            )

    def parse_dns(self, pkt):
        if not self.is_sniffing:
            return
        if not (pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return

        try:
            src = pkt[IP].src
            dst = pkt[IP].dst
            query = (
                pkt[DNS].qd.qname.decode(errors="ignore").strip(".")
                if pkt[DNS].qd
                else "-"
            )
            now = time.time()
            ttl = pkt[DNS].an.ttl if pkt[DNS].an and hasattr(pkt[DNS].an, "ttl") else 0

            current_ips = []
            if pkt[DNS].an:
                for index in range(getattr(pkt[DNS], "ancount", 0)):
                    try:
                        rr = pkt[DNS].an[index]
                        if hasattr(rr, "rdata"):
                            ip_value = str(rr.rdata)
                            self.domain_cache[query]["ips"].add(ip_value)
                            current_ips.append(ip_value)
                    except Exception:
                        continue

            self.domain_cache[query]["timestamps"].append(now)
            ip_count = len(self.domain_cache[query]["ips"])
            query_count = len(
                [
                    timestamp
                    for timestamp in self.domain_cache[query]["timestamps"]
                    if now - timestamp < FAST_FLUX_WINDOW
                ]
            )

            domain_length = len(query)
            entropy = shannon_entropy(query)
            digit_ratio = sum(ch.isdigit() for ch in query) / max(len(query), 1)
            subdomain_depth = query.count(".")
            ttl_val = ttl if ttl > 0 else 3600
            unique_ip_count = ip_count if ip_count > 0 else max(len(current_ips), 1)
            query_rate = query_count
            features = [
                domain_length,
                entropy,
                digit_ratio,
                subdomain_depth,
                ttl_val,
                unique_ip_count,
                query_rate,
            ]

            prediction = self.classify_domain(query, ttl_val, unique_ip_count, query_rate)
            ai_label = prediction["label"]
            conf = prediction["confidence"]
            recommendation = prediction["recommendation"]
            asn_diversity = self.get_asn_diversity(current_ips)
            explanation = self.get_explanation(features)

            status = "Benign"
            tag = "benign"
            if query in self.whitelist:
                status = "WHITELISTED"
            elif ai_label == "Benign" and conf >= 0.55:
                status = "Benign"
            elif ai_label in {"Fast-Flux", "fast_flux"} and asn_diversity < 0.3:
                status = "Benign (CDN)"
            elif ai_label == "fast_flux":
                status = "fast_flux"
                tag = "malicious"
            elif ai_label != "Benign" and conf >= 0.62:
                status = ai_label.upper()
                tag = "malicious"
            elif ai_label != "Benign" and conf >= 0.55:
                status = "SUSPICIOUS"
                tag = "malicious"
            else:
                # Default to benign for anything else
                status = "Benign"
                tag = "benign"

            packet_payload = {
                "src": src,
                "dst": dst,
                "query": query,
                "ttl": ttl,
                "confidence": conf,
                "status": status,
                "tag": tag,
                "details": {
                    "query_info": {
                        "domain": query,
                        "ttl": ttl_val,
                        "ips": current_ips,
                        "ip_count": ip_count,
                    },
                    "network_context": {
                        "asn_diversity": round(asn_diversity, 2),
                        "query_rate": query_rate,
                    },
                    "ai_analysis": {
                        "label": ai_label,
                        "confidence": conf,
                        "recommendation": recommendation,
                        "explanation": explanation,
                        "probabilities": prediction.get("probabilities"),
                        "is_fastflux": prediction.get("is_fastflux", False),
                        "ff_score": prediction.get("ff_score"),
                        "fastflux_analysis": prediction.get("fastflux_analysis", {}),
                    },
                    "raw_features": dict(zip(FEATURE_NAMES, features)),
                    "status": status,
                    "captured_at": datetime.now().isoformat(),
                },
            }

            self.packet_queue.put({"type": "packet", "payload": packet_payload})
        except Exception as exc:
            logger.exception("Packet processing error")
            self.packet_queue.put(
                {"type": "detail", "message": f"[SYSTEM] PACKET ERROR: {exc}\n"}
            )

    def classify_domain(self, domain, ttl, unique_ip_count, query_rate):
        ttl = int(ttl)
        unique_ip_count = max(int(unique_ip_count), 1)
        query_rate = max(float(query_rate), 1.0)

        try:
            result = self.classifier.classify(
                domain=domain,
                ttl=ttl,
                unique_ip_count=unique_ip_count,
                query_rate=query_rate,
            )
            fastflux = self.classifier.detect_fastflux(
                domain=domain,
                ttl=ttl,
                unique_ip_count=unique_ip_count,
                query_rate=query_rate,
            )
        except Exception as exc:
            logger.warning("Local model classification failed for %s: %s", domain, exc)
            return {
                "label": "Benign",
                "confidence": 0.5,
                "recommendation": "REVIEW",
                "probabilities": None,
                "is_fastflux": False,
                "ff_score": None,
                "fastflux_analysis": {},
            }

        prediction = result.get("final_prediction", "Benign")
        normalized = prediction if prediction != "Unknown" else "Benign"
        confidence = float(
            result.get("confidence", result.get("base_confidence", 0.5))
        )
        fastflux_analysis = result.get("fastflux_analysis") or {}
        if fastflux:
            fastflux_analysis.update(fastflux)

        ff_score = float(fastflux_analysis.get("fastflux_score", 0.0))
        is_fastflux = bool(fastflux_analysis.get("is_fastflux", False))

        if is_fastflux:
            normalized = "fast_flux"
            confidence = 100 * ff_score

        return {
            "label": normalized,
            "confidence": confidence,
            "recommendation": "BLOCK" if normalized != "Benign" else "ALLOW",
            "probabilities": {
                "base_prediction": result.get("base_prediction"),
                "base_class": result.get("base_class"),
                "base_confidence": float(result.get("base_confidence", 0.5)),
                "final_class": result.get("final_class"),
            },
            "is_fastflux": is_fastflux,
            "ff_score": ff_score,
            "fastflux_analysis": fastflux_analysis,
        }

    def get_asn_diversity(self, ip_list):
        if not ip_list or IPASN is None or Net is None:
            return 0.0

        asns = set()
        for ip_address in ip_list:
            if ip_address in self.asn_cache:
                asns.add(self.asn_cache[ip_address])
                continue
            try:
                lookup = IPASN(Net(ip_address)).lookup()
                asn = lookup.get("asn")
                self.asn_cache[ip_address] = asn
                asns.add(asn)
            except Exception:
                continue
        return len(asns) / len(ip_list) if ip_list else 0.0

    def get_explanation(self, features):
        explanations = []
        if features[1] > 4.5:
            explanations.append("HIGH ENTROPY")
        if features[4] < 120 and features[5] > 5:
            explanations.append("IP CHURN")
        if features[2] > 0.3:
            explanations.append("DIGIT DENSITY")
        return " | ".join(explanations) if explanations else "AI-DETECTED ANOMALY"

    def analyze_threat_with_llm(self, packet_data):
        api_key = os.getenv("GOOGLE_API_KEY")
        domain = packet_data["query_info"]["domain"]

        if not api_key or genai is None:
            analysis = packet_data.get("ai_analysis", {})
            return (
                f"Forensic Offline: domain={domain}\n"
                f"Model verdict={analysis.get('label', 'Unknown')} | "
                f"confidence={analysis.get('confidence', 0):.2f}\n"
                f"Reason={analysis.get('explanation', 'No explanation available')}"
            )

        prompt = (
            f"Forensic Scan: {domain}.\n"
            "1. Attack: Yes/No?\n"
            "2. Goal: DGA/Fast-Flux/Exfil?\n"
            "3. If No, why did the AI flag it?\n"
            "Answer in exactly 2-3 lines."
        )
        try:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            return response.text
        except Exception as exc:
            return f"Forensic Offline: {exc}"

    def process_ui_queue(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if item["type"] == "detail":
                    self.write_detail(item["message"])
                    continue

                payload = item["payload"]
                bar = self.render_confidence_bar(payload["confidence"])
                
                # Determine tag based on status for better coloring
                row_index = len(self.tree.get_children())
                is_even = row_index % 2 == 0
                
                if payload["tag"] == "benign":
                    tag = "benign" if is_even else "benign_alt"
                elif payload["tag"] == "malicious":
                    if "SUSPICIOUS" in payload["status"]:
                        tag = "suspicious" if is_even else "suspicious_alt"
                    else:
                        tag = "malicious" if is_even else "malicious_alt"
                else:
                    tag = "benign" if is_even else "benign_alt"
                
                item_id = self.tree.insert(
                    "",
                    "end",
                    values=(
                        payload["src"],
                        payload["dst"],
                        payload["query"],
                        payload["ttl"],
                        bar,
                        payload["status"],
                    ),
                    tags=(tag,),
                )
                details = payload["details"]
                self.packet_details[item_id] = details
                self.session_packet_details.append(details)

                if len(self.tree.get_children()) > MAX_ROWS:
                    oldest = self.tree.get_children()[0]
                    self.tree.delete(oldest)
                    self.packet_details.pop(oldest, None)
        except queue.Empty:
            pass
        finally:
            self.root.after(150, self.process_ui_queue)

    @staticmethod
    def render_confidence_bar(confidence):
        normalized_confidence = confidence / 100 if confidence > 1 else confidence
        filled = max(0, min(10, int(normalized_confidence * 10)))
        percentage = int(confidence if confidence > 1 else confidence * 100)
        
        # Better visual representation
        bar = f"[{'▓' * filled}{'░' * (10 - filled)}] {percentage:>3d}%"
        return bar


def main():
    root = tk.Tk()
    app = DNSThreatDashboard(root)
    root.mainloop()
    return app


if __name__ == "__main__":
    main()
