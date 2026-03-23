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

from fastflux_integration import IntegratedThreatClassifier


load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


BG_DARK = "#0a0a0a"
BG_PANEL = "#161b22"
ACCENT_GREEN = "#238636"
ACCENT_RED = "#da3633"
ACCENT_AMBER = "#d29922"
TEXT_MAIN = "#c9d1d9"
DETAIL_BLUE = "#79c0ff"
DETAIL_BG = "#0d1117"
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
        self.asn_cache = {}
        self.whitelist = load_whitelist()
        self.stats = {"Benign": 0, "Suspicious": 0, "DGA": 0, "Fast-Flux": 0}

        self.build_ui()
        self.root.after(150, self.process_ui_queue)

        self.sniffer_thread = threading.Thread(target=self.start_capture_loop, daemon=True)
        self.sniffer_thread.start()

    def build_ui(self):
        header = tk.Frame(self.root, bg=BG_DARK, pady=10)
        header.pack(fill="x")
        tk.Label(
            header,
            text="  DOMAIN_WATCH THE THREAT ANALYZER",
            font=("Consolas", 20, "bold"),
            fg=ACCENT_GREEN,
            bg=BG_DARK,
        ).pack(side="left")

        controls = tk.Frame(self.root, bg=BG_DARK, pady=5)
        controls.pack(fill="x", padx=10)

        self.btn_start = tk.Button(
            controls,
            text="START SNIFFING",
            bg=ACCENT_GREEN,
            fg="white",
            font=("Consolas", 10, "bold"),
            command=self.toggle_sniffing,
            width=15,
        )
        self.btn_start.pack(side="left", padx=5)

        tk.Button(
            controls,
            text="STATS",
            bg=ACCENT_AMBER,
            fg="black",
            font=("Consolas", 10, "bold"),
            command=self.analyze_stats,
        ).pack(side="left", padx=5)

        tk.Button(
            controls,
            text="SAVE",
            bg="#444d56",
            fg="white",
            font=("Consolas", 10),
            command=self.download_logs,
        ).pack(side="left", padx=5)

        tk.Button(
            controls,
            text="CLEAR WHITELIST",
            bg="#444d56",
            fg="white",
            font=("Consolas", 10),
            command=self.clear_full_whitelist,
        ).pack(side="left", padx=5)

        tk.Button(
            controls,
            text="DEEP ANALYSIS",
            bg=ACCENT_GREEN,
            fg="white",
            font=("Consolas", 10, "bold"),
            command=self.trigger_llm,
        ).pack(side="right", padx=5)

        self.status_lbl = tk.Label(
            controls,
            text="STATUS: PAUSED",
            font=("Consolas", 10),
            fg="orange",
            bg=BG_DARK,
        )
        self.status_lbl.pack(side="right", padx=15)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=BG_PANEL,
            foreground=TEXT_MAIN,
            fieldbackground=BG_PANEL,
            rowheight=30,
            font=("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#21262d",
            foreground=ACCENT_GREEN,
            font=("Consolas", 10, "bold"),
        )

        tree_frame = tk.Frame(self.root, bg=BG_DARK)
        tree_frame.pack(fill="both", expand=True, padx=10)

        cols = ("src", "dst", "query", "ttl", "conf", "status")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        for key, title in zip(cols, ("SRC", "DST", "DNS_QUERY", "TTL", "AI_CONF", "STATUS")):
            self.tree.heading(key, text=title)
            self.tree.column(key, anchor="center", width=100)
        self.tree.column("query", width=350, anchor="w")
        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure("malicious", background="#3e1a19", foreground="#ff7b72")
        self.tree.tag_configure("benign", foreground="#3fb950")

        self.detail_box = tk.Text(
            self.root,
            height=12,
            bg=DETAIL_BG,
            fg=DETAIL_BLUE,
            font=("Consolas", 10),
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.detail_box.pack(fill="both", padx=10, pady=10)

        self.popup_menu = tk.Menu(
            self.root,
            tearoff=0,
            bg=BG_PANEL,
            fg=TEXT_MAIN,
            font=("Consolas", 10),
        )
        self.popup_menu.add_command(
            label="Mark as False Positive (Whitelist)",
            command=self.mark_false_positive,
        )
        self.popup_menu.add_command(
            label="Remove from Whitelist",
            command=self.unwhitelist_selected,
        )

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def toggle_sniffing(self):
        self.is_sniffing = not self.is_sniffing
        if self.is_sniffing:
            self.btn_start.config(text="STOP SNIFFING", bg=ACCENT_RED)
            self.status_lbl.config(text="STATUS: ACTIVE", fg=ACCENT_GREEN)
            self.write_detail("[SYSTEM] Live sniffing started.\n")
        else:
            self.btn_start.config(text="START SNIFFING", bg=ACCENT_GREEN)
            self.status_lbl.config(text="STATUS: PAUSED", fg="orange")
            self.write_detail("[SYSTEM] Live sniffing paused.\n")

    def analyze_stats(self):
        stats = {"Benign": 0, "Suspicious": 0, "DGA": 0, "Fast-Flux": 0}
        for item in self.packet_details.values():
            status = item.get("status", "Benign")
            if "Fast-Flux" in status or "FAST-FLUX" in status:
                stats["Fast-Flux"] += 1
            elif "DGA" in status:
                stats["DGA"] += 1
            elif "SUSPICIOUS" in status or "Suspicious" in status:
                stats["Suspicious"] += 1
            else:
                stats["Benign"] += 1

        self.stats = stats
        top = tk.Toplevel(self.root)
        top.title("Session Analysis")
        top.geometry("300x250")
        top.configure(bg=BG_PANEL)
        tk.Label(
            top,
            text="LIVE STATS",
            font=("Consolas", 14, "bold"),
            bg=BG_PANEL,
            fg="white",
        ).pack(pady=10)
        for label, value in stats.items():
            tk.Label(
                top,
                text=f"{label}: {value}",
                font=("Consolas", 12),
                bg=BG_PANEL,
                fg=TEXT_MAIN,
            ).pack()

    def download_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
        )
        if not filename:
            return

        data_to_save = list(self.packet_details.values())
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
        self.write_detail(
            f">>> INSPECTION: {packet['query_info']['domain']}\n"
            + json.dumps(packet, indent=4)
        )

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
            elif ai_label == "Fast-Flux" and asn_diversity < 0.3:
                status = "Benign (CDN)"
            elif ai_label != "Benign" and conf >= 0.75:
                status = ai_label.upper()
                tag = "malicious"
            elif ai_label != "Benign" and conf >= 0.60:
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

        if is_fastflux and ff_score > 0.65:
            normalized = "Fast-Flux"
            confidence = max(confidence, ff_score)

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
                    tags=(payload["tag"],),
                )
                self.packet_details[item_id] = payload["details"]

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
        filled = max(0, min(10, int(confidence * 10)))
        return f"[{'■' * filled}{'□' * (10 - filled)}] {int(confidence * 100)}%"


def main():
    root = tk.Tk()
    app = DNSThreatDashboard(root)
    root.mainloop()
    return app


if __name__ == "__main__":
    main()
