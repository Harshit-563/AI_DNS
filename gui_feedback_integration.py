"""
GUI Integration for Feedback Learning System
Adds "Mark False Positive/Negative" buttons to DNS Sniffer GUI
"""

import tkinter as tk
from tkinter import messagebox, ttk
import requests
import threading
from typing import Callable, Optional


class FeedbackPanel:
    """
    Add-on panel for DNS Sniffer GUI that provides feedback functionality
    
    Features:
    - Mark False Positive button
    - Mark False Negative button
    - Feedback status display
    - Retraining progress indicator
    """
    
    def __init__(
        self,
        parent_widget: tk.Widget,
        api_url: str = "http://localhost:5000",
        on_feedback_submitted: Optional[Callable] = None
    ):
        """
        Initialize feedback panel
        
        Args:
            parent_widget: Parent Tkinter widget
            api_url: Base URL of API server
            on_feedback_submitted: Callback when feedback is submitted
        """
        self.parent = parent_widget
        self.api_url = api_url
        self.on_feedback_submitted = on_feedback_submitted
        self.current_domain = None
        self.current_confidence = None
        self.current_prediction = None
        self.api_available = False
        
        # Create UI elements
        self.create_widgets()
        self.check_api_health()
    
    def create_widgets(self):
        """Build feedback UI components"""
        # Main container frame
        self.frame = ttk.LabelFrame(
            self.parent,
            text="Feedback Learning System",
            padding=10
        )
        self.frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        # ===== Row 1: Status =====
        status_frame = ttk.Frame(self.frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text="Feedback Status:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(
            status_frame,
            text="Checking API...",
            foreground="orange"
        )
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # ===== Row 2: Feedback Details =====
        details_frame = ttk.Frame(self.frame)
        details_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(details_frame, text="Domain:").pack(side=tk.LEFT, padx=5)
        self.domain_label = ttk.Label(details_frame, text="(None)", font=("Arial", 9))
        self.domain_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(details_frame, text="| Confidence:").pack(side=tk.LEFT, padx=5)
        self.confidence_label = ttk.Label(details_frame, text="(None)", font=("Arial", 9))
        self.confidence_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(details_frame, text="| Prediction:").pack(side=tk.LEFT, padx=5)
        self.prediction_label = ttk.Label(details_frame, text="(None)", font=("Arial", 9))
        self.prediction_label.pack(side=tk.LEFT, padx=5)
        
        # ===== Row 3: Action Buttons =====
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            buttons_frame,
            text="Mark as False Positive",
            command=self.mark_false_positive
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Mark as False Negative",
            command=self.mark_false_negative
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Trigger Retraining",
            command=self.trigger_retraining
        ).pack(side=tk.LEFT, padx=5)
        
        # ===== Row 4: Retraining Progress =====
        progress_frame = ttk.Frame(self.frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Retrain Progress:").pack(side=tk.LEFT, padx=5)
        
        self.progress_var = tk.StringVar(value="0 / 100")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(side=tk.LEFT, padx=5)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=200
        )
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        
        # Disable buttons until API is ready
        self.buttons_enabled(False)
    
    def buttons_enabled(self, enabled: bool):
        """Enable/disable feedback buttons"""
        for child in self.frame.winfo_children():
            if isinstance(child, ttk.Frame):
                for widget in child.winfo_children():
                    if isinstance(widget, ttk.Button):
                        widget.config(state=tk.NORMAL if enabled else tk.DISABLED)
    
    def check_api_health(self):
        """Check if API is running"""
        def check():
            try:
                response = requests.get(
                    f"{self.api_url}/api/v1/health",
                    timeout=2
                )
                if response.status_code == 200:
                    self.api_available = True
                    self.update_status("API Ready", "green")
                    self.buttons_enabled(True)
                    self.refresh_feedback_status()
                else:
                    self.update_status("API Error", "red")
            except:
                self.update_status("API Unavailable", "red")
        
        # Run in background thread
        threading.Thread(target=check, daemon=True).start()
    
    def update_status(self, text: str, color: str):
        """Update status label"""
        self.status_label.config(text=text, foreground=color)
    
    def set_current_classification(
        self,
        domain: str,
        prediction: str,
        confidence: float
    ):
        """Update current classification being displayed"""
        self.current_domain = domain
        self.current_prediction = prediction
        self.current_confidence = confidence
        
        # Update labels
        self.domain_label.config(text=domain)
        self.prediction_label.config(text=prediction)
        self.confidence_label.config(text=f"{confidence:.1%}")
    
    def mark_false_positive(self):
        """Mark current domain as false positive (should be benign)"""
        if not self.current_domain:
            messagebox.showwarning("No Domain", "Select a domain first")
            return
        
        # Ask for comment
        comment = self._ask_for_comment(
            "Mark as False Positive",
            f"Is '{self.current_domain}' actually benign?\n\nOptional comment:"
        )
        
        if comment is None:  # User cancelled
            return
        
        self._submit_feedback("false_positive", comment)
    
    def mark_false_negative(self):
        """Mark current domain as false negative (should be malicious)"""
        if not self.current_domain:
            messagebox.showwarning("No Domain", "Select a domain first")
            return
        
        comment = self._ask_for_comment(
            "Mark as False Negative",
            f"Is '{self.current_domain}' actually malicious?\n\nOptional comment:"
        )
        
        if comment is None:
            return
        
        self._submit_feedback("false_negative", comment)
    
    def _ask_for_comment(self, title: str, prompt: str) -> Optional[str]:
        """Show dialog to ask for user comment"""
        dialog = tk.Toplevel(self.parent)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text=prompt).pack(padx=10, pady=10)
        
        # Text area for comment
        text_widget = tk.Text(dialog, height=4, width=45)
        text_widget.pack(padx=10, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        result = [None]
        
        def submit():
            result[0] = text_widget.get("1.0", tk.END).strip()
            dialog.destroy()
        
        def cancel():
            result[0] = None
            dialog.destroy()
        
        ttk.Button(button_frame, text="Submit", command=submit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        return result[0]
    
    def _submit_feedback(self, feedback_type: str, comment: str):
        """Submit feedback to API"""
        if not self.api_available:
            messagebox.showerror("API Error", "API is not available")
            return
        
        # Determine endpoint
        endpoint = "/api/v1/feedback/mark-false-positive" if feedback_type == "false_positive" \
                  else "/api/v1/feedback/mark-false-negative"
        
        # Prepare request
        payload = {
            "domain": self.current_domain,
            "confidence_before": self.current_confidence,
            "comment": comment,
            "current_model_version": "1.0"
        }
        
        def submit_async():
            try:
                response = requests.post(
                    f"{self.api_url}{endpoint}",
                    json=payload,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    messagebox.showinfo(
                        "Success",
                        f"{data.get('message')}\n\n"
                        f"Total feedback: {data.get('feedback_count')}"
                    )
                    
                    # Refresh feedback status
                    self.refresh_feedback_status()
                    
                    if self.on_feedback_submitted:
                        self.on_feedback_submitted(data)
                else:
                    error_msg = response.json().get('message', 'Unknown error')
                    messagebox.showerror("Error", f"Failed to submit feedback: {error_msg}")
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect to API: {str(e)[:100]}")
        
        # Submit in background
        threading.Thread(target=submit_async, daemon=True).start()
    
    def refresh_feedback_status(self):
        """Refresh feedback status from API"""
        if not self.api_available:
            return
        
        def fetch():
            try:
                response = requests.get(
                    f"{self.api_url}/api/v1/feedback/status",
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    count = data.get('feedback_count', 0)
                    threshold = data.get('retrain_threshold', 100)
                    
                    # Update progress
                    self.progress_var.set(f"{count} / {threshold}")
                    self.progress_bar['value'] = min(100, (count / threshold) * 100)
                    
                    if data.get('retrain_suggested'):
                        self.update_status("Ready to Retrain!", "blue")
            except:
                pass
        
        threading.Thread(target=fetch, daemon=True).start()
    
    def trigger_retraining(self):
        """Trigger model retraining"""
        if not self.api_available:
            messagebox.showerror("API Error", "API is not available")
            return
        
        if messagebox.askyesno(
            "Retrain Model",
            "Start retraining with current feedback data?\n\n"
            "This may take 5-10 minutes."
        ):
            self._run_retraining()
    
    def _run_retraining(self):
        """Run retraining in background"""
        # Show progress window
        progress_window = tk.Toplevel(self.parent)
        progress_window.title("Model Retraining")
        progress_window.geometry("400x150")
        progress_window.resizable(False, False)
        
        ttk.Label(progress_window, text="Retraining in progress...").pack(pady=10)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(
            progress_window,
            mode='indeterminate',
            length=350
        )
        progress_bar.pack(pady=10)
        progress_bar.start()
        
        status_label = ttk.Label(progress_window, text="Initializing...")
        status_label.pack(pady=10)
        
        def retrain_async():
            try:
                response = requests.post(
                    f"{self.api_url}/api/v1/feedback/retrain",
                    json={"force": True},
                    timeout=600  # 10 minute timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    progress_window.destroy()
                    
                    messagebox.showinfo(
                        "Retraining Complete",
                        f"✓ Retraining successful!\n\n"
                        f"New Version: {data.get('version')}\n"
                        f"Accuracy: {data.get('accuracy'):.2%}\n"
                        f"F1-Score: {data.get('f1'):.2%}\n"
                        f"Feedback Used: {data.get('feedback_count')}"
                    )
                    self.refresh_feedback_status()
                else:
                    error_msg = response.json().get('message', 'Unknown error')
                    progress_window.destroy()
                    messagebox.showerror("Error", f"Retraining failed: {error_msg}")
            
            except Exception as e:
                progress_window.destroy()
                messagebox.showerror("Error", f"Retraining error: {str(e)[:100]}")
        
        # Run in background
        threading.Thread(target=retrain_async, daemon=True).start()


# ============================================================================
# INTEGRATION WITH EXISTING DNS SNIFFER GUI
# ============================================================================

INTEGRATION_EXAMPLE = """
# Add to dns_sniffer_gui.py after building the main UI:

from gui_feedback_integration import FeedbackPanel

class DNSSnifferGUI:
    def __init__(self, root):
        # ... existing code ...
        
        # Add feedback panel AFTER building main UI
        self.feedback_panel = FeedbackPanel(
            parent_widget=self.root,
            api_url=self.api_url,
            on_feedback_submitted=self.on_feedback_submitted
        )
    
    def update_classification_display(self, domain, prediction, confidence):
        # When displaying a classification result, update the feedback panel:
        self.feedback_panel.set_current_classification(
            domain=domain,
            prediction=prediction,
            confidence=confidence
        )
    
    def on_feedback_submitted(self, feedback_data):
        # Called when feedback is successfully submitted
        self.status_label.config(
            text=f"Feedback recorded. Total: {feedback_data.get('feedback_count')}"
        )
        self.root.update()
"""

if __name__ == "__main__":
    print(INTEGRATION_EXAMPLE)
