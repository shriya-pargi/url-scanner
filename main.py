import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from ttkthemes import ThemedTk
import re
import requests
import whois
import textwrap
from datetime import datetime
from threading import Lock, Event
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import io
import time
import csv
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

# ------------------ CONFIGURATION ------------------

DEFAULT_VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
vt_cache = {}
nvd_cache = {}
cache_lock = Lock()

DARK_BG = "#23272e"
DARK_FG = "#e0e0e0"
ACCENT_GREEN = "#00b894"
ACCENT_ORANGE = "#fdcb6e"
ACCENT_RED = "#d63031"
ACCENT_PURPLE = "#6c5ce7"
ACCENT_BLUE = "#0984e3"
ROW_COLORS = {
    "Safe": "#2ecc71",
    "Suspicious": "#fdcb6e",
    "Unsafe": "#e17055",
    "Very Unsafe": "#d63031",
}

# ------------------ HEURISTIC FUNCTIONS ------------------

def is_ip_in_url(url):
    return bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', url))

def has_suspicious_words(url, sensitivity=1):
    suspicious_words = ['login', 'secure', 'update', 'bank', 'verify', 'signin', 'signup', 'reset', 'auth']
    url_lower = url.lower()
    return sum(word in url_lower for word in suspicious_words) >= sensitivity

def has_phishing_keywords(url, sensitivity=1):
    phishing_words = [
        'free', 'bonus', 'prize', 'login', 'secure', 'account', 'update',
        'verify', 'bank', 'confirm', 'click', 'urgent', 'winner'
    ]
    url_lower = url.lower()
    return sum(word in url_lower for word in phishing_words) >= sensitivity

def has_suspicious_tld(url):
    suspicious_tlds = ['.biz', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']
    url_lower = url.lower()
    return any(url_lower.endswith(tld) for tld in suspicious_tlds)

def is_url_too_long(url):
    return len(url) > 75

def get_domain_from_url(url):
    try:
        domain = re.findall(r'https?://(?:www\.)?([^/:]+)', url)
        return domain[0] if domain else None
    except Exception:
        return None

def get_domain_age_days(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return -1
        age = (datetime.now() - creation_date).days
        return age
    except Exception:
        return -1

def simple_ml_phishing_score(url):
    phishing_words = [
        'free', 'bonus', 'prize', 'login', 'secure', 'account', 'update',
        'verify', 'bank', 'confirm', 'click', 'urgent', 'winner'
    ]
    url_lower = url.lower()
    count = sum(url_lower.count(word) for word in phishing_words)
    return count

def extract_cve_details(nvd_data, max_cves=5):
    cve_list = []
    for item in nvd_data.get('vulnerabilities', [])[:max_cves]:
        cve_id = item.get('cve', {}).get('id', 'N/A')
        metrics = item.get('cve', {}).get('metrics', {})
        severity = 'Unknown'
        if 'cvssMetricV31' in metrics:
            severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
        elif 'cvssMetricV30' in metrics:
            severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
        elif 'cvssMetricV2' in metrics:
            severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'Unknown')
        cve_list.append(f"{cve_id} ({severity})")
    return cve_list

def get_nvd_keyword(domain):
    domain = domain.lower()
    for key in ["apache", "wordpress", "openssl", "microsoft", "drupal", "nginx", "php", "joomla", "oracle", "adobe"]:
        if key in domain:
            return key
    return domain.split(".")[0]

# ------------------ SCANNING LOGIC ------------------

def scan_url(url, vt_api_key, heuristics_sensitivity=1, timeout=5):
    status = None
    try:
        response = requests.get(url, timeout=timeout)
        status = response.status_code
    except Exception:
        status = 'Unreachable'

    score = 0
    reasons = []

    if is_ip_in_url(url):
        score += 1
        reasons.append("URL contains IP address")

    if has_suspicious_words(url, heuristics_sensitivity):
        score += 1
        reasons.append("URL contains suspicious words")

    if has_phishing_keywords(url, heuristics_sensitivity):
        score += 1
        reasons.append("URL contains phishing keywords")

    if has_suspicious_tld(url):
        score += 1
        reasons.append("URL has suspicious TLD")

    if is_url_too_long(url):
        score += 1
        reasons.append("URL length is unusually long")

    domain = get_domain_from_url(url)
    domain_age = -1
    if domain:
        domain_age = get_domain_age_days(domain)
        if domain_age == -1:
            pass
        elif 0 <= domain_age < 180:
            score += 1
            reasons.append(f"Domain is very new ({domain_age} days old)")

    vt_malicious = 0
    with cache_lock:
        vt_data = vt_cache.get(url)
    if not vt_data:
        try:
            headers = {"x-apikey": vt_api_key}
            vt_url = "https://www.virustotal.com/api/v3/urls"
            submit_resp = requests.post(vt_url, headers=headers, data={'url': url}, timeout=15)
            if submit_resp.status_code == 200:
                submit_json = submit_resp.json()
                analysis_id = submit_json.get('data', {}).get('id')
                if analysis_id:
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    for _ in range(10):
                        analysis_resp = requests.get(analysis_url, headers=headers, timeout=15)
                        if analysis_resp.status_code == 200:
                            analysis_data = analysis_resp.json()
                            if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                                status_ = analysis_data['data']['attributes'].get('status')
                                if status_ == 'completed':
                                    break
                        time.sleep(3)
                    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                    vt_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                    vt_response = requests.get(vt_report_url, headers=headers, timeout=15)
                    if vt_response.status_code == 200:
                        vt_data = vt_response.json()
                        with cache_lock:
                            vt_cache[url] = vt_data
        except Exception:
            vt_data = None

    if vt_data:
        try:
            stats = vt_data['data']['attributes']['last_analysis_stats']
            vt_malicious = stats.get('malicious', 0)
            if vt_malicious > 0:
                score += vt_malicious
                reasons.append(f"VirusTotal flagged malicious ({vt_malicious} detections)")
        except Exception:
            vt_malicious = 0

    nvd_cve_count = 0
    nvd_cve_details = []
    if domain:
        nvd_keyword = get_nvd_keyword(domain)
        with cache_lock:
            nvd_data = nvd_cache.get(nvd_keyword)
        if not nvd_data:
            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={nvd_keyword}&resultsPerPage=10"
                resp = requests.get(nvd_url, timeout=15)
                if resp.status_code == 200:
                    nvd_data = resp.json()
                    with cache_lock:
                        nvd_cache[nvd_keyword] = nvd_data
            except Exception:
                nvd_data = None
        if nvd_data:
            try:
                nvd_cve_count = len(nvd_data.get('vulnerabilities', []))
                if nvd_cve_count > 0:
                    nvd_cve_details = extract_cve_details(nvd_data, max_cves=5)
                    score += nvd_cve_count
                    reasons.append(f"NVD reported {nvd_cve_count} CVEs: {', '.join(nvd_cve_details)}")
            except Exception:
                nvd_cve_count = 0

    ml_score = simple_ml_phishing_score(url)
    if ml_score > 0:
        score += ml_score
        reasons.append(f"Phishing keywords score: {ml_score}")

    trusted_domains = {
        "youtube.com", "google.com", "facebook.com", "twitter.com", "github.com", "wikipedia.org",
        "linkedin.com", "instagram.com", "microsoft.com", "apple.com", "amazon.com", "example.com"
    }
    if domain and any(td in domain for td in trusted_domains):
        score = 0
        reasons = ["Trusted major domain"]

    if score >= 5:
        safety = "Very Unsafe"
    elif score >= 3:
        safety = "Unsafe"
    elif score >= 2:
        safety = "Suspicious"
    else:
        safety = "Safe"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "url": url,
        "status": status,
        "score": score,
        "safety": safety,
        "reasons": "; ".join(reasons) if reasons else "None",
        "vt_malicious": vt_malicious,
        "nvd_cve": nvd_cve_count,
        "nvd_cve_details": nvd_cve_details,
        "timestamp": timestamp,
    }
    return result

# ------------------ PDF EXPORT FUNCTION ------------------

def append_to_report_pdf(results, filename="scan_report.pdf"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(colors.black)
    c.drawString(50, height - 50, "URL Safety Scan Report")
    y = height - 80
    line_height = 16

    for res in results:
        if y < 100:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica-Bold", 16)
            c.setFillColor(colors.black)
            c.drawString(50, height - 50, "URL Safety Scan Report (cont.)")
            y = height - 80

        if res.get('safety') == "Safe":
            c.setFillColor(colors.green)
        elif res.get('safety') == "Suspicious":
            c.setFillColor(colors.orange)
        elif res.get('safety') == "Unsafe":
            c.setFillColor(colors.red)
        elif res.get('safety') == "Very Unsafe":
            c.setFillColor(colors.darkred)
        else:
            c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"URL: {res.get('url', 'N/A')}")
        y -= line_height

        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"Scan Conclusion: {res.get('safety', 'N/A')}")
        y -= line_height

        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Status: {res.get('status', 'N/A')}")
        y -= line_height
        c.drawString(50, y, f"Suspicion Score: {res.get('score', 'N/A')}")
        y -= line_height

        reasons = res.get('reasons', 'N/A')
        for i, line in enumerate(textwrap.wrap(reasons, width=90)):
            prefix = "Reasons: " if i == 0 else ""
            c.drawString(50, y, f"{prefix}{line}")
            y -= line_height

        c.drawString(50, y, f"VirusTotal Malicious Count: {res.get('vt_malicious', 'N/A')}")
        y -= line_height
        c.drawString(50, y, f"NVD CVE Count: {res.get('nvd_cve', 'N/A')}")
        y -= line_height

        cve_list = res.get('nvd_cve_details', [])
        if len(cve_list) > 5:
            cve_display = ', '.join(cve_list[:5]) + ', ...'
        else:
            cve_display = ', '.join(cve_list)
        for i, line in enumerate(textwrap.wrap(cve_display, width=90)):
            prefix = "NVD CVEs: " if i == 0 else ""
            c.drawString(50, y, f"{prefix}{line}")
            y -= line_height

        c.drawString(50, y, f"Timestamp: {res.get('timestamp', 'N/A')}")
        y -= line_height

        c.setStrokeColor(colors.grey)
        c.line(40, y, width - 40, y)
        y -= line_height

    c.save()
    buffer.seek(0)
    with open(filename, "wb") as f:
        f.write(buffer.getvalue())

# ------------------ TKINTER GUI CLASS ------------------

class URLScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Threatify - URL Safety Scanner")
        self.root.geometry("1100x700")
        self.root.configure(bg=DARK_BG)
        self.urls = []
        self.results = []
        self.scan_thread = None
        self.pause_event = Event()
        self.cancel_event = Event()
        self.settings = {
            "vt_api_key": DEFAULT_VT_API_KEY,
            "timeout": 5,
            "heuristics_sensitivity": 1
        }
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style(self.root)
        style.theme_use('equilux')
        style.configure("Treeview", background=DARK_BG, fieldbackground=DARK_BG, foreground=DARK_FG, rowheight=28, font=("Consolas", 11))
        style.configure("Treeview.Heading", background=ACCENT_PURPLE, foreground="#fff", font=("Arial", 12, "bold"))
        style.map("Treeview", background=[('selected', ACCENT_BLUE)])
        style.configure("TButton", background=ACCENT_GREEN, foreground="#fff", font=("Arial", 11), borderwidth=0)
        style.configure("TEntry", fieldbackground=DARK_BG, foreground=DARK_FG, font=("Consolas", 12))
        style.configure("TLabel", background=DARK_BG, foreground=DARK_FG, font=("Arial", 12))
        style.configure("TFrame", background=DARK_BG)
        style.configure("TScrollbar", background=DARK_BG)

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # URL Entry and Controls
        entry_frame = ttk.Frame(frame)
        entry_frame.grid(row=0, column=0, columnspan=4, sticky="ew")
        self.url_entry = ttk.Entry(entry_frame, width=70)
        self.url_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.url_entry.bind("<Return>", lambda e: self.add_url())
        ttk.Button(entry_frame, text="Add URL", command=self.add_url).pack(side="left", padx=5)
        ttk.Button(entry_frame, text="Load from File", command=self.load_from_file).pack(side="left", padx=5)
        ttk.Button(entry_frame, text="Clear URLs", command=self.clear_urls).pack(side="left", padx=5)
        ttk.Button(entry_frame, text="Settings", command=self.open_settings).pack(side="left", padx=5)

        # URL Listbox
        self.url_listbox = tk.Listbox(frame, font=("Consolas", 11), width=80, height=6, bg=DARK_BG, fg=DARK_FG, selectbackground=ACCENT_BLUE, selectforeground="#fff")
        self.url_listbox.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        self.url_listbox.bind("<Delete>", lambda e: self.remove_selected_url())
        ttk.Button(frame, text="Remove Selected", command=self.remove_selected_url).grid(row=1, column=3, padx=5, pady=5)

        # Search Bar
        search_frame = ttk.Frame(frame)
        search_frame.grid(row=2, column=0, columnspan=4, sticky="ew")
        ttk.Label(search_frame, text="Search Results:").pack(side="left", padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.update_tree_filter)
        ttk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side="left", padx=5, fill="x", expand=True)

        # Scan Controls
        scan_btn = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        scan_btn.grid(row=3, column=0, padx=5, pady=10, sticky="ew")
        ttk.Button(frame, text="Pause", command=self.pause_scan).grid(row=3, column=1, padx=5, pady=10, sticky="ew")
        ttk.Button(frame, text="Resume", command=self.resume_scan).grid(row=3, column=2, padx=5, pady=10, sticky="ew")
        ttk.Button(frame, text="Cancel", command=self.cancel_scan).grid(row=3, column=3, padx=5, pady=10, sticky="ew")

        # Progress Bar
        self.progress = ttk.Progressbar(frame, orient="horizontal", mode="determinate", length=900)
        self.progress.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        # Results Table
        self.tree = ttk.Treeview(frame, columns=("URL", "Status", "Score", "Safety", "VT", "CVE", "Timestamp"), show="headings", height=10)
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor="center")
        self.tree.grid(row=5, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")
        self.tree.bind("<Motion>", self.on_tree_motion)

        # Log Output
        self.log_text = scrolledtext.ScrolledText(frame, font=("Consolas", 10), height=8, width=110, bg="#181c22", fg="#fff")
        self.log_text.grid(row=6, column=0, columnspan=4, padx=5, pady=5, sticky="ew")

        # Export Buttons
        export_frame = ttk.Frame(frame)
        export_frame.grid(row=7, column=0, columnspan=4, pady=10, sticky="ew")
        ttk.Button(export_frame, text="Export PDF", command=self.export_pdf).pack(side="left", padx=5)
        ttk.Button(export_frame, text="Export CSV", command=self.export_csv).pack(side="left", padx=5)
        ttk.Button(export_frame, text="Export JSON", command=self.export_json).pack(side="left", padx=5)

        frame.grid_rowconfigure(5, weight=1)
        frame.grid_columnconfigure(0, weight=1)

    def add_url(self):
        url = self.url_entry.get().strip()
        if url and url not in self.urls:
            if not re.match(r'https?://', url):
                messagebox.showwarning("Invalid URL", "URL must start with http:// or https://")
                return
            self.urls.append(url)
            self.url_listbox.insert(tk.END, url)
            self.url_entry.delete(0, tk.END)

    def load_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r") as f:
                for line in f:
                    url = line.strip()
                    if url and url not in self.urls:
                        if re.match(r'https?://', url):
                            self.urls.append(url)
                            self.url_listbox.insert(tk.END, url)

    def clear_urls(self):
        self.urls.clear()
        self.url_listbox.delete(0, tk.END)

    def remove_selected_url(self):
        selected = self.url_listbox.curselection()
        for idx in reversed(selected):
            self.urls.pop(idx)
            self.url_listbox.delete(idx)

    def start_scan(self):
        if not self.urls:
            messagebox.showwarning("No URLs", "Please add URLs to scan.")
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.log_text.delete(1.0, tk.END)
        self.pause_event.clear()
        self.cancel_event.clear()
        self.progress["value"] = 0
        self.progress["maximum"] = len(self.urls)
        self.scan_thread = ThreadPoolExecutor(max_workers=5)
        self.root.after(100, self.scan_urls_parallel)

    def scan_urls_parallel(self):
        futures = []
        for url in self.urls:
            if self.cancel_event.is_set():
                self.update_log("Scan cancelled by user.")
                break
            while self.pause_event.is_set():
                time.sleep(0.3)
            futures.append(self.scan_thread.submit(
                scan_url, url,
                self.settings["vt_api_key"],
                self.settings["heuristics_sensitivity"],
                self.settings["timeout"]
            ))
        completed = 0
        for future in as_completed(futures):
            if self.cancel_event.is_set():
                break
            result = future.result()
            self.results.append(result)
            self.insert_tree_row(result)
            completed += 1
            self.progress["value"] = completed
            self.update_log(f"Scanned: {result['url']} | {result['safety']}")
        self.update_log("Scan completed.")

    def pause_scan(self):
        self.pause_event.set()
        self.update_log("Scan paused.")

    def resume_scan(self):
        self.pause_event.clear()
        self.update_log("Scan resumed.")

    def cancel_scan(self):
        self.cancel_event.set()
        self.update_log("Cancelling scan...")

    def update_log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def insert_tree_row(self, result):
        row_id = self.tree.insert("", tk.END, values=(
            result["url"], result["status"], result["score"], result["safety"],
            result["vt_malicious"], result["nvd_cve"], result["timestamp"]
        ))
        color = ROW_COLORS.get(result["safety"], DARK_BG)
        self.tree.tag_configure(result["safety"], background=color, foreground="#000" if result["safety"] == "Safe" else "#fff")
        self.tree.item(row_id, tags=(result["safety"],))

    def update_tree_filter(self, *args):
        search = self.search_var.get().lower()
        for row in self.tree.get_children():
            vals = self.tree.item(row, "values")
            if any(search in str(val).lower() for val in vals):
                self.tree.reattach(row, '', 'end')
            else:
                self.tree.detach(row)

    def on_tree_motion(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            vals = self.tree.item(row, "values")
            reasons = ""
            for res in self.results:
                if res["url"] == vals[0]:
                    reasons = res["reasons"]
                    break
            self.tree.tooltip = reasons
        else:
            self.tree.tooltip = ""

    def export_pdf(self):
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if file_path:
            append_to_report_pdf(self.results, file_path)
            messagebox.showinfo("Exported", f"PDF report saved to:\n{file_path}")

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Status", "Score", "Safety", "VT Malicious", "NVD CVE", "Timestamp", "Reasons"])
                for res in self.results:
                    writer.writerow([
                        res["url"], res["status"], res["score"], res["safety"],
                        res["vt_malicious"], res["nvd_cve"], res["timestamp"], res["reasons"]
                    ])
            messagebox.showinfo("Exported", f"CSV report saved to:\n{file_path}")

    def export_json(self):
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "w", encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            messagebox.showinfo("Exported", f"JSON report saved to:\n{file_path}")

    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.configure(bg=DARK_BG)
        tk.Label(win, text="VirusTotal API Key:", bg=DARK_BG, fg=DARK_FG).grid(row=0, column=0, sticky="e", padx=5, pady=5)
        api_var = tk.StringVar(value=self.settings["vt_api_key"])
        api_entry = tk.Entry(win, textvariable=api_var, show="*", width=40, bg=DARK_BG, fg=DARK_FG, insertbackground=DARK_FG)
        api_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(win, text="Timeout (seconds):", bg=DARK_BG, fg=DARK_FG).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        timeout_var = tk.IntVar(value=self.settings["timeout"])
        tk.Entry(win, textvariable=timeout_var, width=10, bg=DARK_BG, fg=DARK_FG, insertbackground=DARK_FG).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        tk.Label(win, text="Heuristics Sensitivity (1-3):", bg=DARK_BG, fg=DARK_FG).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        heur_var = tk.IntVar(value=self.settings["heuristics_sensitivity"])
        tk.Entry(win, textvariable=heur_var, width=10, bg=DARK_BG, fg=DARK_FG, insertbackground=DARK_FG).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        def save_settings():
            self.settings["vt_api_key"] = api_var.get()
            self.settings["timeout"] = timeout_var.get()
            self.settings["heuristics_sensitivity"] = heur_var.get()
            win.destroy()
        tk.Button(win, text="Save", command=save_settings, bg=ACCENT_GREEN, fg="#fff").grid(row=3, column=0, columnspan=2, pady=10)

# ------------------ MAIN ------------------

if __name__ == '__main__':
    root = ThemedTk(theme="equilux")
    app = URLScannerGUI(root)
    root.mainloop()
