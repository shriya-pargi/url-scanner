# URL Safety Scanner

This project is a Python desktop application for bulk URL safety and threat scanning. It features a modern Tkinter GUI, leverages heuristics, VirusTotal, and NVD CVE databases to flag suspicious or malicious URLs, and offers parallel scanning with detailed PDF/CSV/JSON exports.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Usage](#usage)
    - [Add/Load URLs](#addload-urls)
    - [Start Scan](#start-scan)
    - [Pause/Resume/Cancel](#pauseresumecancel)
    - [Search/Filter](#searchfilter)
    - [Export Results](#export-results)
    - [Settings](#settings)
- [Scanning Logic](#scanning-logic)
    - [Heuristics](#heuristics)
    - [VirusTotal Integration](#virustotal-integration)
    - [NVD CVE Integration](#nvd-cve-integration)
    - [Trusted Domains](#trusted-domains)
    - [Safety Score](#safety-score)
- [GUI Overview](#gui-overview)
- [Extending & Customizing](#extending--customizing)
- [Limitations](#limitations)
- [License](#license)

---

## Features

- **Modern Tkinter (ttkthemes) based GUI**
- **Bulk scan** URLs for phishing, malware, and vulnerabilities
- Heuristics for common phishing/red-flag patterns
- **VirusTotal** API integration
- **NVD (CVE)** database search for reported domain vulnerabilities
- **Parallel scanning** with progress and logs
- Table with safety color-coded rows and instant search/filter
- **Export** results to PDF, CSV, or JSON
- Adjustable **settings**: API key, timeout, heuristics
- Session-level caches for API responses

---

## Project Structure

- `main.py` (all code in a single file as presented)
- All app logic (scanning, GUI, PDF/CSV/JSON export) in one file

---

## Installation

1. **Clone or copy the repository/project files.**

2. **Install dependencies:**

    ```
    pip install tkinter ttkthemes requests python-whois reportlab
    ```

    - For Linux: You may need to install `python3-tk` and `python3-pil`.
    - For MacOS: Tkinter is included with Python, but ensure your python install supports it.

3. **Obtain a VirusTotal API key:**
    - Sign up at [virustotal.com](https://www.virustotal.com/) for a free parent key.

4. **Set your API key in the code or via the settings window.**

---

## Dependencies

- `tkinter`, `ttkthemes` — GUI
- `requests` — HTTP requests
- `python-whois` — Domain age lookup
- `reportlab` — PDF generation
- `csv`, `json` — Export
- `concurrent.futures`, `threading` — Parallel scans
- `re`, `base64`, `io`, `time`, `textwrap`, `datetime`

---

## Configuration

- The default VirusTotal API key is set via `DEFAULT_VT_API_KEY`.
- You **must** provide your own personal VirusTotal API key in the settings.
- Other configurable settings: request timeout, heuristics sensitivity (threshold for heuristic rules.)

---

## Usage

### Add/Load URLs

- Type or paste a URL (must start with `http://` or `https://`) and click **"Add URL"**.
- Or use **"Load from File"** to import a text file (one URL per line).

### Start Scan

- Click **"Start Scan"** to scan all URLs in the list.
- The scan runs in parallel (up to 5 workers by default), progress and results update in real-time.
- **Results Table**: Green (Safe), Yellow (Suspicious), Orange (Unsafe), Red (Very Unsafe).

### Pause/Resume/Cancel

- **Pause**: Temporarily stop scanning.
- **Resume**: Continue paused scan.
- **Cancel**: Abort ongoing scans.

### Search/Filter

- Instant search on results table. Enter any term (URL, score, status) in the "Search Results" box.

### Export Results

- **Export PDF**: Save a formatted scan report as PDF.
- **Export CSV**: Save a spreadsheet-ready CSV.
- **Export JSON**: Save all data in JSON format.

### Settings

- Open **Settings** (button).
- Set your VirusTotal API Key, timeout, and heuristics sensitivity.

---

## Scanning Logic

### Heuristics

- **Red Flags Checked:**
    - URL contains IP address.
    - Suspicious words (login, secure, verify, bank, ...)
    - Phishing keywords (free, bonus, urgent, winner, ...)
    - Suspicious TLDs (`.biz`, `.xyz` etc.)
    - URL excessively long (>75 chars)
    - Domain is very new (e.g. < 180 days)
    - Many phishing keywords in the URL
- **Each red flag increases the suspicion score.**

### VirusTotal Integration

- Submits each URL to VirusTotal (using your API key).
- Fetches scan results if already available.
- Adds the VT "malicious" count to suspicion score.

### NVD CVE Integration

- Uses the NVD (National Vulnerability Database) API to search for vulnerabilities related to the URL's domain or technology.
- Reports any CVEs found and bumps the suspicion score.

### Trusted Domains

- Known major domains (e.g. youtube.com, google.com) are whitelisted and always marked Safe.

### Safety Score

- **Safe**: low/no score
- **Suspicious**: a couple of red flags
- **Unsafe**: several flags or evidence of compromise
- **Very Unsafe**: high suspicion score or confirmed malicious

---

## GUI Overview

- **URL Entry controls**: Add, load, clear, remove
- **URL List**: Shows all currently queued URLs
- **Scan Controls**: Start, Pause, Resume, Cancel
- **Progress Bar**: Indicates batch progress
- **Results Table**: All scanned URLs with details (color-coded)
- **Detailed Log Output**: Operational logs
- **Export Buttons**: Save as PDF, CSV, JSON
- **Settings Dialog**: API key and preferences

---

## Extending & Customizing

- **To add custom heuristics**: Add logic in `scan_url` or the helper functions.
- **To increase parallelism**: Change the `max_workers` parameter in the ThreadPool.
- **Result columns and exports**: Adjust GUI and export code as needed.
- **PDF styling**: Edit the `append_to_report_pdf` function.

---

## Limitations

- VirusTotal API rate limits: Free tier has limitations on requests per minute/day.
- Depends on public APIs for VT and NVD; connection errors or outages may affect functionality.
- Suspicion heuristics are simple and can be bypassed by advanced attackers.
- Whois (domain age) data is not always available for every domain.
- For large lists and slow connections, scanning can be slow.
- PDF export depends on ReportLab; complex data is truncated after 5 CVEs.

---

## License

MIT License — Use, copy, modify freely for non-commercial and commercial purposes.

---

© 2025 Shriya Pargi
