<h1 align="center">PHAROS</h1>

<p align="center">
  <strong>Open-source email triage and phishing analysis platform</strong><br>
  Manual <code>.eml</code> analysis, IMAP collection, risk scoring, observables extraction, attachment preview, and local reputation feedback.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/status-active-success" alt="Status">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-local--first-informational" alt="Platform">
</p>

---

## Overview

PHAROS is a local web-based tool designed to analyze suspicious emails and help classify them through technical indicators and human feedback.

It supports:
- manual `.eml` analysis,
- IMAP-based collection,
- phishing-oriented scoring,
- extraction of URLs, domains, IPs and headers,
- attachment preview,
- local sender/domain reputation tracking.

---

## Features

- Manual email analysis from `.eml` files
- IMAP collection from a mailbox
- Risk scoring with severity levels
- SPF / DKIM / DMARC inspection
- URL, domain, IP and email extraction
- Redirect chain analysis
- Attachment listing and preview
- Feedback loop for:
  - false positives
  - false negatives
  - legitimate emails
  - malicious emails
- Local reputation store for senders and domains
- Web dashboard with technical detail panels

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/AdnanTL/Pharos.git
cd Pharos
```

### 2. Create and activate the virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create your local environment file

```bash
cp .env.example .env
```

Then edit `.env` with your own values.

### 5. Run PHAROS

```bash
source .venv/bin/activate
python3 main.py
```

Then open the local URL displayed in the terminal.

---

## Configuration

PHAROS uses a local `.env` file for configuration.

Example variables:

```env
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
APP_NAME=PHAROS
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000

IMAP_ENABLED=false
IMAP_HOST=imap.example.com
IMAP_PORT=993
IMAP_USER=your_email@example.com
IMAP_PASSWORD=your_imap_password
IMAP_FOLDER=INBOX

```

### Important

- `.env` must stay local and private
- API keys must never be committed
- each user must provide their own VirusTotal and IMAP credentials if needed

---

## Usage

### Manual analysis

1. Launch the application
2. Open the web interface
3. Go to the manual analysis tab
4. Upload an `.eml` file
5. Review:
   - summary
   - observables
   - domains
   - redirects
   - attachments
   - indicators

### IMAP analysis

If IMAP is enabled in `.env`, PHAROS can collect emails directly from a mailbox and analyze them through the dashboard.

### Feedback

PHAROS supports analyst feedback to improve local classification behavior:
- false positive
- false negative
- legitimate
- malicious

---

## Project Structure

```text
PHAROS/
├── core/
│   ├── alerter.py
│   ├── analyzers.py
│   ├── collector.py
│   ├── eml_parser.py
│   ├── extractor.py
│   ├── reputation_store.py
│   ├── scoring.py
│   └── storage.py
├── templates/
│   ├── index.html
│   └── pdf_viewer.html
├── data/
│   └── .gitkeep
├── exports/
│   ├── .gitkeep
│   └── attachments/
│       └── .gitkeep
├── main.py
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Runtime Data

The following folders are used for local runtime data:
- `data/`
- `exports/`
- `exports/attachments/`

They are intentionally kept almost empty in the repository with `.gitkeep` files only.

Generated files, databases, exports and local reputation data are not meant to be committed.

---

## Security Notes

- Never commit `.env`
- Never commit API keys or IMAP passwords
- Never publish local exports or runtime databases
- Review `.gitignore` before pushing changes
- Use your own VirusTotal key if you enable that integration

---

## Contributing

Contributions are welcome, especially for:
- reducing false positives
- improving scoring logic
- improving explainability
- refining UI/UX
- improving documentation
- extending attachment analysis

---

## License

This project is released under the MIT License.
