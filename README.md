# EMLNaitor

Perfect 👍 I’ll prepare you a **professional English explanation** for your GitHub repo (`README.md`) that describes how your code works step by step. You can copy-paste this directly or adapt it.

---

# 📌 How the Code Works

This project is a **cybersecurity analysis tool** designed to process `.eml` email files and extract valuable security information about the sender, domains, and any associated web content.

### 🔍 Workflow Overview

1. **Input and Base64 Decoding**

   * The script takes an `.eml` file as input.
   * It decodes the Base64 content of the email and stores it as a plain text file (`mail.txt`).

2. **Email Header & Security Analysis**

   * Extracts key authentication results such as **DKIM, ARC, and SPF** from the headers.
   * Verifies whether the domains in the `From`, `DKIM`, and `SPF` fields match, which helps detect spoofing attempts.
   * Detects if the email has been **forwarded**.

3. **Sender Information Extraction**

   * Extracts the **"From:"** field and the sender’s domain.
   * Retrieves the **SMTP mailfrom** field.
   * Extracts the **email subject** for reference.

4. **HTML & URL Extraction**

   * If the email contains an **HTML body**, it extracts it into `mail.html` and automatically opens it in Firefox for inspection.
   * Finds and lists all **URLs** contained in the email body.

5. **Domain & Reputation Checks**

   * Performs a **Whois lookup** to retrieve domain creation date (useful for spotting newly registered suspicious domains).
   * Queries **VirusTotal API** to fetch domain reputation, categories, and detection ratios.
   * Queries **urlscan.io API** to generate a report and retrieve a live screenshot of the domain for visual inspection.

6. **Reporting**

   * Consolidates all findings into a structured console report, including:

     * Authentication results (SPF, DKIM, ARC).
     * Sender information.
     * Reputation lookups.
     * Whois creation date.
     * Screenshot from urlscan.io.
     * Extracted URLs from the email body.

### ⚙️ Key Features

* **Base64 decoding** of `.eml` email files.
* **SPF, DKIM, ARC authentication analysis**.
* **Sender and domain extraction**.
* **Automated HTML preview** of the email.
* **Integration with VirusTotal and urlscan.io APIs**.
* **Whois lookup** to check domain registration details.
* **Formatted security report** for quick investigation.

### 🛠️ Requirements

* Python 3.x
* Dependencies listed in `requirements.txt`:

  ```
  requests
  python-whois
  colorama
  pyreadline (Windows only)
  ```

### 🚀 Usage

1. Place your `.eml` file in the project folder.
2. Run the script:

   ```bash
   python main.py
   ```
3. Enter the name of your `.eml` file when prompted.
4. The tool will:

   * Decode the email.
   * Analyze headers.
   * Query VirusTotal and urlscan.io.
   * Print a full security report.
   * Extract HTML and open it in Firefox.

<img width="1933" height="1180" alt="image" src="https://github.com/user-attachments/assets/3e520e08-6fbc-4e2c-93ff-e6f6e4012d97" />

So as a resume

Here’s the translation in English:

📥 An `.eml` file is loaded.

🔑 It is Base64 decoded → `mail.txt`.

📧 Email headers are analyzed (SPF, DKIM, ARC, From, etc.).

🌐 Domains are extracted.

🕵️ Reputation checks are performed (VirusTotal, urlscan.io, Whois).

💻 HTML content is extracted → `mail.html`.

🔗 URLs are extracted.

📊 A final security report is generated.


