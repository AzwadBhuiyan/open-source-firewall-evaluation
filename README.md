# Investigation and Evaluation of Open-Source Web Application Firewalls

**Project Scale:** `20,000+ Payloads Tested` | `4 Attack Categories` | `Custom Python Automation` | `Multi-OS Virtual Lab (Kali, Ubuntu, Windows)`

This repository contains the custom testing scripts, curated attack payload lists, raw CSV log results, and virtual lab documentation for our capstone investigation into open-source Web Application Firewalls (WAFs).

The goal of this project is to test, compare, and evaluate how effectively free, open-source web firewalls—specifically **ModSecurity** and **NAXSI** (with **Coraza** in the extended scope)—detect and block real-world web attacks when configured with industry-standard security rules.

> 📄 **Final Comparative Report:** This README covers the project background, virtual lab setup, and testing methodology. For the complete cross-firewall data analysis, findings, and final recommendations, see the **[Report (PDF)](./docs/Final_WAF_Comparison_Report.pdf)** *(uploaded upon completion of all test stages)*.

---

## 1. Background & Key Concepts (Plain-English Overview)

To make this project clear to readers from outside cybersecurity—including recruiters, hiring managers, and academic assessors—this section explains the core concepts behind our work:

### What is a Web Application Firewall (WAF)?
Standard network firewalls protect computers from unauthorized network connections, but they must allow normal web traffic (HTTP/HTTPS) through so people can visit websites. A **Web Application Firewall (WAF)** sits directly in front of a website and inspects every incoming request—such as a user logging in, typing into a search bar, or uploading a file. If the WAF detects malicious code hidden inside a request, it blocks the traffic before it can reach the website or database.

### What are the OWASP Top 10 and the Core Rule Set (CRS)?
* **OWASP Top 10:** Maintained by the Open Worldwide Application Security Project (OWASP), this is the globally recognized standard listing the ten most critical security risks facing web applications today.
* **OWASP Core Rule Set (CRS):** A firewall engine by itself does not know what an attack looks like until it is given rules. The **Core Rule Set** is an open-source rulebook plugged into firewalls like ModSecurity. It provides hundreds of detection patterns built to catch OWASP Top 10 attacks.

### How Firewall Scoring, Logs, and Results Work
When we send thousands of test attacks at a firewall, several different outcomes can happen. Understanding these terms is essential to reading our CSV results and logs:
* **Blocked Request (`HTTP 403 Forbidden`):** The firewall recognized the request as an attack and stopped it immediately. The payload never reached the website.
* **Allowed Request (`HTTP 200 OK`):** The request passed through the firewall and reached the website.
* **Detected / Alerted, But Still Allowed:** Firewalls using the OWASP Core Rule Set rely on **anomaly scoring**. Instead of blocking a request the moment it looks slightly unusual, each triggered rule adds points to a threat score (the default blocking threshold is **5**). If a sneaky attack only triggers a low-severity rule worth 2 or 3 points, the firewall writes a warning in its **Alert Log** (`Detected = Yes`), but still lets the request pass through to the website (`Blocked = No`).
* **False Negative (Bypass):** A real attack that slips past the firewall without being blocked—either because no rule matched it, or because its threat score stayed below the blocking threshold.
* **False Positive:** When a normal, harmless user request (for example, someone with an apostrophe in their last name like *O'Connor*) accidentally triggers a firewall rule and gets blocked by mistake.

---

## 2. Why We Switched from Automated Scanners to Custom Scripts

In the first phase of our project (COMP6015), we tested the firewalls using automated vulnerability scanners like **OWASP ZAP**, **Nikto**, and **SQLmap** (archived in the `ZAP_Attack_Logs/` folder). 

While automated scanners are fast, they fire thousands of unorganized requests at once. That made it difficult to see which specific payload triggered which firewall rule, and often overloaded the virtual machines.

To make our testing rigorous, repeatable, and clear, we built a custom scripted pipeline:
1. **Single-Request Python Scripts:** We wrote custom Python scripts that load attack payloads from text files and send **one request at a time** to the target web application.
2. **Curated Real-World Payloads:** Our payload lists were gathered and refined from respected security resources, including the **PortSwigger Web Security Academy**, **SecLists**, **PayloadsAllTheThings**, **DirBuster (`directory-list-2.3-big.txt`)**, **Assetnote**, **GitHub `payload-box`**, and **Xfeed**.
3. **Automated Log Correlation:** For every single request sent, our Python script records the exact payload, the HTTP status code returned (`200` vs `403`), the server response time in milliseconds, and the exact firewall rule IDs triggered in the backend logs, saving the output directly to a structured CSV file.

---

## 3. Attack Categories Tested

Each firewall is evaluated against four major web attack types:

* **SQL Injection (SQLi):** Sending malicious database commands through input fields to bypass login screens or extract private data from the backend database.
* **Cross-Site Scripting (XSS):** Injecting malicious JavaScript code into web pages to steal session tokens or hijack user browsers. We tested both **Reflected XSS** (`GET` requests via URL parameters) and **Stored XSS** (`POST` requests saved into the application database).
* **Path Traversal (Directory Traversal):** Manipulating file paths (such as `../../../../etc/passwd`) to break out of the web server folder and read restricted operating system files.
* **XML External Entity (XXE):** Sending crafted XML payloads to trick the application parser into exposing local server files or interacting with internal network services.

---

## 4. Virtual Lab Architecture

All testing was conducted inside an isolated virtual network so that no external systems or live networks were affected:

```text
[ Attacker VM: Kali Linux ]
   │  (Runs custom Python scripts & curated payload files)
   ▼
   │  Sends 1 HTTP Request at a time
   ▼
[ Open-Source WAF: ModSecurity (OWASP CRS) / NAXSI ]
   │
   ├──► Blocked (HTTP 403) ──► Recorded in WAF Alert Log (Attack stopped)
   │
   └──► Allowed (HTTP 200) ──► Reaches [ Target Web App: DVWA ]
                                  └──► Recorded in Web Server Access Log & WAF Log
```

### Virtual Machines (`OVA_Files/`)
* **Offensive Machine:** Kali Linux OVA (used by all team members to run identical Python scripts and payload lists).
* **Victim / Target Machines:** 
  * **Ubuntu Server** (Primary target hosting Apache/Nginx, the WAFs, and DVWA).
  * **Windows Server & Windows 11 Client** (Secondary target environments configured with DVWA and WAF instances for cross-platform testing).
* **Target Web Application:** **DVWA (Damn Vulnerable Web Application)**—an intentionally vulnerable web application designed for controlled security testing.

---

## 5. Repository Structure

```text
open-source-firewall-evaluation/
├── modsecurity/                # ModSecurity + OWASP Core Rule Set test suites
│   ├── SQLi/                   # SQL Injection payloads, Python runner, CSV results, notes
│   ├── XSS/                    # Reflected & Stored XSS payloads, script, CSV results, notes
│   ├── Path_traversal/         # Directory traversal wordlists, script, CSV results, notes
│   └── XML_attack_XXE/         # XXE payloads, Python script, CSV results, notes
│
├── naxsi/                      # Identical attack suites executed against the NAXSI firewall
│   ├── SQLi/
│   ├── XSS/
│   ├── Path_traversal/
│   └── XML_attack_XXE/
│
├── ZAP_Attack_Logs/            # Baseline logs from earlier automated scanner testing (ZAP)
├── OVA_Files/                  # VM specifications, setup guide, and external image links
├── docs/                       # Project reports and Final Comparative Evaluation PDF
├── requirements.txt            # Python libraries required to run the testing scripts
└── README.md
```

Inside each attack directory (e.g., `modsecurity/SQLi/` or `naxsi/XSS/`), you will find:
* **`payloads/`** — Text files containing the attack strings sent during testing.
* **`results/`** — Raw CSV files containing per-request outcomes, response times, and matched firewall rules.
* **`*.py`** — The custom Python automation script used to execute the payloads and parse the logs.
* **`*.docx` / `*.md`** — Documentation covering the test setup, observations, and analysis for that attack type.

---

## 6. Sample Baseline Findings (ModSecurity + OWASP CRS)

Below is a snapshot of our baseline results on ModSecurity before comparing against NAXSI:

### SQL Injection Benchmark (7,229 Payloads)
| Metric | Count | Rate | Plain-English Meaning |
| :--- | :--- | :--- | :--- |
| **Total Requests Sent** | 7,229 | 100.00% | All scheduled SQLi payloads completed without script errors |
| **Rule Alerts Logged** | 7,229 | 100.00% | Every request triggered at least one ModSecurity log entry |
| **Blocked (`HTTP 403`)** | 3,609 | 49.92% | Roughly half of the attacks were stopped by the firewall |
| **Detected but Allowed (`HTTP 200`)** | 3,620 | 50.08% | Triggered low-score rules, but stayed below the block threshold |

### Cross-Site Scripting (XSS) Benchmark (10,000 Payloads)
| Metric | Reflected XSS (`GET`) | Stored XSS (`POST`) | Combined Total |
| :--- | :--- | :--- | :--- |
| **Total Requests Sent** | 5,000 | 5,000 | 10,000 |
| **Rule Alerts Logged** | 5,000 (100%) | 5,000 (100%) | 10,000 (100.00%) |
| **Blocked (`HTTP 403`)** | 5,000 (100%) | 5,000 (100%) | 10,000 (100.00%) |
| **Allowed (`HTTP 200`)** | 0 (0%) | 0 (0%) | 0 (0.00%) |

* **Key Takeaway:** Under default OWASP CRS settings, ModSecurity blocked 100% of XSS payloads (via the `941xxx` rule group), whereas 50.08% of SQLi requests passed through because their anomaly scores did not reach the default blocking threshold. Full comparisons with NAXSI and Path Traversal / XXE results are detailed in the individual folders and final report.

---

## 7. How to Run the Scripts & Read the Results

### 1. Clone the repository and install dependencies
```bash
git clone [https://github.com/](https://github.com/)<your-username>/open-source-firewall-evaluation.git
cd open-source-firewall-evaluation
pip install -r requirements.txt
```

### 2. Run an attack test script
Make sure your target VM is running and reachable on the isolated lab network, then run the Python script inside the desired attack folder:
```bash
cd modsecurity/SQLi/
python3 run_sqli.py
```
*(Note: Our Python scripts write results to disk after every single request so no data is lost if a virtual machine connection drops during multi-thousand-payload runs.)*

### 3. Understanding the CSV Columns
Each output file in `results/` records the following columns:
* `request_id` / `payload_id`: Unique ID tracking the test number.
* `payload`: The exact attack string sent to DVWA.
* `http_status`: `403` (Blocked by WAF) or `200` (Allowed through to DVWA).
* `waf_detected`: `Yes` if any WAF rule was logged during the request.
* `waf_blocked`: `Yes` if the WAF actively dropped/blocked the request.
* `time_ms`: Round-trip response time in milliseconds.
* `rules`: The exact rule IDs and descriptions triggered (e.g., `942100: SQL Injection Attack Detected via libinjection`).

---

## 8. Project Governance & Academic Details

* **Unit:** COMP6016 Capstone Project — Curtin University
* **Supervisor:** Mihai Lazarescu
* **Group:** Group 6
* **Project Management:** Managed using **Jira** (Scrum/Kanban boards) for sprint planning and task tracking, and **GitHub** for version control and dataset sharing.
