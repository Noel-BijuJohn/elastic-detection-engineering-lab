# Project Report — Elastic SIEM Threat Detection

> This report documents the design, implementation, and validation of a SIEM-based threat detection lab using Elastic Stack.

**Author:** Noel Biju John
**Role:** SOC Analyst Intern
**Date:** March 2026
**Platform:** Elastic Stack (Kibana, Elasticsearch, Fleet, Packetbeat)

---

## Executive Summary

This project designed and validated a custom threat detection environment using the Elastic SIEM platform to identify three distinct attack techniques: credential stuffing, DNS tunneling, and PowerShell exploitation. A controlled lab was built from scratch consisting of a Kali Linux attacker machine, a Windows 11 target host, and an Elastic Stack deployment. Detection rules were engineered for each scenario, attacks were simulated live, and all five rules generated confirmed alerts in the Elastic Security dashboard.

---

## Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Set up a functional SIEM environment using Elastic Stack | ✅ Complete |
| 2 | Ingest and parse logs from Windows, network, and custom application sources | ✅ Complete |
| 3 | Simulate credential stuffing, DNS tunneling, and PowerShell exploitation | ✅ Complete |
| 4 | Design and implement detection rules targeting each attack technique | ✅ Complete |
| 5 | Validate rules through live attack simulation and confirm alert generation | ✅ Complete |

---

## Scenario 1 — Credential Stuffing

### Attack Overview
An attacker iterates through a list of stolen credentials against a login endpoint. The attack produces a high volume of failed authentication events, sometimes followed by a successful login when a valid credential is found.

### Detection Approach
Two complementary rules were created:
- A **threshold rule** targeting volume: ≥20 failures from a single source IP within 5 minutes
- An **EQL sequence rule** targeting the moment of compromise: a failure-then-success sequence from the same IP and username within 5 minutes

### Key Engineering Decisions
- The EQL rule targets a more specific behavioral pattern than the threshold rule — effective even when an attacker stays below the failure threshold
- Both rules provide **layered coverage**: the threshold rule detects the attempt phase; the EQL rule detects the compromise phase
- A custom ingest pipeline (`auth-log-parser`) was built to parse flat log lines into ECS-compliant fields using a dissect processor, enabling structured queries and rule evaluation

### Troubleshooting
The EQL rule initially failed to fire. Investigation revealed a case sensitivity mismatch: the pipeline had normalized `event.outcome` to lowercase, but the rule query used uppercase values (`"FAILURE"`, `"SUCCESS"`). Correcting the query to lowercase resolved the issue.

### Alert Results
| Rule | Severity | Risk Score | Triggered At |
|---|---|---|---|
| Credential Stuffing — Failed Logins from Single IP | High | 70 | 21:14:11, March 9 2026 |
| Credential Stuffing — Failure Followed by Successful Login | High | 80 | 21:40:38, March 9 2026 |

---

## Scenario 2 — DNS Tunneling

### Attack Overview
DNS tunneling encodes data within DNS queries to communicate with external systems or exfiltrate information. Because DNS traffic is generally permitted through firewalls, it can serve as a covert channel that blends with normal network activity.

### Detection Approach
A **threshold rule** was created to detect abnormally high DNS query volume from a single source IP:
- ≥50 queries within a 5-minute window, grouped by `source.ip`
- Deliberately avoids domain-specific matching — targets behavioral anomaly instead
- Remains effective even when attackers rotate domains or infrastructure

Network-level packet capture was enabled using the **Packetbeat** integration in Fleet, capturing DNS traffic on port 53 and indexing it under `logs-network*`.

### Key Engineering Decisions
- NXDOMAIN responses during simulation are **expected and do not invalidate detection** — DNS tunneling encodes data in the query name itself, not the response
- Threshold of 50 queries per 5 minutes was calibrated to clearly exceed normal browsing behavior while catching early-stage tunneling activity

### Troubleshooting
No DNS logs appeared in Elasticsearch during the initial simulation. Investigation found that the Network Packet Capture integration had not yet been enabled in Fleet, so Packetbeat was not capturing traffic. Enabling the integration and updating the agent policy resolved the issue.

### Alert Results
| Rule | Severity | Risk Score | Triggered At |
|---|---|---|---|
| DNS Tunneling — Abnormal Query Volume | High | 73 | 21:51:09, March 9 2026 |

---

## Scenario 3 — PowerShell Exploitation

### Attack Overview
PowerShell is a legitimate Windows administration tool frequently abused by attackers during post-exploitation. Common uses include establishing reverse shells, downloading remote payloads, executing encoded commands, and bypassing execution policies.

### Detection Approach
A **keyword-based query rule** was created targeting PowerShell Script Block Logging events (Event ID 4104). The rule matches on keywords associated with malicious PowerShell usage: `TCPClient`, `IEX`, `Invoke-Expression`, `DownloadString`, `bypass`, `EncodedCommand`, `FromBase64String`, and `Net.WebClient`.

An additional **EQL sequence rule** (`powershell_network_correlation.eql.ndjson`) correlates a suspicious script block execution with an outbound network connection from the same host within 30 seconds — targeting the causal relationship between script execution and reverse shell establishment.

### Key Engineering Decisions
- **Script Block Logging (Event ID 4104)** captures the full content of executed PowerShell commands at runtime — including interactively-typed commands
- Significantly richer telemetry than simply detecting the PowerShell process launching
- Rule targets **command content**, not process execution — effective even when attackers rename the binary or use living-off-the-land techniques

### Alert Results
| Rule | Severity | Risk Score | Triggered At |
|---|---|---|---|
| PowerShell — Suspicious Execution Keywords | High | 70 | 22:17:57, March 9 2026 |

Script block content captured in Kibana Discover confirmed the exact `TCPClient` reverse shell command was recorded at execution time.

---

## Detection Rules Summary

| File | Type | Scenario | Index | Severity |
|---|---|---|---|---|
| `credential_stuffing_threshold.ndjson` | Threshold | Credential Stuffing | `logs-xampp-auth*` | High |
| `credential_stuffing_sequence.eql.ndjson` | EQL Sequence | Credential Stuffing | `logs-xampp-auth*` | High |
| `dns_tunneling_volume_threshold.ndjson` | Threshold | DNS Tunneling | `logs-network*` | High |
| `powershell_suspicious_args.ndjson` | KQL Query | PowerShell | `logs-windows*` | High |
| `powershell_network_correlation.eql.ndjson` | EQL Sequence | PowerShell | `logs-windows*` | Critical |

---

## Skills Developed

### Detection Engineering
- Rule design is not transferable across techniques — threshold rules, EQL sequences, and keyword queries each serve distinct detection purposes
- Must understand how an attack manifests in log data before a rule can be written effectively

### Log Ingestion and Parsing
- Built a full custom ingestion pipeline: dissect pattern → lowercase normalizer → ECS field mapping
- Direct experience with the full data lifecycle from raw log line to queryable structured event

### Network-Level Telemetry
- Packetbeat captures at the network level — a fundamentally different class of telemetry from file-based or Windows event log ingestion
- Understanding the distinction between host-based and network-based visibility is essential for full detection coverage

### Systematic Troubleshooting
- Both issues encountered (EQL case sensitivity mismatch, Packetbeat not enabled) were diagnosed by reasoning through the complete data pipeline
- This end-to-end pipeline thinking reflects real SOC operational practice

---

## Conclusion

All five detection rules were successfully implemented and validated through live attack simulation. Key outcomes:

- Each scenario presented a distinct engineering challenge — pipeline construction, network packet capture configuration, and behavioral threshold design
- The troubleshooting process was as instructive as the implementation itself, reinforcing the importance of end-to-end pipeline understanding
- The project demonstrates detection engineering capability across the full lifecycle: **lab design → log ingestion → rule authoring → attack simulation → alert validation**
