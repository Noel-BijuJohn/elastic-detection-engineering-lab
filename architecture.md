# Lab Architecture

## Overview

This project uses a three-node virtual lab to simulate, detect, and alert on three distinct attack techniques. All components run on the same physical host using a local network bridge.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PHYSICAL HOST                               │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐   ┌───────────────┐  │
│  │   Kali Linux     │    │   Windows 11     │   │ Elastic Stack │  │
│  │   (Attacker)     │    │   (Target)       │   │  (SIEM)       │  │
│  │                  │    │                  │   │               │  │
│  │ curl loop        │───▶│ XAMPP / PHP app  │   │ Elasticsearch │  │
│  │ nslookup loop    │    │ auth.log         │──▶│ Kibana        │  │
│  │ PowerShell rev   │    │ Elastic Agent    │   │ Fleet         │  │
│  │   shell listener │    │ Packetbeat       │   │               │  │
│  │                  │    │ WinEvtLog        │   │ Detection     │  │
│  │ 172.30.80.2 /    │    │                  │   │ Rules Engine  │  │
│  │ 172.30.89.150    │    │ 172.30.80.1      │   │               │  │
│  └──────────────────┘    └──────────────────┘   └───────────────┘  │
│                                    │                    ▲           │
│                                    └────────────────────┘           │
│                              Log forwarding (Elastic Agent)         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Components

### Kali Linux — Attacker Machine
- Simulates attacker activity for all three scenarios
- Tools used: `curl`, `nslookup`, `netcat`
- Generates credential stuffing traffic, DNS query bursts, and reverse shell connections
- IPs: `172.30.80.2` (credential stuffing), `172.30.89.150` (PowerShell C2 listener)

### Windows 11 — Target / Monitored Host (`pavillion15`)
- Runs XAMPP to host the vulnerable PHP login application at `/lab/login.php`
- Generates `auth.log` at `C:\xampp\htdocs\lab\auth.log`
- Elastic Agent installed and enrolled in Fleet
- Packetbeat captures DNS traffic on the network interface
- Windows Event Log forwarding enabled (Security + PowerShell channels)
- PowerShell Script Block Logging enabled (Event ID 4104)
- IP: `172.30.80.1`

### Elastic Stack — SIEM Platform
- **Elasticsearch**: Log storage and indexing
- **Kibana**: Analysis interface, detection rule management, alert dashboard
- **Fleet**: Centralized agent and integration management
- **Elastic Security**: Detection rule engine and alert triage

---

## Data Flows

### Scenario 1 — Credential Stuffing

```
Kali curl loop
  → HTTP POST to Windows XAMPP (172.30.80.1/lab/login.php)
    → auth.log written to C:\xampp\htdocs\lab\auth.log
      → Elastic Agent (Filestream) ingests log lines
        → Ingest pipeline (auth-log-parser) parses into ECS fields
          → Indexed in logs-xampp-auth*
            → Threshold rule + EQL rule evaluate → Alerts in Kibana
```

### Scenario 2 — DNS Tunneling

```
Windows nslookup loop
  → DNS queries sent to resolver (port 53)
    → Packetbeat captures packets on network interface
      → DNS events forwarded to Elasticsearch
        → Indexed in logs-network*
          → Threshold rule evaluates query volume → Alert in Kibana
```

### Scenario 3 — PowerShell Exploitation

```
Windows PowerShell execution (TCPClient reverse shell)
  → Script Block Logging writes Event ID 4104 to PowerShell/Operational log
    → Elastic Agent (Windows integration) forwards event
      → Indexed in logs-windows*
        → Keyword query rule matches script_block_text → Alert in Kibana
```

---

## Ingest Pipeline — `auth-log-parser`

Applied to the Filestream integration for `auth.log`. Three processors in sequence:

| Step | Processor | Action |
|---|---|---|
| 1 | Dissect | Parses raw log line into `source.ip`, `user.name`, `event.outcome` |
| 2 | Lowercase | Normalises `event.outcome` values to lowercase (`failure`, `success`) |
| 3 | Set | Adds `event.category: authentication` for ECS compliance |

**Dissect pattern:**
```
%{auth.timestamp} | IP: %{source.ip} | USER: %{user.name} | STATUS: %{event.outcome}
```

---

## Index Patterns

| Index | Contents |
|---|---|
| `logs-xampp-auth*` | Parsed authentication events from XAMPP auth.log |
| `logs-network*` | DNS and network events from Packetbeat |
| `logs-windows*` | Windows Security and PowerShell event logs |

---

## Detection Rules Summary

| Rule File | Type | Scenario | Severity |
|---|---|---|---|
| `credential_stuffing_threshold.ndjson` | Threshold | Credential Stuffing | High |
| `credential_stuffing_sequence.eql.ndjson` | EQL Sequence | Credential Stuffing | High |
| `dns_tunneling_volume_threshold.ndjson` | Threshold | DNS Tunneling | High |
| `powershell_suspicious_args.ndjson` | Query (KQL) | PowerShell Exploitation | High |
| `powershell_network_correlation.eql.ndjson` | EQL Sequence | PowerShell Exploitation | Critical |
