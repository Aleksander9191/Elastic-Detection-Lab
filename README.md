
# Elastic Detection Lab

Detection Engineering portfolio built with **Elastic Security**, **Sysmon**, and **Atomic Red Team**.

The goal of this repository is to simulate MITRE ATT&CK techniques, investigate collected telemetry, evaluate built-in Elastic detections, and develop custom detection rules.

---

## Lab Stack

| Component | Technology |
|-----------|------------|
| SIEM | Elastic Security 9.4 |
| Endpoint Telemetry | Sysmon |
| Agent | Elastic Agent |
| Attack Simulation | Atomic Red Team |
| Framework | MITRE ATT&CK |

---

## Methodology

Each technique follows the same workflow:

1. Execute Atomic Red Team simulation
2. Analyze collected telemetry in Elastic Discover
3. Validate existing Elastic detection rules
4. Develop a custom detection rule (if required)
5. Validate alert generation
6. Document findings

---


## Completed Techniques

| Technique | Status |
|-----------|--------|
| T1087.001 – Local Account Discovery | ✅ |
| T1059.001 – PowerShell | ✅ |
| T1110.001 - Password Guessing | ✅ |
| T1218.010 - Regsvr32 Scriptlet Execution | ✅ |
| T1105 - Ingress Tool Transfer | ✅ |
| T1685.005 - Disable or Modify Tools: Clear Windows Event Logs | ✅ |
---

## Technologies

- Elastic Security
- Elastic Agent
- Sysmon
- Atomic Red Team
- MITRE ATT&CK
- Detection Engineering
- Threat Hunting

---

## Future Work

- Additional MITRE ATT&CK techniques
- EQL sequence rules
- Sigma rule equivalents
- ECS normalization
- Investigation guides
- Detection tuning
- False positive analysis
