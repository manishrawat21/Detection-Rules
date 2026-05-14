# APT29 Detection Engineering

Production-ready Sigma detection rules developed from analysis of 196,071 Sysmon events in the MITRE ATT&CK Evaluations APT29 dataset.

## Overview

This repository contains validated detection rules for adversary behaviors observed during APT29 simulation. Each rule was tested against the actual attack data, converted to Splunk SPL, and validated for false positives.

**Analysis published at:** [Detection Desk](https://manishrawat21.substack.com)

## Detection Coverage

| MITRE Technique | Rule Name | Severity | Status |
|----------------|-----------|----------|--------|
| T1003.001 | [LSASS Process Access with Full Permissions](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Lsass_Process/Lsass_process_detection_rule.yaml) | High | Tested |
| T1059.001, T1027 | [Suspicious PowerShell Execution Patterns](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Powershell_Commands/Detection_Rule.yaml) | High | Tested |
| T1547, T1059.006 | [Abnormal DLL Loads](https://github.com/manishrawat21/Detection-Rules/tree/main/Abnormal%20DLL%20loads/Detection_Rule.yaml) | High | Tested |

## Rules

### Credential Access

**[LSASS Process Access with Full Permissions](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Lsass_Process/Lsass_process_detection_rule.yaml)**
- **Detects:** PowerShell or cmd.exe accessing lsass.exe with GrantedAccess 0x1fffff
- **MITRE:** T1003.001 (Credential Dumping)
- **Validated Against:** APT29 credential dumping at 23:05:16, ProcessID 3852
- **False Positives:** Low (security tools, antivirus)

**Splunk Query:** [View SPL](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Lsass_Process/Validated_SPL_Query.md)

### Execution

**[Suspicious PowerShell Execution Patterns](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Powershell_Commands/Detection_Rule.yaml)**
- **Detects:** PowerShell with encoding, Office-spawned PowerShell with evasion or network activity
- **MITRE:** T1059.001 (PowerShell), T1027 (Obfuscation), T1566.001 (Phishing)
- **Validated Against:** APT29 dataset EventID 1 PowerShell executions
- **False Positives:** Medium (legitimate automation, software deployment)

**Splunk Query:** [View SPL](https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Powershell_Commands/suspicious-powershell-execution.spl)

**[Abnormal DLL Loads](https://github.com/manishrawat21/Detection-Rules/tree/main/Abnormal%20DLL%20loads/Detection_Rule.yaml)**
- **Detects:** Detects unsigned executables in Temp loading modules or DLLs
- **MITRE:** T1574(Hijacking Execution), T1059.006(Command & Scripting: Python)
- **Validated Against:** APT29 dataset EventID 7 Malicious DLL Loading 
- **False Positive:** Low (Legitimate files in TEMP dir, Python development env )

**Splunk Query:** [View SPL](https://github.com/manishrawat21/Detection-Rules/blob/main/Abnormal%20DLL%20loads/Validated_Spl_Query.spl)

## Usage

### Convert to Splunk

```bash
sigma convert -t splunk -p sysmon https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Powershell_Commands/Detection_Rule.yaml
```

### Convert to Elastic

```bash
sigma convert -t elasticsearch -p sysmon https://github.com/Manishrawat21/SOC_Dectection_Rules/blob/main/Suspicious_Powershell_Commands/Detection_Rule.yaml
```

### Test in Your Environment

1. Deploy to SIEM test environment
2. Monitor for 7 days
3. Document false positives
4. Add exclusions as needed
5. Promote to production

## Validation Methodology

Each rule was tested using:
- MITRE ATT&CK Evaluations APT29 dataset (196,071 events)
- Splunk Free Tier with Sysmon logs
- ProcessID and ProcessGuid correlation
- Network traffic validation
- Parent-child process tree analysis


## About This Project

I analyzed the complete APT29 attack simulation to understand how advanced persistent threats operate in real environments. The goal was to write detection rules that catch actual adversary behavior, not theoretical attacks.

**Analysis series:**
- [Part 1: Initial Access and Steganography](https://manishrawat21.substack.com/p/hunting-apt29-in-196071-logs-what)
- [Part 2: Credential Dumping and Collection](https://manishrawat21.substack.com/p/hunting-apt29-part-2-i-searched-one)
- [Part 3: Complete Execution Chain](https://manishrawat21.substack.com/p/hunting-apt29-part-3-i-traced-the)
- [Part 4: Lateral Movement via PsExec](https://manishrawat21.substack.com/p/i-found-hardcoded-credentials-in)

## Contributing

These rules are shared for the security community. If you:
- Find false positives in your environment
- Improve detection logic
- Add conversions for other SIEMs

Submit a pull request or open an issue.

## Author

**Manish Rawat**
- LinkedIn: [linkedin.com/in/rawat-manish-mr2000](https://www.linkedin.com/in/manishrawat-soc/)
- Substack: [Detection Desk](https://manishrawat21.substack.com)
- Email: rawatmanish21@outlook.com

Detection Engineer | Threat Hunter | CompTIA Security+ & CEH Certified

## License

MIT License - Use freely, attribution appreciated# SOC_Dectection_Rules
Written some detection rules to catch some abnormal activites. These are writen after my APT29 detection series, I hope these works for as they did for myself.
