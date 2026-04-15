```
title: Suspicious Process Access to LSASS with Full Permissions
id: 077f2e3f-6fd3-48dc-8916-0be392129b3c
status: experimental 
description: Detects Powershell.exe or cmd.exe accessing lsass.exe with full or near full access rights, indicating potential credential dumping activity
author: Manish Rawat
date: 2026/04/09
references:
    - https://attack.mitre.org/techniques/T1003/001
    - https://github.com/OTRF/Security-Datasets
logsource:
    category: process_access


detection:
    selection:
        EventID: 10
        TargetImage|endswith: 
            - '\lsass.exe'
        SourceImage|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        GrantedAccess:
            - '0x1fffff'
            - '0x1f3fff'
    condition: selection
falsepositives:
    - Security monitoring tools
    - Administrative Powershell scripts performing legitimate system checks
severity: high
tags:
    - attack.t1003
    - attack.t1003.001
fields:
    - SourceImage
    - TargetImage
    - GrantedAccess
```
