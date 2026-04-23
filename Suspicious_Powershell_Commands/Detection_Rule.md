***This is my 2nd validated rule to detect almost every abnormal powershell activity.***


```
title: Suspicious PowerShell Execution Patterns
id: 0fdd6acd-9878-40f7-8a82-af40c4a11a41
description: Detects Suspicious PowerShell Execution Patterns
author: Manish Rawat
status: experimental
author: Manish Rawat
date: 2026/04/23
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://github.com/OTRF/Security-Datasets

logsource:
    product: windows
    category: process_creation

detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    
    selection_Parameter:
        CommandLine|contains:
            - '-encoded'
            - '-enc' 
            - '-e ' 
            - '-EncodedCommand'
            - '-en' 
            - '-enco'
    selection_Process:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\outlook.exe'
            - '\wscript.exe'
            - '\mshta.exe'
            - '\cmd.exe'
            - '\control.exe'
            - '\powershell.exe'
    selection_evasion:
        CommandLine|contains:
            - '-NoLogo'
            - '-NoProfile'
            - '-nopi'
            - '-nop'
            - '-noexit'
            - '-ep bypass'
            - '-window hidden'        
    selection_network:
        CommandLine|contains:
            - 'wget'
            - 'curl'
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Start-Process'
    condition: selection and (selection_Parameter or (selection_Process and selection_network) or (selection_Process and selection_evasion))
falsepositive:
    legitimate admin activity 
    legitimate network activity
severity: high
tags:
    - attack.t1027
    - attack.t1059.001
fields:
    - CommandLine
    - ParentImage
    - ParentCommandLine
    - User
    - IntegrityLevel
