# modules/integrations.py

import requests
import datetime
from rich.console import Console

console = Console()

def check_virustotal(hash_value, api_key):
    """Check a file hash against VirusTotal"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            total = sum(stats.values())
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            detection_rate = (malicious + suspicious) / total if total > 0 else 0
            
            # Get scanning engines results
            engines = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            detections = [
                {
                    "engine": engine,
                    "category": data.get('category', 'unknown'),
                    "result": data.get('result', 'unknown')
                }
                for engine, data in engines.items()
                if data.get('category') in ['malicious', 'suspicious']
            ]
            
            return {
                "found": True,
                "detection_rate": detection_rate,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
                "detections": detections,
                "first_seen": result.get('data', {}).get('attributes', {}).get('first_submission_date'),
                "last_seen": result.get('data', {}).get('attributes', {}).get('last_analysis_date')
            }
        elif response.status_code == 404:
            return {"found": False, "message": "File not found in VirusTotal database"}
        else:
            return {"found": False, "message": f"Error: {response.status_code} - {response.text}"}
    except Exception as e:
        console.print(f"[red]Error checking VirusTotal: {str(e)}[/red]")
        return {"found": False, "message": str(e)}

def map_to_mitre_attack(analysis_results):
    """Map detected techniques to MITRE ATT&CK framework"""
    try:
        # This would typically use an API or local database of MITRE ATT&CK data
        # For example purposes, we'll use a simplified mapping
        technique_mapping = {
            "Process Injection": {
                "id": "T1055",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Process injection is a method of executing arbitrary code in the address space of a separate live process."
            },
            "Process Hollowing": {
                "id": "T1055.012",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Process hollowing occurs when a process is created in a suspended state and its memory is replaced with malicious code."
            },
            "DLL Search Order Hijacking": {
                "id": "T1574.001",
                "tactic": "Persistence, Privilege Escalation, Defense Evasion",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs."
            },
            "Keylogging": {
                "id": "T1056.001",
                "tactic": "Collection, Credential Access",
                "description": "Adversaries may log user keystrokes to intercept credentials as the user types them."
            },
            "Registry Run Keys / Startup Folder": {
                "id": "T1547.001",
                "tactic": "Persistence, Privilege Escalation",
                "description": "Adversaries may configure system settings to automatically execute a program during system boot."
            },
            "Credential Dumping": {
                "id": "T1003",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to dump credentials to obtain account login and credential material."
            },
            "Access Token Manipulation": {
                "id": "T1134",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls."
            },
            "Hooking": {
                "id": "T1179",
                "tactic": "Persistence, Privilege Escalation, Credential Access",
                "description": "Adversaries may use hooking to load and execute malicious code within the context of another process."
            },
            "Code Injection": {
                "id": "T1055",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Adversaries may inject code into processes to evade process-based defenses and potentially elevate privileges."
            },
            "Modify Registry": {
                "id": "T1112",
                "tactic": "Defense Evasion",
                "description": "Adversaries may modify the registry to hide configuration information and maintain persistence on the system."
            },
            "Process Discovery": {
                "id": "T1057",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get information about running processes on a system to determine weak points for defense evasion."
            },
            "System Information Discovery": {
                "id": "T1082",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get detailed information about the operating system and hardware to tailor follow-on behaviors."
            },
            "API Hooking": {
                "id": "T1056.004",
                "tactic": "Collection, Credential Access",
                "description": "Adversaries may hook into Windows API functions to collect user credentials or monitor activity."
            },
            "Execution through API": {
                "id": "T1106",
                "tactic": "Execution",
                "description": "Adversaries may use the Windows API to execute commands or programs for defense evasion."
            },
            "File and Directory Discovery": {
                "id": "T1083",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories to understand the organizational layout and locate valuable data."
            },
            "Data Encrypted": {
                "id": "T1022",
                "tactic": "Exfiltration",
                "description": "Adversaries may encrypt data to make it unreadable during exfiltration to avoid detection."
            }
        }
        
        # Collect all attack techniques mentioned in the APIs
        attack_techniques = set()
        if 'malicious_apis' in analysis_results:
            for api in analysis_results['malicious_apis']:
                for attack in api.get('attacks', []):
                    attack_techniques.add(attack)
        
        # Map them to MITRE ATT&CK
        mitre_techniques = []
        for technique in attack_techniques:
            if technique in technique_mapping:
                mitre_techniques.append({
                    "name": technique,
                    "id": technique_mapping[technique]["id"],
                    "tactic": technique_mapping[technique]["tactic"],
                    "description": technique_mapping[technique]["description"]
                })
        
        # Look for additional indicators in strings and headers
        if 'string_analysis' in analysis_results:
            # Check for registry keys related to persistence
            if any('run' in key.lower() for key in analysis_results['string_analysis'].get('registry_keys', [])):
                technique = "Registry Run Keys / Startup Folder"
                if technique not in attack_techniques and technique in technique_mapping:
                    mitre_techniques.append({
                        "name": technique,
                        "id": technique_mapping[technique]["id"],
                        "tactic": technique_mapping[technique]["tactic"],
                        "description": technique_mapping[technique]["description"]
                    })
        
            # Check for credential-related strings
            cred_keywords = ['password', 'login', 'credential', 'auth']
            if any(any(kw in s.lower() for kw in cred_keywords) for s in analysis_results['string_analysis'].get('other', [])):
                technique = "Credential Dumping"
                if technique not in attack_techniques and technique in technique_mapping:
                    mitre_techniques.append({
                        "name": technique,
                        "id": technique_mapping[technique]["id"],
                        "tactic": technique_mapping[technique]["tactic"],
                        "description": technique_mapping[technique]["description"]
                    })
            
            # Check for process discovery
            proc_keywords = ['process', 'task', 'tasklist', 'enum']
            if any(any(kw in s.lower() for kw in proc_keywords) for s in analysis_results['string_analysis'].get('commands', [])):
                technique = "Process Discovery"
                if technique not in attack_techniques and technique in technique_mapping:
                    mitre_techniques.append({
                        "name": technique,
                        "id": technique_mapping[technique]["id"],
                        "tactic": technique_mapping[technique]["tactic"],
                        "description": technique_mapping[technique]["description"]
                    })
        
        # Check for high entropy sections (possible encryption)
        if 'entropy_analysis' in analysis_results:
            high_entropy_sections = [section for section in analysis_results['entropy_analysis'] if section['entropy'] > 7.5]
            if high_entropy_sections:
                technique = "Data Encrypted"
                if technique not in attack_techniques and technique in technique_mapping:
                    mitre_techniques.append({
                        "name": technique,
                        "id": technique_mapping[technique]["id"],
                        "tactic": technique_mapping[technique]["tactic"],
                        "description": technique_mapping[technique]["description"]
                    })
        
        return mitre_techniques
    except Exception as e:
        console.print(f"[red]Error mapping to MITRE ATT&CK: {str(e)}[/red]")
        return []
