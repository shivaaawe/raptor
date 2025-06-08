# modules/yara.py

import os
import datetime
import hashlib
import pefile
from rich.console import Console

console = Console()

def generate_yara_rule(file_path, analysis_results):
    """Generate a YARA rule based on file characteristics"""
    try:
        pe = pefile.PE(file_path)
        file_name = os.path.basename(file_path)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d")
        
        # Get file hashes
        md5 = analysis_results.get('file_md5', '')
        sha1 = analysis_results.get('file_sha1', '')
        sha256 = analysis_results.get('file_sha256', '')
        
        if not md5 or not sha1 or not sha256:
            with open(file_path, 'rb') as f:
                data = f.read()
                if not md5:
                    md5 = hashlib.md5(data).hexdigest()
                if not sha1:
                    sha1 = hashlib.sha1(data).hexdigest()
                if not sha256:
                    sha256 = hashlib.sha256(data).hexdigest()
        
        # Start building the rule
        rule = f"""
rule Raptor_Generated_{md5[:8]} {{
    meta:
        description = "Auto-generated rule for {file_name}"
        author = "Raptor Malware Analyzer"
        date = "{timestamp}"
        hash_md5 = "{md5}"
        hash_sha1 = "{sha1}"
        hash_sha256 = "{sha256}"
        
    strings:
"""
        
        # Add strings
        string_index = 1
        if 'string_analysis' in analysis_results:
            # Add URLs
            for string in analysis_results['string_analysis'].get('urls', [])[:5]:  # Limit to 5 URLs
                escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
                rule += f'        $url{string_index} = "{escaped_string}"\n'
                string_index += 1
            
            # Add IPs
            for string in analysis_results['string_analysis'].get('ips', [])[:5]:  # Limit to 5 IPs
                escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
                rule += f'        $ip{string_index} = "{escaped_string}"\n'
                string_index += 1
            
            # Add commands
            for string in analysis_results['string_analysis'].get('commands', [])[:5]:  # Limit to 5 commands
                escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
                rule += f'        $cmd{string_index} = "{escaped_string}"\n'
                string_index += 1
            
            # Add registry keys
            for string in analysis_results['string_analysis'].get('registry_keys', [])[:5]:  # Limit to 5 registry keys
                escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
                rule += f'        $reg{string_index} = "{escaped_string}"\n'
                string_index += 1
            
            # Add a few interesting strings from 'other' category
            interesting_keywords = ['password', 'admin', 'login', 'crypt', 'http', 'cmd', 'powershell', 'exec']
            interesting_strings = []
            
            for string in analysis_results['string_analysis'].get('other', []):
                if any(keyword in string.lower() for keyword in interesting_keywords):
                    interesting_strings.append(string)
                    if len(interesting_strings) >= 5:  # Limit to 5 interesting strings
                        break
            
            for string in interesting_strings:
                escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
                rule += f'        $s{string_index} = "{escaped_string}"\n'
                string_index += 1
        
        # Add API functions
        api_index = 1
        if 'malicious_apis' in analysis_results:
            for api in analysis_results['malicious_apis'][:10]:  # Limit to 10 APIs
                rule += f'        $api{api_index} = "{api["function_name"]}"\n'
                api_index += 1
        
        # Add section names
        section_index = 1
        if 'entropy_analysis' in analysis_results:
            for section in analysis_results['entropy_analysis']:
                if section['entropy'] > 7.0:  # Only high entropy sections
                    rule += f'        $sec{section_index} = "{section["name"]}"\n'
                    section_index += 1
        
        # Add condition
        rule += """
    condition:
        uint16(0) == 0x5A4D and  // MZ header
"""
        
        # Base condition on number of strings/indicators found
        conditions = []
        
        # URL condition
        if string_index > 1:
            all_strings = string_index - 1
            conditions.append(f"any of them")
        
        # API condition
        if api_index > 1:
            api_count = min(api_index - 1, 3)  # Require at least 3 or all if less than 3
            if api_count == api_index - 1:
                conditions.append(f"all of ($api*)")
            else:
                conditions.append(f"{api_count} of ($api*)")
        
        # Section condition for entropy
        if section_index > 1:
            conditions.append(f"any of ($sec*)")
        
        # If no specific conditions, use file size
        if not conditions:
            file_size = os.path.getsize(file_path)
            conditions.append(f"filesize < {file_size + 1024} and filesize > {max(0, file_size - 1024)}")
        
        # Combine conditions
        if len(conditions) > 1:
            rule += f"        ({') and ('.join(conditions)})"
        else:
            rule += f"        {conditions[0]}"
        
        rule += "\n}"
        
        return rule
    except Exception as e:
        console.print(f"[red]Error generating YARA rule: {str(e)}[/red]")
        return None
