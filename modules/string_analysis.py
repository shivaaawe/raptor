# modules/string_analysis.py

import re
from rich.console import Console

console = Console()

def extract_strings(file_path, min_length=4):
    """Extract readable strings from the binary file"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Find ASCII strings
        ascii_strings = re.findall(b'[\x20-\x7E]{%d,}' % min_length, content)
        
        # Find Unicode strings (UTF-16LE, common in Windows)
        unicode_strings = []
        unicode_regex = re.compile(b'(?:[\x20-\x7E]\x00){%d,}' % min_length)
        for match in unicode_regex.finditer(content):
            # Ensure the start is aligned for UTF-16
            if match.start() % 2 == 0:
                unicode_strings.append(match.group())
        
        # Combine and decode strings
        all_strings = []
        
        # Decode ASCII strings
        for s in ascii_strings:
            try:
                all_strings.append(s.decode('ascii'))
            except UnicodeDecodeError:
                pass  # Skip if can't decode

        # Decode Unicode strings
        for s in unicode_strings:
            try:
                all_strings.append(s.decode('utf-16le'))
            except UnicodeDecodeError:
                pass  # Skip if can't decode
        
        # Remove duplicates while maintaining order
        unique_strings = []
        seen = set()
        for s in all_strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)
        
        # Categorize strings
        indicators = {
            'urls': [],
            'ips': [],
            'file_paths': [],
            'registry_keys': [],
            'commands': [],
            'emails': [],
            'domains': [],
            'other': []
        }
        
        for string in unique_strings:
            # URL detection
            if re.search(r'https?://[^\s/$.?#].[^\s]*', string):
                indicators['urls'].append(string)
            # IP detection
            elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', string):
                indicators['ips'].append(string)
            # File path detection
            elif re.search(r'[a-zA-Z]:\\[^\\/:*?"<>|\r\n]*|\.exe|\.dll|\.sys|\.bat|\.ps1|\.vbs|\.cmd', string, re.IGNORECASE):
                indicators['file_paths'].append(string)
            # Registry key detection
            elif re.search(r'HKEY_|HKLM\\|HKCU\\|CurrentVersion|Software\\|REGISTRY\\', string, re.IGNORECASE):
                indicators['registry_keys'].append(string)
            # Command detection
            elif re.search(r'\bcmd\.exe\b|\bpowershell\b|\btaskkill\b|\bnetsh\b|\bsc\s|\bwmic\b', string, re.IGNORECASE):
                indicators['commands'].append(string)
            # Email detection
            elif re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', string):
                indicators['emails'].append(string)
            # Domain detection
            elif re.search(r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,6})+', string) and not re.search(r'@', string):
                indicators['domains'].append(string)
            else:
                indicators['other'].append(string)
        
        # Limit the 'other' category to avoid overwhelming the report
        indicators['other'] = indicators['other'][:100]
        
        return indicators
    except Exception as e:
        console.print(f"[red]Error extracting strings: {str(e)}[/red]")
        return {
            'urls': [],
            'ips': [],
            'file_paths': [],
            'registry_keys': [],
            'commands': [],
            'emails': [],
            'domains': [],
            'other': []
        }
