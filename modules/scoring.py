# modules/scoring.py

from rich.console import Console

console = Console()

def calculate_threat_score(analysis_results):
    """Calculate a threat score based on various indicators"""
    score = 0
    max_score = 100
    indicators = []
    
    # Check malicious APIs
    if 'malicious_apis' in analysis_results and analysis_results['malicious_apis']:
        api_count = len(analysis_results['malicious_apis'])
        api_score = min(40, api_count * 5)  # Max 40 points from APIs
        score += api_score
        
        attack_techniques = set()
        for api in analysis_results['malicious_apis']:
            for attack in api.get('attacks', []):
                attack_techniques.add(attack)
        
        # More points for diversity of attack techniques
        technique_score = min(20, len(attack_techniques) * 5)
        score += technique_score
        
        indicators.append(f"Malicious APIs: {api_count} (+{api_score})")
        indicators.append(f"Attack techniques: {len(attack_techniques)} (+{technique_score})")
    
    # Check entropy
    if 'entropy_analysis' in analysis_results and analysis_results['entropy_analysis']:
        high_entropy_sections = sum(1 for section in analysis_results['entropy_analysis'] 
                                   if section['entropy'] > 7.0)
        entropy_score = min(15, high_entropy_sections * 5)
        score += entropy_score
        
        # Extra points for sections that are both high-entropy and executable
        suspicious_sections = sum(1 for section in analysis_results['entropy_analysis'] 
                                if section['entropy'] > 7.0 and section['executable'])
        suspicious_section_score = min(10, suspicious_sections * 5)
        score += suspicious_section_score
        
        indicators.append(f"High entropy sections: {high_entropy_sections} (+{entropy_score})")
        if suspicious_sections:
            indicators.append(f"Suspicious sections (high entropy + executable): {suspicious_sections} (+{suspicious_section_score})")
    
    # Check strings
    if 'string_analysis' in analysis_results and analysis_results['string_analysis']:
        string_score = 0
        
        # Check for suspicious URLs
        if analysis_results['string_analysis'].get('urls'):
            url_count = len(analysis_results['string_analysis']['urls'])
            url_score = min(5, url_count)
            string_score += url_score
            indicators.append(f"Suspicious URLs: {url_count} (+{url_score})")
        
        # Check for IP addresses
        if analysis_results['string_analysis'].get('ips'):
            ip_count = len(analysis_results['string_analysis']['ips'])
            ip_score = min(5, ip_count)
            string_score += ip_score
            indicators.append(f"IP addresses: {ip_count} (+{ip_score})")
        
        # Check for command strings
        if analysis_results['string_analysis'].get('commands'):
            cmd_count = len(analysis_results['string_analysis']['commands'])
            cmd_score = min(5, cmd_count)
            string_score += cmd_score
            indicators.append(f"Shell commands: {cmd_count} (+{cmd_score})")
        
        # Check for registry keys
        if analysis_results['string_analysis'].get('registry_keys'):
            reg_count = len(analysis_results['string_analysis']['registry_keys'])
            reg_score = min(5, reg_count)
            string_score += reg_score
            indicators.append(f"Registry keys: {reg_count} (+{reg_score})")
        
        score += string_score
    
    # Check header analysis
    if 'header_analysis' in analysis_results and analysis_results['header_analysis']:
        header_score = min(10, len(analysis_results['header_analysis']) * 2)
        score += header_score
        indicators.append(f"Suspicious header characteristics: {len(analysis_results['header_analysis'])} (+{header_score})")
    
    # Check VirusTotal results if available
    if 'virustotal' in analysis_results and analysis_results['virustotal'].get('found', False):
        vt = analysis_results['virustotal']
        detection_rate = vt['detection_rate']
        
        if detection_rate > 0:
            vt_score = min(20, int(detection_rate * 100 / 3))  # Max 20 points from VT (scaled)
            score += vt_score
            indicators.append(f"VirusTotal detection: {detection_rate*100:.1f}% of scanners ({vt['malicious'] + vt['suspicious']}/{vt['total']}) (+{vt_score})")
    
    # Calculate final normalized score (0-100)
    final_score = min(score, max_score)
    
    # Determine threat level
    if final_score >= 75:
        threat_level = "Critical"
    elif final_score >= 50:
        threat_level = "High"
    elif final_score >= 25:
        threat_level = "Medium"
    else:
        threat_level = "Low"
    
    return {
        "score": final_score,
        "threat_level": threat_level,
        "indicators": indicators
    }
