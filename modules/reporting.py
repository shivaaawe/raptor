# modules/reporting.py

import os
import datetime
import json
from rich.console import Console
from rich.table import Table
import pefile
import hashlib

console = Console()

def display_analysis_results(malicious_apis):
    """Display the analysis results in a formatted table"""
    table = Table(title="Potentially Malicious API Functions")
    table.add_column("Function Name", style="cyan")
    table.add_column("Description", style="magenta")
    table.add_column("Library", style="green")
    table.add_column("Associated Attacks", style="red")
    
    for api in malicious_apis:
        table.add_row(
            api['function_name'],
            api['description'],
            api['library'],
            ", ".join(api['attacks']) if api['attacks'] else "N/A"
        )
    
    return table

def save_results_to_file(results, output_file):
    """Save the analysis results to a text file"""
    try:
        with open(output_file, 'w') as f:
            f.write(f"Raptor Malware Analysis Report\n")
            f.write(f"============================\n\n")
            
            f.write(f"File: {results['file_name']}\n")
            if 'file_md5' in results:
                f.write(f"MD5: {results['file_md5']}\n")
            if 'file_sha1' in results:
                f.write(f"SHA1: {results['file_sha1']}\n")
            if 'file_sha256' in results:
                f.write(f"SHA256: {results['file_sha256']}\n")
            f.write(f"Analysis Time: {results['analysis_time']}\n\n")
            
            # Write threat score
            if 'threat_score' in results:
                f.write(f"Threat Score: {results['threat_score']['score']}/100 - {results['threat_score']['threat_level']} Risk\n")
                f.write("Threat Indicators:\n")
                for indicator in results['threat_score']['indicators']:
                    f.write(f"  • {indicator}\n")
                f.write("\n")
            
            # Write malicious APIs
            if 'malicious_apis' in results and results['malicious_apis']:
                f.write(f"Potentially Malicious API Functions ({len(results['malicious_apis'])} found):\n")
                f.write("-" * 80 + "\n")
                for api in results['malicious_apis']:
                    f.write(f"Function Name: {api['function_name']}\n")
                    f.write(f"Description: {api['description']}\n")
                    f.write(f"Library: {api['library']}\n")
                    f.write(f"Associated Attacks: {', '.join(api['attacks']) if api['attacks'] else 'N/A'}\n")
                    f.write(f"Documentation: {api['doc_link']}\n")
                    f.write("-" * 80 + "\n")
            else:
                f.write("No potentially malicious API functions found.\n\n")
            
            # Write PE header analysis
            if 'header_analysis' in results and results['header_analysis']:
                f.write("\nSuspicious PE Header Characteristics:\n")
                for item in results['header_analysis']:
                    f.write(f"  • {item}\n")
                f.write("\n")
            
            # Write entropy analysis
            if 'entropy_analysis' in results and results['entropy_analysis']:
                f.write("\nSection Entropy Analysis:\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Section':<15} {'Entropy':<10} {'Size':<15} {'Permissions':<15} {'Suspicion Level':<30}\n")
                f.write("-" * 80 + "\n")
                for section in results['entropy_analysis']:
                    permissions = []
                    if section['executable']:
                        permissions.append("Executable")
                    if section['writable']:
                        permissions.append("Writable")
                    
                    f.write(f"{section['name']:<15} {section['entropy']:<10.2f} {section['size']:<15} {', '.join(permissions):<15} {section['suspicion_level']:<30}\n")
                f.write("\n")
            
            # Write string analysis
            if 'string_analysis' in results:
                for category, strings in results['string_analysis'].items():
                    if strings:
                        f.write(f"\nExtracted {category.replace('_', ' ').title()} ({len(strings)}):\n")
                        f.write("-" * 80 + "\n")
                        for i, string in enumerate(strings, 1):
                            if i <= 100:  # Limit to 100 per category
                                f.write(f"  {string}\n")
                        if len(strings) > 100:
                            f.write(f"  ... ({len(strings) - 100} more)\n")
                        f.write("\n")
            
            # Write MITRE ATT&CK mapping
            if 'mitre_mapping' in results and results['mitre_mapping']:
                f.write("\nMITRE ATT&CK Techniques:\n")
                f.write("-" * 80 + "\n")
                for technique in results['mitre_mapping']:
                    f.write(f"Technique: {technique['name']}\n")
                    f.write(f"ID: {technique['id']}\n")
                    f.write(f"Tactics: {technique['tactic']}\n")
                    f.write(f"Description: {technique['description']}\n")
                    f.write("-" * 80 + "\n")
            
            # Write VirusTotal results
            if 'virustotal' in results and results['virustotal'].get('found', False):
                vt = results['virustotal']
                f.write("\nVirusTotal Results:\n")
                f.write("-" * 80 + "\n")
                f.write(f"Detection Rate: {vt['detection_rate'] * 100:.1f}% ({vt['malicious'] + vt['suspicious']}/{vt['total']})\n")
                f.write(f"First Seen: {datetime.datetime.fromtimestamp(vt['first_seen']).strftime('%Y-%m-%d %H:%M:%S') if vt.get('first_seen') else 'N/A'}\n")
                f.write(f"Last Analysis: {datetime.datetime.fromtimestamp(vt['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if vt.get('last_seen') else 'N/A'}\n")
                
                if 'detections' in vt and vt['detections']:
                    f.write("\nPositive Detections:\n")
                    for detection in vt['detections'][:20]:
                        f.write(f"  • {detection['engine']}: {detection['result']} ({detection['category']})\n")
                    if len(vt['detections']) > 20:
                        f.write(f"  ... ({len(vt['detections']) - 20} more)\n")
                f.write("\n")
            elif 'virustotal' in results:
                f.write("\nVirusTotal Results: ")
                if 'message' in results['virustotal']:
                    f.write(f"{results['virustotal']['message']}\n\n")
                else:
                    f.write("Not available\n\n")
            
            # Write YARA rule if generated
            if 'yara_rule' in results and results['yara_rule']:
                f.write("\nGenerated YARA Rule:\n")
                f.write("-" * 80 + "\n")
                f.write(results['yara_rule'])
                f.write("\n")
            
            f.write("\n--- End of Report ---\n")
        
        return True
    except Exception as e:
        console.print(f"[red]Error saving results to file: {str(e)}[/red]")
        return False

def generate_html_report(file_path, analysis_results, output_file):
    """Generate a comprehensive HTML report of analysis results with improved charts and layout"""
    try:
        file_size = os.path.getsize(file_path)
        
        # Get compilation timestamp if available
        timestamp = "N/A"
        try:
            pe = pefile.PE(file_path)
            if pe.FILE_HEADER.TimeDateStamp > 0:
                timestamp = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        
        # Build HTML content with improved styling and responsive design
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Raptor Analysis Report - {os.path.basename(file_path)}</title>
            <style>
                :root {{
                    --primary-color: #2c3e50;
                    --secondary-color: #34495e;
                    --accent-color: #3498db;
                    --danger-color: #e74c3c;
                    --warning-color: #f39c12;
                    --success-color: #2ecc71;
                    --light-bg: #f8f9fa;
                    --border-color: #dee2e6;
                }}
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0;
                    padding: 0;
                    line-height: 1.6; 
                    color: #333; 
                    background-color: #f8f9fa;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: var(--primary-color);
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin-bottom: 30px;
                    border-radius: 0 0 10px 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                h1, h2, h3 {{ 
                    color: var(--primary-color);
                    margin-top: 30px;
                }}
                header h1 {{
                    color: white;
                    margin: 0;
                }}
                header p {{
                    margin: 5px 0 0 0;
                    opacity: 0.8;
                }}
                .card {{
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 25px;
                    overflow: hidden;
                }}
                .card-header {{
                    background-color: var(--secondary-color);
                    color: white;
                    padding: 12px 20px;
                    font-weight: bold;
                    font-size: 1.2em;
                }}
                .card-body {{
                    padding: 20px;
                }}
                table {{ 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin-bottom: 20px;
                    font-size: 0.95em;
                }}
                th, td {{ 
                    border: 1px solid var(--border-color); 
                    padding: 10px; 
                    text-align: left; 
                }}
                th {{ 
                    background-color: var(--light-bg);
                    font-weight: 600;
                }}
                tr:nth-child(even) {{ 
                    background-color: rgba(0,0,0,0.02);
                }}
                tr:hover {{
                    background-color: rgba(0,0,0,0.05);
                }}
                .danger {{ color: var(--danger-color); }}
                .warning {{ color: var(--warning-color); }}
                .success {{ color: var(--success-color); }}
                .flex-container {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .flex-item {{
                    flex: 1;
                    min-width: 300px;
                }}
                .chart-container {{
                    position: relative;
                    height: 300px;
                    margin: 20px 0;
                }}
                pre {{
                    background-color: #f6f8fa;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                    font-size: 0.9em;
                    border: 1px solid #eaeaea;
                }}
                .high {{ background-color: rgba(231, 76, 60, 0.1); }}
                .medium {{ background-color: rgba(243, 156, 18, 0.1); }}
                
                .score-container {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                }}
                .score-box {{
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    width: 100px;
                    height: 100px;
                    border-radius: 50%;
                    font-size: 28px;
                    font-weight: bold;
                    color: white;
                    margin-right: 20px;
                }}
                .score-details {{
                    flex: 1;
                }}
                .critical {{ background-color: #d32f2f; }}
                .high-risk {{ background-color: #f44336; }}
                .medium-risk {{ background-color: #ff9800; }}
                .low-risk {{ background-color: #4caf50; }}
                
                .string-list {{
                    max-height: 300px;
                    overflow-y: auto;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                }}
                
                .footer {{
                    text-align: center;
                    padding: 20px;
                    margin-top: 50px;
                    background-color: var(--secondary-color);
                    color: white;
                    border-radius: 10px;
                }}
                
                @media (max-width: 768px) {{
                    .flex-item {{
                        min-width: 100%;
                    }}
                }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
        </head>
        <body>
            <header>
                <h1>Raptor Malware Analysis Report</h1>
                <p>Rapid API Threat Observer &amp; Reporter</p>
            </header>
            
            <div class="container">
                <div class="flex-container">
                    <div class="flex-item card">
                        <div class="card-header">File Information</div>
                        <div class="card-body">
                            <table>
                                <tr><th>File Name</th><td>{os.path.basename(file_path)}</td></tr>
                                <tr><th>File Size</th><td>{file_size:,} bytes</td></tr>
                                <tr><th>MD5</th><td>{analysis_results.get('file_md5', 'N/A')}</td></tr>
                                <tr><th>SHA-1</th><td>{analysis_results.get('file_sha1', 'N/A')}</td></tr>
                                <tr><th>SHA-256</th><td>{analysis_results.get('file_sha256', 'N/A')}</td></tr>
                                <tr><th>Compilation Time</th><td>{timestamp}</td></tr>
                                <tr><th>Analysis Time</th><td>{analysis_results.get('analysis_time', 'N/A')}</td></tr>
                            </table>
                        </div>
                    </div>
        """
        
        # Add threat score if available
        if analysis_results.get('threat_score'):
            score = analysis_results['threat_score']
            score_class = ""
            if score['threat_level'] == "Critical":
                score_class = "critical"
            elif score['threat_level'] == "High":
                score_class = "high-risk"
            elif score['threat_level'] == "Medium":
                score_class = "medium-risk"
            else:
                score_class = "low-risk"
                
            html_content += f"""
                    <div class="flex-item card">
                        <div class="card-header">Threat Assessment</div>
                        <div class="card-body">
                            <div class="score-container">
                                <div class="score-box {score_class}">{score['score']}</div>
                                <div class="score-details">
                                    <h3>{score['threat_level']} Risk</h3>
                                    <p>Based on {len(score['indicators'])} indicators</p>
                                </div>
                            </div>
                            <table>
                                <tr><th>Indicator</th></tr>
            """
            
            for indicator in score['indicators']:
                html_content += f"<tr><td>{indicator}</td></tr>"
                
            html_content += """
                            </table>
                        </div>
                    </div>
            """
        
        html_content += "</div>"  # Close flex-container
        
        # Add API analysis results
        if analysis_results.get('malicious_apis'):
            html_content += """
                <div class="card">
                    <div class="card-header">Malicious API Functions</div>
                    <div class="card-body">
                        <table>
                            <tr>
                                <th>Function Name</th>
                                <th>Description</th>
                                <th>Library</th>
                                <th>Associated Attacks</th>
                            </tr>
            """
            
            for api in analysis_results['malicious_apis']:
                attacks = ", ".join(api['attacks']) if api['attacks'] else "N/A"
                attack_class = "danger" if api['attacks'] else ""
                html_content += f"""
                            <tr>
                                <td>{api['function_name']}</td>
                                <td>{api['description']}</td>
                                <td>{api['library']}</td>
                                <td class="{attack_class}">{attacks}</td>
                            </tr>
                """
            
            html_content += """
                        </table>
                    </div>
                </div>
            """
        
        # Add section entropy analysis
        if analysis_results.get('entropy_analysis'):
            html_content += """
                <div class="card">
                    <div class="card-header">Section Entropy Analysis</div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="entropyChart"></canvas>
                        </div>
                        <table>
                            <tr>
                                <th>Section</th>
                                <th>Entropy</th>
                                <th>Size</th>
                                <th>Permissions</th>
                                <th>Suspicion Level</th>
                            </tr>
            """
            
            for section in analysis_results['entropy_analysis']:
                permissions = []
                if section['executable']:
                    permissions.append("Executable")
                if section['writable']:
                    permissions.append("Writable")
                
                row_class = ""
                if "High" in section['suspicion_level']:
                    row_class = "high"
                elif "Medium" in section['suspicion_level']:
                    row_class = "medium"
                
                html_content += f"""
                            <tr class="{row_class}">
                                <td>{section['name']}</td>
                                <td>{section['entropy']:.2f}</td>
                                <td>{section['size']:,} bytes</td>
                                <td>{', '.join(permissions)}</td>
                                <td>{section['suspicion_level']}</td>
                            </tr>
                """
            
            html_content += """
                        </table>
                    </div>
                </div>
            """
            
            # Add JavaScript for improved entropy chart
            section_names = [section['name'] for section in analysis_results['entropy_analysis']]
            entropy_values = [section['entropy'] for section in analysis_results['entropy_analysis']]
            
            html_content += f"""
                <script>
                    document.addEventListener('DOMContentLoaded', function() {{
                        const ctx = document.getElementById('entropyChart').getContext('2d');
                        const entropyChart = new Chart(ctx, {{
                            type: 'bar',
                            data: {{
                                labels: {json.dumps(section_names)},
                                datasets: [{{
                                    label: 'Entropy (0-8)',
                                    data: {json.dumps(entropy_values)},
                                    backgroundColor: {json.dumps(['rgba(231, 76, 60, 0.8)' if e > 7.0 else 'rgba(243, 156, 18, 0.8)' if e > 6.5 else 'rgba(46, 204, 113, 0.8)' for e in entropy_values])},
                                    borderColor: {json.dumps(['rgba(231, 76, 60, 1)' if e > 7.0 else 'rgba(243, 156, 18, 1)' if e > 6.5 else 'rgba(46, 204, 113, 1)' for e in entropy_values])},
                                    borderWidth: 1
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{
                                        position: 'top',
                                    }},
                                    tooltip: {{
                                        callbacks: {{
                                            afterLabel: function(context) {{
                                                const index = context.dataIndex;
                                                const suspicion = {json.dumps([section['suspicion_level'] for section in analysis_results['entropy_analysis']])};
                                                return 'Suspicion: ' + suspicion[index];
                                            }}
                                        }}
                                    }}
                                }},
                                scales: {{
                                    y: {{
                                        beginAtZero: true,
                                        max: 8,
                                        title: {{
                                            display: true,
                                            text: 'Entropy Value'
                                        }}
                                    }},
                                    x: {{
                                        title: {{
                                            display: true,
                                            text: 'Section Name'
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }});
                </script>
            """
        
        # Add PE header analysis
        if analysis_results.get('header_analysis'):
            html_content += """
                <div class="card">
                    <div class="card-header">PE Header Analysis</div>
                    <div class="card-body">
                        <table>
                            <tr><th>Suspicious Characteristics</th></tr>
            """
            
            for item in analysis_results['header_analysis']:
                html_content += f"<tr><td>{item}</td></tr>"
                
            html_content += """
                        </table>
                    </div>
                </div>
            """
        
        # Add string analysis
        if analysis_results.get('string_analysis'):
            html_content += """
                <div class="card">
                    <div class="card-header">String Analysis</div>
                    <div class="card-body">
            """
            
            # Create tabs for string categories
            categories = []
            for category, strings in analysis_results['string_analysis'].items():
                if strings:
                    categories.append(category)
            
            if categories:
                html_content += """
                    <style>
                        .tabs {
                            display: flex;
                            flex-wrap: wrap;
                            border-bottom: 1px solid var(--border-color);
                            margin-bottom: 15px;
                        }
                        .tab-button {
                            background: none;
                            border: none;
                            padding: 10px 20px;
                            cursor: pointer;
                            opacity: 0.6;
                            font-size: 1em;
                            border-bottom: 2px solid transparent;
                        }
                        .tab-button:hover {
                            opacity: 1;
                            background-color: rgba(0,0,0,0.03);
                        }
                        .tab-button.active {
                            opacity: 1;
                            border-bottom: 2px solid var(--accent-color);
                            font-weight: 600;
                        }
                        .tab-content {
                            display: none;
                        }
                        .tab-content.active {
                            display: block;
                        }
                    </style>
                    
                    <div class="tabs">
                """
                
                for i, category in enumerate(categories):
                    active = " active" if i == 0 else ""
                    display_name = category.replace('_', ' ').title()
                    count = len(analysis_results['string_analysis'][category])
                    html_content += f'<button class="tab-button{active}" onclick="openTab(event, \'{category}\')">{display_name} ({count})</button>'
                
                html_content += "</div>"
                
                for i, category in enumerate(categories):
                    active = " active" if i == 0 else ""
                    strings = analysis_results['string_analysis'][category]
                    html_content += f"""
                        <div id="{category}" class="tab-content{active}">
                            <div class="string-list">
                                <table>
                                    <tr><th>{category.replace('_', ' ').title()}</th></tr>
                    """
                    
                    for string in strings[:100]:  # Limit to 100 entries
                        html_content += f"<tr><td>{string}</td></tr>"
                    
                    if len(strings) > 100:
                        html_content += f"<tr><td>... ({len(strings) - 100} more)</td></tr>"
                        
                    html_content += """
                                </table>
                            </div>
                        </div>
                    """
                
                html_content += """
                    <script>
                        function openTab(evt, tabName) {
                            var i, tabContent, tabButtons;
                            tabContent = document.getElementsByClassName("tab-content");
                            for (i = 0; i < tabContent.length; i++) {
                                tabContent[i].className = tabContent[i].className.replace(" active", "");
                            }
                            tabButtons = document.getElementsByClassName("tab-button");
                            for (i = 0; i < tabButtons.length; i++) {
                                tabButtons[i].className = tabButtons[i].className.replace(" active", "");
                            }
                            document.getElementById(tabName).className += " active";
                            evt.currentTarget.className += " active";
                        }
                    </script>
                """
            
            html_content += """
                    </div>
                </div>
            """
        
        # Add MITRE ATT&CK mapping
        if analysis_results.get('mitre_mapping'):
            html_content += """
                <div class="card">
                    <div class="card-header">MITRE ATT&CK Mapping</div>
                    <div class="card-body">
                        <table>
                            <tr>
                                <th>Technique</th>
                                <th>ID</th>
                                <th>Tactics</th>
                                <th>Description</th>
                            </tr>
            """
            
            for technique in analysis_results['mitre_mapping']:
                html_content += f"""
                            <tr>
                                <td>{technique['name']}</td>
                                <td>{technique['id']}</td>
                                <td>{technique['tactic']}</td>
                                <td>{technique['description']}</td>
                            </tr>
                """
                
            html_content += """
                        </table>
                    </div>
                </div>
            """
        
        # Add VirusTotal results
        if analysis_results.get('virustotal') and analysis_results['virustotal'].get('found', False):
            vt = analysis_results['virustotal']
            detection_percent = vt['detection_rate'] * 100
            
            html_content += f"""
                <div class="card">
                    <div class="card-header">VirusTotal Results</div>
                    <div class="card-body">
                        <div class="chart-container" style="height: 250px;">
                            <canvas id="vtChart"></canvas>
                        </div>
                        <table>
                            <tr><th>Detection Rate</th><td>{detection_percent:.1f}% ({vt['malicious'] + vt['suspicious']}/{vt['total']})</td></tr>
                            <tr><th>First Seen</th><td>{datetime.datetime.fromtimestamp(vt['first_seen']).strftime('%Y-%m-%d %H:%M:%S') if vt.get('first_seen') else 'N/A'}</td></tr>
                            <tr><th>Last Analysis</th><td>{datetime.datetime.fromtimestamp(vt['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if vt.get('last_seen') else 'N/A'}</td></tr>
                        </table>
            """
            
            if 'detections' in vt and vt['detections']:
                html_content += """
                        <h3>Positive Detections</h3>
                        <table>
                            <tr>
                                <th>Engine</th>
                                <th>Result</th>
                                <th>Category</th>
                            </tr>
                """
                
                for detection in vt['detections'][:20]:
                    category_class = "danger" if detection['category'] == "malicious" else "warning"
                    html_content += f"""
                            <tr>
                                <td>{detection['engine']}</td>
                                <td>{detection['result']}</td>
                                <td class="{category_class}">{detection['category']}</td>
                            </tr>
                    """
                
                if len(vt['detections']) > 20:
                    html_content += f"<tr><td colspan='3'>... ({len(vt['detections']) - 20} more)</td></tr>"
                    html_content += """
                        </table>
                    </div>
                </div>
            """
            
            # Add JavaScript for VirusTotal chart
            html_content += f"""
                <script>
                    document.addEventListener('DOMContentLoaded', function() {{
                        const vtCtx = document.getElementById('vtChart').getContext('2d');
                        const vtChart = new Chart(vtCtx, {{
                            type: 'doughnut',
                            data: {{
                                labels: ['Malicious', 'Suspicious', 'Clean/Undetected'],
                                datasets: [{{
                                    data: [{vt['malicious']}, {vt['suspicious']}, {vt['total'] - vt['malicious'] - vt['suspicious']}],
                                    backgroundColor: [
                                        'rgba(231, 76, 60, 0.8)',  // Red for malicious
                                        'rgba(243, 156, 18, 0.8)',  // Orange for suspicious
                                        'rgba(46, 204, 113, 0.8)'   // Green for clean
                                    ],
                                    borderColor: [
                                        'rgba(231, 76, 60, 1)',
                                        'rgba(243, 156, 18, 1)',
                                        'rgba(46, 204, 113, 1)'
                                    ],
                                    borderWidth: 1
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{
                                        position: 'right',
                                        labels: {{
                                            font: {{
                                                size: 14
                                            }}
                                        }}
                                    }},
                                    tooltip: {{
                                        callbacks: {{
                                            label: function(context) {{
                                                const label = context.label;
                                                const value = context.raw;
                                                const total = {vt['total']};
                                                const percentage = Math.round((value / total) * 100);
                                                return `${{label}}: ${{value}} (${{percentage}}%)`;
                                            }}
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }});
                </script>
            """
        elif analysis_results.get('virustotal'):
            html_content += f"""
                <div class="card">
                    <div class="card-header">VirusTotal Results</div>
                    <div class="card-body">
                        <p>{analysis_results['virustotal'].get('message', 'Not available')}</p>
                    </div>
                </div>
            """
        
        # Add YARA rule if generated
        if analysis_results.get('yara_rule'):
            html_content += f"""
                <div class="card">
                    <div class="card-header">Generated YARA Rule</div>
                    <div class="card-body">
                        <pre>{analysis_results['yara_rule']}</pre>
                    </div>
                </div>
            """
        
        # Close HTML with footer
        html_content += """
                <div class="footer">
                    <p>Generated by Raptor Malware Analyzer - Rapid API Threat Observer & Reporter</p>
                    <p>Analysis completed: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True
    except Exception as e:
        console.print(f"[red]Error generating HTML report: {str(e)}[/red]")
        return False
