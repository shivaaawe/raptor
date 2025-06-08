#!/usr/bin/env python3
# raptor.py - Main script

import argparse
import os
import sys
import time
import pathlib
import appdirs
from rich.console import Console
from rich.panel import Panel

# Import modules
from modules.api_analysis import extract_apis_from_executable, fetch_api_data, fetch_new_apis, load_cache, save_cache, collect_malicious_apis
from modules.pe_analysis import analyze_section_entropy, analyze_pe_header
from modules.string_analysis import extract_strings
from modules.reporting import display_analysis_results, save_results_to_file, generate_html_report
from modules.integrations import check_virustotal, map_to_mitre_attack
from modules.scoring import calculate_threat_score
from modules.yara import generate_yara_rule

console = Console()

def get_cache_path():
    """Get the appropriate cache file path for the system"""
    cache_dir = pathlib.Path(appdirs.user_cache_dir("raptor-analyzer"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "raptor_cache.json"

def print_banner():
    banner = """
    ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
    ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
    ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    
    Rapid API Threat Observer & Reporter
    By SHIVA SAI REDDY MIKKILI
    """
    console.print(Panel(banner, title="Raptor Malware Analyzer", expand=False))

def analyze_executable(file_path, cache_file, config):
    """Enhanced analysis that includes multiple analysis techniques"""
    import datetime
    import hashlib
    
    results = {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "analysis_time": datetime.datetime.now().isoformat()
    }
    
    # Extract basic APIs from executable (original functionality)
    apis = extract_apis_from_executable(file_path)
    if not apis:
        console.print("[yellow]Warning: No APIs were extracted from the executable.[/yellow]")
    else:
        console.print(f"[green]Extracted {len(apis)} unique API functions from the executable.[/green]")
    
    # Load cache with error handling
    cache = load_cache(cache_file)
    
    # Determine which APIs need to be fetched
    apis_to_fetch = [api for api in apis if api not in cache]
    
    # Fetch new APIs if needed
    if apis_to_fetch:
        console.print(f"[yellow]Fetching data for {len(apis_to_fetch)} new APIs...[/yellow]")
        cache = fetch_new_apis(apis_to_fetch, cache, config.get('max_workers', 20))
        save_cache(cache, cache_file)
    
    # Collect malicious APIs
    malicious_apis = collect_malicious_apis(apis, cache)
    results['malicious_apis'] = malicious_apis
    
    # Run additional analysis modules
    with console.status("[bold blue]Performing enhanced analysis..."):
        # String analysis
        console.print("[blue]Extracting and analyzing strings...[/blue]")
        results['string_analysis'] = extract_strings(file_path)
        
        # Entropy analysis
        console.print("[blue]Analyzing section entropy...[/blue]")
        results['entropy_analysis'] = analyze_section_entropy(file_path)
        
        # PE Header analysis
        console.print("[blue]Analyzing PE header...[/blue]")
        results['header_analysis'] = analyze_pe_header(file_path)
        
        # Calculate file hashes for reporting and APIs
        with open(file_path, 'rb') as f:
            file_data = f.read()
            results['file_md5'] = hashlib.md5(file_data).hexdigest()
            results['file_sha1'] = hashlib.sha1(file_data).hexdigest()
            results['file_sha256'] = hashlib.sha256(file_data).hexdigest()
        
        # MITRE ATT&CK mapping
        if config.get('map_mitre', False):
            console.print("[blue]Mapping to MITRE ATT&CK framework...[/blue]")
            results['mitre_mapping'] = map_to_mitre_attack(results)
        
        # Generate YARA rule
        if config.get('generate_yara', False):
            console.print("[blue]Generating YARA rule...[/blue]")
            results['yara_rule'] = generate_yara_rule(file_path, results)
        
        # VirusTotal check
        if config.get('virustotal_api_key'):
            console.print("[blue]Checking VirusTotal...[/blue]")
            results['virustotal'] = check_virustotal(results['file_sha256'], config.get('virustotal_api_key'))
    
    # Calculate threat score
    results['threat_score'] = calculate_threat_score(results)
    
    return results

def main():
    # Print banner first, before argparse
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Raptor Malware Analyzer - Rapid API Threat Observer & Reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="raptor"
    )
    parser.add_argument("file_path", help="Path to the executable file to analyze")
    parser.add_argument("--output", help="Output file to save the analysis results")
    parser.add_argument("--cache", default=str(get_cache_path()), help="Cache file for API data")
    parser.add_argument("--max-workers", type=int, default=20, help="Maximum number of worker threads")
    parser.add_argument("--html-report", help="Generate HTML report and save to specified file")
    parser.add_argument("--yara", action="store_true", help="Generate YARA rule")
    parser.add_argument("--virustotal-key", help="VirusTotal API key")
    parser.add_argument("--mitre", action="store_true", help="Map to MITRE ATT&CK framework")
    args = parser.parse_args()

    if os.path.exists(args.file_path):
        start_time = time.time()
        
        # Create config dictionary from args
        config = {
            'max_workers': args.max_workers,
            'generate_yara': args.yara,
            'virustotal_api_key': args.virustotal_key,
            'map_mitre': args.mitre,
        }
        
        # Run enhanced analysis
        results = analyze_executable(args.file_path, args.cache, config)
        end_time = time.time()
        
        # Display summary of results
        if results.get('malicious_apis'):
            console.print(f"[yellow]Found {len(results['malicious_apis'])} potentially malicious API functions.[/yellow]")
            table = display_analysis_results(results['malicious_apis'])
            console.print(table)
        else:
            console.print("[green]No potentially malicious API functions found.[/green]")
        
        # Display threat score
        if results.get('threat_score'):
            score = results['threat_score']
            score_color = "red" if score['threat_level'] in ["Critical", "High"] else "yellow" if score['threat_level'] == "Medium" else "green"
            console.print(f"\n[bold {score_color}]Threat Score: {score['score']}/100 - {score['threat_level']} Risk[/bold {score_color}]")
            
            console.print("\n[bold]Threat Indicators:[/bold]")
            for indicator in score['indicators']:
                console.print(f"  • {indicator}")
        
        # Display MITRE ATT&CK mapping
        if results.get('mitre_mapping') and args.mitre:
            from rich.table import Table
            console.print("\n[bold]MITRE ATT&CK Techniques:[/bold]")
            mitre_table = Table()
            mitre_table.add_column("Technique", style="cyan")
            mitre_table.add_column("ID", style="magenta")
            mitre_table.add_column("Tactics", style="green")
            
            for technique in results['mitre_mapping']:
                mitre_table.add_row(
                    technique['name'],
                    technique['id'],
                    technique['tactic']
                )
            
            console.print(mitre_table)
        
        # Save results to file if requested
        if args.output:
            save_results_to_file(results, args.output)
            console.print(f"[green]Results saved to {args.output}[/green]")
        
        # Generate HTML report if requested
        if args.html_report:
            if generate_html_report(args.file_path, results, args.html_report):
                console.print(f"[green]HTML report generated at {args.html_report}[/green]")
            else:
                console.print(f"[red]Failed to generate HTML report.[/red]")
        
        # Display YARA rule if generated
        if args.yara and results.get('yara_rule'):
            console.print("\n[bold]Generated YARA Rule:[/bold]")
            console.print(results['yara_rule'])
        
        console.print(f"[blue]Analysis completed in {end_time - start_time:.2f} seconds.[/blue]")
    else:
        console.print("[red]File not found. Please check the path and try again.[/red]")

if __name__ == "__main__":
    main()
