#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
import pefile
import os
import argparse
from rich.panel import Panel
import multiprocessing
import json
from functools import partial
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import appdirs
import pathlib

console = Console()

def fetch_api_data(api_name, session):
    """Fetch and parse API data from MalAPI.io"""
    url = f"https://malapi.io/winapi/{api_name}"
    try:
        response = session.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        function_name = soup.find('div', class_='content').text.strip() if soup.find('div', class_='content') else "N/A"
        description_tag = soup.find_all('div', class_='content')[1] if len(soup.find_all('div', class_='content')) > 1 else None
        description = description_tag.text.strip() if description_tag else "N/A"
        library_tag = soup.find_all('div', class_='content')[2] if len(soup.find_all('div', class_='content')) > 2 else None
        library = library_tag.text.strip() if library_tag else "N/A"
        
        attacks_tag = soup.find('div', id='extra-spacing')
        attacks = [span.text.strip() for span in attacks_tag.find_all('span')] if attacks_tag else []
        
        doc_tag = soup.find('a', class_='link')
        doc_link = doc_tag['href'] if doc_tag else "N/A"
        
        return api_name, {
            "function_name": function_name,
            "description": description,
            "library": library,
            "attacks": attacks,
            "doc_link": doc_link
        }
    except requests.RequestException as e:
        console.print(f"[red]Error fetching data for {api_name}: {str(e)}[/red]")
        return api_name, None

def extract_apis_from_executable(file_path):
    """Extract imported API functions from an executable"""
    try:
        pe = pefile.PE(file_path)
        apis = set()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    apis.add(imp.name.decode())
        return apis
    except Exception as e:
        console.print(f"[red]Error analyzing executable: {str(e)}[/red]")
        return set()
def get_cache_path():
    """Get the appropriate cache file path for the system"""
    cache_dir = pathlib.Path(appdirs.user_cache_dir("raptor-analyzer"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "raptor_cache.json"

def analyze_executable(file_path, cache_file, max_workers=20):
    """
    Analyze an executable and check its APIs against MalAPI.io
    
    Args:
        file_path (str): Path to the executable file
        cache_file (str): Path to the cache file
        max_workers (int): Maximum number of concurrent workers
        
    Returns:
        list: List of malicious APIs found
    """
    # Extract APIs from executable
    apis = extract_apis_from_executable(file_path)
    if not apis:
        console.print("[yellow]Warning: No APIs were extracted from the executable.[/yellow]")
        return []
        
    console.print(f"[green]Extracted {len(apis)} unique API functions from the executable.[/green]")
    
    # Load cache with error handling
    cache = load_cache(cache_file)
    
    # Determine which APIs need to be fetched
    apis_to_fetch = [api for api in apis if api not in cache]
    
    # Fetch new APIs if needed
    if apis_to_fetch:
        console.print(f"[yellow]Fetching data for {len(apis_to_fetch)} new APIs...[/yellow]")
        cache = fetch_new_apis(apis_to_fetch, cache, max_workers)
        save_cache(cache, cache_file)
    
    # Collect and return results
    return collect_malicious_apis(apis, cache)

def load_cache(cache_file):
    """Load the cache file with error handling"""
    try:
        with open(cache_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print("[yellow]Cache file not found. Creating new cache.[/yellow]")
        return {}
    except json.JSONDecodeError:
        console.print("[yellow]Cache file corrupted. Creating new cache.[/yellow]")
        return {}
    except Exception as e:
        console.print(f"[yellow]Error loading cache: {str(e)}. Creating new cache.[/yellow]")
        return {}

def save_cache(cache, cache_file):
    """Save the cache file with error handling"""
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        console.print(f"[yellow]Error saving cache: {str(e)}. Analysis results are still valid.[/yellow]")

def fetch_new_apis(apis_to_fetch, cache, max_workers):
    """Fetch new API data using thread pool"""
    try:
        with requests.Session() as session:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_api = {
                    executor.submit(fetch_api_data, api, session): api 
                    for api in apis_to_fetch
                }
                
                # Add progress indicator
                total = len(apis_to_fetch)
                completed = 0
                
                for future in as_completed(future_to_api):
                    api, result = future.result()
                    if result:
                        cache[api] = result
                    
                    # Update progress
                    completed += 1
                    console.print(f"[blue]Progress: {completed}/{total} APIs processed[/blue]", end='\r')
                
                console.print() # New line after progress complete
    except Exception as e:
        console.print(f"[red]Error during API fetching: {str(e)}[/red]")
    
    return cache

def collect_malicious_apis(apis, cache):
    """Collect malicious APIs from cache"""
    malicious_apis = []
    try:
        for api in apis:
            if (api in cache and 
                cache[api] and 
                cache[api].get('description') not in [None, "N/A"]):
                malicious_apis.append(cache[api])
    except Exception as e:
        console.print(f"[red]Error collecting results: {str(e)}[/red]")
    
    return malicious_apis

def display_analysis_results(results):
    """Display the analysis results in a formatted table"""
    table = Table(title="Potentially Malicious API Functions")
    table.add_column("Function Name", style="cyan")
    table.add_column("Description", style="magenta")
    table.add_column("Library", style="green")
    table.add_column("Associated Attacks", style="red")
    
    for api in results:
        table.add_row(
            api['function_name'],
            api['description'],
            api['library'],
            ", ".join(api['attacks']) if api['attacks'] else "N/A"
        )
    
    return table

def save_results_to_file(results, output_file):
    """Save the analysis results to a file"""
    with open(output_file, 'w') as f:
        for api in results:
            f.write(f"Function Name: {api['function_name']}\n")
            f.write(f"Description: {api['description']}\n")
            f.write(f"Library: {api['library']}\n")
            f.write(f"Associated Attacks: {', '.join(api['attacks']) if api['attacks'] else 'N/A'}\n")
            f.write(f"Documentation: {api['doc_link']}\n")
            f.write("\n")

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

def main():
    parser = argparse.ArgumentParser(
        description="Raptor Malware Analyzer - Rapid API Threat Observer & Reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="raptor"  # This ensures the correct tool name in help message
    )
    parser.add_argument("file_path", help="Path to the executable file to analyze")
    parser.add_argument("--output", help="Output file to save the analysis results")
    parser.add_argument("--cache", default="raptor_cache.json", help="Cache file for API data")
    parser.add_argument("--max-workers", type=int, default=20, help="Maximum number of worker threads")
    args = parser.parse_args()

    print_banner()

    if os.path.exists(args.file_path):
        start_time = time.time()
        results = analyze_executable(args.file_path, args.cache, args.max_workers)
        end_time = time.time()
        
        if results:
            console.print(f"[yellow]Found {len(results)} potentially malicious API functions.[/yellow]")
            table = display_analysis_results(results)
            console.print(table)

            if args.output:
                save_results_to_file(results, args.output)
                console.print(f"[green]Results saved to {args.output}[/green]")
        else:
            console.print("[green]No potentially malicious API functions found.[/green]")
        
        console.print(f"[blue]Analysis completed in {end_time - start_time:.2f} seconds.[/blue]")
    else:
        console.print("[red]File not found. Please check the path and try again.[/red]")

if __name__ == "__main__":
    main()
