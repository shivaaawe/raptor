# modules/api_analysis.py

import requests
from bs4 import BeautifulSoup
import pefile
import json
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()

def extract_apis_from_executable(file_path):
    """Extract imported API functions from an executable"""
    try:
        pe = pefile.PE(file_path)
        apis = set()
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        apis.add(imp.name.decode())
        else:
            console.print("[yellow]Warning: No import directory found in the executable.[/yellow]")
            
        return apis
    except Exception as e:
        console.print(f"[red]Error analyzing executable: {str(e)}[/red]")
        return set()

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
        attacks = [span.text.strip() for span in attacks_tag.find_all('span')] if attacks_tag and attacks_tag.find_all('span') else []
        
        doc_tag = soup.find('a', class_='link')
        doc_link = doc_tag['href'] if doc_tag and 'href' in doc_tag.attrs else "N/A"
        
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
