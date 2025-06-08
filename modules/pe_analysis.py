# modules/pe_analysis.py

import pefile
import math
from collections import Counter
from rich.console import Console

console = Console()

def calculate_entropy(data):
    """Calculate Shannon entropy of binary data"""
    if not data:
        return 0
    
    entropy = 0
    counter = Counter(data)
    length = len(data)
    
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_section_entropy(file_path):
    """Analyze entropy of PE sections to detect packing/encryption"""
    try:
        pe = pefile.PE(file_path)
        results = []
        
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            entropy = calculate_entropy(section.get_data())
            size = section.SizeOfRawData
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writable = bool(section.Characteristics & 0x80000000)
            
            suspicion = "Normal"
            if entropy > 7.0:
                suspicion = "High (possible packing/encryption)"
            elif entropy > 6.5:
                suspicion = "Medium (possible obfuscation)"
            
            results.append({
                "name": name,
                "entropy": entropy,
                "size": size,
                "executable": is_executable,
                "writable": is_writable,
                "suspicion_level": suspicion
            })
        
        return results
    except Exception as e:
        console.print(f"[red]Error analyzing section entropy: {str(e)}[/red]")
        return []

def analyze_pe_header(file_path):
    """Analyze PE header for suspicious characteristics"""
    try:
        pe = pefile.PE(file_path)
        suspicious_indicators = []
        
        # Check timestamp
        if pe.FILE_HEADER.TimeDateStamp == 0:
            suspicious_indicators.append("Zero timestamp (common in packed files)")
        
        # Check for TLS callbacks (can be used to execute code before entry point)
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
            suspicious_indicators.append("Contains TLS callbacks (possible anti-debugging)")
        
        # Check for abnormal section names
        standard_sections = [b'.text', b'.data', b'.rdata', b'.rsrc', b'.reloc']
        for section in pe.sections:
            if not any(section.Name.startswith(std) for std in standard_sections):
                suspicious_indicators.append(f"Non-standard section name: {section.Name.decode().strip('\\x00')}")
        
        # Check section permissions
        for section in pe.sections:
            # Check for writable + executable sections (often malicious)
            if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                suspicious_indicators.append(f"Section {section.Name.decode().strip('\\x00')} is both writable and executable")
        
        # Check for abnormal number of imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
            if import_count < 5:
                suspicious_indicators.append(f"Unusually few imports ({import_count}) - possible packed/obfuscated file")
        
        # Check for suspicious DLLs
        suspicious_dlls = ['dbghelp.dll', 'sfc_os.dll', 'psapi.dll']
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.decode().lower() in suspicious_dlls:
                    suspicious_indicators.append(f"Imports from potentially suspicious DLL: {entry.dll.decode()}")
        
        # Check for abnormal entrypoint
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in pe.sections:
            if ep >= section.VirtualAddress and ep < section.VirtualAddress + section.Misc_VirtualSize:
                if section.Name.decode().strip('\x00') not in ['.text', 'CODE']:
                    suspicious_indicators.append(f"Entry point in non-standard section: {section.Name.decode().strip('\\x00')}")
                break
        
        # Check for resource encryption/obfuscation
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        data_rva = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        resource_data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                        resource_entropy = calculate_entropy(resource_data)
                        if resource_entropy > 7.0:
                            suspicious_indicators.append(f"High entropy resource (possible encrypted resource)")
                            break
                    else:
                        continue
                    break
                else:
                    continue
                break
        
        return suspicious_indicators
    except Exception as e:
        console.print(f"[red]Error analyzing PE header: {str(e)}[/red]")
        return []
