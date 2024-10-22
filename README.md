# RAPTOR - Rapid API Threat Observer & Reporter

<div align="center">


[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/shivaaawe/raptor/graphs/commit-activity)

*A powerful tool for analyzing potentially malicious Windows API calls in executable files*

Created by [shivaaawe](https://github.com/shivaaawe)
</div>

## 📋 Overview

RAPTOR (Rapid API Threat Observer & Reporter) is a Python-based malware analysis tool that examines Windows executables to identify potentially malicious API calls. It cross-references the API calls with the MalAPI.io database to provide detailed information about each suspicious function.

## ✨ Features

- 🔍 Extracts and analyzes Windows API calls from executable files
- 🌐 Cross-references findings with MalAPI.io database
- 📊 Provides detailed information about potentially malicious APIs
- 💨 Implements caching for faster subsequent analyses
- 🎨 Rich console output with color-coded information
- 📁 Option to save analysis results to a file
- 🚀 Multi-threaded API data fetching for improved performance

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/shivaaawe/raptor.git
cd raptor
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/Mac):
```bash
chmod +x raptor
```

## 📦 Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - beautifulsoup4
  - rich
  - pefile
  - appdirs

## 🚀 Usage

Basic usage:
```bash
raptor /path/to/executable
```

With additional options:
```bash
raptor /path/to/executable --output results.txt --max-workers 30
```

Help command:
```bash
raptor -h
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `file_path` | Path to the executable file to analyze |
| `--output` | Output file to save the analysis results |
| `--cache` | Cache file location (default: system cache directory) |
| `--max-workers` | Maximum number of worker threads (default: 20) |

## 📝 Example Output

```
    ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
    ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
    ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝

    Rapid API Threat Observer & Reporter
    By shivaaawe

[+] Extracted 150 unique API functions from the executable.
[+] Found 23 potentially malicious API functions.
[+] Analysis completed in 2.34 seconds.
```

## 🔧 Cache System

RAPTOR uses a caching system to store API information for faster subsequent analyses. The cache file is automatically created in the system's cache directory:
- Linux: `~/.cache/raptor-analyzer/`
- Windows: `C:\Users\<username>\AppData\Local\raptor-analyzer\Cache`
- macOS: `~/Library/Caches/raptor-analyzer/`

## ⚠️ Disclaimer

This tool is intended for security research and malware analysis purposes only. Do not use it to analyze files unless you have explicit permission to do so. The authors are not responsible for any misuse of this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- [MalAPI.io](https://malapi.io) for providing the API information database
- All contributors who have helped to improve this tool

## 📧 Contact

shivaaawe - [@shivaaawe](https://github.com/shivaaawe)

Project Link: [https://github.com/shivaaawe/raptor](https://github.com/shivaaawe/raptor)
