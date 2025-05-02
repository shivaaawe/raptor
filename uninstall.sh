#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

echo "Uninstalling Raptor Malware Analyzer..."

# Remove the raptor command
if [ -f /usr/local/bin/raptor ]; then
    echo "Removing raptor command..."
    rm -f /usr/local/bin/raptor
fi

# Remove the raptor.py script
if [ -f /usr/local/bin/raptor.py ]; then
    echo "Removing raptor.py script..."
    rm -f /usr/local/bin/raptor.py
fi

# Remove the virtual environment
if [ -d /opt/raptor_venv ]; then
    echo "Removing virtual environment..."
    rm -rf /opt/raptor_venv
fi

# Remove cache directory
CACHE_DIR=$(python3 -c "import appdirs; print(appdirs.user_cache_dir('raptor-analyzer'))" 2>/dev/null)
if [ ! -z "$CACHE_DIR" ] && [ -d "$CACHE_DIR" ]; then
    echo "Removing cache directory at $CACHE_DIR..."
    rm -rf "$CACHE_DIR"
else
    # Fallback method if appdirs module is not available
    echo "Searching for cache directories..."
    for user_home in /home/*; do
        if [ -d "$user_home/.cache/raptor-analyzer" ]; then
            echo "Removing cache directory at $user_home/.cache/raptor-analyzer..."
            rm -rf "$user_home/.cache/raptor-analyzer"
        fi
    done
    
    # Also check root's cache
    if [ -d "/root/.cache/raptor-analyzer" ]; then
        echo "Removing cache directory at /root/.cache/raptor-analyzer..."
        rm -rf "/root/.cache/raptor-analyzer"
    fi
fi

echo "Raptor Malware Analyzer has been completely uninstalled from your system."
