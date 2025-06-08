#!/bin/bash
#
# Raptor Malware Analyzer - Uninstallation Script
# This script safely removes all Raptor components, data, and dependencies
#

# Set text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Raptor installation directory - modify if installed elsewhere
RAPTOR_DIR="${HOME}/raptor"
VENV_DIR="${RAPTOR_DIR}/venv"
CACHE_DIR="${RAPTOR_DIR}/cache"
CONFIG_DIR="${HOME}/.config/raptor"
LOG_DIR="/var/log/raptor"

# Print banner
echo -e "${BLUE}"
echo "======================================================"
echo "  RAPTOR MALWARE ANALYZER - UNINSTALLATION SCRIPT"
echo "======================================================"
echo -e "${NC}"

# Check if running as root for system-wide cleanup
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Warning: Not running as root. System-wide components may not be fully removed.${NC}"
    echo "Consider running with sudo if you installed Raptor system-wide."
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Uninstallation cancelled.${NC}"
        exit 1
    fi
fi

echo -e "${YELLOW}This script will completely remove Raptor Malware Analyzer and all its data.${NC}"
echo -e "The following components will be removed:"
echo "  - Raptor main application"
echo "  - Virtual environment and all dependencies"
echo "  - API cache database"
echo "  - Configuration files"
echo "  - Log files"
echo "  - Report directory"

# Confirm uninstallation
echo ""
read -p "Are you sure you want to continue? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Uninstallation cancelled.${NC}"
    exit 1
fi

# Check if service is running and stop it
echo -e "${BLUE}Checking for running Raptor services...${NC}"
if systemctl is-active --quiet raptor 2>/dev/null; then
    echo "Stopping Raptor service..."
    sudo systemctl stop raptor
    sudo systemctl disable raptor
    echo -e "${GREEN}Raptor service stopped and disabled.${NC}"
elif pgrep -f "raptor" > /dev/null; then
    echo "Killing running Raptor processes..."
    pkill -f "raptor"
    echo -e "${GREEN}Running Raptor processes terminated.${NC}"
else
    echo -e "${GREEN}No running Raptor services found.${NC}"
fi

# Remove main application directory
echo -e "${BLUE}Removing Raptor main directory...${NC}"
if [ -d "$RAPTOR_DIR" ]; then
    rm -rf "$RAPTOR_DIR"
    echo -e "${GREEN}Removed: $RAPTOR_DIR${NC}"
else
    echo -e "${YELLOW}Directory not found: $RAPTOR_DIR${NC}"
fi

# Remove configuration files
echo -e "${BLUE}Removing configuration files...${NC}"
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}Removed: $CONFIG_DIR${NC}"
else
    echo -e "${YELLOW}Directory not found: $CONFIG_DIR${NC}"
fi

# Remove log files (requires root)
echo -e "${BLUE}Removing log files...${NC}"
if [ -d "$LOG_DIR" ]; then
    if [[ $EUID -eq 0 ]]; then
        rm -rf "$LOG_DIR"
        echo -e "${GREEN}Removed: $LOG_DIR${NC}"
    else
        echo -e "${YELLOW}Cannot remove log directory (requires root): $LOG_DIR${NC}"
    fi
else
    echo -e "${YELLOW}Directory not found: $LOG_DIR${NC}"
fi

# Remove systemd service file if it exists
if [ -f "/etc/systemd/system/raptor.service" ]; then
    echo -e "${BLUE}Removing systemd service file...${NC}"
    if [[ $EUID -eq 0 ]]; then
        rm /etc/systemd/system/raptor.service
        systemctl daemon-reload
        echo -e "${GREEN}Removed systemd service file${NC}"
    else
        echo -e "${YELLOW}Cannot remove systemd service file (requires root)${NC}"
    fi
fi

# Remove command line symlink if it exists
if [ -L "/usr/local/bin/raptor" ]; then
    echo -e "${BLUE}Removing command-line symlink...${NC}"
    if [[ $EUID -eq 0 ]]; then
        rm /usr/local/bin/raptor
        echo -e "${GREEN}Removed command-line symlink${NC}"
    else
        echo -e "${YELLOW}Cannot remove symlink (requires root): /usr/local/bin/raptor${NC}"
    fi
fi

# Remove Python package if installed system-wide
if pip list | grep -q "raptor-analyzer"; then
    echo -e "${BLUE}Removing Raptor Python package...${NC}"
    pip uninstall -y raptor-analyzer
    echo -e "${GREEN}Removed Python package: raptor-analyzer${NC}"
fi

# Clean up any remaining cache files in home directory
if [ -d "${HOME}/.cache/raptor" ]; then
    echo -e "${BLUE}Removing cache files...${NC}"
    rm -rf "${HOME}/.cache/raptor"
    echo -e "${GREEN}Removed: ${HOME}/.cache/raptor${NC}"
fi

# Finish up
echo ""
echo -e "${GREEN}======================================================"
echo "  RAPTOR MALWARE ANALYZER SUCCESSFULLY UNINSTALLED"
echo "======================================================${NC}"
echo ""
echo "Thank you for using Raptor Malware Analyzer."
echo "All components have been removed from your system."
echo ""

exit 0
                                                      
