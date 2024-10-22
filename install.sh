#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Check if python3-venv is installed (needed for virtual environments)
if ! dpkg -l | grep -q python3-venv; then
    echo "python3-venv is not installed. Installing it now..."
    apt update && apt install -y python3-venv
fi

# Create a virtual environment for Raptor in /opt/raptor_venv
echo "Creating virtual environment..."
python3 -m venv /opt/raptor_venv

# Activate the virtual environment
source /opt/raptor_venv/bin/activate

# Install Python dependencies in the virtual environment
echo "Installing dependencies..."
/opt/raptor_venv/bin/pip3 install -r requirements.txt

# Make the raptor.py script executable
chmod +x raptor.py

# Copy the raptor.py to /usr/local/bin
cp raptor.py /usr/local/bin

# Create a symlink to make 'raptor' command available
ln -s /usr/local/bin/raptor.py /usr/local/bin/raptor

# Deactivate the virtual environment
deactivate

echo "Raptor CLI Tool has been installed in a virtual environment at /opt/raptor_venv."
echo "To run it, simply use 'raptor' from the terminal."
