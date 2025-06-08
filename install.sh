#!/bin/bash

# Raptor Malware Analyzer Installer
# By SHIVA SAI REDDY MIKKILI

echo "Installing Raptor Malware Analyzer..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if Python 3 is installed
if command -v python3 &>/dev/null; then
    echo "Python 3 found."
else
    echo "Python 3 is required but not found. Please install Python 3 and try again."
    exit 1
fi

# Create a virtual environment
echo "Creating a virtual environment for Raptor..."
if python3 -m venv .venv; then
    echo "Virtual environment created successfully."
else
    echo "Failed to create virtual environment. Installing python3-venv if needed..."
    sudo apt install -y python3-venv
    python3 -m venv .venv || {
        echo "Failed to create virtual environment. Please check your Python installation."
        exit 1
    }
fi

# Activate the virtual environment
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies in the virtual environment..."
pip install -r requirements.txt || {
    echo "Failed to install dependencies. Please check your internet connection and try again."
    exit 1
}

# Make the main script executable
chmod +x raptor.py

# Create a wrapper script to run raptor from anywhere
echo "Creating wrapper script..."
cat > raptor-wrapper.sh << 'EOF'
#!/bin/bash

# Get the actual directory where this script is located (resolving symlinks)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
    DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# Activate the virtual environment
source "$SCRIPT_DIR/.venv/bin/activate"

# Run raptor with all arguments passed to this script
python "$SCRIPT_DIR/raptor.py" "$@"
EOF

chmod +x raptor-wrapper.sh

# Create symbolic link for local use only
if sudo mkdir -p /usr/local/bin/ 2>/dev/null; then
    echo "Creating a symbolic link in /usr/local/bin..."
    FULL_PATH="$(readlink -f "$(pwd)/raptor-wrapper.sh")"
    sudo ln -sf "$FULL_PATH" /usr/local/bin/raptor || {
        echo "Failed to create a symbolic link. You may need to run this script with sudo."
        echo "You can still run Raptor using './raptor-wrapper.sh' from this directory."
    }
else
    echo "Cannot create directory in /usr/local/bin. You can run Raptor using './raptor-wrapper.sh' from this directory."
fi

echo "Installation complete!"
echo "You can now run Raptor using 'raptor' or './raptor-wrapper.sh [options] file_to_analyze'"
echo ""
echo "To use Raptor in this terminal session, run:"
echo "  source .venv/bin/activate"
echo ""
echo "For help, run 'raptor --help'"
