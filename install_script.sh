#!/bin/bash

# Advanced Subdomain Takeover Scanner - Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/subtakeover/main/install.sh | bash

set -e

TOOL_NAME="subtakeover"
INSTALL_DIR="/usr/local/bin"
REPO_URL="https://raw.githubusercontent.com/yourusername/subtakeover/main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Advanced Subdomain Takeover Scanner${NC}"
echo -e "${BLUE}         Installation Script${NC}"
echo -e "${BLUE}============================================${NC}"

# Check if running as root for system installation
if [[ $EUID -eq 0 ]]; then
    INSTALL_SYSTEM=true
    echo -e "${GREEN}[INFO]${NC} Installing system-wide..."
else
    INSTALL_SYSTEM=false
    INSTALL_DIR="$HOME/.local/bin"
    echo -e "${YELLOW}[INFO]${NC} Installing for current user..."
    mkdir -p "$INSTALL_DIR"
fi

# Check Python version
echo -e "${BLUE}[INFO]${NC} Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo -e "${GREEN}[OK]${NC} Python $PYTHON_VERSION found"
    
    # Check if Python version is 3.7+
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 7) else 1)'; then
        echo -e "${GREEN}[OK]${NC} Python version is compatible"
    else
        echo -e "${RED}[ERROR]${NC} Python 3.7+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    echo -e "${RED}[ERROR]${NC} Python3 not found. Please install Python 3.7+"
    exit 1
fi

# Check pip
echo -e "${BLUE}[INFO]${NC} Checking pip installation..."
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} pip3 found"
else
    echo -e "${RED}[ERROR]${NC} pip3 not found. Please install pip3"
    exit 1
fi

# Install Python dependencies
echo -e "${BLUE}[INFO]${NC} Installing Python dependencies..."
pip3 install --user aiohttp dnspython || {
    echo -e "${RED}[ERROR]${NC} Failed to install dependencies"
    exit 1
}
echo -e "${GREEN}[OK]${NC} Dependencies installed"

# Download the main script
echo -e "${BLUE}[INFO]${NC} Downloading subtakeover script..."
curl -sSL "$REPO_URL/subtakeover.py" -o "/tmp/$TOOL_NAME.py" || {
    echo -e "${RED}[ERROR]${NC} Failed to download script"
    exit 1
}

# Install the script
echo -e "${BLUE}[INFO]${NC} Installing script to $INSTALL_DIR..."
if [ "$INSTALL_SYSTEM" = true ]; then
    cp "/tmp/$TOOL_NAME.py" "$INSTALL_DIR/$TOOL_NAME"
    chmod +x "$INSTALL_DIR/$TOOL_NAME"
else
    cp "/tmp/$TOOL_NAME.py" "$INSTALL_DIR/$TOOL_NAME"
    chmod +x "$INSTALL_DIR/$TOOL_NAME"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo -e "${YELLOW}[INFO]${NC} Adding $HOME/.local/bin to PATH..."
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        echo -e "${YELLOW}[INFO]${NC} Please run: source ~/.bashrc"
    fi
fi

# Cleanup
rm "/tmp/$TOOL_NAME.py"

# Test installation
echo -e "${BLUE}[INFO]${NC} Testing installation..."
if "$INSTALL_DIR/$TOOL_NAME" --help &> /dev/null; then
    echo -e "${GREEN}[SUCCESS]${NC} Installation completed successfully!"
    echo -e "${GREEN}[INFO]${NC} You can now use: $TOOL_NAME --help"
else
    echo -e "${RED}[ERROR]${NC} Installation verification failed"
    exit 1
fi

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Usage examples:"
echo -e "  $TOOL_NAME -d subdomain.example.com"
echo -e "  $TOOL_NAME -l domains.txt -o results.json"
echo -e "  $TOOL_NAME -l domains.txt -c 5 -t 20"
echo ""
echo -e "For