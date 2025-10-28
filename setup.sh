#!/bin/bash
# MCP Security Project Setup Script

set -e  # Exit on error

echo "============================================"
echo "  MCP Security Project Setup"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please do not run as root"
    exit 1
fi

echo "Step 1: Installing system dependencies..."
sudo apt update
sudo apt install -y curl build-essential python3-pip python3-venv
print_success "System dependencies installed"
echo ""

echo "Step 2: Setting up Python virtual environment..."
if [ ! -d "venv_mcp" ]; then
    python3 -m venv venv_mcp
    print_success "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

source venv_mcp/bin/activate
print_success "Virtual environment activated"
echo ""

echo "Step 3: Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
print_success "Python dependencies installed"
echo ""

echo "Step 4: Installing Ollama..."
if command -v ollama &> /dev/null; then
    print_info "Ollama already installed ($(ollama --version))"
else
    print_info "Downloading and installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    print_success "Ollama installed"
fi
echo ""

echo "Step 5: Starting Ollama service..."
# Check if Ollama is already running
if pgrep -x "ollama" > /dev/null; then
    print_info "Ollama is already running"
else
    print_info "Starting Ollama in background..."
    nohup ollama serve > logs/ollama.log 2>&1 &
    sleep 2
    print_success "Ollama service started"
fi
echo ""

echo "Step 6: Pulling Llama 3.1 model..."
print_info "This may take a few minutes (4.7 GB download)..."
ollama pull llama3.1
print_success "Llama 3.1 model downloaded"
echo ""

echo "Step 7: Creating storage directories..."
mkdir -p cache files logs
print_success "Storage directories created"
echo ""

echo "Step 8: Testing Ollama..."
print_info "Sending test query to Ollama..."
TEST_RESPONSE=$(ollama run llama3.1 "Say 'Setup successful!' and nothing else" 2>&1)
if [[ $TEST_RESPONSE == *"successful"* ]]; then
    print_success "Ollama is working correctly"
else
    print_error "Ollama test failed"
    echo "Response: $TEST_RESPONSE"
fi
echo ""

echo "============================================"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "============================================"
echo ""
echo "To get started:"
echo "  1. Activate virtual environment:"
echo "     source venv_mcp/bin/activate"
echo ""
echo "  2. Start MCP Server:"
echo "     python -m server.vulnerable_server"
echo ""
echo "  3. Run attacks (in another terminal):"
echo "     python -m attacks.forward.attack1_cache_poisoning"
echo "     python -m attacks.run_all_attacks"
echo ""
echo "Ollama is running in background. Logs: logs/ollama.log"
echo "To stop Ollama: pkill ollama"
echo ""