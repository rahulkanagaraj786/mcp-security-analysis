#!/bin/bash
# Quick Start Script for MCP Security Project

set -e

echo "============================================"
echo "  MCP Security Project - Quick Start"
echo "============================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv_mcp" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "Please run ./setup.sh first to set up the environment."
    exit 1
fi

# Activate virtual environment
source venv_mcp/bin/activate

# Check if we're in the right directory
if [ ! -f "server/vulnerable_server.py" ]; then
    echo "[ERROR] Please run this script from the mcp_security_project directory"
    exit 1
fi

echo "[OK] Virtual environment activated"
echo ""

# Check if MCP is installed
if ! python -c "import mcp" 2>/dev/null; then
    echo "[ERROR] MCP package not found. Installing dependencies..."
    pip install -r requirements.txt
fi

echo "============================================"
echo "Choose an option:"
echo "============================================"
echo "1. Run Attack Demonstrations (automated)"
echo "2. Interactive Ollama Demo"
echo "3. Start MCP Server (interactive)"
echo "4. Run setup script"
echo "5. Check Ollama status"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        echo ""
        echo "Running automated attack demonstrations..."
        python demo/attack_demonstrations.py
        ;;
    2)
        echo ""
        echo "Starting Interactive Ollama Demo..."
        python demo/interactive_ollama_demo.py
        ;;
    3)
        echo ""
        echo "Starting MCP Server..."
        echo "The server will run and wait for connections via stdio."
        echo "Press Ctrl+C to stop."
        echo ""
        python -m server.vulnerable_server
        ;;
    4)
        echo ""
        echo "Running setup script..."
        bash setup.sh
        ;;
    5)
        echo ""
        echo "Checking Ollama status..."
        if command -v ollama &> /dev/null; then
            if pgrep -x "ollama" > /dev/null; then
                echo "[OK] Ollama is running"
                ollama list
            else
                echo "[WARNING] Ollama is installed but not running"
                echo "Start it with: ollama serve"
            fi
        else
            echo "[ERROR] Ollama is not installed"
            echo "Install it with: curl -fsSL https://ollama.com/install.sh | sh"
        fi
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

