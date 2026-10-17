#!/usr/bin/env bash
# ════════════════════════════════════════════════
#  HYDRA — Bootstrap Setup Script
#  Installs all dependencies and security tools
# ════════════════════════════════════════════════
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  HYDRA — AI Bug Bounty Operating System                  ║"
    echo "║  Bootstrap Setup                                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
info()  { echo -e "${CYAN}[*]${NC} $1"; }

# ── Detect OS ────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &>/dev/null; then
            echo "debian"
        elif command -v dnf &>/dev/null; then
            echo "fedora"
        elif command -v apk &>/dev/null; then
            echo "alpine"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# ── Install system dependencies ──────────────
install_system_deps() {
    local os_type=$(detect_os)
    info "Detected OS: $os_type"

    case "$os_type" in
        debian)
            info "Installing system dependencies via apt..."
            sudo apt-get update -qq
            sudo apt-get install -y -qq python3 python3-pip python3-venv \
                git curl wget nmap whatweb jq build-essential
            ;;
        macos)
            info "Installing system dependencies via brew..."
            brew install python3 git curl nmap jq
            ;;
        alpine)
            info "Installing system dependencies via apk..."
            apk add --no-cache python3 py3-pip git curl nmap jq
            ;;
        *)
            warn "Unknown OS — please install python3, git, curl, nmap manually"
            ;;
    esac
}

# ── Install Go ───────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        log "Go already installed: $(go version)"
        return
    fi

    info "Installing Go..."
    local GO_VERSION="1.22.3"
    local ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
    esac

    curl -sLO "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"
    rm -f "go${GO_VERSION}.linux-${ARCH}.tar.gz"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    log "Go installed: $(go version)"
}

# ── Install Go-based security tools ─────────
install_go_tools() {
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    local tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/owasp-amass/amass/v4/...@master"
    )

    for tool in "${tools[@]}"; do
        local name=$(echo "$tool" | grep -oP '[^/]+(?=@)')
        if command -v "$name" &>/dev/null; then
            log "$name already installed"
        else
            info "Installing $name..."
            go install -v "$tool" 2>/dev/null && log "$name installed" || warn "Failed to install $name"
        fi
    done

    # Update nuclei templates
    info "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null || warn "Nuclei template update failed"
}

# ── Install pip-based security tools ─────────
install_pip_tools() {
    info "Installing pip-based security tools..."
    pip3 install --quiet wafw00f dirsearch 2>/dev/null || warn "Some pip tools failed"
    log "pip tools installed"
}

# ── Setup Python environment ─────────────────
setup_python() {
    info "Setting up Python environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Virtual environment created"
    fi

    source venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    log "Python dependencies installed"
}

# ── Create directories ───────────────────────
setup_dirs() {
    mkdir -p data logs results reports wordlists
    log "Data directories created"
}

# ── Download wordlists ───────────────────────
setup_wordlists() {
    if [ ! -f "wordlists/common.txt" ]; then
        info "Downloading wordlists..."
        curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
            -o wordlists/common.txt
        log "Wordlists downloaded"
    else
        log "Wordlists already present"
    fi
}

# ── Setup .env ───────────────────────────────
setup_env() {
    if [ ! -f ".env" ]; then
        cp .env.example .env 2>/dev/null || true
        log ".env file created — edit it to add your API keys"
    else
        log ".env file already exists"
    fi
}

# ── Verify installation ─────────────────────
verify() {
    echo ""
    info "Verifying installation..."
    echo "──────────────────────────────────────────"

    local tools=("subfinder" "httpx" "nuclei" "ffuf" "amass" "katana" "gau" "nmap")
    local ok=0
    local fail=0

    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log "$tool — available"
            ((ok++))
        else
            err "$tool — NOT FOUND"
            ((fail++))
        fi
    done

    echo "──────────────────────────────────────────"
    log "Results: $ok available, $fail missing"
    echo ""
}

# ── Main ─────────────────────────────────────
main() {
    banner

    info "Starting HYDRA bootstrap..."
    echo ""

    install_system_deps
    install_go
    install_go_tools
    install_pip_tools
    setup_python
    setup_dirs
    setup_wordlists
    setup_env
    verify

    echo -e "${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  ✅ HYDRA setup complete!                                ║"
    echo "║                                                          ║"
    echo "║  Run:  python -m hydra.main --target example.com         ║"
    echo "║  Or:   docker compose up                                 ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

main "$@"
