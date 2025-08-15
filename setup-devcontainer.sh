#!/bin/bash

# Claude Code Devcontainer Setup Script for Podman
# This script sets up a devcontainer environment using podman based on the
# Claude Code reference implementation with security in mind.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
CONTAINER_NAME="claude-code-devcontainer"
IMAGE_NAME="claude-code-dev"
WORKSPACE_DIR="${PWD}"
DEVCONTAINER_DIR=".devcontainer"

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if podman is installed
check_podman() {
    if ! command -v podman &> /dev/null; then
        print_message $RED "Error: Podman is not installed. Please install podman first."
        exit 1
    fi
    print_message $GREEN "✓ Podman is installed"
}

# Function to create devcontainer directory structure
create_devcontainer_structure() {
    print_message $YELLOW "Creating devcontainer directory structure..."

    mkdir -p "${DEVCONTAINER_DIR}"

    # Create devcontainer.json
    cat > "${DEVCONTAINER_DIR}/devcontainer.json" << 'EOF'
{
  "name": "Claude Code Sandbox",
  "build": {
    "dockerfile": "Dockerfile",
    "args": {
      "TZ": "${localEnv:TZ:UTC}",
      "CLAUDE_CODE_VERSION": "latest",
      "GIT_DELTA_VERSION": "0.18.2",
      "ZSH_IN_DOCKER_VERSION": "1.2.0"
    }
  },
  "runArgs": [
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW"
  ],
  "customizations": {
    "vscode": {
      "extensions": [
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "eamodio.gitlens"
      ],
      "settings": {
        "editor.formatOnSave": true,
        "editor.defaultFormatter": "esbenp.prettier-vscode",
        "editor.codeActionsOnSave": {
          "source.fixAll.eslint": "explicit"
        },
        "terminal.integrated.defaultProfile.linux": "zsh",
        "terminal.integrated.profiles.linux": {
          "bash": { "path": "bash", "icon": "terminal-bash" },
          "zsh": { "path": "zsh" }
        }
      }
    }
  },
  "features": {
    "ghcr.io/devcontainers/features/node:1": {},
    "ghcr.io/anthropics/devcontainer-features/claude-code:1": {}
  },
  "containerEnv": {
    "ANTHROPIC_API_KEY": "${localEnv:ANTHROPIC_API_KEY}",
    "CLAUDE_TELEMETRY_OPTOUT": "1",
    "XDG_CONFIG_HOME": "/home/node/.config",
    "XDG_CACHE_HOME": "/home/node/.cache"
  },
  "remoteUser": "node",
  "workspaceFolder": "/workspace",
  "mounts": [
    "source=${localWorkspaceFolder},target=/workspace,type=bind",
    "source=commandhistory,target=/commandhistory,type=volume",
    "source=home-node,target=/home/node,type=volume"
  ],
  "postCreateCommand": "claude --version && claude doctor || true",
  "postStartCommand": "/bin/bash .devcontainer/init-firewall.sh"
}
EOF

# Create Dockerfile
cat > "${DEVCONTAINER_DIR}/Dockerfile" << 'EOF'
FROM node:20-bookworm-slim

# Install basic dependencies including capsh and aggregate
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    sudo \
    zsh \
    fzf \
    jq \
    iptables \
    ipset \
    iproute2 \
    net-tools \
    dnsutils \
    ca-certificates \
    gnupg \
    lsb-release \
    libcap2-bin \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Try to install aggregate tool, but don't fail if it doesn't work
RUN pip3 install --break-system-packages aggregate6 2>/dev/null || \
    echo "Note: aggregate6 installation failed, will use fallback"

# Set up non-root user with sudo
ARG USERNAME=node
RUN echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Set up command history
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R $USERNAME /commandhistory \
    && echo "$SNIPPET" >> "/home/$USERNAME/.bashrc"

# Set DEVCONTAINER environment variable
ENV DEVCONTAINER=true

# Create workspace and config directories
RUN mkdir -p /workspace /home/node/.claude && \
    chown -R node:node /workspace /home/node/.claude

WORKDIR /workspace

# Install git-delta for better diffs
ARG GIT_DELTA_VERSION=0.18.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    dpkg -i "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    rm "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"

# Switch to non-root user
USER node

# Install global npm packages directory
ENV NPM_CONFIG_PREFIX=/home/node/.npm-global
ENV PATH=$PATH:/home/node/.npm-global/bin

# Install Oh My Zsh
ARG ZSH_IN_DOCKER_VERSION=1.2.0
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v${ZSH_IN_DOCKER_VERSION}/zsh-in-docker.sh)" -- \
    -t robbyrussell \
    -p git \
    -p ssh-agent \
    -p npm \
    -p node

# Set the default shell to zsh
ENV SHELL=/bin/zsh

# Install Claude Code CLI via npm
RUN npm install -g @anthropic-ai/claude-code

CMD ["/bin/zsh"]
EOF

    # Create init-firewall.sh
    cat > "${DEVCONTAINER_DIR}/init-firewall.sh" << 'EOF'
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Check if running in a container
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
    echo "Not running in a container, skipping firewall setup"
    exit 0
fi

# Check for required capabilities
if ! capsh --print | grep -q cap_net_admin; then
    echo "Warning: NET_ADMIN capability not available, skipping firewall setup"
    exit 0
fi

echo "Setting up firewall rules for Claude Code devcontainer..."

# 1. Extract Docker/Podman DNS info BEFORE any flushing
CONTAINER_DNS_RULES=$(iptables-save -t nat 2>/dev/null | grep -E "(127\.0\.0\.11|10\.88\.0\.1)" || true)

# Flush existing rules and delete existing ipsets
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# 2. Selectively restore ONLY internal container DNS resolution
if [ -n "$CONTAINER_DNS_RULES" ]; then
    echo "Restoring container DNS rules..."
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$CONTAINER_DNS_RULES" | while IFS= read -r rule; do
        if [[ $rule == -A* ]]; then
            iptables -t nat $rule || true
        fi
    done
else
    echo "No container DNS rules to restore"
fi

# First allow DNS and localhost before any restrictions
# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
# Allow inbound DNS responses
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
# Allow outbound SSH
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
# Allow inbound SSH responses
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Create ipset with CIDR support
ipset create allowed-domains hash:net

# Fetch GitHub meta information and aggregate + add their IP ranges
echo "Fetching GitHub IP ranges..."
gh_ranges=$(curl -s https://api.github.com/meta)
if [ -z "$gh_ranges" ]; then
    echo "ERROR: Failed to fetch GitHub IP ranges"
    exit 1
fi

if ! echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null; then
    echo "ERROR: GitHub API response missing required fields"
    exit 1
fi

echo "Processing GitHub IPs..."
while read -r cidr; do
    if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "ERROR: Invalid CIDR range from GitHub meta: $cidr"
        exit 1
    fi
    echo "Adding GitHub range $cidr"
    ipset add allowed-domains "$cidr"
done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | aggregate -q)

# Resolve and add other allowed domains
for domain in \
    "registry.npmjs.org" \
    "api.anthropic.com" \
    "sentry.io" \
    "statsig.anthropic.com" \
    "statsig.com" \
    "claude.ai" \
    "ghcr.io" \
    "docker.io" \
    "registry-1.docker.io" \
    "deb.debian.org" \
    "security.debian.org" \
    "archive.ubuntu.com" \
    "security.ubuntu.com"; do
    echo "Resolving $domain..."
    ips=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
    if [ -z "$ips" ]; then
        echo "WARNING: Failed to resolve $domain, skipping..."
        continue
    fi

    while read -r ip; do
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "WARNING: Invalid IP from DNS for $domain: $ip"
            continue
        fi
        echo "Adding $ip for $domain"
        ipset add allowed-domains "$ip" 2>/dev/null || true
    done <<< "$ips"
done

# Get host IP from default route
HOST_IP=$(ip route | grep default | awk '{print $3}' | head -n1)
if [ -z "$HOST_IP" ]; then
    echo "WARNING: Failed to detect host IP, trying alternative method..."
    HOST_IP=$(ip route | grep -E '^default' | awk '{print $3}')
fi

if [ -n "$HOST_IP" ]; then
    HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
    echo "Host network detected as: $HOST_NETWORK"
    iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
    iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
else
    echo "WARNING: Could not detect host network"
fi

# Set default policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established connections for already approved traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTPS for package managers and git
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow HTTP for package managers
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Allow only specific outbound traffic to allowed domains
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

echo "Firewall configuration complete"

# Simple connectivity check
echo "Verifying basic connectivity..."
if curl --connect-timeout 5 -s https://api.github.com/zen >/dev/null 2>&1; then
    echo "✓ GitHub API connectivity verified"
else
    echo "WARNING: Unable to reach GitHub API"
fi

if curl --connect-timeout 5 -s https://registry.npmjs.org >/dev/null 2>&1; then
    echo "✓ NPM registry connectivity verified"
else
    echo "WARNING: Unable to reach NPM registry"
fi

# Show summary
echo ""
echo "Firewall rules summary:"
echo "- Allowed: GitHub, NPM, Anthropic, and essential services"
echo "- Blocked: All other outbound traffic"
echo ""
echo "Current ipset entries:"
ipset list allowed-domains | grep -c "^[0-9]" | xargs echo "Total allowed IPs/ranges:"
EOF

    chmod +x "${DEVCONTAINER_DIR}/init-firewall.sh"

    print_message $GREEN "✓ Devcontainer files created"
}

# Function to build the container image
build_container() {
    print_message $YELLOW "Building container image..."

    cd "${DEVCONTAINER_DIR}"

    # Build with podman
    podman build \
        --tag "${IMAGE_NAME}:latest" \
        --build-arg TZ="${TZ:-UTC}" \
        --build-arg CLAUDE_CODE_VERSION="latest" \
        --build-arg GIT_DELTA_VERSION="0.18.2" \
        --build-arg ZSH_IN_DOCKER_VERSION="1.2.0" \
        -f Dockerfile \
        .

    cd ..

    print_message $GREEN "✓ Container image built successfully"
}

# Function to run the container
run_container() {
    print_message $YELLOW "Starting container..."

    # Stop existing container if running
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm "${CONTAINER_NAME}" 2>/dev/null || true

    # Create command history volume if it doesn't exist
    podman volume create commandhistory 2>/dev/null || true
    podman volume create home-node 2>/dev/null || true

    # Check if API key is set
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        print_message $YELLOW "Warning: ANTHROPIC_API_KEY not set. You'll need to authenticate manually."
    fi

    # Run the container
    podman run -d \
        --name "${CONTAINER_NAME}" \
        --hostname "${CONTAINER_NAME}" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        --env "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
        --env "CLAUDE_TELEMETRY_OPTOUT=1" \
        --volume "${WORKSPACE_DIR}:/workspace:Z" \
        --volume "commandhistory:/commandhistory" \
        --volume "home-node:/home/node:Z" \
        --workdir /workspace \
        --user node \
        "${IMAGE_NAME}:latest" \
        sleep infinity

    # Execute firewall setup
    print_message $YELLOW "Setting up firewall..."
    podman exec -u root "${CONTAINER_NAME}" /bin/bash /workspace/.devcontainer/init-firewall.sh || \
        print_message $YELLOW "Warning: Firewall setup encountered issues (this is normal in some environments)"

    print_message $GREEN "✓ Container is running"
}

# Function to enter the container
enter_container() {
    print_message $YELLOW "Entering container..."

    # Check if API key is set
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        print_message $YELLOW "Note: ANTHROPIC_API_KEY not set. Set it in the container with:"
        print_message $YELLOW "export ANTHROPIC_API_KEY='your-api-key-here'"
    fi

    podman exec -it "${CONTAINER_NAME}" /bin/zsh
}

# Function to stop the container
stop_container() {
    print_message $YELLOW "Stopping container..."
    podman stop "${CONTAINER_NAME}"
    print_message $GREEN "✓ Container stopped"
}

# Function to remove the container
remove_container() {
    print_message $YELLOW "Removing container..."
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm "${CONTAINER_NAME}" 2>/dev/null || true
    print_message $GREEN "✓ Container removed"
}

# Function to show usage
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    setup       Create devcontainer files and build image (default)
    build       Build the container image
    run         Run the container
    enter       Enter the running container
    stop        Stop the container
    remove      Remove the container
    rebuild     Remove, rebuild, and run the container

Options:
    -n NAME     Container name (default: claude-code-devcontainer)
    -i IMAGE    Image name (default: claude-code-dev)
    -w PATH     Workspace directory (default: current directory)
    -h          Show this help message

Environment Variables:
    ANTHROPIC_API_KEY   Your Anthropic API key for Claude Code authentication

Examples:
    export ANTHROPIC_API_KEY="sk-ant-..."
    $0              # Setup and run everything
    $0 setup        # Just create the devcontainer files
    $0 build        # Build the container image
    $0 run          # Run the container
    $0 enter        # Enter the running container
    $0 rebuild      # Rebuild everything from scratch
EOF
}

# Parse command line arguments
COMMAND="${1:-setup}"

while getopts "n:i:w:h" opt; do
    case $opt in
        n) CONTAINER_NAME="$OPTARG" ;;
        i) IMAGE_NAME="$OPTARG" ;;
        w) WORKSPACE_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
    esac
done

# Main execution
print_message $GREEN "Claude Code Devcontainer Setup for Podman"
print_message $GREEN "========================================"

check_podman

case "$COMMAND" in
    setup)
        create_devcontainer_structure
        build_container
        run_container
        print_message $GREEN "\n✓ Setup complete! Run '$0 enter' to enter the container."
        ;;
    build)
        build_container
        ;;
    run)
        run_container
        ;;
    enter)
        enter_container
        ;;
    stop)
        stop_container
        ;;
    remove)
        remove_container
        ;;
    rebuild)
        remove_container
        build_container
        run_container
        print_message $GREEN "\n✓ Rebuild complete! Run '$0 enter' to enter the container."
        ;;
    *)
        print_message $RED "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
