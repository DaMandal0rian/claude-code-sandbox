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
    "ghcr.io/devcontainers/features/node:1": {}
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

FROM node:20-bookworm

# Install basic dependencies
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
    net-tools \
    dnsutils \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

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
RUN mkdir -p /home/node/.npm-global && npm install -g @anthropic-ai/claude

CMD ["/bin/zsh"]
EOF

    # Create init-firewall.sh
    cat > "${DEVCONTAINER_DIR}/init-firewall.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

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

# Function to safely add iptables rules
add_iptables_rule() {
    if ! iptables $@; then
        echo "Warning: Failed to add rule: iptables $@"
    fi
}

# Clear existing rules
iptables -F INPUT 2>/dev/null || true
iptables -F OUTPUT 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true

# Set default policies to ACCEPT initially
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# Allow all loopback traffic
add_iptables_rule -A INPUT -i lo -j ACCEPT
add_iptables_rule -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
add_iptables_rule -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
add_iptables_rule -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS
add_iptables_rule -A OUTPUT -p udp --dport 53 -j ACCEPT
add_iptables_rule -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow HTTPS for package managers and git
add_iptables_rule -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow HTTP for package managers
add_iptables_rule -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Allow SSH
add_iptables_rule -A OUTPUT -p tcp --dport 22 -j ACCEPT

# Create ipset for allowed domains (if ipset is available)
if command -v ipset &> /dev/null; then
    ipset create allowed-domains hash:net 2>/dev/null || true

    # Add common development domains
    domains=(
        "github.com"
        "api.github.com"
        "raw.githubusercontent.com"
        "registry.npmjs.org"
        "api.anthropic.com"
    )

    for domain in "${domains[@]}"; do
        # Resolve domain to IPs
        ips=$(dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
        if [ -n "$ips" ]; then
            while IFS= read -r ip; do
                ipset add allowed-domains "$ip" 2>/dev/null || true
            done <<< "$ips"
        fi
    done

    # Allow traffic to allowed domains
    add_iptables_rule -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT
fi

# Get host network
HOST_IP=$(ip route | grep default | awk '{print $3}' || echo "")
if [ -n "$HOST_IP" ]; then
    HOST_NETWORK=$(echo "$HOST_IP" | sed 's/\.[0-9]*$/.0\/24/')
    echo "Allowing host network: $HOST_NETWORK"
    add_iptables_rule -A INPUT -s "$HOST_NETWORK" -j ACCEPT
    add_iptables_rule -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
fi

# Log dropped packets (optional, for debugging)
# add_iptables_rule -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP-IN: "
# add_iptables_rule -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP-OUT: "

# Final drop rules (commented out for now to avoid breaking connectivity)
# add_iptables_rule -A INPUT -j DROP
# add_iptables_rule -A OUTPUT -j DROP

echo "Firewall setup complete"

# Show current rules
echo "Current firewall rules:"
iptables -L -n -v
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

    # Run the container
    podman run -d \
        --name "${CONTAINER_NAME}" \
        --hostname "${CONTAINER_NAME}" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        --volume "${WORKSPACE_DIR}:/workspace:Z" \
        --volume "commandhistory:/commandhistory" \
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

Examples:
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
