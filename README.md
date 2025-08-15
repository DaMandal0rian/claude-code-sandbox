# Claude Code Devcontainer for Podman

A secure, production-ready development container setup for Claude Code using Podman. This repository provides two container configurations: a standard development environment and a security-hardened version for sensitive projects.

## 🚀 Quick Start

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Clone or download the setup script
curl -O https://raw.githubusercontent.com/DaMandal0rian/claude-code-sandbox/refs/heads/main/setup-devcontainer.sh
chmod +x setup-devcontainer.sh

# Run the setup (creates files, builds, and starts container)
./setup-devcontainer.sh

# Enter the container
./setup-devcontainer.sh enter

# Verify Claude Code is working
claude --version
```

## 🔑 Authentication

Claude Code requires authentication to work. When running in a container, you cannot use browser-based authentication, so you must use an API key.

### Getting an API Key

1. Go to [Anthropic Console](https://console.anthropic.com/settings/keys)
2. Create a new API key
3. Copy the key (it starts with `sk-ant-`)

### Using the API Key

**Method 1: Environment Variable (Recommended)**

```bash
# Set before running the container
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
./setup-devcontainer.sh run
```

**Method 2: Inside the Container**

```bash
# Enter the container first
./setup-devcontainer.sh enter

# Then set the API key
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Test it works
claude "Hello, can you hear me?"
```

**Method 3: Add to Shell Configuration**

```bash
# Inside the container, add to ~/.zshrc
echo 'export ANTHROPIC_API_KEY="sk-ant-your-key-here"' >> ~/.zshrc
source ~/.zshrc
```

### Security Best Practices for API Keys

- **Never commit API keys** to version control
- **Use environment variables** instead of hardcoding
- **Rotate keys regularly** for production use
- **Use separate keys** for different projects
- **Store securely** using a password manager or secrets tool

For production environments, consider using:

```bash
# Using a secrets file (not in git)
source ~/.claude-secrets
./setup-hardened-devcontainer.sh run

# Using a password manager
export ANTHROPIC_API_KEY=$(pass show anthropic/api-key)
./setup-hardended-devcontainer.sh run
```

## 📋 Prerequisites

- **Podman** 3.0 or higher
- **Git**
- **Linux/macOS** (Windows users can use WSL2)
- **Anthropic API Key** (get one at <https://console.anthropic.com>)
- At least 4GB of available RAM
- 10GB of free disk space

## 🏗️ Architecture

Both container versions are based on the official Claude Code reference implementation with adaptations for Podman:

- **Base Image**: Node.js 20 on Debian Bookworm
- **User**: Non-root `node` user with limited sudo
- **Shell**: ZSH with Oh My Zsh
- **Languages**: Node.js
- **Claude Code**: Installed via npm (`@anthropic-ai/claude-code`)
- **Authentication**: API key-based (no browser required)

## 📦 Available Versions

### 1. Standard Development Container

The standard version provides a fully-featured development environment with:

- **Developer Tools**: Git, fzf, jq, git-delta, capsh
- **Network Security**: Basic firewall with configurable rules
- **VS Code Integration**: Pre-configured extensions and settings
- **Persistent Storage**: Command history and home directory
- **API Key Support**: Automatic environment variable passing

**Use this version for:**

- General development work
- Learning and experimentation
- Projects without sensitive data
- Quick prototyping

### 2. Hardened Security Container

The hardened version adds multiple security layers:

- **Minimal Capabilities**: Drops ALL capabilities, adds only essential ones
- **Read-only Filesystem**: Root filesystem is read-only with specific tmpfs mounts
- **Strict Firewall**: Default DROP policy with domain-based allowlisting
- **Resource Limits**: CPU, memory, and process limits
- **Security Monitoring**: Process and network connection monitoring
- **Audit Logging**: Comprehensive security event logging
- **Additional Tools**: bandit, safety, pip-audit for security scanning

**Use this version for:**

- Client projects with sensitive data
- Production code development
- Security-critical applications
- Compliance-required environments

## 🛠️ Installation & Usage

### Basic Commands

```bash
# Setup (creates files, builds image, runs container)
./setup-devcontainer.sh setup

# Build only
./setup-devcontainer.sh build

# Run container
./setup-devcontainer.sh run

# Enter running container
./setup-devcontainer.sh enter

# Stop container
./setup-devcontainer.sh stop

# Remove container
./setup-devcontainer.sh remove

# Rebuild from scratch
./setup-devcontainer.sh rebuild
```

### Command Options

```bash
-n NAME     # Container name (default: claude-code-devcontainer)
-i IMAGE    # Image name (default: claude-code-dev)
-w PATH     # Workspace directory (default: current directory)
-h          # Show help message

# Hardened version only:
-s          # Enable strict mode (default: true)
-S          # Enable seccomp filtering (default: true)
-a          # Enable AppArmor if available (default: false)
```

### Security Audit (Hardened Version)

```bash
# Run comprehensive security audit
./setup-hardened-devcontainer.sh audit

# View security report inside container
./setup-hardened-devcontainer.sh enter
cat /tmp/security-report.txt

# Monitor active connections
./setup-hardened-devcontainer.sh enter
monitor-connections

# Check firewall status
./setup-hardened-devcontainer.sh enter
fw-status
```

## 🔧 Configuration

### Environment Variables

```bash
# Required for Claude Code
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Optional configurations
export TZ="America/New_York"
export CLAUDE_TELEMETRY_OPTOUT=1  # Disable telemetry

# For hardened version
export ENABLE_STRICT_MODE=true
export ENABLE_SECCOMP=true
export ENABLE_APPARMOR=false
```

### Docker Compose Alternative

Create a `docker-compose.yml` for easier management:

```yaml
version: '3.8'
services:
  claude-code:
    image: claude-code-dev:latest
    container_name: claude-code-devcontainer
    hostname: claude-code-devcontainer
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - CLAUDE_TELEMETRY_OPTOUT=1
      - TZ=${TZ:-UTC}
    volumes:
      - .:/workspace:Z
      - commandhistory:/commandhistory
      - home-node:/home/node
    working_dir: /workspace
    user: node
    command: sleep infinity

volumes:
  commandhistory:
  home-node:
```

### Customizing Allowed Domains (Hardened Version)

Edit the `ALLOWED_DOMAINS` array in `init-security.sh`:

```bash
ALLOWED_DOMAINS=(
    "registry.npmjs.org"
    "github.com"
    "api.anthropic.com"
    # Add your domains here
    "your-company-registry.com"
)
```

### Resource Limits (Hardened Version)

Modify these variables in the script:

```bash
readonly MAX_MEMORY="4g"      # Maximum memory
readonly MAX_CPU="2"          # Maximum CPU cores
readonly MAX_PIDS="512"       # Maximum process IDs
```

## 🔒 Security Features Comparison

| Feature | Standard | Hardened |
|---------|----------|----------|
| Non-root user | ✅ | ✅ |
| Basic firewall | ✅ | ✅ |
| API key authentication | ✅ | ✅ |
| Capability dropping | Partial | ALL dropped |
| Read-only root filesystem | ❌ | ✅ |
| Domain allowlisting | ✅ | ✅ |
| Resource limits | Basic | Strict |
| Security monitoring | ❌ | ✅ |
| Seccomp filtering | ❌ | Optional |
| Process monitoring | ❌ | ✅ |
| Audit logging | ❌ | ✅ |

## 🚨 Troubleshooting

### Claude Code Authentication Issues

```bash
# Check if API key is set
echo $ANTHROPIC_API_KEY

# Test Claude directly
claude --version
claude doctor

# If "unauthorized" error, verify your API key
# Make sure it starts with "sk-ant-"
```

### Container won't start

```bash
# Check Podman version
podman --version

# View container logs
podman logs claude-code-devcontainer

# Check if container exists
podman ps -a
```

### Firewall issues

```bash
# Check if capsh is available
which capsh

# View firewall logs
podman exec claude-code-devcontainer sudo iptables -L -v

# Some environments don't support NET_ADMIN
# Run without strict firewall:
podman run --cap-drop=NET_ADMIN ...
```

### Permission denied errors

```bash
# Ensure SELinux labels are correct (Fedora/RHEL)
# The script uses :Z flag for this automatically

# Check SELinux status
sestatus

# If issues persist, try :z instead of :Z
```

### Network connectivity issues

```bash
# Test API connectivity inside container
curl -I https://api.anthropic.com

# Check allowed domains
podman exec claude-code-devcontainer sudo ipset list allowed-domains

# For debugging, temporarily allow all traffic
podman exec claude-code-devcontainer sudo iptables -P OUTPUT ACCEPT
```

## 📚 VS Code Integration

The devcontainer.json is configured for VS Code with:

### Extensions

- ESLint
- Prettier
- GitLens

### Settings

- Format on save
- ZSH as default terminal
- API key passed automatically

To use with VS Code:

1. Install the "Remote - Containers" extension
2. Set your API key: `export ANTHROPIC_API_KEY="sk-ant-..."`
3. Open your project folder
4. Click "Reopen in Container" when prompted

## 🧪 Development Workflow

### Standard Version

```bash
# 1. Set API key
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# 2. Setup and enter container
./setup-devcontainer.sh
./setup-devcontainer.sh enter

# 3. Start coding with Claude
claude "help me create a REST API with Express"

# 4. Use git normally
git add .
git commit -m "Add API endpoints"
git push
```

### Hardened Version

```bash
# 1. Set API key securely
export ANTHROPIC_API_KEY=$(pass show anthropic/api-key)

# 2. Setup with security
./setup-hardened-devcontainer.sh

# 3. Run security audit
./setup-hardened-devcontainer.sh audit

# 4. Enter and verify security
./setup-hardened-devcontainer.sh enter
security-report

# 5. Development with monitoring
claude "create a secure authentication system"

# 6. Run security scans
security-scan
pip-audit
```

## 🔄 Maintenance

### Updating Claude Code

```bash
# Inside the container
npm update -g @anthropic-ai/claude-code

# Or rebuild the container
./setup-devcontainer.sh rebuild
```

### Updating the Container

```bash
# Pull latest base image and rebuild
podman pull node:20-bookworm-slim
./setup-devcontainer.sh rebuild
```

### Cleaning Up

```bash
# Remove container
./setup-devcontainer.sh remove

# Remove volumes
podman volume rm commandhistory home-node

# Remove image
podman rmi claude-code-dev:latest

# Clean up API key
unset ANTHROPIC_API_KEY
```

### Backup and Restore

```bash
# Backup workspace
tar -czf workspace-backup.tar.gz /path/to/workspace

# Backup volumes (includes Claude settings)
podman volume export commandhistory > commandhistory.tar
podman volume export home-node > home-node.tar

# Restore volumes
podman volume import commandhistory < commandhistory.tar
podman volume import home-node < home-node.tar
```

## ⚡ Performance Tips

1. **Allocate sufficient resources**: Increase CPU/memory limits for better performance
2. **Use local storage**: Avoid network-mounted workspaces
3. **Cache dependencies**: Use volume mounts for package caches
4. **Persistent API key**: Add to shell config to avoid re-entering

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test your changes with both versions
4. Submit a pull request

## 📄 License

This project is based on the official Claude Code devcontainer reference implementation and is provided as-is for educational and development purposes.

## 🔗 Resources

- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code)
- [Anthropic API Keys](https://console.anthropic.com/settings/keys)
- [Podman Documentation](https://docs.podman.io/)
- [Devcontainers Specification](https://containers.dev/)
- [VS Code Remote Containers](https://code.visualstudio.com/docs/remote/containers)

## ⚠️ Security Disclaimer

While the hardened version implements multiple security layers, no system is completely secure. Always:

- **Protect your API keys** - never commit them to version control
- Keep the container and tools updated
- Review security logs regularly
- Follow security best practices
- Never disable security features in production
- Audit third-party dependencies
- Rotate API keys periodically

For sensitive projects, consider additional security measures such as:

- Network isolation
- Encrypted storage
- Access logging
- Regular security audits
- Compliance scanning
- API key rotation policies

---

**Note**: This is an unofficial implementation adapted for Podman. For the official Claude Code setup, refer to the [Anthropic documentation](https://docs.anthropic.com/en/docs/claude-code).
