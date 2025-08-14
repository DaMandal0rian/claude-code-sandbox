# Claude Code Devcontainer for Podman

A secure, production-ready development container setup for Claude Code using Podman. This repository provides two container configurations: a standard development environment and a security-hardened version for sensitive projects.

## 🚀 Quick Start

```bash
# Clone or download the setup script
curl -O https://raw.githubusercontent.com/DaMandal0rian/claude-code-sandbox/refs/heads/main/setup-devcontainer.sh
chmod +x setup-devcontainer.sh

# Run the setup (creates files, builds, and starts container)
./setup-devcontainer.sh

# Enter the container
./setup-devcontainer.sh enter
```

## 📋 Prerequisites

- **Podman** 3.0 or higher
- **Git**
- **Linux/macOS** (Windows users can use WSL2)
- At least 4GB of available RAM
- 10GB of free disk space

## 🏗️ Architecture

Both container versions are based on the official Claude Code reference implementation with adaptations for Podman:

- **Base Image**: Node.js 20 on Debian Bookworm
- **User**: Non-root `node` user with limited sudo
- **Shell**: ZSH with Oh My Zsh
- **Languages**: Node.js, Python 3
- **Claude Code**: Installed via devcontainer features

## 📦 Available Versions

### 1. Standard Development Container

The standard version provides a fully-featured development environment with:

- **Developer Tools**: Git, fzf, jq, git-delta
- **Python Support**: Python 3, pip, venv
- **Network Security**: Basic firewall with configurable rules
- **VS Code Integration**: Pre-configured extensions and settings
- **Persistent Storage**: Command history and home directory

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
./setup-devcontainer.sh audit

# View security report inside container
./setup-devcontainer.sh enter
cat /tmp/security-report.txt

# Monitor active connections
./setup-devcontainer.sh enter
monitor-connections

# Check firewall status
./setup-devcontainer.sh enter
fw-status
```

## 🔧 Configuration

### Environment Variables

```bash
# Timezone
export TZ="America/New_York"

# For hardened version
export ENABLE_STRICT_MODE=true
export ENABLE_SECCOMP=true
export ENABLE_APPARMOR=false
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

## 🐍 Python Development

Both versions include Python 3 with development tools:

```bash
# Create virtual environment
python -m venv ~/.venvs/myproject
source ~/.venvs/myproject/bin/activate

# Install packages
pip install requests pandas numpy

# Security scanning (hardened version)
security-scan  # Runs bandit and safety
pip-audit      # Audit installed packages
```

## 🔒 Security Features Comparison

| Feature | Standard | Hardened |
|---------|----------|----------|
| Non-root user | ✅ | ✅ |
| Basic firewall | ✅ | ✅ |
| Capability dropping | Partial | ALL dropped |
| Read-only root filesystem | ❌ | ✅ |
| Domain allowlisting | ❌ | ✅ |
| Resource limits | Basic | Strict |
| Security monitoring | ❌ | ✅ |
| Seccomp filtering | ❌ | Optional |
| Process monitoring | ❌ | ✅ |
| Audit logging | ❌ | ✅ |

## 🚨 Troubleshooting

### Container won't start

```bash
# Check Podman version
podman --version

# View container logs
podman logs claude-code-devcontainer

# Check if container exists
podman ps -a
```

### Firewall issues (Hardened Version)

```bash
# Some environments don't support NET_ADMIN
# Run without strict firewall:
ENABLE_STRICT_MODE=false ./setup-devcontainer.sh run
```

### Permission denied errors

```bash
# Ensure SELinux labels are correct (Fedora/RHEL)
# The script uses :Z flag for this automatically

# Check SELinux status
sestatus
```

### Network connectivity issues

```bash
# For hardened version, add required domains to ALLOWED_DOMAINS
# Edit .devcontainer/init-security.sh

# Test connectivity inside container
curl -I https://api.anthropic.com
```

## 📚 VS Code Integration

The devcontainer.json is configured for VS Code with:

### Extensions

- ESLint
- Prettier
- GitLens
- Python (hardened version)
- Pylance (hardened version)

### Settings

- Format on save
- ZSH as default terminal
- Python linting enabled

To use with VS Code:

1. Install the "Remote - Containers" extension
2. Open your project folder
3. Click "Reopen in Container" when prompted

## 🧪 Development Workflow

### Standard Version

```bash
# 1. Setup and enter container
./setup-devcontainer.sh
./setup-devcontainer.sh enter

# 2. Start coding with Claude
claude "help me create a REST API with Express"

# 3. Use git normally
git add .
git commit -m "Add API endpoints"
git push
```

### Hardened Version

```bash
# 1. Setup with security
./setup-devcontainer.sh

# 2. Run security audit
./setup-devcontainer.sh audit

# 3. Enter and verify security
./setup-devcontainer.sh enter
security-report

# 4. Development with monitoring
claude "create a secure authentication system"

# 5. Run security scans
security-scan
pip-audit
```

## 🔄 Maintenance

### Updating the Container

```bash
# Pull latest base image and rebuild
podman pull node:20-bookworm
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
```

### Backup and Restore

```bash
# Backup workspace
tar -czf workspace-backup.tar.gz /path/to/workspace

# Backup volumes
podman volume export commandhistory > commandhistory.tar
podman volume export home-node > home-node.tar

# Restore volumes
podman volume import commandhistory < commandhistory.tar
podman volume import home-node < home-node.tar
```

## ⚡ Performance Tips

1. **Allocate sufficient resources**: Increase CPU/memory limits for better performance
2. **Use local storage**: Avoid network-mounted workspaces
3. **Limit background processes**: Disable unnecessary monitoring in standard version
4. **Cache dependencies**: Use volume mounts for package caches

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test your changes with both versions
4. Submit a pull request

## 📄 License

This project is based on the official Claude Code devcontainer reference implementation and is provided as-is for educational and development purposes.

## 🔗 Resources

- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code/overview)
- [Podman Documentation](https://docs.podman.io/)
- [Devcontainers Specification](https://containers.dev/)
- [VS Code Remote Containers](https://code.visualstudio.com/docs/remote/containers)

## ⚠️ Security Disclaimer

While the hardened version implements multiple security layers, no system is completely secure. Always:

- Keep the container and tools updated
- Review security logs regularly
- Follow security best practices
- Never disable security features in production
- Audit third-party dependencies

For sensitive projects, consider additional security measures such as:

- Network isolation
- Encrypted storage
- Access logging
- Regular security audits
- Compliance scanning

---

**Note**: This is an unofficial implementation adapted for Podman. For the official Claude Code setup, refer to the [Anthropic documentation](https://docs.anthropic.com/en/docs/claude-code/devcontainer).
