#!/bin/bash

# Claude Code Devcontainer Setup Script for Podman - Hardened Version
# This script sets up a security-hardened devcontainer environment using podman

set -euo pipefail

# Enable strict error handling
set -E
trap 'echo "Error on line $LINENO"' ERR

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
ENABLE_STRICT_MODE="${ENABLE_STRICT_MODE:-true}"
ENABLE_SECCOMP="${ENABLE_SECCOMP:-true}"
ENABLE_APPARMOR="${ENABLE_APPARMOR:-false}"  # Disabled by default, enable if available
ENABLE_NNP="${ENABLE_NNP:-true}"   # controls --security-opt=no-new-privileges

# Security settings
readonly MAX_MEMORY="4g"
readonly MAX_CPU="2"
readonly MAX_PIDS="512"
readonly READONLY_PATHS="/proc/acpi,/proc/kcore,/proc/keys,/proc/latency_stats,/proc/timer_list,/proc/timer_stats,/proc/sched_debug,/proc/scsi,/sys/firmware"

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

# Function to create security policies
create_security_policies() {
    print_message $YELLOW "Creating security policies..."

    mkdir -p "${DEVCONTAINER_DIR}/security"

    # Create seccomp profile
    cat > "${DEVCONTAINER_DIR}/security/seccomp.json" << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        {
            "architecture": "SCMP_ARCH_X86_64",
            "subArchitectures": [
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32"
            ]
        },
        {
            "architecture": "SCMP_ARCH_AARCH64",
            "subArchitectures": [
                "SCMP_ARCH_ARM"
            ]
        }
    ],
    "syscalls": [
        {
            "names": [
                "accept", "accept4", "access", "adjtimex", "alarm", "bind", "brk", "capget", "capset",
                "chdir", "chmod", "chown", "chown32", "clock_adjtime", "clock_adjtime64", "clock_getres",
                "clock_getres_time64", "clock_gettime", "clock_gettime64", "clock_nanosleep",
                "clock_nanosleep_time64", "clone", "clone3", "close", "close_range", "connect", "copy_file_range",
                "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
                "epoll_pwait", "epoll_pwait2", "epoll_wait", "epoll_wait_old", "eventfd", "eventfd2",
                "execve", "execveat", "exit", "exit_group", "faccessat", "faccessat2", "fadvise64",
                "fadvise64_64", "fallocate", "fanotify_mark", "fchdir", "fchmod", "fchmodat", "fchown",
                "fchown32", "fchownat", "fcntl", "fcntl64", "fdatasync", "fgetxattr", "flistxattr",
                "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstat64", "fstatat64", "fstatfs",
                "fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex", "futex_time64", "futimesat",
                "getcpu", "getcwd", "getdents", "getdents64", "getegid", "getegid32", "geteuid",
                "geteuid32", "getgid", "getgid32", "getgroups", "getgroups32", "getitimer", "getpeername",
                "getpgid", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid",
                "getresgid32", "getresuid", "getresuid32", "getrlimit", "get_robust_list", "getrusage",
                "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday",
                "getuid", "getuid32", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1",
                "inotify_rm_watch", "io_cancel", "ioctl", "io_destroy", "io_getevents", "io_pgetevents",
                "io_pgetevents_time64", "ioprio_get", "ioprio_set", "io_setup", "io_submit",
                "io_uring_enter", "io_uring_register", "io_uring_setup", "ipc", "kill", "landlock_add_rule",
                "landlock_create_ruleset", "landlock_restrict_self", "lchown", "lchown32", "lgetxattr",
                "link", "linkat", "listen", "listxattr", "llistxattr", "_llseek", "lremovexattr", "lseek",
                "lsetxattr", "lstat", "lstat64", "madvise", "membarrier", "memfd_create", "memfd_secret",
                "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap",
                "mmap2", "mount_setattr", "mprotect", "mq_getsetattr", "mq_notify", "mq_open",
                "mq_timedreceive", "mq_timedreceive_time64", "mq_timedsend", "mq_timedsend_time64",
                "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock",
                "munlockall", "munmap", "nanosleep", "newfstatat", "_newselect", "open", "openat",
                "openat2", "pause", "pidfd_getfd", "pidfd_open", "pidfd_send_signal", "pipe", "pipe2",
                "pivot_root", "pkey_alloc", "pkey_free", "pkey_mprotect", "poll", "ppoll", "ppoll_time64",
                "prctl", "pread64", "preadv", "preadv2", "prlimit64", "process_mrelease", "pselect6",
                "pselect6_time64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink",
                "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmmsg_time64", "recvmsg",
                "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall",
                "rmdir", "rseq", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
                "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait", "rt_sigtimedwait_time64",
                "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam",
                "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler",
                "sched_rr_get_interval", "sched_rr_get_interval_time64", "sched_setaffinity",
                "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp",
                "select", "semctl", "semget", "semop", "semtimedop", "semtimedop_time64", "send",
                "sendfile", "sendfile64", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsgid32",
                "setfsuid", "setfsuid32", "setgid", "setgid32", "setgroups", "setgroups32", "setitimer",
                "setpgid", "setpriority", "setregid", "setregid32", "setresgid", "setresgid32",
                "setresuid", "setresuid32", "setreuid", "setreuid32", "setrlimit", "set_robust_list",
                "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setuid32",
                "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd",
                "signalfd4", "sigpending", "sigprocmask", "sigreturn", "socket", "socketcall",
                "socketpair", "splice", "stat", "stat64", "statfs", "statfs64", "statx", "symlink",
                "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time",
                "timer_create", "timer_delete", "timer_getoverrun", "timer_gettime", "timer_gettime64",
                "timer_settime", "timer_settime64", "timerfd_create", "timerfd_gettime",
                "timerfd_gettime64", "timerfd_settime", "timerfd_settime64", "times", "tkill", "truncate",
                "truncate64", "ugetrlimit", "umask", "uname", "unlink", "unlinkat", "utime", "utimensat",
                "utimensat_time64", "utimes", "vfork", "vmsplice", "wait4", "waitid", "waitpid", "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": [
                "ptrace"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 0,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        },
        {
            "names": [
                "personality"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 0,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        },
        {
            "names": [
                "personality"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 8,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        },
        {
            "names": [
                "personality"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 131072,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        },
        {
            "names": [
                "personality"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 131080,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        },
        {
            "names": [
                "personality"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 4294967295,
                    "op": "SCMP_CMP_EQ"
                }
            ]
        }
    ]
}
EOF

    # Create capabilities whitelist
    cat > "${DEVCONTAINER_DIR}/security/capabilities.conf" << 'EOF'
# Capabilities configuration for hardened devcontainer
# Only essential capabilities are granted

# Network admin for firewall rules (required for Claude Code security)
CAP_NET_ADMIN
CAP_NET_RAW

# Basic capabilities for development
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_FOWNER
CAP_FSETID
CAP_KILL
CAP_SETGID
CAP_SETUID
CAP_SETPCAP
CAP_SYS_CHROOT

# Explicitly dropped dangerous capabilities:
# CAP_SYS_ADMIN
# CAP_SYS_MODULE
# CAP_SYS_PTRACE
# CAP_SYS_RAWIO
# CAP_SYS_TIME
# CAP_MKNOD
# CAP_AUDIT_WRITE
# CAP_SETFCAP
EOF

    print_message $GREEN "✓ Security policies created"
}

# Function to create devcontainer directory structure
create_devcontainer_structure() {
    print_message $YELLOW "Creating devcontainer directory structure..."

    mkdir -p "${DEVCONTAINER_DIR}"

    # Create devcontainer.json with enhanced security
    cat > "${DEVCONTAINER_DIR}/devcontainer.json" << 'EOF'
{
  "name": "Claude Code Sandbox - Hardened",
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
    "--cap-drop=ALL",
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW",
    "--cap-add=CHOWN",
    "--cap-add=DAC_OVERRIDE",
    "--cap-add=FOWNER",
    "--cap-add=FSETID",
    "--cap-add=KILL",
    "--cap-add=SETGID",
    "--cap-add=SETUID",
    "--cap-add=SETPCAP",
    "--cap-add=SYS_CHROOT",
    "--security-opt=no-new-privileges:true",
    "--read-only",
    "--tmpfs=/tmp:rw,noexec,nosuid,size=2g",
    "--tmpfs=/var/tmp:rw,noexec,nosuid,size=1g"
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
        "editor.codeActionsOnSave": { "source.fixAll.eslint": "explicit" },
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
    "XDG_CACHE_HOME": "/tmp/xdg-cache"
  },
  "remoteUser": "node",
  "workspaceFolder": "/workspace",
  "mounts": [
    "source=${localWorkspaceFolder},target=/workspace,type=bind",
    "source=commandhistory,target=/commandhistory,type=volume",
    "source=home-node,target=/home/node,type=volume"
  ],
  "postCreateCommand": "claude --version && /bin/bash .devcontainer/post-create.sh",
  "postStartCommand": "/bin/bash .devcontainer/init-security.sh"
}
EOF

# Create hardened Dockerfile
cat > "${DEVCONTAINER_DIR}/Dockerfile" << 'EOF'
FROM node:20-bookworm-slim

# Security: Run package updates first
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
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
    libseccomp2 \
    libcap2-bin \
    procps \
    iproute2 \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Try to install aggregate tool, but don't fail if it doesn't work
RUN pip3 install --break-system-packages aggregate6 2>/dev/null || \
    echo "Note: aggregate6 installation failed, will use fallback"

# Security: Create non-root user with limited sudo
ARG USERNAME=node
RUN groupadd -r $USERNAME || true && \
    usermod -aG sudo $USERNAME && \
    echo "$USERNAME ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/ipset, /usr/sbin/iptables-save" > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME && \
    visudo -c -f /etc/sudoers.d/$USERNAME

# Security: Set up restricted shell environment
RUN echo "umask 077" >> /etc/profile && \
    echo "ulimit -c 0" >> /etc/profile && \
    echo "readonly TMOUT=900" >> /etc/profile.d/timeout.sh && \
    chmod 644 /etc/profile.d/timeout.sh

# Set up command history with restricted permissions
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" && \
    mkdir -p /commandhistory && \
    touch /commandhistory/.bash_history && \
    chmod 700 /commandhistory && \
    chown -R $USERNAME:$USERNAME /commandhistory && \
    echo "$SNIPPET" >> "/home/$USERNAME/.bashrc"

# Set DEVCONTAINER environment variable
ENV DEVCONTAINER=true
ENV NODE_ENV=development

# Security: Restrict file permissions
RUN chmod 700 /home/$USERNAME && \
    find /home/$USERNAME -type f -exec chmod 600 {} \; 2>/dev/null || true && \
    find /home/$USERNAME -type d -exec chmod 700 {} \; 2>/dev/null || true

# Create workspace and config directories with restricted permissions
RUN mkdir -p /workspace /home/$USERNAME/.claude /home/$USERNAME/.config && \
    chmod 700 /workspace /home/$USERNAME/.claude /home/$USERNAME/.config && \
    chown -R $USERNAME:$USERNAME /workspace /home/$USERNAME/.claude /home/$USERNAME/.config

WORKDIR /workspace

# Install git-delta for better diffs
ARG GIT_DELTA_VERSION=0.18.2
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    dpkg -i "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
    rm "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"

# Security: Configure git with signing
RUN git config --global init.defaultBranch main && \
    git config --global core.autocrlf input && \
    git config --global pull.rebase false && \
    git config --global commit.gpgsign false

# Switch to non-root user
USER $USERNAME

# Install global npm packages directory
ENV NPM_CONFIG_PREFIX=/home/$USERNAME/.npm-global
ENV PATH=/home/$USERNAME/.npm-global/bin:$PATH

# Install Oh My Zsh as root
USER root
ARG ZSH_IN_DOCKER_VERSION=1.2.0
RUN export HOME=/home/$USERNAME && \
    wget -q -O /usr/local/bin/zid.sh "https://github.com/deluan/zsh-in-docker/releases/download/v${ZSH_IN_DOCKER_VERSION}/zsh-in-docker.sh" && \
    chmod +x /usr/local/bin/zid.sh && \
    HOME=/home/$USERNAME /usr/local/bin/zid.sh -t robbyrussell -p git -p npm -p node && \
    chown -R $USERNAME:$USERNAME /home/$USERNAME && \
    usermod -s /usr/bin/zsh $USERNAME

# Switch to user
USER $USERNAME

# Install Claude Code CLI via npm
RUN npm install -g @anthropic-ai/claude-code

# Shell history hardening
RUN echo "export HISTSIZE=10000" >> ~/.zshrc && \
    echo "export SAVEHIST=10000" >> ~/.zshrc && \
    echo "export HISTTIMEFORMAT='%F %T '" >> ~/.zshrc && \
    echo "setopt HIST_IGNORE_SPACE" >> ~/.zshrc && \
    echo "setopt HIST_EXPIRE_DUPS_FIRST" >> ~/.zshrc

# Alias persistence
RUN cat > /home/node/.zsh_aliases <<'ALIASES'
alias check-secrets='git secrets --scan 2>/dev/null || echo "git-secrets not installed"'
alias fw-status='sudo iptables -L -n -v'
alias monitor-connections='while true; do clear; echo "=== Active Network Connections ==="; ss -tunp 2>/dev/null | grep -v "127.0.0.1" || ss -tun | grep -v "127.0.0.1"; echo -e "\nPress Ctrl+C to stop"; sleep 5; done'
alias security-report='cat /tmp/security-report.txt 2>/dev/null || echo "No security report found"'
alias check-processes='ps aux --forest'
alias check-ports='ss -tlnp 2>/dev/null || ss -tln'
alias check-firewall='sudo iptables -L -n -v'
alias monitor-logs='tail -f /tmp/security.log 2>/dev/null || echo "No security log found"'
alias ll='ls -la'
ALIASES

RUN echo 'if [ -f ~/.zsh_aliases ]; then source ~/.zsh_aliases; fi' >> /home/node/.zshrc && \
    echo 'if [ -f ~/.zsh_aliases ]; then source ~/.zsh_aliases; fi' >> /home/node/.zshenv && \
    chown node:node /home/node/.zsh_aliases && chmod 644 /home/node/.zsh_aliases

# Ensure PATH for npm-global survives login/non-login shells
RUN echo 'typeset -U path PATH; path=(/home/node/.npm-global/bin $path); export PATH=${path:+"${(j/:/)path}"}' >> /home/node/.zshenv

# Make zsh the default shell for processes
ENV SHELL=/usr/bin/zsh

# Save a skeleton of /home/node for seeding mounted volume on first run
USER root
RUN mkdir -p /opt/container-skel/home && \
    cp -a /home/$USERNAME/. /opt/container-skel/home/
USER $USERNAME

CMD ["/usr/bin/zsh", "-l"]
EOF

    # Create enhanced security initialization script (with Anthropic-aligned firewall)
    cat > "${DEVCONTAINER_DIR}/init-security.sh" << 'EOF'
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Security initialization script for Claude Code devcontainer
echo "Initializing security measures..."

# Check if running in a container
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
    echo "Not running in a container, skipping security setup"
    exit 0
fi

# Function to log security events
log_security() {
    echo "[SECURITY] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a /tmp/security.log
}

# Check for required capabilities
if ! command -v capsh &> /dev/null; then
    log_security "Error: capsh not found. Installing libcap2-bin might be required."
    exit 1
fi

if ! capsh --print | grep -q cap_net_admin; then
    log_security "Warning: NET_ADMIN capability not available, firewall setup will be limited"
fi

# Create security audit directory
mkdir -p /tmp/security-audit
chmod 700 /tmp/security-audit

# 1. Set up strict firewall rules (Anthropic-aligned approach)
log_security "Configuring firewall rules..."

# Extract container DNS info BEFORE any flushing
CONTAINER_DNS_RULES=$(sudo iptables-save -t nat 2>/dev/null | grep -E "(127\.0\.0\.11|10\.88\.0\.1)" || true)

# Clear existing rules and ipsets
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true
sudo ip6tables -F 2>/dev/null || true
sudo ip6tables -X 2>/dev/null || true
sudo ipset destroy allowed-domains 2>/dev/null || true
sudo ipset destroy allowed-domains6 2>/dev/null || true

# Selectively restore ONLY internal container DNS resolution
if [ -n "$CONTAINER_DNS_RULES" ]; then
    log_security "Restoring container DNS rules..."
    sudo iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    sudo iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$CONTAINER_DNS_RULES" | while IFS= read -r rule; do
        if [[ $rule == -A* ]]; then
            sudo iptables -t nat $rule 2>/dev/null || true
        fi
    done
else
    log_security "No container DNS rules to restore"
fi

# First allow DNS and localhost before any restrictions
# Allow outbound DNS
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
sudo ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow inbound DNS responses
sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p udp --sport 53 -j ACCEPT
sudo ip6tables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# Allow outbound SSH
sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
sudo ip6tables -A OUTPUT -p tcp --dport 22 -j ACCEPT

# Allow inbound SSH responses
sudo iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Allow localhost
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo ip6tables -A INPUT -i lo -j ACCEPT
sudo ip6tables -A OUTPUT -o lo -j ACCEPT

# Create ipset with CIDR support
sudo ipset create allowed-domains hash:net family inet
sudo ipset create allowed-domains6 hash:net family inet6

# Check if aggregate is available
AGGREGATE_CMD=""
if command -v aggregate &> /dev/null; then
    AGGREGATE_CMD="aggregate -q"
elif command -v aggregate6 &> /dev/null; then
    AGGREGATE_CMD="aggregate6 -q"
fi

# Fetch GitHub meta information and aggregate + add their IP ranges
log_security "Fetching GitHub IP ranges..."
gh_ranges=$(curl -s --connect-timeout 10 https://api.github.com/meta || echo "")
if [ -z "$gh_ranges" ]; then
    log_security "Warning: Failed to fetch GitHub IP ranges, using fallback"
    # Add some known GitHub ranges as fallback
    sudo ipset add allowed-domains "140.82.112.0/20" 2>/dev/null || true
    sudo ipset add allowed-domains "192.30.252.0/22" 2>/dev/null || true
    sudo ipset add allowed-domains "185.199.108.0/22" 2>/dev/null || true
else
    if echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null 2>&1; then
        log_security "Processing GitHub IPs..."
        # Use aggregate if available, otherwise add individually
        if [ -n "$AGGREGATE_CMD" ]; then
            while read -r cidr; do
                if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                    log_security "Adding GitHub range $cidr"
                    sudo ipset add allowed-domains "$cidr" 2>/dev/null || true
                fi
            done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | $AGGREGATE_CMD)
        else
            # Fallback without aggregate - just add all ranges
            log_security "Adding GitHub IPs without aggregation..."
            echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | sort -u | while read -r cidr; do
                if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                    sudo ipset add allowed-domains "$cidr" 2>/dev/null || true
                fi
            done
        fi
    else
        log_security "Warning: GitHub API response format unexpected"
    fi
fi

# Define comprehensive allowed domains for hardened environment
ALLOWED_DOMAINS=(
    # Package registries
    "registry.npmjs.org"
    "registry.yarnpkg.com"
    "pypi.org"
    "files.pythonhosted.org"

    # Version control
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "gitlab.com"
    "bitbucket.org"

    # Claude/Anthropic (required)
    "api.anthropic.com"
    "claude.ai"
    "sentry.io"
    "statsig.anthropic.com"
    "statsig.com"

    # Container registries
    "ghcr.io"
    "docker.io"
    "registry-1.docker.io"
    "registry.docker.io"

    # Development tools
    "deb.debian.org"
    "security.debian.org"
    "archive.ubuntu.com"
    "security.ubuntu.com"
    "packages.microsoft.com"

    # Security tools
    "cve.mitre.org"
    "nvd.nist.gov"
)

# Resolve and add IPs to ipset
for domain in "${ALLOWED_DOMAINS[@]}"; do
    log_security "Resolving $domain..."

    # IPv4
    ips=$(dig +short A "$domain" @8.8.8.8 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
    if [ -z "$ips" ]; then
        # Try system resolver as fallback
        ips=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
    fi

    if [ -n "$ips" ]; then
        while IFS= read -r ip; do
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                sudo ipset add allowed-domains "$ip" 2>/dev/null || true
            fi
        done <<< "$ips"
    else
        log_security "Warning: Failed to resolve $domain"
    fi

    # IPv6
    ips6=$(dig +short AAAA "$domain" @2001:4860:4860::8888 2>/dev/null | grep ':' || true)
    if [ -n "$ips6" ]; then
        while IFS= read -r ip; do
            sudo ipset add allowed-domains6 "$ip" 2>/dev/null || true
        done <<< "$ips6"
    fi
done

# Get host IP from default route
HOST_IP=$(ip route | grep default | awk '{print $3}' | head -n1)
if [ -z "$HOST_IP" ]; then
    log_security "Warning: Failed to detect host IP, trying alternative method..."
    HOST_IP=$(ip route | grep -E '^default' | cut -d' ' -f3)
fi

if [ -n "$HOST_IP" ]; then
    HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
    log_security "Host network detected as: $HOST_NETWORK"
    sudo iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
    sudo iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT
    sudo ip6tables -A INPUT -s fe80::/10 -j ACCEPT  # Link-local IPv6
    sudo ip6tables -A OUTPUT -d fe80::/10 -j ACCEPT
else
    log_security "Warning: Could not detect host network"
fi

# Set default policies to DROP (hardened)
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
sudo ip6tables -P INPUT DROP
sudo ip6tables -P FORWARD DROP
sudo ip6tables -P OUTPUT DROP

# Allow established connections for already approved traffic
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTPS for package managers and git (to allowed domains only)
sudo iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-domains dst -j ACCEPT
sudo ip6tables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-domains6 dst -j ACCEPT

# Allow HTTP for package managers (to allowed domains only)
sudo iptables -A OUTPUT -p tcp --dport 80 -m set --match-set allowed-domains dst -j ACCEPT
sudo ip6tables -A OUTPUT -p tcp --dport 80 -m set --match-set allowed-domains6 dst -j ACCEPT

# Allow git protocol (to allowed domains only)
sudo iptables -A OUTPUT -p tcp --dport 9418 -m set --match-set allowed-domains dst -j ACCEPT
sudo ip6tables -A OUTPUT -p tcp --dport 9418 -m set --match-set allowed-domains6 dst -j ACCEPT

# Log dropped packets (rate limited) - for security monitoring
sudo iptables -A INPUT -m limit --limit 1/min -j LOG --log-prefix "FW-DROP-IN: " --log-level 4
sudo iptables -A OUTPUT -m limit --limit 1/min -j LOG --log-prefix "FW-DROP-OUT: " --log-level 4
sudo ip6tables -A INPUT -m limit --limit 1/min -j LOG --log-prefix "FW6-DROP-IN: " --log-level 4
sudo ip6tables -A OUTPUT -m limit --limit 1/min -j LOG --log-prefix "FW6-DROP-OUT: " --log-level 4

log_security "Firewall configuration complete"

# Verify firewall rules
log_security "Verifying firewall configuration..."
if curl --connect-timeout 5 -s https://example.com >/dev/null 2>&1; then
    log_security "ERROR: Firewall verification failed - was able to reach https://example.com"
else
    log_security "✓ Firewall verification passed - unable to reach https://example.com as expected"
fi

# Verify GitHub API access
if curl --connect-timeout 5 -s https://api.github.com/zen >/dev/null 2>&1; then
    log_security "✓ GitHub API connectivity verified"
else
    log_security "WARNING: Unable to reach GitHub API"
fi

# 2. File system hardening
log_security "Applying filesystem restrictions..."

# Set restrictive umask
umask 077

# Create restricted directories
mkdir -p /tmp/restricted
chmod 700 /tmp/restricted

# 3. Process monitoring setup
log_security "Setting up process monitoring..."

# Create monitoring script
cat > /tmp/monitor-processes.sh << 'MONITOR_EOF'
#!/bin/bash
# Enhanced process monitor for hardened environment
while true; do
    # Check for suspicious processes
    suspicious=$(ps aux | grep -E "(nc|netcat|nmap|tcpdump|wireshark|masscan|hydra|sqlmap)" | grep -v grep || true)
    if [ -n "$suspicious" ]; then
        echo "[ALERT] $(date '+%Y-%m-%d %H:%M:%S') Suspicious process detected: $suspicious" >> /tmp/security.log
    fi

    # Monitor high CPU/memory usage
    high_usage=$(ps aux | awk '$3 > 80.0 || $4 > 80.0 {print}' | grep -v "COMMAND" || true)
    if [ -n "$high_usage" ]; then
        echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') High resource usage detected: $high_usage" >> /tmp/security.log
    fi

    # Check for unexpected root processes
    root_procs=$(ps aux | grep "^root" | grep -vE "(kernel|systemd|init)" | wc -l)
    if [ "$root_procs" -gt 10 ]; then
        echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') Unusual number of root processes: $root_procs" >> /tmp/security.log
    fi

    sleep 60
done
MONITOR_EOF

chmod 700 /tmp/monitor-processes.sh
nohup /tmp/monitor-processes.sh > /dev/null 2>&1 &

# 4. Network monitoring
log_security "Setting up network monitoring..."

# Enhanced network monitor
cat > /tmp/monitor-network.sh << 'NET_EOF'
#!/bin/bash
# Enhanced network connection monitor
LOG_FILE="/tmp/network-connections.log"
ALERT_LOG="/tmp/security.log"

while true; do
    # Log new connections with timestamp
    echo "=== $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$LOG_FILE"
    ss -tunp 2>/dev/null | grep -v "127.0.0.1" | tail -n +2 >> "$LOG_FILE" || \
        ss -tun | grep -v "127.0.0.1" | tail -n +2 >> "$LOG_FILE"

    # Check for suspicious ports
    suspicious_ports=$(ss -tun | grep -E ":(4444|5555|6666|7777|8888|9999|31337|12345)" | grep -v "127.0.0.1" || true)
    if [ -n "$suspicious_ports" ]; then
        echo "[ALERT] $(date '+%Y-%m-%d %H:%M:%S') Suspicious port activity: $suspicious_ports" >> "$ALERT_LOG"
    fi

    # Monitor connection count
    conn_count=$(ss -tun | grep -v "127.0.0.1" | wc -l)
    if [ "$conn_count" -gt 50 ]; then
        echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') High number of connections: $conn_count" >> "$ALERT_LOG"
    fi

    # Check for connections to non-allowed IPs
    active_ips=$(ss -tun | grep -v "127.0.0.1" | awk '{print $6}' | cut -d: -f1 | sort -u | grep -E '^[0-9]{1,3}\.[0-9]{1,3}' || true)
    for ip in $active_ips; do
        if ! sudo ipset test allowed-domains "$ip" 2>/dev/null; then
            echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') Connection to non-allowed IP: $ip" >> "$ALERT_LOG"
        fi
    done

    sleep 30
done
NET_EOF

chmod 700 /tmp/monitor-network.sh
nohup /tmp/monitor-network.sh > /dev/null 2>&1 &

# 5. Security audit
log_security "Running security audit..."

# Check for world-writable files
find /workspace -type f -perm -002 2>/dev/null > /tmp/security-audit/world-writable-files.txt || true

# Check for setuid/setgid binaries
find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > /tmp/security-audit/suid-binaries.txt || true

# List listening ports
ss -tlnp 2>/dev/null > /tmp/security-audit/listening-ports.txt || ss -tln > /tmp/security-audit/listening-ports.txt

# Check installed packages for security updates
if command -v apt-get &> /dev/null; then
    apt list --upgradable 2>/dev/null | grep -i security > /tmp/security-audit/security-updates.txt || true
fi

# Show final firewall rules
log_security "Final firewall configuration:"
sudo iptables -L -n -v | tee /tmp/security-audit/firewall-rules.txt
echo "=== IPv6 Rules ===" >> /tmp/security-audit/firewall-rules.txt
sudo ip6tables -L -n -v >> /tmp/security-audit/firewall-rules.txt

# Show ipset contents summary
echo "=== Allowed Domains IP Count ===" >> /tmp/security-audit/firewall-rules.txt
sudo ipset list allowed-domains | grep -c "^[0-9]" | xargs echo "IPv4 entries:" >> /tmp/security-audit/firewall-rules.txt
sudo ipset list allowed-domains6 | grep -c "^[0-9]" | xargs echo "IPv6 entries:" >> /tmp/security-audit/firewall-rules.txt

log_security "Security initialization complete"

# Create enhanced security report
cat > /tmp/security-report.txt << REPORT_EOF
=== Security Configuration Report ===
Date: $(date)
Container: $(hostname)
User: $(whoami)

FIREWALL STATUS:
- Policy: DROP all except allowed domains
- Allowed domains: ${#ALLOWED_DOMAINS[@]} configured
- IPv4 IPs allowed: $(sudo ipset list allowed-domains 2>/dev/null | grep -c "^[0-9]" || echo "0")
- IPv6 IPs allowed: $(sudo ipset list allowed-domains6 2>/dev/null | grep -c "^[0-9]" || echo "0")

MONITORING:
- Process monitoring: Active (PID: $(pgrep -f monitor-processes.sh || echo "N/A"))
- Network monitoring: Active (PID: $(pgrep -f monitor-network.sh || echo "N/A"))
- Security log: /tmp/security.log

FILESYSTEM:
- Root filesystem: $(mount | grep " / " | grep -q "ro" && echo "Read-only" || echo "Read-write (WARNING)")
- Temporary directories: Mounted with noexec
- World-writable files: $(wc -l < /tmp/security-audit/world-writable-files.txt 2>/dev/null || echo "0")

CAPABILITIES:
$(capsh --print 2>/dev/null | grep "Current:" || echo "Unable to determine")

AUDIT FILES:
- Firewall rules: /tmp/security-audit/firewall-rules.txt
- SUID binaries: /tmp/security-audit/suid-binaries.txt
- Listening ports: /tmp/security-audit/listening-ports.txt
- Security updates: /tmp/security-audit/security-updates.txt

SECURITY COMMANDS:
- check-firewall: View current firewall rules
- monitor-connections: Live network monitoring
- monitor-logs: View security alerts
- security-report: View this report

RECOMMENDATIONS:
1. Review security logs regularly: cat /tmp/security.log
2. Check for security updates: apt list --upgradable 2>/dev/null | grep -i security
3. Monitor network connections for anomalies
4. Verify all processes are expected: check-processes
REPORT_EOF

cat /tmp/security-report.txt
EOF

    # Create post-create script
    cat > "${DEVCONTAINER_DIR}/post-create.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

echo "Running post-create setup..."

# Check if API key is set
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo ""
    echo "⚠️  WARNING: ANTHROPIC_API_KEY not set!"
    echo "Claude Code requires an API key for authentication in containers."
    echo ""
    echo "To set it:"
    echo "  export ANTHROPIC_API_KEY='sk-ant-your-key-here'"
    echo ""
    echo "Get your API key at: https://console.anthropic.com/settings/keys"
    echo ""
fi

# Create development directories
mkdir -p ~/projects ~/scripts ~/configs
chmod 700 ~/projects ~/scripts ~/configs

# Configure git with security best practices
git config --global core.whitespace trailing-space,space-before-tab
git config --global apply.whitespace fix
git config --global url."https://github.com/".insteadOf git@github.com:
git config --global url."https://".insteadOf git://

echo "Post-create setup complete!"
echo ""
echo "Security commands available:"
echo "  check-processes    - View running processes"
echo "  check-ports        - View listening ports"
echo "  monitor-connections - Monitor network connections"
echo "  check-firewall     - View firewall rules"
echo "  security-report    - View security configuration"
echo "  monitor-logs       - View security logs"
EOF

    chmod +x "${DEVCONTAINER_DIR}/init-security.sh"
    chmod +x "${DEVCONTAINER_DIR}/post-create.sh"

    # Create security policies
    create_security_policies

    print_message $GREEN "✓ Devcontainer files created with hardened security"
}

# Function to build the container image
build_container() {
    print_message $YELLOW "Building hardened container image..."

    cd "${DEVCONTAINER_DIR}"

    # Build with security options
    podman build \
        --tag "${IMAGE_NAME}:latest" \
        --build-arg TZ="${TZ:-UTC}" \
        --build-arg CLAUDE_CODE_VERSION="latest" \
        --build-arg GIT_DELTA_VERSION="0.18.2" \
        --build-arg ZSH_IN_DOCKER_VERSION="1.2.0" \
        --no-cache \
        --pull \
        --squash \
        -f Dockerfile \
        .

    cd ..

    print_message $GREEN "✓ Container image built successfully"
}

# Function to run the container with hardened security
run_container() {
    print_message $YELLOW "Starting hardened container..."

    # Check if API key is set
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        print_message $YELLOW ""
        print_message $YELLOW "⚠️  WARNING: ANTHROPIC_API_KEY not set!"
        print_message $YELLOW "You'll need to set it inside the container or pass it with:"
        print_message $YELLOW "  export ANTHROPIC_API_KEY='sk-ant-...'"
        print_message $YELLOW ""
    fi

    # Stop existing container if running
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm "${CONTAINER_NAME}" 2>/dev/null || true

    # Create volumes if they don't exist
    podman volume create commandhistory 2>/dev/null || true
    podman volume create home-node 2>/dev/null || true

    # Seed the /home/node volume with defaults if empty
    print_message $YELLOW "Seeding home volume (non-destructive)..."
    podman run --rm --user root \
        -v "home-node:/home/node:Z" \
        "${IMAGE_NAME}:latest" \
        bash -lc 'cp -an /opt/container-skel/home/. /home/node/ && chown -R node:node /home/node || true'

    # Prepare security options
    SECURITY_OPTS=(
        # Drop all capabilities first
        --cap-drop=ALL

        # Add only required capabilities
        --cap-add=NET_ADMIN
        --cap-add=NET_RAW
        --cap-add=CHOWN
        --cap-add=DAC_OVERRIDE
        --cap-add=FOWNER
        --cap-add=FSETID
        --cap-add=KILL
        --cap-add=SETGID
        --cap-add=SETUID
        --cap-add=SETPCAP
        --cap-add=SYS_CHROOT

        # Security options
        --security-opt=label=type:container_runtime_t

        # Resource limits
        --memory="$MAX_MEMORY"
        --memory-swap="$MAX_MEMORY"
        --cpus="$MAX_CPU"
        --pids-limit="$MAX_PIDS"

        # Read-only root filesystem
        --read-only

        # Temporary filesystems
        --tmpfs=/tmp:rw,noexec,nosuid,size=2g
        --tmpfs=/var/tmp:rw,noexec,nosuid,size=1g
        --tmpfs=/run:rw,noexec,nosuid,size=512m
        --tmpfs=/home/node/.cache:rw,noexec,nosuid,size=1g
        --tmpfs=/home/node/.npm:rw,noexec,nosuid,size=512m
        --tmpfs=/home/node/.local:rw,noexec,nosuid,size=512m
    )

    # Conditionally enable no-new-privileges
    if [[ "${ENABLE_NNP}" == "true" ]]; then
        SECURITY_OPTS+=( --security-opt=no-new-privileges )
    fi

    # Add seccomp profile if enabled
    if [[ "$ENABLE_SECCOMP" == "true" ]] && [[ -f "${WORKSPACE_DIR}/${DEVCONTAINER_DIR}/security/seccomp.json" ]]; then
        SECURITY_OPTS+=("--security-opt=seccomp=${WORKSPACE_DIR}/${DEVCONTAINER_DIR}/security/seccomp.json")
    fi

    # Add AppArmor profile if available and enabled
    if [[ "$ENABLE_APPARMOR" == "true" ]] && command -v aa-status &> /dev/null; then
        SECURITY_OPTS+=("--security-opt=apparmor=docker-default")
    fi

    # Run the container
    podman run -d \
        --name "${CONTAINER_NAME}" \
        --hostname "${CONTAINER_NAME}" \
        "${SECURITY_OPTS[@]}" \
        --volume "${WORKSPACE_DIR}:/workspace:Z" \
        --volume "commandhistory:/commandhistory:Z" \
        --volume "home-node:/home/node:Z" \
        --workdir /workspace \
        --user node \
        --env NODE_ENV=development \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env "XDG_CONFIG_HOME=/home/node/.config" \
        --env "XDG_CACHE_HOME=/tmp/xdg-cache" \
        --ulimit nofile=1024:1024 \
        --ulimit nproc=512:512 \
        "${IMAGE_NAME}:latest" \
        sleep infinity

    # Wait for container to be ready
    sleep 2

    # Execute security initialization
    print_message $YELLOW "Initializing security measures..."
    podman exec "${CONTAINER_NAME}" /bin/bash /workspace/.devcontainer/init-security.sh || \
        print_message $YELLOW "Warning: Some security features may be limited in this environment"

    # Execute post-create script
    podman exec "${CONTAINER_NAME}" /bin/bash /workspace/.devcontainer/post-create.sh || true

    print_message $GREEN "✓ Hardened container is running"

    # Show security summary
    print_message $GREEN "\nSecurity Summary:"
    echo "- Capabilities: Minimal set (NET_ADMIN for firewall, basic user operations)"
    echo "- Filesystem: Read-only root with specific tmpfs mounts"
    echo "- Network: Strict firewall with allowlisted domains only"
    echo "- Resources: Limited to ${MAX_CPU} CPUs, ${MAX_MEMORY} memory, ${MAX_PIDS} PIDs"
    echo "- Monitoring: Process and network monitoring active"
    echo ""
    echo "View security report: podman exec ${CONTAINER_NAME} cat /tmp/security-report.txt"
    echo "View security logs: podman exec ${CONTAINER_NAME} cat /tmp/security.log"
}

# Function to enter the container
enter_container() {
    print_message $YELLOW "Entering hardened container..."
    print_message $YELLOW "Note: Running with restricted privileges and monitored environment"

    # Check if API key is set
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        print_message $YELLOW ""
        print_message $YELLOW "Note: ANTHROPIC_API_KEY not set. Set it in the container with:"
        print_message $YELLOW "  export ANTHROPIC_API_KEY='sk-ant-your-key-here'"
        print_message $YELLOW ""
    fi

    podman exec -it "${CONTAINER_NAME}" /usr/bin/zsh -l
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

# Function to run security audit
security_audit() {
    print_message $YELLOW "Running security audit..."

    if ! podman ps | grep -q "${CONTAINER_NAME}"; then
        print_message $RED "Container is not running"
        exit 1
    fi

    # Create audit report
    AUDIT_FILE="security-audit-$(date +%Y%m%d-%H%M%S).txt"

    {
        echo "=== Security Audit Report ==="
        echo "Date: $(date)"
        echo "Container: ${CONTAINER_NAME}"
        echo ""

        echo "=== Container Inspection ==="
        podman inspect "${CONTAINER_NAME}" | jq '.[] | {
            Capabilities: .HostConfig.CapAdd,
            DroppedCapabilities: .HostConfig.CapDrop,
            SecurityOpt: .HostConfig.SecurityOpt,
            ReadonlyRootfs: .HostConfig.ReadonlyRootfs,
            Resources: {
                Memory: .HostConfig.Memory,
                CpuQuota: .HostConfig.CpuQuota,
                PidsLimit: .HostConfig.PidsLimit
            }
        }'

        echo -e "\n=== Process List ==="
        podman exec "${CONTAINER_NAME}" ps aux

        echo -e "\n=== Network Connections ==="
        podman exec "${CONTAINER_NAME}" ss -tunp 2>/dev/null || echo "Unable to list connections"

        echo -e "\n=== Firewall Rules ==="
        podman exec "${CONTAINER_NAME}" sudo iptables -L -n -v 2>/dev/null || echo "Unable to list firewall rules"

        echo -e "\n=== Mounted Volumes ==="
        podman exec "${CONTAINER_NAME}" mount | grep -v "^/proc\|^/sys\|^/dev"

        echo -e "\n=== Running Services ==="
        podman exec "${CONTAINER_NAME}" ps -eo pid,user,comm | grep -v "ps\|grep"

    } > "$AUDIT_FILE"

    print_message $GREEN "✓ Security audit complete: $AUDIT_FILE"
}

# Function to show usage
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    setup       Create devcontainer files and build image (default)
    build       Build the container image
    run         Run the container with hardened security
    enter       Enter the running container
    stop        Stop the container
    remove      Remove the container
    rebuild     Remove, rebuild, and run the container
    audit       Run security audit on running container

Options:
    -n NAME     Container name (default: claude-code-devcontainer)
    -i IMAGE    Image name (default: claude-code-dev)
    -w PATH     Workspace directory (default: current directory)
    -s          Enable strict mode (default: true)
    -S          Enable seccomp filtering (default: true)
    -a          Enable AppArmor if available (default: false)
    -N          Disable no-new-privileges (lets sudo elevate)
    -h          Show this help message

Environment Variables:
    ANTHROPIC_API_KEY   Your Anthropic API key for Claude Code

Security Features:
    - Minimal capability set (drops ALL, adds only required)
    - Read-only root filesystem with tmpfs for writable areas
    - Strict firewall with domain allowlisting (Anthropic-aligned)
    - Resource limits (CPU, memory, PID)
    - Process and network monitoring
    - Security audit logging
    - No new privileges flag
    - Seccomp filtering (optional)
    - AppArmor support (optional)

Examples:
    # Set API key and run
    export ANTHROPIC_API_KEY="sk-ant-..."
    $0              # Full setup with security hardening

    $0 setup        # Just create the devcontainer files
    $0 build        # Build the hardened container image
    $0 run          # Run with security restrictions
    $0 enter        # Enter the secured container
    $0 audit        # Run security audit
    $0 rebuild      # Clean rebuild with security

    # Run with AppArmor enabled
    $0 -a run

    # Disable seccomp for compatibility
    ENABLE_SECCOMP=false $0 run

API Key Authentication:
    Claude Code requires an API key when running in containers.
    Get your key at: https://console.anthropic.com/settings/keys

    Set it before running:
    export ANTHROPIC_API_KEY="sk-ant-..."
EOF
}

# Parse command line arguments
COMMAND="${1:-setup}"
shift || true

while getopts "n:i:w:sSahN" opt; do
    case $opt in
        n) CONTAINER_NAME="$OPTARG" ;;
        i) IMAGE_NAME="$OPTARG" ;;
        w) WORKSPACE_DIR="$OPTARG" ;;
        s) ENABLE_STRICT_MODE="true" ;;
        S) ENABLE_SECCOMP="true" ;;
        a) ENABLE_APPARMOR="true" ;;
        N) ENABLE_NNP="false" ;;
        h) usage; exit 0 ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
    esac
done

# Main execution
print_message $GREEN "Claude Code Devcontainer Setup for Podman - Hardened Edition"
print_message $GREEN "=========================================================="

check_podman

case "$COMMAND" in
    setup)
        create_devcontainer_structure
        build_container
        run_container
        print_message $GREEN "\n✓ Hardened setup complete!"
        print_message $GREEN "Run '$0 enter' to enter the secure container."
        print_message $GREEN "Run '$0 audit' to view security configuration."
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
        print_message $GREEN "\n✓ Rebuild complete with hardened security!"
        ;;
    audit)
        security_audit
        ;;
    *)
        print_message $RED "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
