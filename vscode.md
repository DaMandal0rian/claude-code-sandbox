# VS Code Dev Containers Integration Guide

This section explains how to use the Claude Code devcontainer with VS Code's Dev Containers extension for a seamless development experience.

## 🎯 Prerequisites

- **VS Code** installed on your host machine
- **Podman** installed and running
- **Dev Containers extension** for VS Code
- The devcontainer setup script

## 📦 Installing Required Components

### 1. Install the Dev Containers Extension

1. Open VS Code
2. Press `Ctrl/Cmd + Shift + X` to open Extensions
3. Search for "Dev Containers"
4. Install the official Microsoft extension:
   - Name: **Dev Containers**
   - ID: `ms-vscode-remote.remote-containers`
   - Publisher: Microsoft

### 2. Configure VS Code for Podman

Since you're using Podman instead of Docker, configure VS Code to use Podman:

1. Open VS Code settings (`Ctrl/Cmd + ,`)
2. Search for "dev.containers.dockerPath"
3. Set the value to `podman`

Alternatively, add to your VS Code settings.json:

```json
{
    "dev.containers.dockerPath": "podman",
    "dev.containers.dockerComposePath": "podman-compose"
}
```

## 🚀 Using Dev Containers with Your Project

### Method 1: Open Existing Project in Container

1. **Prepare your project**:

   ```bash
   cd /path/to/your/project

   # Run the setup script to create .devcontainer files
   ./setup-devcontainer.sh setup
   ```

2. **Open in VS Code**:

   ```bash
   # Open VS Code in the project directory
   code .
   ```

3. **Reopen in Container**:
   - VS Code will detect the `.devcontainer` folder
   - You'll see a notification popup: "Folder contains a Dev Container configuration file"
   - Click **"Reopen in Container"**

   Or manually:
   - Press `F1` or `Ctrl/Cmd + Shift + P`
   - Type: "Dev Containers: Reopen in Container"
   - Press Enter

### Method 2: Clone Repository Directly in Container

1. **Open VS Code**
2. **Press** `F1` or `Ctrl/Cmd + Shift + P`
3. **Run**: "Dev Containers: Clone Repository in Container Volume"
4. **Enter** your repository URL
5. VS Code will:
   - Clone the repository
   - Build the container
   - Open the project inside the container

### Method 3: Create New Project in Container

1. **Create a new folder** for your project
2. **Copy** the `.devcontainer` folder into it
3. **Open** the folder in VS Code
4. **Reopen in Container** when prompted

## 📁 Workspace Structure

When you open a project in a devcontainer:

```
Your Project/
├── .devcontainer/          # Container configuration
│   ├── devcontainer.json   # VS Code settings
│   ├── Dockerfile          # Container image
│   └── init-firewall.sh    # Security setup
├── src/                    # Your source code
├── package.json           # Node.js dependencies
└── README.md              # Your project docs
```

Inside the container, your project is mounted at `/workspace`.

## ⚡ VS Code Features in Dev Containers

### Integrated Terminal

- Automatically opens in the container
- Uses ZSH with Oh My Zsh by default
- Has access to all container tools (Node.js, Python, Claude Code)

### Extensions

The following extensions are automatically installed in the container:

- **ESLint** - JavaScript linting
- **Prettier** - Code formatting
- **GitLens** - Git supercharged
- **Python** (hardened version) - Python language support
- **Pylance** (hardened version) - Python language server

### Port Forwarding

- VS Code automatically forwards ports from the container
- Access web servers running in the container from your host browser
- See forwarded ports in the "Ports" view (`View → Ports`)

### File Operations

- All file operations happen inside the container
- File watchers work correctly
- Git operations use the container's git configuration

## 🔧 Common Tasks

### Running Claude Code

```bash
# In the VS Code terminal (inside container)
claude "help me create a REST API"
```

### Installing Dependencies

```bash
# Node.js packages
npm install express

# Python packages
pip install --user flask
```

### Running Development Servers

```bash
# Start a Node.js server
npm run dev

# VS Code will detect and forward the port
# Click the notification to open in browser
```

### Debugging

1. Set breakpoints in your code
2. Use VS Code's debugging features as normal
3. The debugger runs inside the container

## 🛠️ Customization

### Adding More Extensions

Edit `.devcontainer/devcontainer.json`:

```json
{
  "customizations": {
    "vscode": {
      "extensions": [
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "eamodio.gitlens",
        // Add more extensions here
        "github.copilot",
        "ms-vscode.live-server"
      ]
    }
  }
}
```

### Environment Variables

Add to `.devcontainer/devcontainer.json`:

```json
{
  "remoteEnv": {
    "MY_API_KEY": "${localEnv:MY_API_KEY}",
    "NODE_ENV": "development"
  }
}
```

### VS Code Settings

Configure editor settings for the container:

```json
{
  "customizations": {
    "vscode": {
      "settings": {
        "editor.fontSize": 14,
        "editor.tabSize": 2,
        "terminal.integrated.fontSize": 14,
        "files.autoSave": "afterDelay"
      }
    }
  }
}
```

## 🔄 Container Lifecycle

### Rebuild Container

When you change the Dockerfile or devcontainer.json:

- Press `F1` → "Dev Containers: Rebuild Container"
- Or click the notification when VS Code detects changes

### Stop Container

- Close the VS Code window
- The container stops automatically
- Your work is preserved in volumes

### Restart Container

- Press `F1` → "Dev Containers: Restart Container"
- Useful after installing system packages

### View Container Logs

- Press `F1` → "Dev Containers: Show Container Log"
- Helpful for debugging container issues

## 🚨 Troubleshooting

### Container Fails to Start

1. **Check Podman is running**:

   ```bash
   podman info
   ```

2. **View detailed logs**:
   - Press `F1` → "Dev Containers: Show Container Log"

3. **Try rebuilding without cache**:
   - Press `F1` → "Dev Containers: Rebuild Container Without Cache"

### Extensions Not Loading

1. **Reload window**:
   - Press `F1` → "Developer: Reload Window"

2. **Check extension compatibility**:
   - Some extensions only work on certain platforms
   - Check the extension's documentation

### Performance Issues

1. **Increase container resources**:

   ```bash
   # Edit the setup script to increase limits
   readonly MAX_MEMORY="8g"
   readonly MAX_CPU="4"
   ```

2. **Exclude large folders** from file watching:

   ```json
   {
     "files.watcherExclude": {
       "**/node_modules/**": true,
       "**/.git/objects/**": true
     }
   }
   ```

### Permission Errors

- The container runs as `node` user
- Use `sudo` for system-level operations
- Check file ownership: `ls -la`

## 💡 Tips and Best Practices

### 1. Use Container-Specific Settings

Create `.vscode/settings.json` in your project:

```json
{
  "remote.containers.defaultExtensions": [
    "dbaeumer.vscode-eslint"
  ],
  "remote.containers.workspaceMountConsistency": "cached"
}
```

### 2. Optimize for Performance

- Keep heavy files (videos, large datasets) outside the workspace
- Use `.dockerignore` to exclude unnecessary files
- Enable file system caching for better performance on macOS

### 3. Version Control

- Commit the `.devcontainer` folder to your repository
- Team members can use the same development environment
- Include a note in your README about using Dev Containers

### 4. Multiple Configurations

Create different configurations for different scenarios:

```
.devcontainer/
├── devcontainer.json          # Default
├── backend/
│   └── devcontainer.json      # Backend-specific
└── frontend/
    └── devcontainer.json      # Frontend-specific
```

### 5. Use Tasks

Define tasks in `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Start Dev Server",
      "type": "shell",
      "command": "npm run dev",
      "group": {
        "kind": "build",
        "isDefault": true
      }
    }
  ]
}
```

## 🔗 Useful Commands Reference

| Command | Description |
|---------|-------------|
| `F1` → "Dev Containers: Reopen in Container" | Open current folder in container |
| `F1` → "Dev Containers: Rebuild Container" | Rebuild the container image |
| `F1` → "Dev Containers: Restart Container" | Restart the running container |
| `F1` → "Dev Containers: Show Container Log" | View container build/runtime logs |
| `F1` → "Dev Containers: Open Folder in Container" | Open a different folder in container |
| `F1` → "Dev Containers: Attach to Running Container" | Attach to an existing container |

## 📚 Additional Resources

- [VS Code Dev Containers Documentation](https://code.visualstudio.com/docs/devcontainers/containers)
- [Dev Container Specification](https://containers.dev/)
- [VS Code Remote Development](https://code.visualstudio.com/docs/remote/remote-overview)
- [Podman Desktop](https://podman-desktop.io/) - GUI for managing Podman containers
