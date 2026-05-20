#!/bin/bash
# install.sh - goes at https://jig.onl/install.sh
# One-line install: curl -L https://jig.onl | sh
# License: MIT (encourage adoption)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l) ARCH="arm" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Installation options
INSTALL_DIR="${JIG_INSTALL_DIR:-$HOME/.jig}"
VERSION="${JIG_VERSION:-latest}"
WITH_EMAIL=false
WITH_SYSTEMD=false
MINIMAL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-email)
            WITH_EMAIL=true
            shift
            ;;
        --with-systemd)
            WITH_SYSTEMD=true
            shift
            ;;
        --minimal)
            MINIMAL=true
            shift
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${GREEN}🚀 Installing Jig Protocol${NC}"
echo "   OS: $OS"
echo "   Arch: $ARCH"
echo "   Version: $VERSION"
echo "   Directory: $INSTALL_DIR"
echo ""

# Create installation directory
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/data"

# Download appropriate binary
BINARY_URL="https://releases.jig.onl/$VERSION/jig-$OS-$ARCH"

if [ "$MINIMAL" = true ]; then
    # Minimal build - just core protocol
    BINARY_URL="https://releases.jig.onl/$VERSION/jig-minimal-$OS-$ARCH"
    echo -e "${YELLOW}📦 Downloading minimal build (no email, no GUI)${NC}"
elif [ "$WITH_EMAIL" = true ]; then
    # Full build with email bridge
    BINARY_URL="https://releases.jig.onl/$VERSION/jig-full-$OS-$ARCH"
    echo -e "${YELLOW}📧 Downloading full build with email bridge${NC}"
else
    # Standard build - all protocols except email
    echo -e "${YELLOW}📦 Downloading standard build${NC}"
fi

# Download binary
echo "Downloading from $BINARY_URL..."
if command -v curl &> /dev/null; then
    curl -L "$BINARY_URL" -o "$INSTALL_DIR/bin/jig"
elif command -v wget &> /dev/null; then
    wget "$BINARY_URL" -O "$INSTALL_DIR/bin/jig"
else
    echo -e "${RED}Error: Neither curl nor wget found${NC}"
    exit 1
fi

# Make executable
chmod +x "$INSTALL_DIR/bin/jig"

# Download default configuration
echo "Setting up configuration..."
cat > "$INSTALL_DIR/config/jig.toml" << 'EOF'
# Auto-generated Jig configuration
# Edit this file to customize your setup

[server]
bind = "127.0.0.1"
port = 7777
federation_enabled = true
anonymous_allowed = true

[storage]
backend = "sqlite"
path = "~/.jig/data/jig.db"

[protocols]
jig_native = true
irc_compat = true
ssh_transport = true

[encryption]
enabled = true
algorithm = "curve25519-xsalsa20-poly1305"
EOF

# Add email configuration if requested
if [ "$WITH_EMAIL" = true ]; then
    cat >> "$INSTALL_DIR/config/jig.toml" << 'EOF'

[email]
smtp_enabled = false  # Enable after setting up MX records
imap_enabled = false  # Enable for email client support
mx_domains = []  # Add your domains here

[email.relay]
primary = "community"  # Free community relay
community_relay = true
donated_quota = 100
EOF
    
    echo -e "${GREEN}✓ Email bridge included${NC}"
    echo "  Configure your MX records to enable email"
    echo "  See: https://jig.onl/docs/email"
fi

# Create systemd service if requested
if [ "$WITH_SYSTEMD" = true ] && [ -d "/etc/systemd/system" ]; then
    echo "Installing systemd service..."
    sudo tee /etc/systemd/system/jig.service > /dev/null << EOF
[Unit]
Description=Jig Protocol Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/jig daemon
Restart=always
Environment="JIG_CONFIG=$INSTALL_DIR/config/jig.toml"

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service installed${NC}"
    echo "  Start with: sudo systemctl start jig"
    echo "  Enable autostart: sudo systemctl enable jig"
fi

# Add to PATH
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "JIG_HOME" "$SHELL_RC"; then
        echo "" >> "$SHELL_RC"
        echo "# Jig Protocol" >> "$SHELL_RC"
        echo "export JIG_HOME=\"$INSTALL_DIR\"" >> "$SHELL_RC"
        echo "export PATH=\"\$JIG_HOME/bin:\$PATH\"" >> "$SHELL_RC"
        echo -e "${GREEN}✓ Added to PATH${NC}"
    fi
fi

# Test installation
if "$INSTALL_DIR/bin/jig" --version &> /dev/null; then
    VERSION_OUTPUT=$("$INSTALL_DIR/bin/jig" --version)
    echo -e "${GREEN}✓ Installation successful!${NC}"
    echo "  Version: $VERSION_OUTPUT"
else
    echo -e "${RED}✗ Installation may have failed${NC}"
    exit 1
fi

# Show quick start
echo ""
echo -e "${GREEN}🎉 Jig is ready!${NC}"
echo ""
echo "Quick start:"
echo "  jig --anon              # Start anonymous chat"
echo "  jig init myserver       # Create a server"
echo "  jig join #general       # Join a channel"
echo ""

# Show email setup if installed
if [ "$WITH_EMAIL" = true ]; then
    echo "Email bridge setup:"
    echo "  jig email setup mydomain.com"
    echo "  jig email test"
    echo ""
fi

echo "Documentation: https://jig.onl/docs"
echo "IRC: #jig on irc.libera.chat"
echo ""

# Optional: Run setup wizard
read -p "Run interactive setup? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    "$INSTALL_DIR/bin/jig" setup-wizard
fi

# SENSITIVE: Phone home for metrics (optional, disclosed)
# Only in non-minimal builds, can be disabled
if [ "$MINIMAL" = false ] && [ "${JIG_TELEMETRY:-true}" = "true" ]; then
    # Send anonymous installation metric
    curl -s -X POST https://metrics.jig.onl/install \
        -H "Content-Type: application/json" \
        -d "{\"os\":\"$OS\",\"arch\":\"$ARCH\",\"email\":$WITH_EMAIL}" \
        > /dev/null 2>&1 || true
fi

echo -e "${GREEN}Happy messaging! 🚀${NC}"