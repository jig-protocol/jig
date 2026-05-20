# docs/EMAIL_SETUP.md

# Email Bridge Setup Guide

### Option 1: Manual DNS Setup (Any Registrar)

Add these DNS records to your domain:

```dns
# MX Records (receive email)
MX    10    mx1.jig.email
MX    20    mx2.jig.email

# TXT Records (Jig discovery + SPF)
TXT   _jig   "v=JIG1 endpoint=wss://yourdomain.jig.email"
TXT   @      "v=spf1 include:jig.email ~all"

# CNAME (optional, for webmail)
CNAME mail   webmail.jig.email
```

### Option 2: Self-Hosted (Advanced)

Run your own Jig email bridge:

```bash
# Install Jig with email module
curl -L https://jig.onl | sh -s -- --with-email

# Configure your domain
jig email setup yourdomain.com

# Start the server
jig init --email
```

## Three Modes of Operation

### 1. Jig ↔ Jig (Native, Encrypted)

When both parties use Jig, messages never touch SMTP:

```
alice@domain1.com → [DNS lookup] → [Found Jig] → [WSS] → bob@domain2.com
                                         ↓
                                   E2E Encrypted
                                   Rich blocks preserved
                                   Instant delivery
```

### 2. Email → Jig (Incoming)

Regular email users can reach you:

```
gmail.com → [SMTP] → mx.jig.email → [Convert] → Your Jig Inbox
                           ↓
                    Spam filtered
                    Threading preserved
                    Attachments via IPFS
```

### 3. Jig → Email (Outgoing with Viral Signature)

You can email anyone:

```
Your Jig → [No Jig found] → [SMTP Relay] → recipient@gmail.com
                                 ↓
                          Includes subtle signature:
                          "📧 Secured by Jig Protocol"
```

## Configuration Options

### Basic Email Bridge

```toml
# ~/.jig/config.toml

[email]
smtp_enabled = true  # Receive email
imap_enabled = false # Set true for Thunderbird/Outlook support

# Your domains
mx_domains = ["yourdomain.com", "youralias.com"]

[email.relay]
# Option 1: Community relay (free, 1000/month)
primary = "community"

# Option 2: SendGrid (free tier: 100/day)
# primary = "sendgrid"
# api_key = "YOUR_API_KEY"

# Option 3: Direct send (requires clean IP)
# primary = "direct"
```

### IMAP Support (Use Existing Email Clients)

```toml
[email]
imap_enabled = true
imap_port = 143
imap_tls_port = 993

# Your email appears in Thunderbird/Outlook!
# Jig channels become IMAP folders
# Rich messages degrade gracefully
```

### Community Relay Participation

Share your unused email quota:

```toml
[email.relay]
community_relay = true
donated_quota = 500  # Share 500 emails/month

# You get credits for sharing!
# $1 credit per 1000 emails donated
```

## Advanced Features

### DNS Auto-Discovery

Other Jig servers will automatically find you:

```bash
# Check if a domain runs Jig
jig discover example.com

# Output:
# ✓ Jig endpoint found: wss://example.com:7777
# ✓ Encryption: curve25519
# ✓ Federation: enabled
```

### Email Enhancement

All emails sent through Jig get superpowers:

- **Read receipts**: Know when your email is read
- **Expiring messages**: Emails that self-destruct
- **E2E encryption**: When recipient upgrades to Jig
- **Rich blocks**: Preserved when both use Jig

### Migration Tools

Import your existing email:

```bash
# From Gmail (via Google Takeout)
jig import gmail-export.mbox

# From Outlook
jig import outlook.pst

# From Thunderbird
jig import thunderbird-profile/

# Live IMAP import
jig import imap://old-server.com --user you@domain.com
```

## Troubleshooting

### Port 25 Blocked?

Many ISPs block port 25. Solutions:

1. **Use our MX servers** (recommended):

   - Point MX records to `mx.jig.email`
   - We handle receiving for you

2. **Use port 2525**:

   ```toml
   [email]
   smtp_port = 2525  # Alternative SMTP port
   ```

3. **Use a VPS**:
   - Get a VPS with port 25 open
   - Run Jig there as your MX

### Emails Going to Spam?

Build reputation gradually:

```bash
# Check your reputation
jig email reputation check

# Warm up your domain
jig email warmup start --daily-limit 10

# Monitor delivery
jig email monitor
```

### Can't Send to Gmail/Yahoo?

They require authentication:

```bash
# Generate DKIM keys
jig email dkim generate

# Add to DNS:
TXT _domainkey "v=DKIM1; k=rsa; p=MIGfMA0..."

# Set up DMARC
TXT _dmarc "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"
```

## Email Provider Comparison

| Feature        | Gmail       | Jig (Free) | Jig (Self-hosted) |
| -------------- | ----------- | ---------- | ----------------- |
| Custom domain  | $12/user/mo | ✓ Free     | ✓ Free            |
| Users          | Limited     | Unlimited  | Unlimited         |
| Storage        | 15GB        | 10GB       | Unlimited         |
| E2E Encryption | ✗           | ✓          | ✓                 |
| Self-destruct  | ✗           | ✓          | ✓                 |
| Federation     | ✗           | ✓          | ✓                 |
| Open source    | ✗           | ✓          | ✓                 |
| No tracking    | ✗           | ✓          | ✓                 |

## Security & Privacy

### What We Can't See

- Message contents (E2E encrypted)
- Who you're talking to (if both use Jig)
- Your email when using IMAP
- Metadata when federated

### What We Can See (on our MX)

- Sender/recipient (for routing)
- Message size
- Timestamp
- Spam score

### Self-Hosting for Maximum Privacy

Run everything yourself:

```bash
# Full independence setup
jig init --full-email-stack

# This installs:
# - SMTP server (port 25)
# - Submission (port 587)
# - IMAP server (port 143/993)
# - Webmail interface (port 443)
# - DNS server (port 53)
```

## API Access

Integrate email programmatically:

```bash
# Send via CLI
echo "Hello" | jig email send to@example.com --subject "Test"

# Via REST API
curl -X POST https://api.jig.email/v1/send \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"to": "user@example.com", "body": "Hello"}'

# Via webhook (receive)
jig email webhook add https://yourapp.com/incoming
```

## Getting Help

- **IRC**: #jig on irc.libera.chat
- **Matrix**: #jig:matrix.org
- **Email**: help@jig.email (how meta!)
- **Docs**: https://jig.onl/docs/email
