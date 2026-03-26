# 🔐 CertFixer

A terminal UI for analyzing and reordering TLS/SSL certificate chains. Select a certificate bundle, preview the current and corrected chain order side-by-side, choose your preferred output order, and write the fixed file — all without leaving the terminal.

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

---

## Installation

```bash
go install github.com/TDBoudreau/certfixer@latest
```

Make sure `~/go/bin` is in your `PATH`:

```bash
# Add to ~/.zshrc or ~/.bashrc
export PATH="$PATH:$(go env GOPATH)/bin"
```

Then run:

```bash
certfixer
```

---

## Supported File Types

`.pem` `.cer` `.crt` `.cert` `.p7b`

---

## Keyboard Reference

### File Picker

| Key | Action |
|---|---|
| `↑` / `w` | Move up |
| `↓` / `s` | Move down |
| `→` / `d` / `Enter` | Open / select |
| `←` / `a` | Go back |
| `?` | Toggle help |
| `q` / `Ctrl+C` | Quit |

### Chain Analysis

| Key | Action |
|---|---|
| `↑` / `w` / `k` | Move up |
| `↓` / `s` / `j` | Move down |
| `Enter` | Write fixed file |
| `Esc` | Back to file picker |
| `?` | Toggle help |
| `q` / `Ctrl+C` | Quit |

---

## How It Works

CertFixer parses all `CERTIFICATE` PEM blocks from the selected file, then sorts them by walking the issuer graph:

1. The **leaf** certificate is identified as the one not issued by any other cert in the file.
2. The chain is walked by matching each cert's issuer DN to the subject DN of the next cert.
3. Walking stops at a **self-signed** cert (subject == issuer), which is the root, or when the issuer is not present (incomplete chain).

If the file contains a cycle or multiple possible leaf certificates, an error is shown and no file is written.