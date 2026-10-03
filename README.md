# vpn_tui

A lightweight, modern, and asynchronous Terminal User Interface (TUI) for managing VPN connections on Linux, built in Rust with [Ratatui](https://github.com/ratatui/ratatui) and [Tokio](https://tokio.rs).

`vpn_tui` provides a unified dashboard to configure, authenticate, and monitor **OpenConnect** (Cisco AnyConnect / ocserv) and **OpenVPN** connections with real-time log streaming, traffic monitoring, preflight SSL certificate probing, and interactive certificate pinning.

---

## Features

- **Multi-Protocol Support**: Seamlessly configure and connect to both OpenConnect and OpenVPN gateways.
- **Account Vault**: Securely manage multiple credentials (username, password, authgroup) and link them to connection profiles.
- **Interactive TUI Dashboard**:
  - Split-pane layout: Accounts, Profiles, Configuration Details/Flags, and Real-Time Logs.
  - Live network throughput metrics (Upload/Download speeds) directly sampled from `/proc/net/dev`.
  - Latency testing with an integrated multi-threaded TCP pinger.
- **SSL Certificate Verification & Pinning**:
  - Preflight SSL probe inspects remote gateways before launching root processes.
  - Interactive certificate warning modal displays the server subject, SHA-256 fingerprint, and reason for failure.
  - One-click certificate pinning (`--servercert=pin-sha256:...`) persisted directly into the profile.
  - Policy enforcement: Choose between `Strict`, `Prompt` (interactive approval), or `Insecure` (`--no-cert-check`).
- **Interactive File Picker**:
  - Built-in filesystem browser for selecting `.ovpn` configuration files.
  - Supports inline path autocompletion (`Tab`) and tilde (`~`) home directory expansion.
- **Robust Clean Architecture**: Hexagonal domain separation ensuring rock-solid state management, channel isolation, and 100% testable port adapters.
- **Non-blocking Async Streaming**: Full async event pipeline ensures terminal stays fluid while capturing stdout, stderr, and tunnel state transitions.
- **Graceful Teardown**: Automatically terminates background VPN processes and restores terminal state on exit (`q` or `Ctrl+C`).

---

## System Requirements

`vpn_tui` runs on **Linux** and requires the appropriate VPN clients installed on your system along with `sudo` privileges to configure network interfaces (`tun0`, `tun1`).

### Prerequisites

| Tool | Purpose | Required |
| :--- | :--- | :--- |
| **Rust toolchain** | Rust compiler (edition 2024 / 1.85+) and `cargo` | To compile from source |
| **openconnect** | Backend runner for Cisco AnyConnect / ocserv protocols | Optional (for OpenConnect profiles) |
| **openvpn** | Backend runner for OpenVPN tunnels | Optional (for OpenVPN profiles) |
| **sudo** | Elevated permissions to spawn network tunnels | Yes |

### Installing Client Dependencies

- **Debian / Ubuntu / Linux Mint**:
  ```bash
  sudo apt update
  sudo apt install openconnect openvpn
  ```

- **Arch Linux / Manjaro**:
  ```bash
  sudo pacman -S openconnect openvpn
  ```

- **Fedora / RHEL**:
  ```bash
  sudo dnf install openconnect openvpn
  ```

- **openSUSE**:
  ```bash
  sudo zypper install openconnect openvpn
  ```

---

## Compilation and Installation

### 1. Build from Source

Ensure you have Rust and Cargo installed ([rustup.rs](https://rustup.rs/)):

```bash
# Clone the repository
git clone https://github.com/your-username/vpn_tui.git
cd vpn_tui

# Build the release binary
cargo build --release
```

The compiled binary will be placed at `target/release/vpn_tui`.

### 2. Install to Your System

#### Option A: Install via Cargo (Recommended for user PATH)
```bash
cargo install --path .
```
Ensure `~/.cargo/bin` is in your `$PATH`.

#### Option B: Install System-Wide
```bash
sudo install -m 755 target/release/vpn_tui /usr/local/bin/vpn_tui
```

### 3. (Optional) Passwordless Sudo Configuration

When connecting to a VPN, `vpn_tui` spawns `openconnect` or `openvpn` using `sudo`. If sudo credentials are not already cached in your terminal session, `vpn_tui` will prompt you with an interactive in-terminal password modal.

If you prefer seamless, passwordless connection launches, add the following entry using `sudo visudo`:

```sudoers
# Allow your user (or wheel/sudo group) to run VPN binaries without entering password
your_username ALL=(ALL) NOPASSWD: /usr/sbin/openconnect, /usr/sbin/openvpn
```
*(Verify the exact binary paths on your distribution with `which openconnect` and `which openvpn`.)*

---

## How to Use

Launch the application in any terminal emulator:

```bash
vpn_tui
```

### 1. Managing Accounts

1. Press `Tab` until the **Accounts** pane is focused (highlighted border).
2. Press `a` to open the **New Account** dialog.
3. Fill in the fields (`Tab` or `Down` to navigate, `Enter` to save):
   - **Account Name**: Label (e.g. `Work Credentials`, `Personal VPN`).
   - **Username**: Gateway login username.
   - **Password**: Gateway login password.
   - **Authgroup**: (Optional) Gateway group/realm for OpenConnect.
4. Press `e` to edit or `x` to delete an existing account.

### 2. Adding a VPN Configuration

1. Press `Tab` to switch focus to the **Configurations** pane.
2. Press `n` to open the **Config Adder** modal.
3. Select your protocol using `Space` or `Left`/`Right` arrow keys:
   - **OpenConnect**: Enter Gateway Endpoint (e.g., `vpn.example.com:443`), choose SSL Verification Policy, and select an associated account.
   - **OpenVPN**: Enter Profile Name, `.ovpn` Configuration File path, and optional remote address overrides.
     - *Tip:* When on the `.ovpn` path field, press **`F2`** to launch the interactive file picker, or press **`Tab`** for inline path autocomplete!
4. Customize protocol-specific flags (e.g., `--no-dtls`, custom CLI flags).
5. Press `Enter` to save the profile.

### 3. Connecting and Monitoring

- **Connect**: Select a profile and press **`Enter`**.
  - If the profile uses OpenConnect and connects to a server with a self-signed or untrusted SSL certificate, `vpn_tui` will pause and display a **Certificate Warning Modal** with the server fingerprint. Press `Enter` or `a` to accept and automatically pin the certificate fingerprint, or `Esc` / `r` to abort.
  - If required, enter your `sudo` password in the secure password modal.
- **Live Logs**: Watch the bottom-right **Connection Logs** pane populate with server messages, IP allocation, and handshake progress.
- **Traffic Stats**: Upon successful tunnel creation (`tun0`), the top banner displays `CONNECTED`, the allocated VPN IP address, and real-time upload/download speeds.
- **Ping Latency**: Press **`p`** at any time to probe the TCP latency of all configured gateway endpoints.
- **Disconnect**: Press **`d`** to safely terminate the active tunnel and restore routing.

---

## Keybindings Reference

### Global / Main Dashboard Navigation

| Key | Action |
| :--- | :--- |
| **`Tab`** / **`BackTab`** | Cycle focus between panes (Accounts → Profiles → Flags → Logs) |
| **`j`** / **`Down`** | Move selection down in the active pane |
| **`k`** / **`Up`** | Move selection up in the active pane |
| **`Enter`** | Connect to the currently selected profile |
| **`d`** | Disconnect active VPN session |
| **`p`** | Ping all profile endpoints for latency |
| **`n`** | Create a new VPN configuration (in Profiles pane) |
| **`a`** | Create a new Account (in Accounts pane) |
| **`e`** | Edit selected profile or account |
| **`x`** | Delete selected profile or account |
| **`q`** / **`Ctrl+C`** | Clean up active connections and quit |

### Modal Dialogs

| Modal | Key | Action |
| :--- | :--- | :--- |
| **Config Adder** | `Tab` / `Down` | Move to next field |
| | `Shift+Tab` / `Up` | Move to previous field |
| | `Space` / `Left` / `Right` | Cycle protocol, cycle account, toggle flags, cycle SSL policy |
| | `F2` | Open interactive file browser (on `.ovpn` file field) |
| | `Tab` | Inline directory and file autocompletion (on `.ovpn` path) |
| | `Enter` | Save profile |
| | `Esc` | Cancel and close modal |
| **File Browser** | `Up` / `Down` | Navigate directory entries |
| | `Enter` | Enter directory / select file |
| | `Backspace` | Navigate up to parent directory |
| | `Esc` | Close file browser |
| **Cert Warning** | `Enter` / `a` | Accept and permanently pin server certificate fingerprint |
| | `Esc` / `r` | Reject certificate and abort connection |
| **Delete Confirm** | `y` / `Enter` | Confirm deletion |
| | `n` / `Esc` | Cancel deletion |
| **Sudo Password** | `Enter` | Submit password |
| | `Esc` | Cancel authentication |

---

## Configuration & Storage Layout

`vpn_tui` persists your profiles and accounts in human-readable TOML files adhering to the XDG Base Directory specification:

```text
~/.config/vpn-tui/
├── accounts.toml         # Account credentials (usernames, encrypted passwords, authgroups)
├── openconnect/          # OpenConnect configuration profiles
│   ├── munich-gw.toml
│   └── corporate-vpn.toml
└── openvpn/              # OpenVPN configuration profiles
    ├── client.ovpn
    └── office-vpn.toml
```

*(Note: If a `./configs/` directory exists in the working directory, `vpn_tui` will operate in portable local mode).*

---

## Testing & Quality

To run the complete automated test suite (unit tests, architecture boundary tests, and end-to-end flow tests):

```bash
cargo test
```

To run linter and formatting checks:

```bash
cargo clippy -- -D warnings
cargo fmt -- --check
```

---

## Architecture Overview

`vpn_tui` follows the **Hexagonal (Ports and Adapters) Architecture**:

```
                       +-------------------------+
                       |    Ratatui / Crossterm  |
                       |    (Terminal User UI)   |
                       +------------+------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  DOMAIN LAYER (Core Entities & Pure State)                            |
|  - Profile, Account, Credentials, SslPolicy, ConnectionState          |
+-----------------------------------------------------------------------+
        ^                                               ^
        |                                               |
+-------+-----------------------+       +---------------+---------------+
|  PORTS (Interfaces)           |       |  INFRASTRUCTURE (Adapters)    |
|  - ConfigStorage trait        | <---  |  - FsConfigStorage (TOML)     |
|  - VpnRunner trait            | <---  |  - SudoProcessRunner (Async)  |
|  - Pinger trait               | <---  |  - TcpPinger (Multi-threaded) |
+-------------------------------+       |  - NetMonitor (/proc/net/dev) |
                                        +-------------------------------+
```

- **Zero Coupling**: Core domain rules and state machine do not depend on Ratatui or process execution.
- **Port Swappability**: Testing uses in-memory storage, mock VPN runners, and mock pingers without needing root privileges or network connectivity.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
