# vpn_tui

A lightweight, modern, and asynchronous Terminal User Interface (TUI) for managing VPN connections on Linux, built in Rust with [Ratatui](https://github.com/ratatui/ratatui) and [Tokio](https://tokio.rs).

`vpn_tui` provides a unified dashboard to configure, authenticate, and monitor **OpenConnect** (Cisco AnyConnect / ocserv) and **OpenVPN** connections with real-time log streaming, traffic monitoring, preflight SSL certificate probing, interactive certificate pinning, and multi-source configuration sync.

```text
+-[ VPN TUI - System Status & Live Telemetry ]----------------------------------+
| ● CONNECTED  [tun0] 10.8.0.42  Uptime: 01:24:12    ▼ DL:  1.4 MB/s [ ▂▃▄▅▆▇██ ]|
| Gateway: vpn.corp.net:443 (openconnect)           ▲ UL:   45 KB/s [    ▂▃▂  ▂ ]|
| Total: RX 142.5 MB | TX 18.2 MB                    Telemetry: 30s live window  |
+-----------------------------------+-------------------------------------------+
| ▶ Accounts (1) [A: Expand]        | CONFIGURATION DETAILS & FLAGS             |
+-----------------------------------+ Name: DE Munich | Protocol: openconnect   |
| CONFIGURATIONS [C: Zoom]        ▲ | Endpoint: vpn.munich.de:443 | Account: Corp|
|                                 █ | Flags: [--no-dtls --servercert=...]       |
| ▼ BioVPN/Cisco (10)             │ +-------------------------------------------+
|   > [OC] DE Munich     [● 24ms] │ | CONNECTION LOGS [f: Zoom]               ▲ |
|   - [OC] NL Amsterdam  [■ 45ms] │ | [10:45:12] SSL negotiation complete     │ |
| - [OV] Standalone Tun  [▲ 78ms] ▼ | [10:45:13] Assigned IP: 10.8.0.42        █ |
|                                   | [10:45:13] Tunnel interface tun0 is UP    ▼ |
+-----------------------------------+-------------------------------------------+
| [Enter] Connect  [Space] Folder  [j/k] Scroll  [PgUp/PgDn] Page  [q] Quit     |
+-------------------------------------------------------------------------------+
```

---

## Features

- **Multi-Protocol Support**: Seamlessly configure and connect to both OpenConnect and OpenVPN gateways.
- **Hierarchical Configuration Folders & Tree Navigation**:
  - Organize profiles into unlimited folder paths (e.g. `BioVPN/Cisco`, `BioVPN/OpenVPN`, `Work/Europe/Frankfurt`).
  - Interactive tree folding: expand and collapse folders with **`Space`**, **`Enter`**, **`←`**, and **`→`**.
  - Folder indicators showing child counts (`▶ BioVPN (12)` / `▼ BioVPN (12)`).
  - Standalone profiles remain neatly at root level.
  - Create empty folders ahead of time (**`m`** / **`M`**) that display with a `(0)` counter and persist across restarts.
  - Cycle and pick from existing folders or create new folders inline during profile creation.
- **Adaptive 2-Column Dashboard & Multi-Level Zoom**:
  - Full-height Configurations list on the left with protocol badges (`[OC]`, `[OV]`), linked accounts, and color-coded latency.
  - Right column features full-width Configuration Details & Flags and expanded real-time Connection Logs.
  - **Full-Height Configs Zoom (`C`)**: Maximize the configuration tree to full screen height to comfortably manage deep hierarchies.
  - **Full-Screen Log Zoom (`f`)**: Toggle logs to full screen to inspect long connection traces.
- **Top Header Live Telemetry**:
  - Live throughput sparklines for Download and Upload powered by Ratatui's `Sparkline` widget directly integrated into the top header block.
  - Dual real-time transfer rates (`▼ DL` / `▲ UL`), session uptime counter (`HH:MM:SS`), active gateway, interface, assigned IP, and total transfer counters.
  - Graceful compact fallback for height-constrained terminal windows.
- **Stateful Viewport Scrolling & Scrollbars**:
  - Native Ratatui `ListState` viewport tracking for Configurations and expanded Accounts with visual vertical scrollbars (`▲`/`▼`).
  - Bi-directional Connection Log scrolling (`k`/`j`, `PageUp`/`PageDown`, `Home`/`End`, `g`/`G`) with automatic scroll pause detection (`[SCROLL PAUSED]`) and bottom resume.
- **Terminal Theme Synchronization & Modern Aesthetics**:
  - Zero hardcoded RGB background colors — uses `Color::Reset` to inherit your terminal's transparency, wallpapers, and colors.
  - High-contrast inverted cursors (`Modifier::REVERSED`) adapting cleanly to both dark and light terminal palettes.
  - Smooth rounded borders (`BorderType::Rounded`) with standard ANSI accent colors.
- **Connection Latency & Health Probing**:
  - Color-coded latency indicators: Green (`< 50ms`), Yellow (`50–120ms`), Red (`> 120ms`), Red Timeout.
  - One-click ping all gateway endpoints simultaneously (**`p`**).
- **Unified Sync & Configuration Import Suite**:
  - **Interactive TUI Sync Modal (`S`)**: One-stop menu for online provider sync, local archive import, and batch server pasting.
  - **OpenVPN Archive Extraction**: Unpacks `.ovpn` files directly from `.zip` bundles into your configuration vault.
  - **Automatic Cisco Profile Generation**: Automatically extracts `remote <host> <port>` directives from `.ovpn` archives to generate matching Cisco OpenConnect profiles.
  - **Batch Server Text Importer**: Paste multi-line server lists (`Name Endpoint`) to bulk-generate profiles in seconds.
  - **Pure Rust BioVPN Online Sync**: 100% native asynchronous synchronization directly from bio4co.com with deterministic compile-time GD font 5 CAPTCHA recognition, zero external Python, pip, or script dependencies.
- **On-Demand Account Vault (`a`)**: Manage credentials in a dedicated popup overlay without wasting dashboard space.
- **SSL Certificate Verification & Pinning**:
  - Preflight SSL probe inspects remote gateways before launching root processes.
  - Interactive certificate warning modal displays the server subject, SHA-256 fingerprint, and failure reason.
  - One-click certificate pinning (`--servercert=pin-sha256:...`) persisted directly into the profile.
  - Policy enforcement: Choose between `Strict`, `Prompt` (interactive approval), or `Insecure` (`--no-cert-check`).
- **Interactive File Picker**: Built-in filesystem browser for selecting `.ovpn` and `.zip` files with Tab autocompletion and tilde (`~`) expansion.
- **Robust Clean Architecture**: Hexagonal domain separation ensuring rock-solid state management, channel isolation, and 100% testable port adapters.

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

If you prefer seamless connection launches without entering your password each time:

```sudoers
# Edit with: sudo visudo
your_username ALL=(ALL) NOPASSWD: /usr/sbin/openconnect, /usr/sbin/openvpn
```

---

## How to Use

Launch the application in any terminal emulator:

```bash
vpn_tui
```

### 1. Connecting and Monitoring

- **Tree Navigation & Folding**: Navigate configuration folders and profiles with `↑`/`↓` (or `j`/`k`). Press **`Space`** or **`Enter`** on a folder node to toggle between expanded (`▼`) and collapsed (`▶`). Press **`←`** to collapse the current folder or jump to its parent; press **`→`** to expand.
- **Connect**: Press **`Enter`** on any profile leaf to initiate a VPN connection.
- **Disconnect**: Press **`d`** to terminate the active tunnel.
- **Configurations Zoom**: Press **`C`** (or `c`) to zoom the Configurations list to full height, hiding the Telemetry and Logs columns. Press **`C`** again or **`Esc`** to return to split view.
- **Log Zoom**: Press **`f`** to maximize the connection logs to full screen. Press **`f`** or **`Esc`** to restore split view.
- **Ping Latency**: Press **`p`** to measure latency across all gateway endpoints simultaneously.

### 2. Syncing and Importing Configurations (`S`)

Press **`S`** anywhere in the app to open the **Sync & Import Configurations** center:

1. **[1] BioVPN Online Sync**:
   - Authenticates and fetches configuration archives directly from your BioVPN account in 100% native Rust.
   - Automatically solves portal CAPTCHA verification codes using deterministic GD font 5 pixel matching.
   - Organizes profiles into `BioVPN/OpenVPN` and `BioVPN/Cisco` folders automatically.
   - Ingests bundles directly in-memory and saves both OpenVPN and Cisco AnyConnect configurations.
2. **[2] Import OpenVPN Archive (.zip)**:
   - Select a downloaded `.zip` file using the built-in file browser.
   - Extracts `.ovpn` files to `openvpn/`.
   - With `[x] Auto-generate Cisco profiles` enabled, automatically extracts `remote <host> <port>` directives to create matching Cisco AnyConnect profiles for `openconnect/`.
3. **[3] Batch Paste Server IPs**:
   - Paste a raw list of server names and endpoints (e.g. `Germany 185.120.45.10:443`).
   - Generates all `.toml` profiles in one go.

### 3. Managing Accounts (`A` / `a`)

The **Accounts Pane** lives directly on the main screen above your Configurations list:
- **Expand / Collapse (`A` or `Space`)**:
  - **Collapsed State**: Takes a minimal 3-line bar showing the active account summary (`▶ Accounts (N) [A: Expand]`).
  - **Expanded State**: Unfolds into a full interactive list (`▼ Accounts [A: Collapse | a: Add | e: Edit | x: Del]`).
- **Navigate & Delete**:
  - Focus the Accounts pane with **`A`** or **`Tab`**.
  - Navigate accounts with **`↑` / `↓`** (or `j`/`k`).
  - Press **`x`** (or **`Delete`**) and confirm with **`y`** to remove the account. Any profiles assigned to this account are safely unlinked.
  - Press **`e`** (or **`Enter`** when expanded) to edit credentials.
  - Press **`Esc`** to collapse and return focus to Configurations.
- **Add Account**: Press **`a`** at any time to open the **Add Account** modal form:
  - **Account Name**: Label (e.g. `Work VPN`, `BioVPN`).
  - **Username**: Gateway username.
  - **Password**: Gateway password.
  - **Authgroup**: (Optional) Gateway group/realm for OpenConnect.

### 4. Creating Folders & Organizing Configs (`m` / `M`)

- **Create Empty Folders Ahead of Time**:
  - Press **`m`** (or **`M`**) from the Configurations pane to open the **New Folder** dialog.
  - Enter a simple name (e.g. `Personal`) or a nested path (e.g. `Work/Europe/Frankfurt`).
  - The folder appears immediately in the tree with a `(0)` profile counter and is automatically expanded.
  - Empty folders persist across restarts in `folders.toml`.
- **Assigning Profiles to Folders**:
  - When creating a profile (**`n`**) or editing an existing one (**`e`**), navigate to the **Folder / Group** field.
  - Use **`Space`**, **`Left`** (`←`), or **`Right`** (`→`) to cycle between `(None / Root)`, all existing folders, or `[+ New Folder]`.
  - When `[+ New Folder]` is selected, type a custom folder path inline. Upon saving, the new folder is created, persisted, and the profile is placed inside it.
- **Deleting Folders (`x` / `Delete`)**:
  - Select any folder node in the Configurations tree and press **`x`** (or **`Delete`**).
  - **Empty Folders**: Displays a prompt to delete the empty folder.
  - **Populated Folders**: Displays a warning with the exact profile count (e.g. `"delete folder 'Work' and all 3 profile(s) inside it"`). Confirm with **`y`** or **`Enter`** to permanently remove the folder and all its contents; cancel with **`n`** or **`Esc`**.
  - **Active Connection Guard**: If any profile inside the folder (or subfolder) is actively connected or connecting, deletion is automatically prevented to safeguard the tunnel.

---

## Keybindings Reference

### Dashboard Navigation

| Key | Action |
| :--- | :--- |
| **`Tab`** / **`BackTab`** | Cycle focus between panes (Profiles → Flags → Logs) |
| **`j`** / **`Down`** | Move selection down (in Configurations/Accounts) or scroll down (in Logs) |
| **`k`** / **`Up`** | Move selection up (in Configurations/Accounts) or scroll up (in Logs) |
| **`PageDown`** | Jump down 10 items / log lines |
| **`PageUp`** | Jump up 10 items / log lines |
| **`Home`** / **`End`** | Jump to first / last item (in Configurations/Accounts) or earliest/latest log |
| **`g`** / **`G`** | In Logs: jump to earliest log (`g`) or latest log & resume auto-scroll (`G`) |
| **`Space`** | Toggle folder expand/collapse (in Profiles) or toggle Accounts pane |
| **`Enter`** | Connect to selected profile (or toggle folder if on a folder) |
| **`Left`** / **`Right`** | Collapse folder / jump to parent (`←`) or expand folder (`→`) |
| **`C`** / **`c`** | Toggle full-height Configurations pane zoom |
| **`f`** | Toggle full-screen Log zoom |
| **`d`** | Disconnect active VPN session |
| **`p`** | Ping all profile endpoints for latency |
| **`S`** / **`s`** | Open Sync & Import Configurations modal |
| **`A`** | Toggle Expand/Collapse Accounts pane on main dashboard |
| **`a`** | Quick-add a new account modal |
| **`m`** / **`M`** | Create a new configuration folder modal |
| **`n`** | Create a new configuration profile manually (with optional folder/group) |
| **`e`** | Edit selected profile or account |
| **`x`** / **`Delete`** | Delete selected profile, folder, or account |
| **`Esc`** | Exit zoom mode / collapse accounts pane |
| **`q`** / **`Ctrl+C`** | Clean up active connections and quit |

### Modals

| Modal | Key | Action |
| :--- | :--- | :--- |
| **New Folder** | `Text Input` | Enter folder name or hierarchical path (e.g. `BioVPN/Cisco`) |
| | `Enter` | Create and persist folder |
| | `Esc` | Cancel and close modal |
| **Sync Manager** | `↑` / `↓` | Select import method |
| | `Tab` | Cycle target account |
| | `Space` | Toggle automatic Cisco profile generation |
| | `Enter` | Proceed with selected method |
| | `Esc` | Cancel and close modal |
| **Batch Add Servers** | `Enter` | Parse and save all server entries |
| | `Esc` | Return to Sync Manager |
| **Config Adder** | `Tab` / `Down` | Move to next field |
| | `Shift+Tab` / `Up` | Move to previous field |
| | `Space` / `Left` / `Right` | Cycle protocol, cycle account, toggle flags, cycle SSL policy, cycle existing folders |
| | `Text Input` | Enter profile name, endpoint, flags, or custom folder path (when `[+ New Folder]` is selected) |
| | `F2` | Open interactive file browser (on `.ovpn` file field) |
| | `Tab` | Inline directory and file autocompletion (on `.ovpn` path) |
| | `Enter` | Save profile |
| | `Esc` | Cancel and close modal |
| **File Browser** | `Up` / `Down` / `j` / `k` | Navigate files and directories |
| | `Enter` | Open directory / select file (`.ovpn` or `.zip`) |
| | `Backspace` / `Left` | Navigate up to parent directory |
| | `Esc` | Close file browser |
| **Cert Warning** | `Enter` / `a` | Accept and permanently pin server certificate fingerprint |
| | `Esc` / `r` | Reject certificate and abort connection |
| **Delete Confirm** | `y` / `Enter` | Confirm deletion of selected profile, folder (and contained profiles), or account |
| | `n` / `Esc` | Cancel deletion |
| **Sudo Password** | `Enter` | Submit password |
| | `Esc` | Cancel authentication |

---

## Configuration & Storage Layout

`vpn_tui` persists your profiles and accounts in human-readable TOML files adhering to the XDG Base Directory specification:

```text
~/.config/bio-vpn-tui/   (or ~/.config/vpn-tui/)
├── accounts.toml         # Account credentials (usernames, passwords, authgroups)
├── folders.toml          # Saved explicit/empty folder paths
├── openconnect/          # OpenConnect configuration profiles
│   ├── nl.toml
│   ├── pl.toml
│   └── de-cisco.toml
└── openvpn/              # OpenVPN configuration profiles & .ovpn files
    ├── client.ovpn
    └── nl-ovpn.toml
```

*(Note: If a `./configs/` directory exists in the working directory, `vpn_tui` will operate in portable local mode).*

---

## Testing & Quality

To run the complete automated test suite (110+ unit tests, architecture boundary tests, and end-to-end flow tests):

```bash
cargo test
python3 tests/test_fetch_biovpn.py
```

To run linter and formatting checks:

```bash
cargo clippy -- -D warnings
cargo fmt -- --check
```

---

## Architecture Overview

`vpn_tui` follows the **Hexagonal (Ports and Adapters) Architecture**:

```text
                       +-------------------------+
                       |    Ratatui / Crossterm  |
                       |    (Terminal User UI)   |
                       +------------+------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|  DOMAIN LAYER (Core Entities & Pure State)                            |
|  - Profile, Account, Credentials, SslPolicy, ConnectionState          |
|  - ProfileImporter (Archive extraction & remote parsing)              |
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

- **Zero Coupling**: Core domain rules, state machines, and importer logic do not depend on Ratatui or process runners.
- **Port Swappability**: Testing uses in-memory storage, mock VPN runners, and mock pingers without needing root privileges or network connectivity.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
