# Trap Panel

**Modular remote administration framework with TLS 1.3 encrypted TCP, 18 plugins, and C#/PowerShell agent deployment.**

Trap Panel is a remote administration framework coded in C# (.NET 8, WPF) featuring TLS 1.3 encrypted TCP communications, a plugin-based architecture for real-time bidirectional control, and both C# and PowerShell agent deployment. It provides a broad feature set ranging from system administration to security research.

## Screenshots

<img src="screenshots/panelss.png" width="320"/> <img src="screenshots/panelss2.png" width="320"/> <img src="screenshots/panelss3.png" width="320"/>

## Features

- **TLS 1.3 encrypted transport** — all traffic secured via SslStream with AES-256-GCM payload encryption
- **18 built-in plugins** — shell, file manager, registry, screen monitor, keystroke monitor, webcam, microphone, remote desktop, SOCKS5 proxy, crypto miner, wallet finder, process guard, persistence, system info, process monitor, API hooks, countdown, auto-update
- **C# + PowerShell agent generation** — Roslyn-compiled .NET executable or lightweight PowerShell script
- **Plugin-based architecture** — modular IServerPlugin interface with per-client session routing
- **Real-time push model** — event-driven command delivery within milliseconds of queuing
- **Auto Tasks engine** — schedule automated plugin execution on client connect
- **8 customizable themes** — Dark, Light, Midnight, Hacker, Nord, Dracula, Solarized, Tokyo Night
- **Rate limiting & environment checks** — connection throttling, debugger and sandbox detection
- **Certificate-based server identity** — auto-generated RSA 4096-bit self-signed certificate

## Built-in Plugins

| Plugin | Description |
|---|---|
| **Shell** | Execute system commands via cmd.exe with async streaming I/O |
| **File Manager** | Browse directories, upload/download/delete/execute files, fetch from URL |
| **Registry** | Full Windows registry editor — read, write, create, delete keys and values |
| **Screen Monitor** | Capture screenshots and stream real-time screen feed |
| **Process Monitor** | List running processes, kill by PID, start new processes |
| **Keystroke Monitor** | Global keyboard hook monitoring input with timestamps |
| **Webcam** | Capture webcam images and stream video feed (AVICAP32 / WinRT) |
| **Microphone** | Real-time audio surveillance via NAudio (16kHz, 16-bit PCM) |
| **Remote Desktop** | Desktop interaction via virtual network computing |
| **SOCKS5 Proxy** | Full SOCKS5 proxy server running on the client (CONNECT, auth methods) |
| **Crypto Miner** | Download and execute XMRig with configurable pool, wallet, and CPU affinity |
| **Wallet Finder** | Search and locate 16+ cryptocurrency wallet files |
| **Process Guard** | Terminate 200+ competing processes |
| **Persistence** | Install startup persistence via Registry Run, Startup folder, Scheduled Task, WMI |
| **System Info** | Gather comprehensive system, hardware, network, software, and service information |
| **Fun** | Swap mouse, flip screen, open CD tray, toggle locks, message boxes, wallpaper |
| **API Hooks** | Userland API hooking via EasyHook for custom filtering |
| **Countdown** | AES-256-CBC file encryption with countdown timer |
| **Update** | Download and replace client agent for self-updates |

## Agent Builder

Configure and generate deployment-ready agents from the Builder tab.

| Option | Description |
|---|---|
| Server IP / Hostname | Server address |
| Port | TCP port for client connection |
| Password | Authentication secret (minimum 12 characters) |
| Encryption Key | AES-256 key for PBKDF2 (optional — TLS secures transport) |
| Silent Mode | Run agent without console or visible window |
| Install Name | Filename for the installed agent |
| Install Directory | Target directory for agent installation |
| Startup Method | Registry / Startup Folder / Scheduled Task |
| Anti Debug | Enable debugger detection |
| Process Guard | Enable competing process termination |
| Output | Standalone .EXE (.NET 8) or .PS1 script |

## Transport Protocol

### Wire Format

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic — `0xDEADBEEF` (big-endian) |
| 4 | 4 | Payload length (big-endian, max 100 MB) |
| 8 | 1 | Message type |
| 9 | N | Encrypted payload (AES-256-GCM) |

### Message Types

| Byte | Type | Direction |
|---|---|---|
| 0x00 | KeepAlive | Bidirectional |
| 0x01 | Handshake | Client → Server |
| 0x02 | HandshakeResponse | Server → Client |
| 0x03 | Auth | Client → Server |
| 0x04 | AuthResponse | Server → Client |
| 0x05 | Command | Bidirectional |
| 0x06 | CommandResult | Bidirectional |
| 0x07 | FileChunk | Bidirectional |
| 0x08 | Error | Bidirectional |
| 0x09 | Disconnect | Bidirectional |

### Handshake Flow

```
Client                                 Server
  │                                        │
  │── TCP Connect ──────────────────────► │
  │                                        │
  │── Handshake (certificate) ───────────►│
  │◄── HandshakeResponse (nonce) ──────── │
  │                                        │
  │── Auth (JSON: password) ─────────────►│
  │◄── AuthResponse (success/failure) ──── │
  │                                        │
  │═══ Bidirectional message loop ═══════►│
```

Authentication JSON format:
```json
{
  "type": "auth",
  "password": "supersecret"
}
```

## System Requirements

| Component | Requirement |
|---|---|
| **Panel OS** | Windows 7 or later |
| **Panel Runtime** | .NET 8 Runtime |
| **Panel Dependencies** | NuGet: DiscordRichPresence, Microsoft.CodeAnalysis.CSharp 5.0, Newtonsoft.Json 13.0, System.Management 8.0 |
| **Client OS** | Windows 7 or later |
| **Client Runtime** | .NET Framework 4.8 or .NET 8 |
| **Client Privileges** | User or Administrator (Admin required for remote desktop, API hooks) |
| **Resolution** | Minimum 1100 x 700 |
| **Network** | Outbound TCP to server |

## Building

```powershell
git clone https://github.com/your-repo/TrapPanel
cd TrapPanel

dotnet build
```

Run the generated executable from `bin\Debug\net8.0-windows7.0\LoaderKeyed.exe`.

## Usage

1. **Launch** — the panel automatically generates an RSA 4096-bit certificate on first run
2. **Set password** — navigate to Settings, set a server password (minimum 12 characters)
3. **Start listening** — click "Start Listening" to begin accepting client connections
4. **Configure builder** — enter server IP, port, and password in the Builder tab
5. **Generate agent** — click "Generate PS1" or "Compile EXE"
6. **Deploy** — run the generated agent on the target machine
7. **Manage** — connected clients appear in the Clients tab; right-click to launch plugins

## Themes

| Theme | Preview |
|---|---|
| Dark | Dark gray background, white text, blue accent |
| Light | White background, black text, blue accent |
| Midnight | Near-black background, teal accent |
| Hacker | Black background, green terminal-style text |
| Nord | Arctic blue palette, cyan and green accents |
| Dracula | Dark purple background, pink and green accents |
| Solarized | Dark brown background, yellow and blue accents |
| Tokyo Night | Deep blue background, cyan and pink accents |

## Security

| Measure | Detail |
|---|---|
| Transport | TLS 1.3 with RSA 4096-bit server certificate |
| Payload | AES-256-GCM with random 96-bit nonce and 128-bit tag |
| Key derivation | PBKDF2 with 100,000 iterations (SHA-256) and 16-byte salt |
| Authentication | Password validated via constant-time comparison over TLS |
| Rate limiting | 100 max concurrent connections, 5 per IP |
| Auto-ban | 1-hour IP ban after 3 failed auth attempts |
| Environment checks | Debugger detection, sandbox detection |
| Protection | Userland API hooking via EasyHook (optional) |

## License

This project is for educational and authorized security research purposes only. Unauthorized use of this software against systems you do not own or have explicit written permission to test is illegal. The authors assume no liability for misuse.
