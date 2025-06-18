# Trap Loader WPF

A proof-of-concept **loader / C2** application written in C# (.NET 8, WPF).  
It pairs a lightweight PowerShell stub with a local HTTP server and a GUI to manage inbound clients and deliver payloads.

---

## How it works

1. **PowerShell stub** (`PSStub/PSStub_Direct.ps1` or the generated stub) polls `http(s)://<server>:<port>/loader/` every few seconds.
2. The stub sends an **encrypted JSON blob** containing:
   * `password` – shared secret
   * `info` – OS version, AV, crypto-wallet presence, etc.
   * `machine_id` – SHA-256 of CPU/Bios/Mainboard IDs
3. **`HttpServer`** (inside the WPF app) decrypts & validates the payload, then looks up a queued file for that client.
4. If a file is waiting it returns **HTTP 200 + binary payload**. Otherwise it returns **HTTP 204** so the client keeps polling.
5. The stub stores the file in **%TEMP%\wuauditer-<random>.exe|.bat** and executes it.

---

## Current GUI features

| Area | What it does |
|------|--------------|
| **Clients tab** | • Live list of all unique `machine_id`s that have pinged the server.<br>• Displays OS, AV, wallet info.<br>• Select multiple clients, queue a file, refresh & search.
| **Logs tab** | Scrollable console output for debugging / auditing.
| **Builder tab** | Generates a ready-to-run PS1 stub with your chosen IP/Port/Password.
| **Status bar** | Shows total clients, last file sent, and current port.

---

## Known weaknesses / To-fix list

| ⚠️  Area | Problem |
|----------|---------|
| **Encryption key** | `TrapLoaderSecureKey123` is hard-coded in both stub and server – anyone can recreate it.  Replace with a per-deployment value or a key-exchange mechanism.
| **HTTPS disabled** | Transport runs over plain HTTP by default.  Enable TLS (listener already supports HTTPS) and require it in the stub.
| **Accepts unencrypted fallback** | Server still honours *unencrypted* JSON if the `data` field is missing.  Remove this for production.
| **Password timing** | `password` is included inside the encrypted blob *but* the code path that accepts unencrypted JSON leaks it in the clear.
| **RCE by design** | Loader executes whatever file is queued – implement whitelist / signatures.
| **Rate-limiting** | Simple per-IP counter; subject to spoofing and easy DoS.
| **Client spoofing** | `machine_id` is asserted by the client – could be faked.  Consider secondary verification.
| **Hard-coded User-Agent** | Minor, but fingerprintable.
| **No persistence** | Queue resets when the app restarts – persist to disk or a DB.

---

## Roadmap – *Tasks* tab

Next major feature is a **Tasks tab** to send scripted actions ("jobs") to clients instead of single file drops.

Suggested architecture:

1. **Task objects** – JSON describing the action (`download`, `run-cmd`, `update`, etc.) plus parameters.
2. **Server queue** – Store tasks per-client in a lightweight DB (SQLite) so they survive restarts.
3. **Stub upgrade** – After executing a task, stub POSTs a result object (`stdout`, `exitCode`, etc.).
4. **GUI** – New tab to create, schedule, cancel and view task results.
5. **Security** – Sign tasks with HMAC and verify on stub.

---

## Building & running

```bash
# Prerequisites: .NET 8 SDK

# Restore & build (Debug)
dotnet build

# Run
cd LoaderKeyed
 dotnet run
```

The first launch listens on port **4333** (default).  
Edit the port/password in the GUI before pressing **Start Listening**.

---

### Cleaning up

`bin/` and `obj/` folders are git-ignored.  Delete them anytime; they are regenerated on the next build.

### Disclaimer

This repository is **for educational purposes only**. Running a loader / C2 infrastructure can be illegal if used on systems you don't own or have permission to test.  Use responsibly.

