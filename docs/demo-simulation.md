# Bonjou Demo Simulation

This walkthrough demonstrates a LAN chat + file/folder transfer between two hosts named **alex-laptop** and **jamie-desktop**. Repeat the steps on real machines or two terminals on the same computer using loopback IPs.

## Preparation

1. Build Bonjou binaries via `./scripts/build.sh`.
2. Install the binary on both devices (copy the appropriate executable to `/usr/local/bin/bonjou` on Linux/macOS or `C:\\Tools\\bonjou.exe` on Windows).
3. Make sure UDP port `46320` and TCP port `46321` are open on local firewalls.

## Session 1 – alex-laptop

```bash
bonjou
# Banner displays
@whoami
```

Output example:

```
Username: alex
IP: 192.168.1.34
Listen port: 46321
```

Leave Bonjou running on alex-laptop.

## Session 2 – jamie-desktop

```bash
bonjou
@users           # discovers alex-laptop via UDP broadcasts
@send alex Hey Alex, testing Bonjou from Jamie.
```

alex-laptop should now display the incoming message in real time.

## File Transfer

On jamie-desktop:

```bash
@file alex ~/Pictures/nano-drone.jpg
```

Progress percentages appear on both terminals. When complete, alex finds the file at:

```
~/.bonjou/received/files/nano-drone.jpg
```

## Folder Transfer

On alex-laptop:

```bash
@folder jamie ./docs/release-notes
```

Bonjou zips the folder, streams it to jamie, and extracts it under:

```
~/.bonjou/received/folders/release-notes
```

## Broadcast and History

On jamie-desktop:

```bash
@broadcast Maintenance window starts in 5 minutes.
@history
```

Both systems log the broadcast and previous transfers in `~/.bonjou/logs/`.

## Update Command

Place an executable script at `~/.bonjou/update.sh` on both hosts:

```bash
#!/usr/bin/env bash
echo "Simulating update..."
```

Then run `@update` inside Bonjou. The script executes, demonstrating the offline-update workflow.

## Cleanup

Use `@exit` on both terminals to end sessions. Optional: clear logs by deleting files in `~/.bonjou/logs`.
