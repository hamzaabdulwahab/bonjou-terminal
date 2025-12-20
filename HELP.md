# Bonjou Command Reference

Bonjou runs entirely from an interactive prompt. Every action is triggered with an `@` prefixed command.

## Core Commands

- `@help` – show this help summary inside Bonjou.
- `@whoami` – print the configured username, IP address, and listening ports.
- `@users` – list discovered LAN peers that announced themselves in the last 15 seconds.
- `@status` – display runtime information such as storage paths and port usage.
- `@history` – dump chat and transfer history from `~/.bonjou/logs`.
- `@clear` – clear the terminal and redraw the welcome banner.
- `@exit` – leave the Bonjou session gracefully.

## Messaging

- `@send <user|ip> <message>` – send a plain text message to the specified user or IPv4 address.
- `@multi <user1,user2,...> <message>` – deliver a text message (or file/folder, see below) to multiple recipients.
- `@broadcast <message>` – send a text message to every discovered peer.

## Transfers

- `@file <user|ip> <path>` – send a single file. Relative paths are resolved from the current working directory.
- `@folder <user|ip> <path>` – send a directory; Bonjou compresses it before transfer and extracts on the recipient.
- `@multi <user1,user2,...> <path>` – if `<path>` points to a file or directory, Bonjou sends that artifact to each peer.

Transfers stream over TCP with integrity validation. Real-time progress updates appear in the prompt area. Received content lands in:

```
~/.bonjou/received/files
~/.bonjou/received/folders
```

## Storage and Paths

- `@setpath <dir>` – change the base directory used for incoming transfers. Bonjou creates `files/` and `folders/` subdirectories automatically and updates `config.json`.

## Updating

- `@update` – execute `bonjou-update` if available on `PATH`, or `~/.bonjou/update.sh` if present. Useful for offline / LAN-hosted repositories.

## Tips

- Use usernames for readability; Bonjou maps usernames to IPs via LAN discovery.
- To target a device directly, supply the IPv4 address (Bonjou assumes the default port 46321).
- When transferring folders, ensure you have permission to read every file inside the directory tree.
- History data can become large on long-lived hosts; clear it by deleting the log files or using `@clear` and removing them manually.
