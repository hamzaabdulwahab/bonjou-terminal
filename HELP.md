# Bonjou Commands

All commands start with `@`. Type them in the Bonjou terminal.

## Basic Commands

| Command | What it does |
|---------|-------------|
| `@help` | Show this help |
| `@whoami` | Show your username, IP, and listen port |
| `@users` | List discovered users with last-seen timestamps |
| `@status` | Show app info and receive path |
| `@history` | Show saved chat and transfer history |
| `@wizard` | Open guided send wizard |
| `@clear` | Clear the screen |
| `@clear history` | Clear saved history logs |
| `@exit` | Quit Bonjou |

## Sending Messages

**To one person:**
```
@send alex Hey, how are you?
```

**To multiple people:**
```
@multi alex,bob Meeting at 3pm
```

**To everyone discovered right now:**
```
@broadcast Lunch break!
```

You can use a username or IP address.

## Wizard

Run:
```
@wizard
```

Wizard options:
- Send message
- Send file
- Send folder
- Send to multiple users
- Broadcast

Single-recipient message/file/folder flows show users as `username (ip)`.

If there are no discovered users for message/file/folder/multi flows, the wizard returns to the menu and shows `No active users discovered.`

Use `Back to wizard menu` on selection screens, or type `/back` in message/path inputs, to return to the main wizard menu.

Wizard message fields may contain multiple lines. This is useful when pasting larger notes, logs, or code snippets.

Broadcast does not require selecting a user first. It sends only to users currently discovered by Bonjou.

After each send attempt or cancel, the wizard returns to the start menu.

Press `Ctrl+C` at any wizard step to close the wizard and return to command mode.

## Sending Files and Folders

**Send a file:**
```
@file alex ~/Documents/report.pdf
```

**Send a folder:**
```
@folder alex ./my-project
```

**Send a file, folder, or message to multiple people:**
```
@multi alex,bob ~/photo.jpg
```

Optional manual override for multi-send:
```
@multi --sequential alex,bob Meeting at 3pm
```

## Receive Approval Queue

Incoming files and folders are first placed in a single pending approval queue as metadata-only transfer offers. No file or folder bytes are downloaded into your final receive folders until you approve them.

### Queue Commands

| Command | What it does |
|---------|-------------|
| `@queue` | List all pending files and folders in one queue |
| `@view <id>` | Inspect one pending item; for folders, show sender-provided manifest metadata before approving or rejecting |
| `@approve <id>` | Approve one pending item |
| `@reject <id>` | Reject one pending item |
| `@approveAll` | Approve all pending items |
| `@rejectAll` | Reject all pending items |

Approved items are saved under:
- `~/.bonjou/received/files/`
- `~/.bonjou/received/folders/`

Folder approval is whole-folder only. Use `@view <id>` to inspect a pending folder offer first, then approve or reject the entire folder queue item.

If you changed the receive path with `@setpath`, Bonjou saves approved files and folders under that custom path instead.

## Discovery Limits

Bonjou announces itself automatically. On the same subnet, users appear quickly via UDP broadcast.

Bonjou discovery is same-subnet only. UDP broadcast generally does not cross routers or VLANs. If someone is not showing up, make sure both devices are on the same Wi‑Fi/LAN segment and that firewall rules allow UDP/TCP on the app ports.

## Settings

**Change your username:**
```
@setname john
```

**Change where approved files and folders are saved:**
```
@setpath ~/Downloads/bonjou
```

## Tips

- Same subnet: users appear automatically in `@users`
- Different subnet: not supported
- Use quotes for paths with spaces: `@file alex "~/My Documents/file.pdf"`
- Use `~` for home directory
- Run `bonjou --version` to check the version
