# Bonjou Commands

All commands start with `@`. Type them in the Bonjou terminal.

If you run `@send`, `@file`, `@folder`, `@setname`, or `@setpath` with missing values, Bonjou now opens guided prompts.

## Basic Commands

| Command | What it does |
|---------|-------------|
| `@help` | Show this help |
| `@whoami` | Show your username and IP |
| `@users` | List people on the network |
| `@status` | Show app info and paths |
| `@wizard` | Guided send flow (peer + message/file/folder) |
| `@history` | Show past messages |
| `@clear` | Clear the screen |
| `@exit` | Quit Bonjou |

## Sending Messages

**To one person:**
```
@send alex Hey, how are you?
```

**Guided fallback (if you omit target/message):**
```
@send
```

**To multiple people:**
```
@multi alex,bob Meeting at 3pm
```

**To everyone:**
```
@broadcast Lunch break!
```

You can use their username or IP address.

**Guided interactive mode:**
```
@wizard
```

To exit wizard mode at any step, press `Ctrl+C`. You return to the normal command prompt and nothing is sent unless you confirm.

## Sending Files

**Send a file:**
```
@file alex ~/Documents/report.pdf
```

**Guided fallback:**
```
@file
```

**Send a folder:**
```
@folder alex ./my-project
```

**Guided fallback:**
```
@folder
```

**Send to multiple people:**
```
@multi alex,bob ~/photo.jpg
```

Files are received in:
- `~/.bonjou/received/files/`
- `~/.bonjou/received/folders/`

## Transfer Status

Bonjou uses clear end-state transfer messages:

- Upload progress line while bytes are being sent
	- Example: `✓ Sent 🗂️ Folder → abd@192.168.1.3:46321 ... 100%`
- Final success confirmation
	- Example: `Delivered: Folder 'Books' to abd`
- Final failure confirmation
	- Example: `Failed to send Folder 'Books' to abd: receiver did not confirm the transfer in time ...`

Treat `Delivered: ...` as the definitive success signal.

## Discovery Limits

Bonjou announces itself automatically. On the same subnet, users appear quickly via UDP broadcast.

Bonjou discovery is same-subnet only (UDP broadcast generally does not cross routers/VLANs). If someone is not showing up, ensure both devices are on the same Wi‑Fi/LAN segment and that firewall rules allow UDP/TCP on the app ports.

## Settings

**Change your username:**
```
@setname john
```

or run `@setname` to open a guided input.

**Change where files are saved:**
```
@setpath ~/Downloads/bonjou
```

or run `@setpath` to choose the directory interactively.

## Tips

- Same lab: users appear automatically in `@users`
- Different lab/subnet: not supported (move both devices to the same subnet)
- Use quotes for paths with spaces: `@file alex "~/My Documents/file.pdf"`
- Use `~` for home directory
- Run `bonjou --version` to check version
- Use `@wizard` for a guided send flow if you prefer prompts over typing full commands
