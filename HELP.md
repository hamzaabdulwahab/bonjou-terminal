# Bonjou Commands

All commands start with `@`. Type them in the Bonjou terminal.

## Basic Commands

| Command | What it does |
|---------|-------------|
| `@help` | Show this help |
| `@whoami` | Show your username and IP |
| `@users` | List people on the network |
| `@status` | Show app info and paths |
| `@history` | Show past messages |
| `@clear` | Clear the screen |
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

**To everyone:**
```
@broadcast Lunch break!
```

You can use their username or IP address.

## Sending Files

**Send a file:**
```
@file alex ~/Documents/report.pdf
```

**Send a folder:**
```
@folder alex ./my-project
```

**Send to multiple people:**
```
@multi alex,bob ~/photo.jpg
```

Files are received in:
- `~/.bonjou/received/files/`
- `~/.bonjou/received/folders/`

## Finding Users in Other Labs

Bonjou automatically scans all subnets when it starts. It detects your network (10.x.x.x or 192.168.x.x) and scans accordingly. Users in other labs should appear in `@users` within 2-3 minutes.

**If someone is not showing up:**

```
@scan
```

This scans ALL subnets (1-255) in your network and takes about 2 minutes.

**If you know their IP:**

```
@connect 10.23.81.71
```

This is faster - sends your info directly to them.

## Settings

**Change your username:**
```
@setname john
```

**Change where files are saved:**
```
@setpath ~/Downloads/bonjou
```

## Tips

- Same lab: users appear automatically in `@users`
- Different lab: wait 2-3 minutes for auto-scan, or use `@scan`
- Know their IP? Use `@connect <ip>` for faster connection
- Use quotes for paths with spaces: `@file alex "~/My Documents/file.pdf"`
- Use `~` for home directory
- Run `bonjou --version` to check version
