# Bonjou Demo

This shows how to use Bonjou between two computers. You can also test on one computer using two terminal windows.

## Setup

1. Install Bonjou on both computers
2. Make sure both are on the same WiFi/network
3. Open firewall ports 46320 (UDP) and 46321 (TCP)

## Example Session

### Computer 1 (Hamza)

Start Bonjou:
```bash
bonjou
```

Check your info:
```
@whoami
```
Output:
```
Username: hamza
IP: 192.168.1.10
Listen port: 46321
```

### Computer 2 (Hassan)

Start Bonjou:
```bash
bonjou
```

See who is on the network:
```
@users
```
Output:
```
hamza (192.168.1.10) • seen just now
```

Send a message:
```
@send hamza Hey Hamza!
```

Hamza will see the message appear.

## Send a File

On Hassan's computer:
```
@file hamza ~/Documents/notes.pdf
```

Hamza will see a pending-transfer notice like:
```
Pending file [1] from hassan: notes.pdf (12.3 KB)
Run @queue, @view 1, @approve 1, or @reject 1
```

Then Hamza can review and approve it:
```
@queue
@approve 1
```

After approval, the file is saved in:
```
~/.bonjou/received/files/notes.pdf
```

## Send a Folder

On Hamza's computer:
```
@folder hassan ./project-files
```

Bonjou zips the folder, sends it, and extracts it into a pending area on the other side.

Hassan will see a pending-transfer notice like:
```
Pending folder [1] from hamza: project-files (248.0 KB)
Run @queue, @view 1, @approve 1, or @reject 1
```

Then Hassan can inspect and approve it:
```
@queue
@view 1
@approve 1
```

After approval, the folder is saved in:
```
~/.bonjou/received/folders/project-files/
```

## Message Everyone

```
@broadcast Break time in 5 minutes!
```

Each discovered user receives this message.

## Check History

```
@history
```

Shows saved chat history and approved transfers.

## Exit

```
@exit
```

Closes Bonjou.
