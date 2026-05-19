package commands

import "strings"

// helpText composes the @help output. Kept in a dedicated file to keep
// the user-facing command catalog easy to find when adding new commands.
func helpText() string {
	const (
		reset   = "\033[0m"
		heading = "\033[36m"
		accent  = "\033[96m"
		dim     = "\033[90m"
	)

	var b strings.Builder
	b.WriteString(reset)
	b.WriteString(heading + "Bonjou Command Guide" + reset + "\n")
	b.WriteString(dim + "Prefix every command with @. Quote paths that contain spaces." + reset + "\n\n")

	b.WriteString(heading + "Messaging" + reset + "\n")
	b.WriteString("  " + accent + "@send <user/ip> <message>" + reset + "\n")
	b.WriteString("    Direct message a peer by username, hostname, or IP." + "\n")
	b.WriteString("  " + accent + "@multi <user1,user2,...> <message|path>" + reset + "\n")
	b.WriteString("    Target a list of peers; send chat text, a file, or a folder." + "\n")
	b.WriteString("    Automatically uses parallel for speed; falls back to sequential if transfers fail." + "\n")
	b.WriteString("  " + accent + "@broadcast <message>" + reset + "\n")
	b.WriteString("    Send the same message to every currently discovered peer." + "\n\n")
	b.WriteString("  " + accent + "@wizard" + reset + "\n")
	b.WriteString("    Interactive sender for message, file, folder, multi-send, and broadcast." + "\n\n")

	b.WriteString(heading + "File Transfer" + reset + "\n")
	b.WriteString("  " + accent + "@file <user/ip> <path>" + reset + "\n")
	b.WriteString("    Share a single file. ~ expansion and quoted paths supported." + "\n")
	b.WriteString("  " + accent + "@folder <user/ip> <dir>" + reset + "\n")
	b.WriteString("    Send an entire directory to one peer." + "\n")
	b.WriteString("  " + accent + "@history" + reset + "\n")
	b.WriteString("    Review recent sends, receives, and system notices." + "\n\n")

	b.WriteString(heading + "Discovery & Status" + reset + "\n")
	b.WriteString("  " + accent + "@users" + reset + "\n")
	b.WriteString("    List discovered peers with last-seen timestamps." + "\n")
	b.WriteString("  " + accent + "@whoami" + reset + "\n")
	b.WriteString("    Show your username, LAN IP, and listening port." + "\n")
	b.WriteString("  " + accent + "@setname <username>" + reset + "\n")
	b.WriteString("    Update the username you broadcast to the LAN." + "\n")
	b.WriteString("  " + accent + "@status" + reset + "\n")
	b.WriteString("    Summarize discovery health and receive directories." + "\n\n")

	b.WriteString(heading + "Trust & Verification" + reset + "\n")
	b.WriteString("  " + accent + "@fingerprint [user/ip]" + reset + "\n")
	b.WriteString("    Show your own (or a peer's) public-key fingerprint for out-of-band verification." + "\n")
	b.WriteString("  " + accent + "@known" + reset + "\n")
	b.WriteString("    List every pinned peer the local store accepts." + "\n")
	b.WriteString("  " + accent + "@trust <user/ip>" + reset + "\n")
	b.WriteString("    Pin the peer's current key after verifying their fingerprint side-channel." + "\n")
	b.WriteString("  " + accent + "@forget <username>" + reset + "\n")
	b.WriteString("    Drop a pinned binding so the next announcement is treated as first-seen." + "\n\n")

	b.WriteString(heading + "Workspace & Maintenance" + reset + "\n")
	b.WriteString("  " + accent + "@setpath <dir>" + reset + "\n")
	b.WriteString("    Change where incoming files and folders are stored." + "\n")
	b.WriteString("  " + accent + "@queue" + reset + "\n")
	b.WriteString("    List every pending approval in one place." + "\n")
	b.WriteString("  " + accent + "@view <id>" + reset + "\n")
	b.WriteString("    Inspect one pending queue item." + "\n")
	b.WriteString("  " + accent + "@approve <id>" + reset + "\n")
	b.WriteString("    Approve one pending queue item." + "\n")
	b.WriteString("  " + accent + "@reject <id>" + reset + "\n")
	b.WriteString("    Reject one pending queue item." + "\n")
	b.WriteString("  " + accent + "@approveAll" + reset + "\n")
	b.WriteString("    Approve all pending queue items." + "\n")
	b.WriteString("  " + accent + "@rejectAll" + reset + "\n")
	b.WriteString("    Reject all pending queue items." + "\n")
	b.WriteString("  " + accent + "@clear [history]" + reset + "\n")
	b.WriteString("    Clear the screen, or include history to remove saved chat and transfer logs." + "\n")
	b.WriteString("  " + accent + "@help" + reset + "\n")
	b.WriteString("    View this guide again." + "\n")
	b.WriteString("  " + accent + "@exit" + reset + "\n")
	b.WriteString("    Quit Bonjou. If approvals are pending, Bonjou will warn you first." + "\n")
	b.WriteString("  " + accent + "@exit!" + reset + "\n")
	b.WriteString("    Force quit even if approvals are still pending." + "\n")

	return strings.TrimRight(b.String(), "\n")
}
