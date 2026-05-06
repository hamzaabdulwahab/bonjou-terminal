# Backlog

## Future discovery improvement: broader subnet support

Bonjou currently relies on UDP broadcast discovery and same-subnet checks using the local interface netmask when available, with a conservative fallback when the interface/netmask cannot be determined.

### Planned work

Investigate and implement a more robust discovery/subnet strategy so Bonjou behaves correctly on networks that are not simple `/24` layouts, including cases such as:

- `/16` networks where the third and fourth octets may differ
- `/8` networks where only the first octet matches
- multi-interface hosts
- environments with VPN, Docker, WSL, or virtual adapters
- networks where broadcast routing or interface selection is ambiguous

### Goals

- Keep discovery behavior correct across macOS, Windows, and major Linux environments
- Prefer the actual interface netmask over octet-based assumptions
- Improve fallback behavior when interface detection is incomplete
- Avoid silently accepting peers from the wrong network
- Preserve the current security rule of trusting the UDP source IP over the payload IP
- Keep user-facing behavior and error messages clear when discovery is uncertain

### Notes

This is future work only. It is not implemented yet and should not be documented as a shipped capability until the behavior is verified across supported operating systems and common LAN setups.