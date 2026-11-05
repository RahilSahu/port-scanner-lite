# Port Scanner Lite

A small, careful TCP connect scanner written in Python, for checking
your own systems during lab work and authorised security assessments.

It answers two questions quickly: which of the common ports are open on
this host, and what does the service on each open port say it is.

For anything larger, use Nmap. This tool exists to be readable: the
whole scanner is one short file, and it is a good way to learn how
connect scanning and banner grabbing actually work.

## Features

- Built-in top ports list (25 common services), or your own list/range
- Concurrent connections with a bounded worker pool (max 200)
- Banner grabbing with short timeouts
- Notes on risky exposures (Telnet, open Redis or MongoDB, SMB, RDP, VNC)
- JSON output for scripting
- Zero dependencies

## Usage

```bash
python3 port_scan.py 192.168.1.10
python3 port_scan.py scanme.example.com --ports 22,80,443,8000-8100
python3 port_scan.py 192.168.1.10 --json --no-banner
```

Example output:

```text
OPEN     22/tcp  ssh  banner: SSH-2.0-OpenSSH_9.6
OPEN    443/tcp  https
OPEN   6379/tcp  redis
      Note: Redis is often deployed without authentication. Never expose it to untrusted networks.
```

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

The tests spin up a local test server on 127.0.0.1, so they run fully
offline:

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only scan hosts you own or are explicitly authorised to test.
Unauthorised scanning can break the law and will get your network
blocked. This tool is intentionally modest in speed and scope.

## License

MIT, see LICENSE.
