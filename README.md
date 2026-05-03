# dockpoint

Cross-platform primitives for the **auto-spawning client-daemon** pattern.

Like `tmux`, `ssh-agent`, `gpg-agent`, and `docker` — a frontend CLI either
connects to an existing background daemon or spawns one on demand.
`dockpoint` provides the low-level mechanism: a canonical, well-known
communication point that only one process can claim, with clients finding
and connecting to it.

- **POSIX**: Unix-domain socket with a sidecar lock file for coordination
- **Windows**: named pipe scoped to the current user's SID

## Concepts

A **`Dockpoint`** is a claimed endpoint — the well-known rendezvous point
that only one process can hold. It accepts incoming client connections and
releases the OS resource when closed. Supports the context manager protocol.

The daemon calls `dockpoint.claim()` to claim a `Dockpoint`, then calls
`.accept()` on it to receive connections.

A **`DockpointConnection`** is a connected byte stream between the daemon
and one client. Clients obtain one by calling `dockpoint.connect()`.

## API

### `dockpoint.claim(app_name, instance="default")` → `Dockpoint | None`

Claim the canonical endpoint and return a `Dockpoint` object. Returns
`None` if another process already owns it.

### `Dockpoint.accept()` → `DockpointConnection`

Accept the next incoming client connection.

### `Dockpoint.close()`

Release the endpoint.

### `dockpoint.connect(app_name, instance="default")` → `DockpointConnection | None`

Connect to an existing endpoint. Returns `None` if no daemon is listening.

### `DockpointConnection.read(max_bytes=65536)` → `bytes`

Read up to `max_bytes` from the stream.

### `DockpointConnection.write(data)` → `int`

Write `data` to the stream. Returns the number of bytes written.

### `DockpointConnection.close()`

Close the connection.

## The pattern

`dockpoint` implements the rendezvous and mutual-exclusion layer for:

```
A: Shared protocol / definitions
B: Daemon   ── calls dockpoint.claim(), serves connections
C: Frontend ── calls dockpoint.connect(), auto-spawns B if needed
```

The auto-spawn logic (detect → spawn → retry-connect) lives above
`dockpoint`, but the critical race-free primitives — atomic endpoint
claim and well-known rendezvous — are what `dockpoint` provides.

## Usage sketch

```python
import dockpoint

# B (daemon) side
dp = dockpoint.claim("my-app")
if dp is None:
    print("Another daemon is already running.")
    exit(1)

with dp:
    while True:
        conn = dp.accept()
        data = conn.read()
        conn.write(b"ack")
        conn.close()
```

```python
import dockpoint

# C (client) side
conn = dockpoint.connect("my-app")
if conn is None:
    # No daemon — spawn one and retry
    ...

conn.write(b"hello\n")
reply = conn.read()
conn.close()
```

## Why the name

A dock is a fixed, well-known place. A dockpoint is the specific spot on
that dock where you tie up. One process *claims the dockpoint* and holds
it. Others *arrive at the dockpoint* to communicate.

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## License

This project is licensed under the [MIT License](LICENSE).
