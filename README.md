## block-copyfail

> **WARNING: This is experimental, unofficial software. It is not
> endorsed by or affiliated with Red Hat. It has not been thoroughly
> tested and may not function correctly. Running BPF LSM programs
> that intercept kernel operations carries inherent risk, including
> the possibility of blocking legitimate workloads, causing
> application failures, or degrading system stability. Use at your
> own risk and test in a non-production environment first. The
> authors accept no liability for any damage caused by this
> software.**

**Zero-reboot** mitigation for **Copy Fail** and **Dirty Frag** kernel
privilege escalation vulnerabilities.

Based on [openshift/block-copyfail](https://github.com/openshift/block-copyfail),
which in turn was based on [atgreen/block-copyfail](https://github.com/atgreen/block-copyfail).
This repo repackages it as RPMs with a systemd service for standalone
RHEL systems.

### What it blocks

| Vulnerability | Hook | What's blocked | Packages |
|---|---|---|---|
| **Copy Fail 1** (CVE-2026-31431) | `socket_bind` | AF_ALG AEAD socket binds | All (EL8, EL9, EL10) |
| **Copy Fail 2** / Dirty Frag ESP | `socket_sendmsg` | `MSG_SPLICE_PAGES` on UDP sockets | All (EL8, EL9, EL10) |
| **Dirty Frag** (rxkad path) | `socket_create` | AF_RXRPC socket creation | All (EL8, EL9, EL10) |

### What's unaffected

- Other AF_ALG usage (hash, skcipher, rng)
- Normal UDP sends via `sendmsg`/`sendto`/`write` (only splice-based
  zero-copy UDP sends are blocked by Copy Fail 2)
- All TCP traffic, including splice-to-TCP
- Normal IPsec / xfrm traffic

### Known side effects

The Copy Fail 2 mitigation blocks `splice()` into UDP sockets. This is
an extremely niche operation (added in upstream 6.5, backported to
RHEL 9), but could affect:

- QUIC implementations using kernel splice for zero-copy UDP sends
- Custom high-performance UDP pipelines using splice

If you run such workloads, test before deploying.

## If you can reboot

The simplest fix for Copy Fail 1 is to blacklist the module:

```bash
echo "blacklist algif_aead" | sudo tee /etc/modprobe.d/block-copyfail.conf
sudo reboot
```

This package is for systems that **cannot be rebooted** — production
servers, long-running workloads, etc.

## Install

RPM packages are available for RHEL 8, 9, and 10 (and compatible
distros like CentOS Stream, AlmaLinux, Rocky Linux). BPF LSM must be
enabled in the kernel (RHEL 8.5+, 9, and 10 have it by default). Note
that BPF LSM on RHEL 8 is classified as Technology Preview by Red Hat.

```bash
sudo dnf config-manager --add-repo \
  https://atgreen.github.io/rhel-block-copyfail/rpm-repo/block-copyfail.repo
sudo dnf install block-copyfail
```

The service enables and starts automatically on install. On upgrade, it
restarts automatically to pick up new protections.

## Verify

```bash
systemctl status block-copyfail
journalctl -u block-copyfail -f
```

You should see a startup message listing the active protections, e.g.:

```
block-copyfail: blocker active — AF_ALG AEAD + UDP splice + AF_RXRPC blocked
```

Blocked attempts are logged with the hook name, PID, and command:

```
block-copyfail: BLOCKED [AF_ALG-AEAD] pid=12345    comm=exploit         time=2026-05-07 12:00:00
block-copyfail: BLOCKED [AF_RXRPC]    pid=12346    comm=dirty_frag      time=2026-05-07 12:00:01
```

## How it works

**Copy Fail 1** (CVE-2026-31431) chains AF_ALG sockets with `authencesn`
AEAD and `splice()` to corrupt arbitrary files in the kernel page cache.
The BPF LSM program hooks `socket_bind` and returns `-EPERM` for any
AF_ALG AEAD bind, preventing exploitation regardless of crypto template
nesting (e.g. `pcrypt(authencesn(...))`).

**Copy Fail 2** uses xfrm ESP-in-UDP with `MSG_SPLICE_PAGES` to achieve
the same page-cache write via a different subsystem. The exploit splices
a target file's page-cache pages into a plain UDP socket (zero-copy, no
data copied); an ESP-in-UDP receiver on loopback then decrypts in-place,
corrupting the shared pages. Because the sending socket is plain UDP
(only the receiver has ESP encap), we block `MSG_SPLICE_PAGES` on all
UDP sockets. Red Hat backported `MSG_SPLICE_PAGES` to the RHEL 9 kernel,
so this protection is enabled on all platforms. On kernels without the
feature (e.g. unpatched EL8), the hook is a harmless no-op.

**Dirty Frag** chains the ESP path with an AF_RXRPC fallback. The rxkad
authentication layer uses `pcbc(fcrypt)` to brute-force keys and modify
page-cache contents in-place via AF_RXRPC sockets. We block AF_RXRPC
socket creation entirely. AFS/rxrpc is unused on nearly all production
RHEL systems (it is not even shipped in the RHEL 8 kernel).

## Removal

```bash
sudo systemctl disable --now block-copyfail
sudo dnf remove block-copyfail
```

The BPF programs detach automatically when the service stops. No reboot
needed.

## Building from source

```bash
sudo dnf install clang llvm bpftool libbpf-devel elfutils-libelf-devel \
  zlib-devel gcc make pkgconfig

make
sudo install -m 0755 block-copyfail /usr/sbin/
sudo install -m 0644 block-copyfail.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now block-copyfail
```

## License

Apache-2.0 (userspace), GPL-2.0-only (BPF programs)
