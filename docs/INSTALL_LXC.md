# Connecting from an LXC Container

This guide covers running the Tezos baker inside an LXC container while the
Russignol device is attached to the LXC host. The USB CDC-ECM link and the
`russignol` network interface must live on the host; only the baker runs in
the container, and reaches the signer over a NAT'd TCP port on the host
bridge.

Tested on a Debian host using the default `lxcbr0` bridge (`10.0.3.0/24`).
Substitute your bridge name and subnet where they differ.

## Prerequisites

### Required software

On the host:

```sh
sudo apt install lxc iproute2 iptables iptables-persistent
```

- `lxc` — runs the container and provides `lxc-attach`.
- `iproute2` — provides `ip` (almost always already installed).
- `iptables` — the DNAT/MASQUERADE rules in Step 3.
- `iptables-persistent` — only needed for Step 5 (rules surviving reboot);
  omit if you will reinstall rules manually each boot.

Inside the container, the baker brings its own dependencies. Install
`octez-client` there as well if you want to run the protocol-level checks
in Step 4 or import the remote key from inside the container.

### Device state

The normal Russignol setup has already been completed on the host:

- USB cable plugged in, signer powered.
- [`host-utility`](INSTALL_HOST_UTILITY.md) has been run once, so the udev
  rule renames the gadget interface to `russignol` and `169.254.1.2/30` is
  configured on it.
- **PIN entered on the device's e-paper display.** The signer does not bind
  port 7732 until the PIN unlocks the secret keys. Until then the device is
  reachable at the IP layer but TCP connections to 7732 are refused. This is
  the most common cause of `Connection refused` and must be done every time
  the device boots.

### Verification

Verify from the host before touching the container.

First, the `russignol` interface is up with the expected address:

```sh
ip -c -br addr show russignol
```

Should show `169.254.1.2/30` and state `UP`.

Then, port 7732 on the signer is reachable:

```sh
timeout 1 bash -c '</dev/tcp/169.254.1.1/7732' && echo open || echo closed
```

`open` means the path works. `closed` means the IP is reachable but nothing
is listening — usually because the PIN has not been entered yet. Complete
PIN entry on the e-paper screen and re-test.

For an end-to-end protocol-level check, use `octez-client` against the
known signer URL:

```sh
octez-client list known remote keys tcp://169.254.1.1:7732 2>/dev/null
```

`2>/dev/null` drops a harmless protocol-version warning unrelated to the
signer.

## Step 1: Find the bridge address

```sh
ip -br addr show lxcbr0
```

You should see something like `10.0.3.1/24`. That `10.0.3.1` is the address
the container will dial as its signer endpoint.

## Step 2: Enable IP forwarding on the host

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```

Persist it:

```sh
echo 'net.ipv4.ip_forward=1' \
  | sudo tee /etc/sysctl.d/60-russignol-forward.conf >/dev/null
```

## Step 3: Install the NAT rules on the host

Two rules. The first rewrites the destination of container traffic so it
lands on the signer; the second rewrites the source so the reply finds its
way back through the host.

```sh
sudo iptables -t nat -A PREROUTING  -i lxcbr0    -p tcp --dport 7732 \
  -j DNAT --to-destination 169.254.1.1:7732
sudo iptables -t nat -A POSTROUTING -o russignol -j MASQUERADE
```

If your host runs INPUT/FORWARD default-drop, also allow the forwarded flow:

```sh
sudo iptables -A FORWARD -i lxcbr0 -o russignol -p tcp --dport 7732 -j ACCEPT
sudo iptables -A FORWARD -i russignol -o lxcbr0 -m conntrack \
  --ctstate ESTABLISHED,RELATED -j ACCEPT
```

## Step 4: Smoke-test from inside the container

```sh
sudo lxc-attach -n <container-name> -- \
  bash -c "timeout 1 bash -c '</dev/tcp/10.0.3.1/7732' && echo open || echo closed"
```

`open` means the data path works end to end. `closed` with the host-side
check passing points to the NAT rules (Step 3) or missing FORWARD accepts —
`sudo iptables -t nat -L PREROUTING -n -v` shows whether packets match the
DNAT rule. If the host-side check also fails, the device has likely
rebooted and needs its PIN re-entered. If `octez-client` is installed in
the container, the protocol-level check is:

```sh
sudo lxc-attach -n <container-name> -- \
  sh -c 'octez-client list known remote keys tcp://10.0.3.1:7732 2>/dev/null'
```

## Step 5: Persist across reboot

```sh
sudo netfilter-persistent save
```

(`iptables-persistent` was installed in Prerequisites; this writes the
current rules to `/etc/iptables/rules.v4` so they reload at boot.)

The rules reference `russignol` by name. When the USB cable is unplugged the
rules stay loaded but inert; when the cable is plugged back in the same
interface name reappears (via the udev rule) and the rules light up again.
No udev hook is needed.

## Step 6: Point the baker at it

In the baker's signer configuration inside the container, use the host
bridge address in place of the signer's link-local address:

```
tcp://10.0.3.1:7732/<tz4-public-key-hash>
```

For example, importing the remote key inside the container:

```sh
octez-client import secret key russignol-consensus \
  tcp://10.0.3.1:7732/<CONSENSUS_TZ4_ADDRESS>
```

## Sanity check after a reboot

After rebooting the host or unplugging/replugging the signer, enter the PIN
on the device's e-paper display, then re-run:

```sh
ip -c -br addr show russignol
timeout 1 bash -c '</dev/tcp/169.254.1.1/7732' && echo open || echo closed
sudo lxc-attach -n <container-name> -- \
  bash -c "timeout 1 bash -c '</dev/tcp/10.0.3.1/7732' && echo open || echo closed"
```

If the host-side check works but the container-side does not, the regression
is in the NAT rules. `sudo iptables -t nat -L PREROUTING -n -v` shows
whether packets are matching the DNAT rule — the counter increments per
connection.

## Caveats

- **Anyone else on `lxcbr0` can reach the signer too.** DNAT on `-i lxcbr0`
  does not distinguish containers. If you run other containers on the same
  bridge, scope the rule by source: add `-s <container-ip>` to the
  PREROUTING rule. The container IP may be DHCP-assigned by `lxc-net`; pin
  a static address on the container if you rely on this filter.
- **The signer sees the host's IP, not the container's**, because of
  MASQUERADE. Fine for the current signer, which has no per-client auth.
