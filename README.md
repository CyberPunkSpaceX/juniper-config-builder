# EX Config Builder

A web GUI (and a small CLI) that builds configuration for **Juniper EX switches**
running Junos with ELS (EX2300, EX3400, EX4100, EX4300, EX4400). Fill in forms, and the
config appears live as `set` commands and as the hierarchical (curly brace)
format, ready to copy or download.

## What it covers

| Area | What you can set |
|---|---|
| Hardware | Model (EX2300 / EX3400 / EX4100 / EX4100-F / EX4300 / EX4400, incl. PoE and multigig), Virtual Chassis members, pre-provisioning with serial numbers, a clickable port map |
| System | Host name, domain, time zone, DNS servers and search domains, NTP (preferred server, source address), login banner, management port (me0/em0) with optional management VRF, auto-snapshot |
| Users | Root password and SSH key, local users with class, password and SSH keys. Passwords are turned into SHA-512 (`$6$`) hashes; plain text never reaches the output or a saved project |
| Remote access | SSH root login, connection and rate limits, NETCONF, J-Web, login retry limits |
| SNMP | Location, contact, v2c communities with allowed clients, v3 users (SHA/SHA-2 + AES/DES), v2c trap receivers |
| Logging | Local level, CLI command log, remote syslog servers with facility, level and port |
| VLANs | Name, ID, description, IRB (layer 3) addresses incl. IPv6, DHCP relay, DHCP snooping, ARP inspection, IP source guard |
| Ports | Port groups with ranges (`ge-0/0/0-23`): access (+ voice VLAN), trunk (+ native VLAN), routed (layer 3), disabled; PoE priority/off, speed, MTU, RSTP edge, MAC limit, DHCP-trusted |
| LAGs | ae interfaces with LACP active/passive/static, fast timers, minimum links; trunk, access or routed |
| Routing | Loopback, router ID, AS number, ECMP, IPv4 and IPv6 static routes (next hop, discard, reject, preference), DHCP relay servers |
| OSPF | Areas (normal, stub, NSSA), interfaces, passive and point-to-point interfaces, MD5 keys, reference bandwidth, export policies |
| BGP | Groups (eBGP / iBGP), neighbors with their own AS and description, local address, import/export policies, BFD, multipath, MD5 |
| Policies | Prefix lists, communities, policy statements with terms: from protocol / prefix list / route filter / community, then local preference, MED, community add, next-hop self, accept / reject / next term |
| EVPN-VXLAN | Leaf, collapsed-core or spine (route reflector) role, iBGP or eBGP overlay, VNI per VLAN, anycast gateway (virtual-gateway-address), tenant VRFs with EVPN type-5 routes, ESI-LAG multihoming. EX4100, EX4400 and EX4300-48MP |
| Services | LLDP, LLDP-MED, RSTP with bridge priority and BPDU guard on edge ports, storm control, IGMP snooping, PoE on all ports, disable unused ports, interface ranges |

It checks what you enter as you type: bad addresses, duplicate VLAN IDs, a port
used twice, a missing root password, VLANs that don't exist, ports the model
doesn't have, Virtual Chassis ports used as network ports, PoE on a non-PoE
model and more. Errors are things Junos would refuse; warnings are things to
double check.

Projects can be downloaded and opened as JSON files, or saved on the server
under "My projects" (each user sees only their own).

## Applying the config on a switch

1. Connect to the console or SSH, type `cli`, then `configure`.
2. Paste the **set** commands.
3. `show | compare` to see the change, `commit check` to test it.
4. `commit confirmed 5`. If you lose access, the switch rolls back by itself
   after 5 minutes. If you're still connected, type `commit` to keep it.

For the hierarchical format use `load merge terminal`, paste, then Ctrl+D. On a
factory-new switch, `load override terminal` replaces everything.

"Start with delete interfaces / delete vlans" (on by default) removes the
factory port settings first, so they can't clash with yours. Turn it off when
you only want to add to an existing config.

## Running it

See [INSTALL.md](INSTALL.md). Quick start with Docker:

```
docker compose -f deploy/docker-compose.yml up -d
```

Then open `http://<host>:8088` and sign in as `admin` / `admin`; you're asked
for a new password straight away. Users, two-factor sign-in (TOTP), API tokens
and sign-in lockout work the same as in firewall-converter.

## CLI and API

```
pip install '.[web]'
exbuilder models                                 # list switch models and ports
exbuilder build project.json                     # set commands to stdout
exbuilder build project.json -f hierarchy -o sw1.conf
```

Scripts can call the server with a user name and an API token (from "My account"):

```
curl -u alice:exb_TOKEN -H 'Content-Type: application/json' \
     --data @project.json 'https://exbuilder.example.com/api/generate?format=set'
```

`format=json` (the default) returns the set and hierarchical text, errors,
warnings and generated password hashes.

## Development

```
pip install -e '.[dev,web]'
pytest -q
exbuilder serve          # http://127.0.0.1:8080, data in $EXB_DATA_DIR
```

Layout: `src/exbuilder/models.py` (switch models and port layouts),
`generator.py` (project JSON to config, with all checks), `junos.py` (config
tree that prints set or hierarchical format), `cryptpw.py` (SHA-512 crypt),
`web/` (Flask app, login and the builder page).

Model port layouts are the common factory layouts. A 1G optic in a 10G uplink
is named `ge-` instead of `xe-`; the builder accepts both.
