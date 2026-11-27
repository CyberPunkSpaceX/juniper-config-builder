# Sample clients

The app ships with three training labs as **sample clients** (`src/switchbuilder/samples/`). Each has its
projects and a network map in Lab and in Production. They're added once on first start (or after an
upgrade), everyone signed in can open them Read-only, and a Super Admin can delete them. A deleted sample
stays deleted; the Clients page has **Add back**. `EXB_SAMPLES=off` stops them being added on start.

Every switch root and user password in the samples is `Sample-Lab-Root1`.

| Sample | What it is |
|---|---|
| Training Lab - EVPN/VXLAN ERB | 2 spines, 4 gateway leaves (anycast IRB), eBGP underlay + overlay, 4 access switches on ESI-LAGs |
| Training Lab - EVPN/VXLAN CRB | Spines are the gateways, OSPF underlay + iBGP overlay (spine route reflectors), 4 access switches on ESI-LAGs |
| Training Lab - Common Mistakes | A small campus (core, 3 access, edge) with mistakes planted on purpose. Answer key below |

To add a sample: drop a JSON file in `src/switchbuilder/samples/` with `key`, `name` (starting with
"Training Lab"), `description`, `projects` and `maps` (each item `{space, name, data}`). Replace every
password hash with the sample password first, because this repository is public.

## Common Mistakes: answer key

Spoilers. Try finding them first: the Compare, Compliance and network map tools catch a lot of them.

<details><summary>Show the answer key</summary>

**cm-core-01**
- M01 VLAN 60 PRINTERS is defined but tagged on no port.
- M02 Static route 10.99.0.0/16 points at 10.250.9.1, which is on no interface.
- M03 GUEST irb 10.10.20.129/25 overlaps USERS 10.10.20.0/24.
- M04 SNMP community `public` with no client restriction.
- M05 NTP is a hostname (pool.ntp.org) but no DNS servers are set.
- M06 Web management is on.

**cm-acc-01**
- M07 The DESKS voice VLAN is set, but QoS for voice is off.
- M08 LLDP-MED is off, so phones never learn the voice VLAN.
- M09 The MYSTERY ports have no access VLAN.
- M10 Voice VLAN on a trunk port (APS).
- M11 ge-0/0/52 doesn't exist on an EX2300-48P.
- M12 DESKS covers ge-0/0/0-31 (check it against the port plan).
- M13 Disabling unused ports is off.
- M24 Bridge priority 4k, the same as the core, so the root bridge is up for grabs.

**cm-acc-02**
- M15 Management 10.10.99.12/24 with gateway 10.10.10.1, outside its subnet.
- M16 No syslog host.
- M17 The SNMPv3 user has authentication but no privacy.
- M19 VLAN 30 is called PHONES (VOICE everywhere else).
- M20 CCTV is VLAN 55 (the core uses 50).
- M21 The uplink trunk carries only USERS and PHONES (no CCTV).
- M22 No native MGMT VLAN on the uplink.
- M23 MTU 9216 only on the core side of the uplink.

**cm-acc-01 / cm-acc-02**
- M18 The cross-link is access/USERS on one end and trunk "all" on the other.

**cm-acc-03 (and core ae3)**
- M25 LACP passive on both ends.
- M26 WIFI is VLAN 41 (40 everywhere else).
- M27 Management IP 10.10.99.12 duplicates cm-acc-02.
- M28 ae0 has 1 member, core ae3 has 2.
- M29 Cameras are on CCTV, but CCTV isn't on the uplink trunk.
- M30 Root guard on edge access ports.
- M31 Static (no-LACP) LAG to the ESXi host.
- M32 BPDU block on edge ports is off.
- M33 Storm control is off.

**cm-edge-01**
- M34 TO-CORE 10.255.0.6/30 and the core's 10.255.0.1/30 are in different subnets.
- M35 No super-user account, only root.
- M36 No login banner.
- M37 The loopback is /24 (should be /32).
- Drift: the live config in the network map differs from the project (telnet, http web management,
  SSH root login allowed, community `public` read-write, ge-0/0/0 disabled). Compare finds these.

</details>
