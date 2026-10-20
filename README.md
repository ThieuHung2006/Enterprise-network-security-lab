# 🛡️ Enterprise Network Infrastructure & Defense-in-Depth Security Lab

![Platform](https://img.shields.io/badge/Platform-EVE--NG-blue?style=for-the-badge&logo=linux)
![Vendor](https://img.shields.io/badge/Cisco-IOS%20%2F%20IOL-1BA0D7?style=for-the-badge&logo=cisco)
![Security](https://img.shields.io/badge/Security-L2%2FL3%20Hardening%20%26%20BGP%20Security-critical?style=for-the-badge)
![Monitoring](https://img.shields.io/badge/NOC%2FSOC-Centralized%20Syslog-success?style=for-the-badge)

---

## 📌 1. Executive Summary

This project implements, validates, and evaluates an enterprise-grade, multi-tier network infrastructure (**Access – Distribution – Core – WAN Edge**) constructed in an **EVE-NG** emulation environment. 

Moving beyond standard routing configurations, this portfolio demonstrates real-world enterprise engineering: **Simulating internal threat vectors via Red Team methodologies** and **Architecting automated Blue Team containment mechanisms coupled with real-time NOC/SOC telemetry**.

### 🎯 Core Engineering Competencies Demonstrated:
* **Layer 2 Access Layer Hardening:** Mitigated Spanning-Tree topology disruption (STP Attacks), MAC Spoofing, Rogue DHCP Server attacks, and Man-in-the-Middle ARP Cache Poisoning using **PortFast, BPDU Guard, Port-Security Sticky MAC, DHCP Snooping, and Dynamic ARP Inspection (DAI)**.
* **Core Transport & Convergence:** Engineered a zero-loss internal transit fabric utilizing **OSPF Area 0**, dynamic Default Route generation, and **MPLS Label Distribution Protocol (LDP)** label forwarding.
* **WAN Edge Peering & eBGP Defense:** Hardened External BGP (eBGP) peering against upstream ISP providers using **TCP MD5 Authentication (RFC 2385)**, **Generalized TTL Security Mechanism (GTSM / RFC 5082)**, and strict **Inbound/Outbound Prefix-List Filtering**.
* **Centralized Telemetry & Operations:** Deployed an automated **Syslog NOC** collection pipeline (`rsyslog` & `tcpdump` over UDP $514$) capturing real-time hardware status changes, interface error-disable events, and routing protocol adjacency flaps.

---

## 🏗️ 2. Network Topology & IP Addressing Plan

### 2.1. Logical Architecture

```text
                       +------------------------+
                       |       ISP_PEER         |
                       |       (AS 64496)       |
                       |   Loopback0: 8.8.8.8   |
                       +-----------+------------+
                                   | e0/0: 203.0.113.2/30
                                   |
                         [ eBGP + MD5 + GTSM ]
                         [ Prefix-List Filter]
                                   |
                                   | e0/1: 203.0.113.1/30 (NAT Outside)
                       +-----------+------------+
                       |          ASBR          |
                       |    (AS 65000 / OSPF)   |
                       +-----------+------------+
                                   | e0/0: 10.0.0.1/30 (NAT Inside)
                                   |
                            [ OSPF Area 0 ]
                            [  MPLS LDP   ]
                                   |
                                   | e0/1: 10.0.0.2/30
                       +-----------+------------+        e0/2: 10.10.99.1/24      +--------------------+
                       |      CORE_ROUTER       +---------------------------------+     Syslog_NOC     |
                       |    (Router-ID 2.2.2.2) |                                 | 10.10.99.10 (UDP514|
                       +-----------+------------+                                 +--------------------+
                                   | e0/0: 10.0.1.1/30
                                   |
                            [ OSPF Area 0 ]
                                   |
                                   | e0/1: 10.0.1.2/30 (Routed Port)
                       +-----------+------------+
                       |      DIST_SWITCH       |
                       |  SVI VLAN10: .10.1/24  |
                       |   (DHCP Server Pool)   |
                       +-----------+------------+
                                   | e0/0 (802.1Q Trunk - Trusted Port)
                                   |
                       +-----------+------------+
                       |     ACCESS_SWITCH      |
                       | (Snooping / DAI / PSec)|
                       +-----+------------+-----+
            e0/1 (Untrusted) |            | e0/2 (Untrusted)
                             |            |
                +------------+---+    +---+------------+
                | Attacker (Kali)|    |  Victim (VPCS) |
                | 192.168.10.x   |    | 192.168.10.11  |
                +----------------+    +----------------+
```

### 2.2. Interface IP Matrix

| Device Name | Interface | IP Address / Mask | Role & Key Protocols |
| :--- | :--- | :--- | :--- |
| **ISP_PEER** | `Ethernet0/0`<br>`Loopback0` | `203.0.113.2/30`<br>`8.8.8.8/32` | Upstream eBGP Peer (AS $64496$), GTSM, MD5<br>Simulated Internet DNS Anchor |
| **ASBR** | `Ethernet0/1`<br>`Ethernet0/0` | `203.0.113.1/30`<br>`10.0.0.1/30` | WAN Uplink (`ip nat outside`), eBGP (AS $65000$)<br>Core Downlink (`ip nat inside`), OSPF Area $0$ |
| **CORE_ROUTER** | `Ethernet0/1`<br>`Ethernet0/0`<br>`Ethernet0/2` | `10.0.0.2/30`<br>`10.0.1.1/30`<br>`10.10.99.1/24` | ASBR Uplink, OSPF Area $0$, MPLS LDP<br>Distribution Downlink, OSPF Area $0$<br>NOC Management Subnet Gateway |
| **DIST_SWITCH** | `Ethernet0/1`<br>`Vlan10`<br>`Ethernet0/0` | `10.0.1.2/30`<br>`192.168.10.1/24`<br>`Trunk (VLAN 10)` | Routed L3 Uplink to Core, OSPF Area $0$<br>VLAN 10 Default Gateway, DHCP Server<br>802.1Q Downlink Trunk to Access Switch |
| **ACCESS_SWITCH** | `Ethernet0/0`<br>`Ethernet0/1-2`<br>`Vlan10` | `802.1Q Trunk`<br>`Access VLAN 10`<br>`192.168.10.2/24` | Trusted Uplink (`DHCP Snooping & DAI Trust`)<br>Hardened Edge (`PortFast`, `BPDU Guard`, `Port-Security`)<br>Management In-Band SVI reporting to Syslog NOC |
| **Syslog_NOC** | `ens3 / eth0` | `10.10.99.10/24` | Centralized Syslog & Security Telemetry Collector |
| **Victim (VPCS)** | `eth0` | `192.168.10.11/24` | Enterprise Client Workstation (DHCP Assigned) |
| **Attacker (Kali)** | `eth0` | `192.168.10.x/24` | Penetration Testing Node (Yersinia, dnsmasq, Scapy) |

---

## ⚔️ 3. Adversary Emulation & Access Layer Defense (Red Team vs. Blue Team)

### Scenario 3.1: Spanning Tree Protocol (STP) Attack & BPDU Guard Containment

* **Threat Vector:** An adversary connects a rogue device running Kali Linux to an edge access port and launches `yersinia` to inject forged **STP Configuration / Topology Change Notification (TCN) BPDUs**, aiming to hijack Root Bridge priority and cause switching loops or traffic sniffing.
* **Defensive Engineering:** Enabled **PortFast** alongside **BPDU Guard** (`spanning-tree bpduguard enable`) globally on edge access ports. Any inbound BPDU frame immediately triggers an operational shutdown to protect network stability.

#### 📸 Proof of Concept (PoC) Evidence:
1. **Red Team Execution:** Transmitting malformed TCN BPDUs using Yersinia on `eth0`:
   ![Yersinia STP Attack](images/01-kali-yersinia-stp-attack.png)

2. **Blue Team Mitigation:** ACCESS_SWITCH intercepts the unauthorized BPDU, triggers `%SPANTREE-2-BLOCK_BPDUGUARD`, and transitions port `Et0/1` into the `err-disable` state:
   ![BPDU Guard Err-Disable](images/02-switch-bpduguard-errdisable.png)

3. **NOC Alert Telemetry:** Syslog NOC captures the Critical priority warning (`local7.critical`) in real-time over UDP $514$:
   ![Syslog NOC BPDU Alert](images/03-syslog-noc-bpdu-alert.png)

---

### Scenario 3.2: MAC Spoofing Attack & Port-Security Sticky Enforcement

* **Threat Vector:** An attacker alters their network interface MAC address or attaches an unauthorized switch to the wall jack to evade network access policies or conduct CAM table exhaustion attacks.
* **Defensive Engineering:** Implemented **Port-Security** with a strict limit of $1$ MAC address per interface, binding the initial valid hardware address permanently via **Sticky Learning** (`switchport port-security mac-address sticky`) with a `violation shutdown` policy.

#### 📸 Proof of Concept (PoC) Evidence:
1. **Baseline State:** ACCESS_SWITCH dynamically records and anchors the legitimate workstation MAC address (`0050.0000.0700`) as `SecureSticky` on `Et0/1`:
   ![Port Security Sticky MAC](images/04-port-security-sticky-mac.png)

2. **Containment Action:** Upon encountering an illegitimate frame sourced from spoofed MAC `0011.2233.4455`, Port-Security immediately shuts down the port (`err-disabled psecure-violation`):
   ![Port Security Violation](images/05-port-security-violation-errdisable.png)

3. **NOC Alert Telemetry:** Centralized logging captures the security violation alert along with the offending hardware address:
   ![Syslog NOC Port-Security Alert](images/06-syslog-noc-portsec-alert.png)

---

### Scenario 3.3: Rogue DHCP Server Mitigation via DHCP Snooping

* **Threat Vector:** An adversary initiates a rogue `dnsmasq` DHCP service on the access subnet, racing the corporate DHCP server to assign an attacker-controlled Default Gateway and DNS IP (`192.168.10.254`), effectively intercepting outbound web sessions.
* **Defensive Engineering:** Deployed **DHCP Snooping** on VLAN $10$. Only the uplink interface (`Et0/0`) towards `DIST_SWITCH` is designated as **Trusted**. All end-user facing ports default to **Untrusted**, enforcing the drop of inbound `DHCPOFFER`, `DHCPACK`, and rate-limiting incoming requests.

#### 📸 Proof of Concept (PoC) Evidence:
1. **Unprotected State (Baseline Breach):** Kali Linux successfully leases rogue IP parameters (`192.168.10.50`) to the target victim:
   ![Rogue DHCP dnsmasq](images/07-rogue-dhcp-dnsmasq-lease.png)

2. **Protocol Analysis:** Wireshark frame inspection confirms rogue `DHCP Offer` packets originated from unauthorized server `192.168.10.254`:
   ![Rogue DHCP Offer](images/08-wireshark-rogue-dhcp-offer.png)

3. **Protected State (Mitigation Active):** ACCESS_SWITCH silences the rogue server; the client VPCS reliably completes the standard DORA sequence with the legitimate gateway (`192.168.10.1`), acquiring `192.168.10.11`:
   ![VPCS DHCP DORA](images/09-vpcs-dhcp-success.png)

4. **Binding Database Construction:** The switch creates an immutable `DHCP Snooping Binding Table` mapping `MAC - IP - Lease - Interface`:
   ![DHCP Snooping Binding](images/10-dhcp-snooping-binding-table.png)

---

### Scenario 3.4: ARP Poisoning (MITM) & Dynamic ARP Inspection (DAI)

* **Threat Vector:** After gaining network connectivity, the attacker broadcasts falsified **Gratuitous ARP (GARP) / Unsolicited ARP Replies**, deceiving the victim into associating the default gateway IP (`192.168.10.1`) with the attacker's MAC address (`00:50:00:00:07:00`), executing Man-in-the-Middle (MITM) traffic interception.
* **Defensive Engineering:** Implemented **Dynamic ARP Inspection (DAI)** on VLAN $10$ (`ip arp inspection vlan 10`) backed by cryptographic Header Validation (`validate src-mac dst-mac ip`). The switch intercepts all ARP traffic on untrusted ports, verifying packets against the trusted DHCP Snooping database.

#### 📸 Proof of Concept (PoC) Evidence:
1. **Attacker Verification:** Confirming the physical MAC identifier of the attacking node (`00:50:00:00:07:00`):
   ![Kali MAC Address](images/11-kali-mac-attacker-check.png)

2. **Unprotected State (ARP Cache Poisoned):** The victim's ARP cache reflects corrupted state, incorrectly pointing gateway IP `192.168.10.1` to the attacker's MAC:
   ![ARP Poisoned VPCS](images/12-vpcs-arp-table-poisoned.png)

3. **Packet Analysis:** Packet capture reveals fraudulent `ARP Reply (Opcode 2)` packets injected into the broadcast domain:
   ![Fake ARP Reply](images/13-wireshark-fake-arp-reply.png)

4. **MITM Interception Active:** Victim traffic to the NOC subnet (`10.10.99.10`) is captured and redirected across the attacker machine, triggering ICMP redirects:
   ![MITM Traffic Capture](images/14-wireshark-mitm-traffic-intercept.png)

5. **Blue Team Mitigation:** ACCESS_SWITCH activates DAI validation, rejecting and dropping 155 spoofed ARP frames with `%SW_DAI-4-DHCP_SNOOPING_DENY`:
   ![DAI Block ARP](images/15-switch-dai-drop-invalid-arp.png)

6. **Network Restoration:** The victim's ARP cache heals, resolving gateway `192.168.10.1` to the authentic Layer 3 interface MAC of `DIST_SWITCH` (`aa:bb:cc:80:40:00`):
   ![ARP Table Restored](images/16-vpcs-arp-table-recovered.png)

---

## 🌐 4. WAN Edge & Core Infrastructure Hardening

### 4.1. Edge BGP Peering Security (ASBR $\leftrightarrow$ ISP_PEER)
To shield the enterprise border gateway from route hijacking, unauthorized BGP session establishment, and off-path TCP attacks, three defensive mechanisms were instituted:
1. **RFC 2385 TCP MD5 Signature:** Applied cryptographic message integrity verification across TCP port $179$ (`password CiscoBGP@123`). Unauthorized peers transmitting synchronization or reset packets are dropped at the kernel level (`%TCP-6-BADAUTH`).
2. **RFC 5082 Generalized TTL Security Mechanism (GTSM):** Configured `neighbor 203.0.113.2 ttl-security hops 1`. BGP packets are transmitted with $\text{TTL} = 255$, and the receiving interface accepts only packets where $\text{TTL} \ge 254$. This completely neutralizes multi-hop spoofed packets injected from the public Internet.
3. **Route Policy Enforcement (Prefix-Lists):**
   * **Inbound (`IN_FROM_ISP`):** Restricts ingress updates strictly to the Default Route (`0.0.0.0/0`) and specific test IP (`8.8.8.8/32`), rejecting Bogons and unintended transit prefixes.
   * **Outbound (`OUT_TO_ISP`):** Restricts enterprise route advertisement solely to the owned public allocation (`203.0.113.0/30`), eliminating accidental RFC 1918 leaks and unauthorized transit service.

### 4.2. Internal Transit (OSPF Area 0, MPLS LDP & NAT Overload)
* **OSPF Area 0 Core Fabric:** Established reliable interior dynamic routing spanning `ASBR`, `CORE_ROUTER`, and `DIST_SWITCH`. ASBR injects default routing downward via `default-information originate always`.
* **MPLS Core:** Enabled MPLS tag forwarding across Core transit links (`mpls ip`) utilizing reserved label spaces (`100 - 199`) to demonstrate high-throughput label-switched paths.
* **Edge Source PAT (NAT Overload):** Configured standardized overload translation on ASBR (`interface Ethernet0/1 overload`), converting internal corporate subnets (`192.168.10.0/24`, `10.10.99.0/24`, `10.0.0.0/16`) to the routable interface address for full outbound Internet access.

---

## ⚙️ 5. Production Configuration Files

<details>
<summary><b>🔹 ACCESS_SWITCH (Layer 2 Hardening)</b></summary>

```text
configure terminal
hostname ACCESS_SWITCH
no ip domain lookup
service timestamps debug datetime msec
service timestamps log datetime msec

! --- LAYER 2 DEFENSE: SNOOPING & DAI ---
ip dhcp snooping
ip dhcp snooping vlan 10
no ip dhcp snooping information option

ip arp inspection vlan 10
ip arp inspection validate src-mac dst-mac ip

! --- TRUSTED UPLINK TO DISTRIBUTION ---
interface Ethernet0/0
 description UPLINK_TRUNK_TO_DIST_SWITCH
 switchport trunk encapsulation dot1q
 switchport mode trunk
 ip dhcp snooping trust
 ip arp inspection trust
 no shutdown
 exit

! --- HARDENED ACCESS PORTS ---
interface range Ethernet0/1 - 2
 description SECURE_ACCESS_PORT
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address sticky
 switchport port-security violation shutdown
 ip dhcp snooping limit rate 15
 no shutdown
 exit

! --- MANAGEMENT SVI & LOGGING ---
interface Vlan10
 ip address 192.168.10.2 255.255.255.0
 no shutdown
 exit

ip default-gateway 192.168.10.1
logging on
logging host 10.10.99.10
logging trap notifications
end
write memory
```
</details>

<details>
<summary><b>🔹 DIST_SWITCH (L3 Core Routing & DHCP Services)</b></summary>

```text
configure terminal
hostname DIST_SWITCH
ip routing
no ip domain lookup
service timestamps log datetime msec

! --- DHCP SERVICE POOL ---
ip dhcp excluded-address 192.168.10.1 192.168.10.10
ip dhcp pool VLAN10_POOL
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 8.8.8.8
 exit

! --- DOWNLINK TRUNK ---
interface Ethernet0/0
 description DOWNLINK_TO_ACCESS_SWITCH
 switchport trunk encapsulation dot1q
 switchport mode trunk
 no shutdown
 exit

! --- ROUTED UPLINK TO CORE ---
interface Ethernet0/1
 no switchport
 description ROUTED_UPLINK_TO_CORE
 ip address 10.0.1.2 255.255.255.252
 no shutdown
 exit

! --- SVI GATEWAY ---
interface Vlan10
 description DEFAULT_GATEWAY_VLAN10
 ip address 192.168.10.1 255.255.255.0
 no shutdown
 exit

! --- OSPF ROUTING ---
router ospf 1
 router-id 1.1.1.1
 network 10.0.1.0 0.0.0.3 area 0
 network 192.168.10.0 0.0.0.255 area 0
 exit

logging on
logging host 10.10.99.10
logging trap notifications
end
write memory
```
</details>

<details>
<summary><b>🔹 CORE_ROUTER (Transit Hub, MPLS & Telemetry)</b></summary>

```text
configure terminal
hostname CORE_ROUTER
no ip domain lookup
service timestamps log datetime msec
ip cef

interface Ethernet0/0
 description DOWNLINK_TO_DIST
 ip address 10.0.1.1 255.255.255.252
 no shutdown
 exit

interface Ethernet0/1
 description UPLINK_TO_ASBR
 ip address 10.0.0.2 255.255.255.252
 mpls ip
 no shutdown
 exit

interface Ethernet0/2
 description TRANSIT_TO_NOC_SUBNET
 ip address 10.10.99.1 255.255.255.0
 no shutdown
 exit

router ospf 1
 router-id 2.2.2.2
 network 10.0.1.0 0.0.0.3 area 0
 network 10.0.0.0 0.0.0.3 area 0
 network 10.10.99.0 0.0.0.255 area 0
 exit

mpls ip
mpls label range 100 199
mpls ldp router-id Ethernet0/1 force

logging on
logging host 10.10.99.10
logging trap notifications
end
write memory
```
</details>

<details>
<summary><b>🔹 ASBR (Edge Boundary, BGP Security & NAT)</b></summary>

```text
configure terminal
hostname ASBR
no ip domain lookup
service timestamps debug datetime msec
service timestamps log datetime msec
ip cef

interface Ethernet0/0
 description DOWNLINK_TO_CORE
 ip address 10.0.0.1 255.255.255.252
 ip nat inside
 duplex auto
 no shutdown
 exit

interface Ethernet0/1
 description WAN_UPLINK_TO_ISP
 ip address 203.0.113.1 255.255.255.252
 ip nat outside
 duplex auto
 no shutdown
 exit

! --- BGP FILTER LISTS ---
ip prefix-list IN_FROM_ISP seq 5 permit 0.0.0.0/0
ip prefix-list IN_FROM_ISP seq 10 permit 8.8.8.8/32
ip prefix-list IN_FROM_ISP seq 100 deny 0.0.0.0/0 le 32

ip prefix-list OUT_TO_ISP seq 5 permit 203.0.113.0/30
ip prefix-list OUT_TO_ISP seq 100 deny 0.0.0.0/0 le 32

! --- BGP WITH MD5 & GTSM ---
router bgp 65000
 bgp router-id 10.0.0.1
 bgp log-neighbor-changes
 neighbor 203.0.113.2 remote-as 64496
 neighbor 203.0.113.2 description PEERING_ISP
 neighbor 203.0.113.2 password CiscoBGP@123
 neighbor 203.0.113.2 ttl-security hops 1
 neighbor 203.0.113.2 prefix-list IN_FROM_ISP in
 neighbor 203.0.113.2 prefix-list OUT_TO_ISP out
 exit

router ospf 1
 router-id 3.3.3.3
 network 10.0.0.0 0.0.0.3 area 0
 default-information originate always
 exit

! --- OUTBOUND PAT ---
ip access-list standard ACL_NAT
 permit 192.168.10.0 0.0.0.255
 permit 10.10.99.0 0.0.0.255
 permit 10.0.0.0 0.0.255.255
 exit

ip nat inside source list ACL_NAT interface Ethernet0/1 overload

logging on
logging host 10.10.99.10
logging trap notifications
end
write memory
```
</details>

<details>
<summary><b>🔹 ISP_PEER (Upstream Provider Simulation)</b></summary>

```text
configure terminal
hostname ISP_PEER
no ip domain lookup

interface Ethernet0/0
 description UPLINK_TO_ASBR
 ip address 203.0.113.2 255.255.255.252
 no shutdown
 exit

interface Loopback0
 description SIMULATED_PUBLIC_INTERNET_DNS
 ip address 8.8.8.8 255.255.255.255
 no shutdown
 exit

router bgp 64496
 bgp log-neighbor-changes
 neighbor 203.0.113.1 remote-as 65000
 neighbor 203.0.113.1 description PEERING_ASBR
 neighbor 203.0.113.1 password CiscoBGP@123
 neighbor 203.0.113.1 ttl-security hops 1
 neighbor 203.0.113.1 default-originate
 network 8.8.8.8 mask 255.255.255.255
 exit
end
write memory
```
</details>

<details>
<summary><b>🔹 Syslog_NOC Collector (Ubuntu / Debian Linux)</b></summary>

```bash
# Enable UDP port 514 within rsyslog
sudo sed -i 's/#module(load="imudp")/module(load="imudp")/g' /etc/rsyslog.conf
sudo sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/g' /etc/rsyslog.conf

# Configure custom Cisco log rules
sudo mkdir -p /var/log/cisco
cat << 'EOF' | sudo tee /etc/rsyslog.d/10-cisco-security.conf
if $msg contains 'BGP' or $msg contains 'ADJCHANGE' then /var/log/cisco/bgp.log
if $fromhost-ip startswith '10.' or $fromhost-ip startswith '192.168.' then /var/log/cisco/devices.log
EOF

# Restart service and verify listener
sudo systemctl restart rsyslog
sudo ss -ulnp | grep 514
```
</details>

---

## 💼 6. Resume & CV Highlights (STAR-Format Bullet Points)

Tailored for direct inclusion under the **Projects / Technical Experience** section on resumes for **Network Engineer**, **Network Security Engineer**, or **SOC Analyst** applications:

* **Engineered a resilient 3-tier enterprise network topology** across Access, Distribution, Core, and WAN Edge using Cisco IOS/IOL within EVE-NG, implementing **OSPF Area 0**, **MPLS LDP**, and **PAT (NAT Overload)** for zero-downtime routing.
* **Spearheaded Layer 2 defense-in-depth mitigations**, successfully neutralizing simulated Red Team STP attacks, MAC spoofing, rogue DHCP servers, and MITM ARP cache poisoning through **BPDU Guard, Port-Security Sticky, DHCP Snooping, and Dynamic ARP Inspection (DAI)**.
* **Hardened public edge eBGP peering** by mandating **RFC 2385 TCP MD5 authentication**, **RFC 5082 Generalized TTL Security Mechanism (GTSM)**, and two-way **Prefix-List route filtering**, protecting border infrastructure from BGP hijacking and unauthorized transit injection.
* **Architected centralized network telemetry** with a Linux-based **Syslog server** (`rsyslog` & `tcpdump` over UDP $514$), capturing real-time hardware faults, port error-disable events, and routing adjacency flaps for immediate SOC escalation.
