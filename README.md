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

# 4. WAN Edge & Core Infrastructure Hardening

## 4.1. Edge BGP Peering Security (ASBR ↔ ISP_PEER)
To shield the enterprise border gateway from route hijacking, unauthorized BGP session establishment, and off-path TCP attacks, three defensive mechanisms were instituted:

1. **RFC 2385 TCP MD5 Signature**: Applied cryptographic message integrity verification across TCP port 179 (password `CiscoBGP@123`). Unauthorized peers transmitting synchronization or reset packets are dropped at the kernel level (`%TCP-6-BADAUTH`).
2. **RFC 5082 Generalized TTL Security Mechanism (GTSM)**: Configured `neighbor 203.0.113.2 ttl-security hops 1`. BGP packets are transmitted with TTL=255, and the receiving interface accepts only packets where TTL≥254. This completely neutralizes multi-hop spoofed packets injected from the public Internet.
3. **Route Policy Enforcement (Prefix-Lists)**:
   - **Inbound (`IN_FROM_ISP`)**: Restricts ingress updates strictly to the Default Route (`0.0.0.0/0`) and specific test IP (`8.8.8.8/32`), rejecting Bogons and unintended transit prefixes.
   - **Outbound (`OUT_TO_ISP`)**: Restricts enterprise route advertisement solely to the owned public allocation (`203.0.113.0/30`), eliminating accidental RFC 1918 leaks and unauthorized transit service.

## 4.2. Internal Transit (OSPF Area 0, MPLS LDP & NAT Overload)
- **OSPF Area 0 Core Fabric**: Established reliable interior dynamic routing spanning ASBR, CORE_ROUTER, and DIST_SWITCH. ASBR injects default routing downward via `default-information originate always`.
- **MPLS Core**: Enabled MPLS tag forwarding across Core transit links (`mpls ip`) utilizing reserved label spaces (100 - 199) to demonstrate high-throughput label-switched paths.
- **Edge Source PAT (NAT Overload)**: Configured standardized overload translation on ASBR (`interface Ethernet0/1 overload`), converting internal corporate subnets (`192.168.10.0/24`, `10.10.99.0/24`, `10.0.0.0/16`) to the routable interface address for full outbound Internet access.

## 4.3. Technical Evidence & Verification (Screenshots)
*Dưới đây là các bằng chứng kỹ thuật được trích xuất từ hệ thống giám sát và thiết bị mạng trong quá trình kiểm thử:*

**1. Data Plane Verification & NetFlow Telemetry**
* **ICMP Ping Generation (Kali Linux):** 
  ![Kali Ping Test](image_5e5726.png)
* **Router Flow Cache (CORE_ROUTER):** 
  ![Router Cache](image_5e5b40.png)
* **DoS Flood Bandwidth Saturation Analysis:** 
  ![DoS Flood 1](image_5e6305.png)
  <br>
  ![DoS Flood 2](netflow_icmp_flood_dos.png)
* **Top Talkers (IP/Bytes):** 
  ![Top Talkers](netflow_top5_ip_bytes.png)
* **Threat Hunting (C2 Beaconing / Port 4444):** 
  ![C2 Traffic](netflow_reverse_shell_port_4444.png)

**2. System Logging & Infrastructure Hardening**
* **Log File Hardening (chattr +a):** 
  ![Log Hardening](log_hardening_chattr_append.png)
* **Core Telemetry Events:** 
  ![Core Telemetry](syslog-core-telemetry.png)
* **Security Alerts (Port Security & BGP Flaps):** 
  ![Security Alerts](security-alerts.png)

---

# 5. Resume & CV Highlights (STAR-Format Bullet Points)
*Tailored for direct inclusion under the Projects / Technical Experience section on resumes for Network Engineer, Network Security Engineer, or SOC Analyst applications:*

* **Engineered** a resilient 3-tier enterprise network topology across Access, Distribution, Core, and WAN Edge using Cisco IOS/IOL within EVE-NG, implementing OSPF Area 0, MPLS LDP, and PAT (NAT Overload) for zero-downtime routing.
* **Spearheaded** Layer 2 defense-in-depth mitigations, successfully neutralizing simulated Red Team STP attacks, MAC spoofing, rogue DHCP servers, and MITM ARP cache poisoning through BPDU Guard, Port-Security Sticky, DHCP Snooping, and Dynamic ARP Inspection (DAI).
* **Hardened** public edge eBGP peering by mandating RFC 2385 TCP MD5 authentication, RFC 5082 Generalized TTL Security Mechanism (GTSM), and two-way Prefix-List route filtering, protecting border infrastructure from BGP hijacking and unauthorized transit injection.
* **Architected** centralized network telemetry with a Linux-based Syslog server (rsyslog & tcpdump over UDP 514), capturing real-time hardware faults, port error-disable events, and routing adjacency flaps for immediate SOC escalation.**BPDU Guard, Port-Security Sticky, DHCP Snooping, and Dynamic ARP Inspection (DAI)**.
* **Hardened public edge eBGP peering** by mandating **RFC 2385 TCP MD5 authentication**, **RFC 5082 Generalized TTL Security Mechanism (GTSM)**, and two-way **Prefix-List route filtering**, protecting border infrastructure from BGP hijacking and unauthorized transit injection.
* **Architected centralized network telemetry** with a Linux-based **Syslog server** (`rsyslog` & `tcpdump` over UDP $514$), capturing real-time hardware faults, port error-disable events, and routing adjacency flaps for immediate SOC escalation.
