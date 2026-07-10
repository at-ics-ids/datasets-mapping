# ATT&CK Mapping Evidence Log

Every technique assignment is grounded in a verbatim passage from the dataset's **own paper or its official release documentation**. For each cell: the attack class (in the source's own wording), the assigned technique and tactic, confidence, the exact location, and the quoted evidence. Enterprise cells are mapped to ATT&CK Enterprise and reported separately. Generated from `data/mapping_evidence.csv`.

**Datasets grounded so far: 10/10** — Edge-IIoTset, ICS-NAD, X-IIoTID, MSU-PWR, ICS-Flow, Rodofile, HIL-WDT, MSU-GP, EDS, SWaT.

---

## Edge-IIoTset

> M. A. Ferrag, O. Friha, D. Hamouda, L. Maglaras, H. Janicke, "Edge-IIoTset: A new comprehensive realistic cyber security dataset of IoT and IIoT applications," IEEE Access, vol. 10, 2022.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| DoS/DDoS (TCP SYN/UDP/HTTP/ICMP flood) | T0814 Denial of Service | Inhibit Response Function | high | Ferrag et al. 2022 IEEE Access Sec.B-1 | "DoS/DDoS attacks make the victim's IoT edge server unavailable to legitimate requests by sending manipulated packets" |
| Information gathering (port scan) | T0846 Remote System Discovery | Discovery | high | Ferrag et al. 2022 Sec.B-2 | "discover which ports are open... discover active hosts using the Nmap and Netcat tools" |
| Information gathering (port scan) | T0840 Network Connection Enumeration | Discovery | high | Ferrag et al. 2022 Sec.B-2 | "obtain the composition of a network's architecture (weakest of the three; port/connection enumeration)" |
| Information gathering (OS fingerprinting) | T0888 Remote System Information Discovery | Discovery | high | Ferrag et al. 2022 Sec.B-2 | "the operating system, active security devices like firewalls" |
| Man in the middle (ARP/DNS spoofing) | T0830 Adversary-in-the-Middle | Collection | high | Ferrag et al. 2022 Sec.B-3 | "compromise and alter the flow of communication between two sides... ARP Spoofing and DNS Spoofing" |

### Enterprise (reported separately)

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Injection attacks (XSS/SQLi/upload) | T1190 Exploit Public-Facing Application | Enterprise | enterprise | Ferrag et al. 2022 Sec.B-4 + ATT&CK Enterprise | "sending a malicious script... access sensitive information, session tokens, cookies (web-app; not ICS)" |
| Malware (backdoor) | T1219 Remote Access Software | Enterprise | enterprise | Ferrag et al. 2022 Sec.B-5 + ATT&CK Enterprise | "installing backdoors to take control of vulnerable IoT network components" |
| Malware (password cracking) | T1110 Brute Force | Enterprise | enterprise | Ferrag et al. 2022 Sec.B-5 + ATT&CK Enterprise | "Password cracking attack" |
| Malware (ransomware) | T1486 Data Encrypted for Impact | Enterprise | enterprise | Ferrag et al. 2022 Sec.B-5 + ATT&CK Enterprise | "Ransomware attack" |

---

## ICS-NAD

> X. Zhou et al., "A dataset collected in real-world industrial control systems for network attack detection," Scientific Data, vol. 13, Art. 399, 2026.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Reconnaissance (IP + port scan) | T0846 Remote System Discovery | Discovery | high | Zhou et al. 2026 Sci.Data Sec. ICS-specific attacks-1 | "surreptitiously collect information about target victims, e.g., IP addresses... Nmap tool to conduct IP scans" |
| Reconnaissance (port scan) | T0840 Network Connection Enumeration | Discovery | high | Zhou et al. 2026 Sec.-1 | "...and open ports... port scans" |
| Reconnaissance (OS fingerprinting) | T0888 Remote System Information Discovery | Discovery | high | Zhou et al. 2026 Sec.-1 | "...operating systems (OSs)..." |
| DoS and DDoS | T0814 Denial of Service | Inhibit Response Function | high | Zhou et al. 2026 Sec.-2 | "send a large number of packets in a short period, resulting in a denial of service... Hping3" |
| MitM (ARP poisoning) + FDI (ICMP redirection) | T0830 Adversary-in-the-Middle | Collection | high | Zhou et al. 2026 Sec.-3/-4 | "MitM: intercept and manipulate communication data... Arpspoof/ARP poisoning; FDI ICMP redirection changes the route message of packets to trick network routing" |

### Removed

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| DROPPED: FDI mislabelled (T1692.002 Reporting Msg) |  | — | removed | Zhou et al. 2026 Sec.-3 (four FDI attacks are ICMP/TCP) | "'FDI' is network-layer packet manipulation (oversized ICMP, ICMP unreachable, wrong TCP flags), NOT forged OT reporting/command. Folds into DoS+AiTM. T1692.002 unsupported." |
| DROPPED: FDI mislabelled (T0832 Manipulation of View) |  | — | removed | Zhou et al. 2026 Sec.-3 | "No operator-view manipulation; FDI is network-protocol trickery via Netwox. T0832 unsupported." |

---

## X-IIoTID

> M. Al-Hawawreh, E. Sitnikova, N. Aboutorab, "X-IIoTID: A connectivity- and device-agnostic intrusion dataset for industrial Internet of Things," IEEE Internet Things J., vol. 9, no. 5, 2022.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Reconnaissance (generic scanning; resource discovery) | T0846 Remote System Discovery | Discovery | high | Al-Hawawreh et al. 2022 IoTJ Sec.III-B-1 | "generic scanning... listening ports, its OS and available services... Nmap; discovering CoAP resources (sensor values, actuators)" |
| Reconnaissance (OS fingerprinting) | T0888 Remote System Information Discovery | Discovery | high | Al-Hawawreh et al. 2022 Sec.III-B-1 | "generic scanning... its Operating System (OS) and available services" |
| Lateral Movement (MQTT broker subscription) | T0811 Data from Information Repositories | Collection | high | Al-Hawawreh et al. 2022 Sec.III-B-4 | "connect to the cloud broker to discover and obtain all the information collected from physical devices... messages containing information about the names of control systems and details of the collected measurements" |
| Lateral Movement (Modbus register reading) | T0861 Point & Tag Identification | Collection | high | Al-Hawawreh et al. 2022 Sec.III-B-4 | "connect with a PLC device... to read and discover connected register addresses and ranges of supported addresses of Modbus/TCP inputs and coils" |
| Exfiltration | T0882 Theft of Operational Information | Impact | medium | Al-Hawawreh et al. 2022 Sec.III-B-6 | "leaking private and sensitive information related to IIoT devices, such as a PLC configuration, sensor data, credentials" |
| Tampering (false data injection) | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | medium | Al-Hawawreh et al. 2022 Sec.III-B-7 | "poisoning of cloud data (i.e., false data injections)... fabricate and inject false data to affect the accuracy of a cloud data analysis" |
| Tampering (fake alarms) | T0832 Manipulation of View | Impact | medium | Al-Hawawreh et al. 2022 Sec.III-B-7 | "send fake e-mail notifications or alarms to connected operators" |
| Ransom DoS (RDoS) | T0814 Denial of Service | Inhibit Response Function | high | Al-Hawawreh et al. 2022 Sec.III-B-9 | "threatening to launch massive DDoS traffic unless a ransom is paid... volumetric attacks over IIoT application protocols (e.g., CoAP)" |

### Enterprise (reported separately)

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Weaponization (SSH brute force) | T1110 Brute Force | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-2 + ATT&CK Enterprise | "explore a password from a dictionary, or word list... against SSH using the Hydra tool... super-user credentials are returned" |
| Exploitation (reverse shell/backdoor) | T1219 Remote Access Software | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-3 + ATT&CK Enterprise | "create a persistent reverse TCP shell/backdoor in the edge gateway" |
| Exploitation (MitM edge gateway-router) | T1557 Adversary-in-the-Middle | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-3 + ATT&CK Enterprise | "exploit communications between the edge gateway and router and send packets with a false source address to fool the edge gateway (IT link, not OT)" |
| Command and Control (DNS tunneling) | T1071.004 Application Layer Protocol: DNS | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-5 + ATT&CK Enterprise | "DNS tunneling in a stealth mode... most common techniques and procedures used by APT" |
| Command and Control (DNS tunneling) | T1572 Protocol Tunneling | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-5 + ATT&CK Enterprise | "DNS tunneling in a stealth mode (based on a common port and protocol)" |
| Crypto-Ransomware | T1486 Data Encrypted for Impact | Enterprise | enterprise | Al-Hawawreh et al. 2022 Sec.III-B-8 + ATT&CK Enterprise | "injects malware to deny access to the data or system and force a victim to pay a fee in the form of cryptocurrency... encrypt the configuration and setting files of physical devices" |

### Documented, unmapped (no ATT&CK technique in either matrix)

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Lateral Movement (TCP relay pivot) | IT network pivoting | — | unmapped | Al-Hawawreh et al. 2022 Sec.III-B-4 + ATT&CK Enterprise | "pivoting... open the channel between an attacker's device and the mail server through the edge gateway... mail server set up in a different network (IT, not OT)" |

---

## MSU-PWR

> U. Adhikari, S. Pan, T. Morris et al., Power System Attack Datasets README (MSU/ORNL, 2014); R. C. B. Hink et al., "Machine learning for power system disturbance and cyber-attack discrimination," ISRCS, 2014.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Data Injection | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-5 | "imitate a valid fault by changing values to parameters such as current, voltage, sequence components etc." |
| Data Injection (blind operator) | T0832 Manipulation of View | Impact | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-5 | "This attack aims to blind the operator and causes a black out" |
| Remote Tripping Command Injection | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-3 + Table III | "an attack that sends a command to a relay which causes a breaker to open (scenarios 15-20 Command Injection to R1-R4)" |
| Remote Tripping (breaker control) | T0831 Manipulation of Control | Impact | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-3 | "command to a relay which causes a breaker to open (unauthorized control of the breaker)" |
| Relay Setting Change | T0836 Modify Parameter | Impair Process Control | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-4 + Table III | "relays are configured with a distance protection scheme and the attacker changes the setting" |
| Relay Setting Change (disable protection) | T0837 Loss of Protection | Impact | high | PowerSystem_Dataset_README (Adhikari/Pan/Morris 2014) Scenario Types-4 | "changes the setting to disable the relay function such that relay will not trip for a valid fault or a valid command" |

---

## ICS-Flow

> A. Dehlaghi-Ghadim, M. H. Moghadam, A. Balador, H. Hansson, "Anomaly detection dataset for industrial control systems," IEEE Access, vol. 11, 2023 (arXiv:2305.09678).

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Reconnaissance (IP-Scanning) | T0846 Remote System Discovery | Discovery | high | Dehlaghi-Ghadim et al. 2023 arXiv:2305.09678 Sec.IV-1 | "IP-Scanning... using Scapy... ARP messages to discover the alive network nodes" |
| Reconnaissance (Port-Scanning) | T0840 Network Connection Enumeration | Discovery | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-1 | "Port-Scanning... we use NMap... to find hosts and ports on them in the network" |
| DDoS | T0814 Denial of Service | Inhibit Response Function | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-3 | "flood the network or service with a large number of packets... a massive flood of reading requests to the PLCs... relentlessly bombards the PLCs" |
| MitM-based false data injection | T0830 Adversary-in-the-Middle | Collection | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-4 | "an attacker intercepts or manipulates communications between two ICS components while they believe they are interacting directly" |
| MitM-based false data injection | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-4 | "We use a MitM attack to inject false data into the controlling system... injecting incorrect data into the controlling system" |
| MitM-based false data injection | T0832 Manipulation of View | Impact | medium | Dehlaghi-Ghadim et al. 2023 Sec.IV-4 | "multiplying their values with a specific factor (deceives the controlling system view of the process)" |
| Replay | T0830 Adversary-in-the-Middle | Collection | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-2 | "the attacker uses ARP poisoning and the MitM technique to sniff network packets for 15 seconds" |
| Replay | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | Dehlaghi-Ghadim et al. 2023 Sec.IV-2 | "a replay attack on a TCP connection reuses only TCP ports, Modbus commands, and arguments to create a new TCP-Connection" |

---

## Rodofile

> N. R. Rodofile et al., "Process control cyber-attacks and labelled datasets on S7Comm critical infrastructure," ACISP, Springer, 2017.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| PLC memory/register manipulation | T0835 Manipulate I/O Image | Inhibit Response Function | high | Rodofile et al. 2017 ACISP Sec.3.1 + Table 1 | "the Attacker writes directly to the memory of the PLC the input validation of the HMI is bypassed" |
| turning sub-processes on/off; conveyor-direction; wash-tank mode | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | Rodofile et al. 2017 Table 1 | "Table 1 attacks 1.1-2.3, 3.1-3.2: Turn Conveyor Belt on/off, Change direction, Turn Wash Tank on/off (Auto/Manual), Turn Pipeline Reactor on/off via S7Comm writes" |
| turning sub-processes on/off; conveyor-direction; wash-tank mode | T0831 Manipulation of Control | Impact | high | Rodofile et al. 2017 Sec.3.1 | "attack 2.3 turns the pump on and leaves it running... the wash tank overflows" |
| reactor-threshold manipulation | T0836 Modify Parameter | Impair Process Control | high | Rodofile et al. 2017 Table 1 + Sec.3.1 | "3.3/3.4 Change upper/lower threshold of Pipeline Reactor (type real); increasing the upper limit so that a pipe bursts" |
| emergency stop; global reset | T0816 Device Restart/Shutdown | Inhibit Response Function | high | Rodofile et al. 2017 Sec.3.1 + Table 1 | "the entire process can be disrupted by sending the command for the emergency stop (4.1) or global reset (4.2)... the process has to be restarted... at least five minutes before it is operational" |

### Removed

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| PLC memory/register manipulation | T0821 Modify Controller Tasking | Execution | removed | Rodofile et al. 2017 Table 1 + Sec.3.1 | "CONFIRMED OUT: all attacks are register-value writes and commands (Table 1 addresses); none modifies the controller program/tasking. T0821 not exercised." |

---

## HIL-WDT

> L. Faramondi, F. Flammini, S. Guarino, R. Setola, "A hardware-in-the-loop water distribution testbed dataset for cyber-physical security testing," IEEE Access, vol. 9, 2021.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| scanning (SYN scan; FIN scan) | T0846 Remote System Discovery | Discovery | high | Faramondi et al. 2021 IEEE Access Sec.III + Table 2 | "we considered specific subclasses such as SYN scan and FIN scan for scanning attacks" |
| Denial of Service (DoS) | T0814 Denial of Service | Inhibit Response Function | high | Faramondi et al. 2021 Fig.7 + Table 2 | "Figure 7 Effect of a DoS attack against PLC1r on physical process... causes the disconnection of PLC1r" |
| MITM | T0830 Adversary-in-the-Middle | Collection | high | Faramondi et al. 2021 Table 2 + Fig.6 | "MITM attacks... attacks against hosts (SCADA, PLC, flow sensor) or communication links" |
| MITM (forge sensor value) | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | medium | Faramondi et al. 2021 Fig.6 + Sec.IV-A | "a MITM attack fixes the required sensor value to the last value read by the victim before the attack... changes the water level value of T6s requested by PLC3s to PLC2s" |
| MITM (falsify controller view) | T0832 Manipulation of View | Impact | medium | Faramondi et al. 2021 Fig.6 | "changes the water level value... requested by PLC3s to PLC2s (T0832 covers manipulating the view of operators OR controllers; here PLC2's view is falsified)" |
| physical attacks (leaks; sensor/pump failures) | T0826 Loss of Availability | Impact | medium | Faramondi et al. 2021 Fig.8 + Sec.IV-A | "physical attack against P4r... breakdown of P4r, which stops water flow towards T5r; effect-level (physical attacks have no effect on the network traffic)" |
| physical attacks (leaks; sensor/pump failures) | T0879 Damage to Property | Impact | medium | Faramondi et al. 2021 Sec.III (physical attacks definition) | "leaks from tanks and pipes, sensors or actuators failures; effect-level mapping, no network vector" |

---

## MSU-GP

> T. Morris, W. Gao, "Industrial control system traffic data sets for intrusion detection research," Critical Infrastructure Protection VIII, Springer, 2014.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Reconnaissance (address scan) | T0846 Remote System Discovery | Discovery | high | Morris & Gao 2014 Sec.4.1 | "The address scan discovers SCADA servers connected [to the network]" |
| Reconnaissance (device identification) | T0888 Remote System Information Discovery | Discovery | high | Morris & Gao 2014 Sec.4.1 | "device identification attack... firmware revisions; function code scan identifies supported MODBUS function codes" |
| Reconnaissance (points scan) | T0861 Point & Tag Identification | Collection | high | Morris & Gao 2014 Sec.4.1 | "The points scan allows the attacker to build a memory map" |
| Response injection (NMRI/CMRI false measurements) | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | high | Morris & Gao 2014 Sec.4.2 | "Response injection attacks alter responses from the server to client, providing false system state information... send false process measurements" |
| Response injection (CMRI mask state) | T0832 Manipulation of View | Impact | medium | Morris & Gao 2014 Sec.4.2 | "CMRI attacks attempt to mask the actual state of the physical process and are designed to appear like normal process" |
| Command injection (MSCI commands) | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | Morris & Gao 2014 Sec.4.3 | "Command injection attacks inject false control and configuration commands to alter system behavior" |
| Command injection (MSCI to critical state) | T0831 Manipulation of Control | Impact | high | Morris & Gao 2014 Sec.4.3 | "MSCI attacks change the state of the process control system to drive the system from a safe state to a critical state... turn on the compressor or pump to increase the pressure" |
| Command injection (MPCI setpoints) | T0836 Modify Parameter | Impair Process Control | high | Morris & Gao 2014 Sec.4.3 | "unauthorized modification of process setpoints... malicious parameter command injection (MPCI)" |
| DoS | T0814 Denial of Service | Inhibit Response Function | high | Morris & Gao 2014 Sec.4 + IJCIP taxonomy | "denial-of-service (DoS) attacks disrupt the communication link between the RTU and MTU or HMI" |

### Removed

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Reconnaissance (DROPPED T0840) | T0840 Network Connection Enumeration | — | removed | Morris & Gao 2014 Sec.4.1 | "Paper's recon is Modbus-specific (address/function/device/points scan), not generic TCP connection enumeration; covered by T0846/T0888/T0861." |

---

## EDS

> Y. Xue et al., "Real-time intrusion detection based on decision fusion in industrial control systems," IEEE Trans. Ind. Cyber-Phys. Syst., vol. 2, 2024.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| Information Leakage | T0846 Remote System Discovery | Discovery | high | Xue et al. 2024 Sec.III-B Attack Models | "Use scanning tools to obtain critical information such as IP addresses... of the devices on the industrial control network" |
| Information Leakage | T0888 Remote System Information Discovery | Discovery | high | Xue et al. 2024 Sec.III-B | "...device models, and operating systems of the devices" |
| Replay Attack | T0830 Adversary-in-the-Middle | Collection | high | Xue et al. 2024 Sec.III-C + III-B | "the man-in-the-middle attack tool of Ettercap... used [for] information leakage/replay; Resend the eavesdropped data to the receiver" |
| Replay Attack | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | Xue et al. 2024 Sec.III-B | "Resend the eavesdropped data to the receiver (S7COMM control traffic replayed to the PLC; command-centric attack set)" |
| Command Injection | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | Xue et al. 2024 Sec.III-B | "Manipulate system behavior or gain unauthorized access by inserting malicious commands into the input" |
| Sensor Data Tampering | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | high | Xue et al. 2024 Sec.III-B | "Maliciously manipulate the parameters of sensors to deceive the system" |
| Sensor Data Tampering | T0832 Manipulation of View | Impact | high | Xue et al. 2024 Sec.III-B | "manipulate the parameters of sensors to deceive the system (falsified sensor view)" |
| Control Parameter Tampering | T0836 Modify Parameter | Impair Process Control | high | Xue et al. 2024 Sec.III-B/III-C | "Control Parameter Tampering... point coercion packets were created... tampering control parameters" |
| Multi-Point Attack | T0831 Manipulation of Control | Impact | high | Xue et al. 2024 Sec.III-B | "design multiple control commands to execute coordinated attacks, aiming to control and disrupt the system" |
| Physical Attack | T0879 Damage to Property | Impact | high | Xue et al. 2024 Sec.III-C | "Physical attacks are realized by artificially opening normally closed valves, causing liquid leakage from the reactor" |

---

## SWaT

> J. Goh, S. Adepu, K. N. Junejo, A. Mathur, "A Dataset to Support Research in the Design of Secure Water Treatment Systems," CRITIS 2016; iTrust SWaT.A1&A2 (Dec 2015) + A6 (Dec 2019) attack docs.

### ICS

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| actuator manipulation (open/close valves; pumps on/off) | T1692.001 Unauthorized Message: Command Message | Impair Process Control | high | SWaT.A1&A2 Dec 2015 List_of_attacks_Final.xlsx (Goh et al. 2016) | "Open MV-101; Turn on P-102; Close MV-304; Turn P-101 off (11 actuator-command attacks in the 41-attack list)" |
| actuator manipulation (process impact) | T0831 Manipulation of Control | Impact | high | SWaT.A1&A2 Dec 2015 List_of_attacks_Final.xlsx | "Expected Impact: Tank overflow; Pipe bursts; Halt of stage 3 (actuator commands drive the process)" |
| sensor spoofing (false sensor values) | T1692.002 Unauthorized Message: Reporting Message | Impair Process Control | high | SWaT.A1&A2 Dec 2015 List_of_attacks_Final.xlsx | "Set value of AIT-202 as 6; Set value of DPIT as >40kpa; Set LIT-101 to above H (17 sensor-spoof attacks)" |
| sensor spoofing (falsify controller/operator view) | T0832 Manipulation of View | Impact | high | SWaT.A1&A2 Dec 2015 List_of_attacks_Final.xlsx | "false sensor readings deceive the PLC/operator (Set value of ... as ...); many attacks note detection relies on the reported value" |
| USB infiltration of SCADA workstation [A6] | T0847 Replication Through Removable Media | Initial Access | high | SWaT.A6 Dec 2019 Log.docx (iTrust) | "Infiltrate SCADA WS via USB thumb drive (A6 Dec 2019)" |
| historian data exfiltration [A6] | T0882 Theft of Operational Information | Impact | high | SWaT.A6 Dec 2019 Log.docx (iTrust) | "First attack: Exfiltrate Historian Data (repeated 1030-1120, A6 Dec 2019)" |

### Removed

| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |
|---|---|---|---|---|---|
| DROPPED: Modify Parameter (T0836) | T0836 Modify Parameter | — | removed | SWaT.A1&A2 Dec 2015 List_of_attacks_Final.xlsx | "CONFIRMED OUT: the 41-attack A1&A2 list has ZERO setpoint/parameter-change attacks; every 'Set value' spoofs a sensor reading (T1692.002), not a stored parameter." |

---

