# agent_page_with_the_example_fingerprint

ThreatPrint

Overview

Live demo

Results

Evaluate

Agent

Research

Organizations

Glossary

Students

LOCAL AGENT AND FINGERPRINT
Run the agent at home. Share only a fingerprint.

The agent is one readable Python file. On your own machine it finds the identifier columns, removes them, maps your attack labels to common attack families and to MITRE ATT&CK, and writes a small fingerprint file: summary statistics per attack type, no records. You look at the file, and only then decide whether to upload it. The agent and the fingerprint are product research; they are not part of the praxis.

$ python threatprint_agent.py my_records.csv
Read 22,073 records, 31 columns from my_records.csv
Removed before anything leaves (11): timestamp, site,
  device_name, device_ip, device_mac, peer_ip, ...
Kept as behavior numbers (19): duration_s, packets_out, ...
  arp_mitm        Adversary in the middle        T1557.002
  port_scan       Reconnaissance and scanning    T1595
  ddos_udp_flood  Distributed denial of service  T1498
  ... and four more attack types
[ok] 7 attack types with at least 50 records
Wrote my_records.fingerprint.json (27 KB calculated payload)
Nothing was sent anywhere.
(output of the agent on the synthetic sample file, shortened)
1
Download the agent

One file, pandas and numpy only, no network code. A security team can read all of it before running it.

2
Run it on your records

It prints what it removed, what it kept, the ATT&CK mapping and a readiness check, and writes the fingerprint next to your file.

3
Upload the fingerprint

This page checks its integrity digest, shows your attack coverage against the library and tells you whether the full evaluation can run on your data.

Download the agent (one Python file)

Example fingerprint (try the upload without a terminal)

Sample file: Water utility (synthetic)

Sample file: Power grid, DNP3 (real)

Sample file: Hospital (synthetic)

Sample file: Manufacturing plant (synthetic)

4 sample files to try the tool with. Upload any of them on the Evaluate page, watch one on the Live demo, or run the agent on it.

Water utility (synthetic). A made-up water utility: 24 devices, 7 attack types, 22,073 records. Device names, addresses and operators are invented. Made by tools/make_sample_org.py. Free to use. It says nothing about real attacks.

Power grid, DNP3 (real). 10,952 real network flows sampled from the DNP3 Intrusion Detection Dataset (CICFlowMeter flows, 120 s timeout). CC BY 4.0. Kelli et al., 2022, Zenodo record 7348493.

Hospital (synthetic). A made-up hospital: 24 medical and building devices (infusion pumps, patient monitors, imaging workstations, nurse stations, building controllers), 6 attack types, 19,507 records. Device names, addresses, wards and badges are invented. Made by tools/make_sample_orgs_more.py. Free to use. It says nothing about real attacks.

Manufacturing plant (synthetic). A made-up plant: 21 devices (PLCs, HMI panels, robot arms, historians), 8 attack types, 21,198 records. Station names, addresses, lines and operators are invented. Made by tools/make_sample_orgs_more.py. Free to use. It says nothing about real attacks.

Example fingerprint. The file the agent wrote for the synthetic water utility. Download it and upload it below to see the coverage, the gaps and the readiness check without running anything.

YOUR FINGERPRINT
Upload a fingerprint

A fingerprint file written by the agent (.json). It is checked, read and compared; it is kept only if you choose to contribute it.

sample...xample.json
44.8KB
add icon
add

Integrity digest matches (SHA3-256 674828a99850d10e...). Agent version 0.3, made 2026-11-09.

7
attack types in the fingerprint
19
behavior numbers kept
11
columns removed before anything left
27 KB
calculated payload of the fingerprint
READINESS
Can the full evaluation run on your data?
7 attack types with at least 50 records (three are needed, so that each of the three organizations can withhold a different one)
about 6,240 normal records (about 300 per organization are needed for the alarm threshold)
19 behavior numbers kept after sanitizing
host or device column: present, 10 to 49 hosts (needed to form organizations by host and to test tracing; without it organizations are random thirds)
time column: present (needed to keep one attack together as an event; without it the ranges are optimistic)
COVERAGE
Your attack coverage, by MITRE ATT&CK
YOUR LABEL	ABOUT HOW MANY RECORDS	ATTACK FAMILY	MITRE ATT&CK TECHNIQUE (CLOSEST)
arp_mitm	2,370	Adversary in the middle	T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning (Enterprise)T0830 Adversary-in-the-Middle (ICS)
port_scan	2,300	Reconnaissance and scanning	T1595 Active Scanning (Enterprise)T1046 Network Service Discovery (Enterprise)T0846 Remote System Discovery (ICS)
ddos_udp_flood	2,290	Distributed denial of service	T1498 Network Denial of Service (Enterprise)T0814 Denial of Service (ICS)
ssh_brute_force	2,250	Brute force and credentials	T1110 Brute Force (Enterprise)
ransomware_smb	2,220	Ransomware	T1486 Data Encrypted for Impact (Enterprise)
modbus_write_injection	2,220	Industrial control messages	T1692.001 Unauthorized Message: Command Message (ICS)
dos_syn_flood	2,150	Denial of service	T1499 Endpoint Denial of Service (Enterprise)T0814 Denial of Service (ICS)
GAPS
What the library holds that you do not

A family marked no is one your detectors have no examples of. The colored cells show how much peers' examples of it helped others in the library; it is not a forecast for your network.

ATTACK FAMILY	IN YOUR FINGERPRINT	DATASETS IN THE LIBRARY THAT HOLD IT	ISOLATED TRAINING	SANITIZED ATTACK-RECORD SHARING	FEDERATED LEARNING	CENTRALIZED TRAINING
Reconnaissance and scanning	yes	21	0.0%	75.7%	54.2%	77.9%
Malware, botnet and command and control	no	17	0.0%	75.2%	76.4%	74.6%
Denial of service	yes	17	0.0%	78.1%	62.5%	82.3%
Distributed denial of service	yes	15	0.0%	85.8%	77.5%	85.3%
Brute force and credentials	yes	13	0.0%	54.3%	45.6%	49.1%
Web and injection	no	11	0.0%	45.8%	42.7%	50.3%
Adversary in the middle	yes	10	0.0%	35.2%	26.1%	33.6%
Exploitation and lateral movement	no	6	0.0%	62.5%	23.7%	61.9%
Industrial control messages	yes	6	0.0%	46.7%	22.4%	49.2%
Ransomware	yes	5	not measured	not measured	not measured	not measured
Exfiltration	no	2	not measured	not measured	not measured	not measured

The four recall columns are library means from local runs of the tool, not the run of record: when an organization had that family withheld, the share of its test records named correctly under each training condition.

CONTRIBUTE
Add this fingerprint to the library (optional)

I am allowed to share this fingerprint, and I agree that the operator of this site keeps it to compare attack coverage across organizations. It holds summary statistics only: no records and no identifier columns.

A contributed fingerprint is kept on the machine that runs this site until its operator deletes it. To have it removed, give the operator the start of its digest, shown above. The agent itself never uploads anything; contributing is this manual step.

Contribute this fingerprint

INSIDE THE FILE
What a fingerprint is, and what it is not
What it holds

For every attack type with at least 50 records: the record count rounded down to the nearest ten, 41 quantiles (1% to 99%) of every behavior number, and the rank correlations between them. A SHA3-256 integrity digest, and a signature field reserved for a post-quantum signature (ML-DSA, FIPS 204); signing is designed, not built.

What it does not hold, and what it does not promise

No rows, no device names, no addresses, no ports, no time stamps. The lowest and highest points it stores are the 1% and 99% quantiles, not the extremes; for a number with few distinct values (a count that is mostly 0) they can equal the smallest or largest value. Normal traffic is not fingerprinted. It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint reveals about the organization that made it has not been measured.

EXPERIMENT, NOT PART OF THE PRAXIS
Does a fingerprint carry enough to help?

Fingerprint sharing was run on 25 datasets of the library as a fifth, experimental arm: the receiver trains on its own records plus made-up records drawn from its peers' fingerprints, with the same training budget and alarm rule as the four training conditions.

25 of 25
datasets where the whole 95% range of its mean gain is above 5 points
19 of 25
datasets where its mean gain is above federated learning's (point estimates)
4 of 25
datasets where its mean gain is above sanitized attack-record sharing's
23 times
fewer bytes than record sharing (median over the datasets)
keyboard_arrow_down

The numbers, dataset by dataset

DATASET	RUN	ISOLATED TRAINING	SANITIZED ATTACK-RECORD SHARING	FEDERATED LEARNING	CENTRALIZED TRAINING	FINGERPRINT SHARING (EXPERIMENTAL)	DATA SENT, SHARING	DATA SENT, FINGERPRINTS
DataSense CIC IIoT 2025 (the study)	local run	baseline	+40.9 [+32.3, +49.5]	+46.0 [+37.1, +54.1]	+44.4 [+36.7, +51.7]	+37.6 [+30.3, +44.7]	3.60 MB	463 KB
Edge-IIoTset (ranking check)	local run	baseline	+71.1 [+69.8, +72.3]	+61.8 [+60.7, +62.9]	+70.3 [+69.1, +71.5]	+69.0 [+67.9, +70.1]	18.54 MB	597 KB
BoT-IoT 5% (Kaggle)	local run	baseline	+76.0 [+74.5, +77.3]	+92.1 [+87.3, +95.8]	+98.8 [+97.9, +99.6]	+39.2 [+35.9, +42.0]	1.51 MB	87 KB
BoT-IoT, 5% release (four files)	local run	baseline	+88.2 [+84.6, +92.0]	+57.5 [+52.3, +63.1]	+91.0 [+88.2, +93.8]	+77.8 [+73.5, +82.3]	9.20 MB	304 KB
CIC-IDS2017 (labelled flows)	local run	baseline	+98.7 [+98.5, +98.9]	+96.6 [+96.3, +97.0]	+99.0 [+98.8, +99.3]	+90.9 [+90.1, +91.7]	20.33 MB	1.24 MB
CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021)	local run	baseline	+97.2 [+96.2, +98.0]	+90.1 [+87.7, +92.6]	+96.6 [+95.6, +97.6]	+90.2 [+87.8, +92.5]	25.73 MB	2.27 MB
CICIoT2023 (merged flows)	local run	baseline	+69.0 [+68.3, +69.7]	+66.2 [+65.9, +66.5]	+75.1 [+74.2, +75.9]	+75.2 [+74.3, +76.0]	17.17 MB	1.40 MB
CIDDS-001 (OpenStack and external server flows)	local run	baseline	+13.0 [+9.9, +16.3]	+0.8 [+0.3, +1.7]	+12.9 [+9.8, +16.1]	+12.1 [+9.1, +15.5]	787 KB	11 KB
CSE-CIC-IDS2018 (seven days)	local run	baseline	+78.4 [+77.6, +79.2]	+70.1 [+68.9, +71.1]	+78.2 [+77.5, +79.0]	+72.6 [+71.8, +73.4]	24.14 MB	1.05 MB
CTU-13 botnet families (NetTiSA flows)	local run	baseline	+92.4 [+88.8, +94.6]	+90.0 [+85.8, +92.8]	+91.3 [+87.4, +93.7]	+54.9 [+51.3, +57.1]	704 KB	40 KB
DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout)	local run	baseline	+60.9 [+59.8, +62.0]	+33.3 [+33.2, +33.3]	+66.7 [+66.7, +66.7]	+66.3 [+65.7, +66.8]	5.53 MB	835 KB
Edge-IIoTset, ML subset (raw packet fields)	local run	baseline	+74.5 [+70.6, +78.6]	+62.8 [+62.2, +63.4]	+77.3 [+73.2, +81.1]	+73.9 [+69.7, +77.9]	11.59 MB	564 KB
Electra Modbus (electric traction substation)	local run	baseline	+50.8 [+49.7, +51.9]	+41.4 [+40.4, +42.2]	+50.6 [+49.6, +51.6]	+50.8 [+49.7, +51.8]	1.50 MB	31 KB
Electra S7comm (electric traction substation)	local run	baseline	+35.6 [+35.2, +36.0]	+33.3 [+33.3, +33.3]	+36.7 [+36.1, +37.3]	+36.7 [+36.1, +37.3]	1.52 MB	25 KB
IEC 60870-5-104 intrusion detection dataset (balanced flows)	local run	baseline	+45.2 [+39.6, +50.5]	+6.6 [+4.9, +8.6]	+40.7 [+35.5, +45.8]	+14.8 [+11.1, +18.7]	1.28 MB	921 KB
InSDN (software-defined network)	local run	baseline	+99.5 [+98.7, +99.9]	+98.9 [+98.5, +99.2]	+99.5 [+98.8, +99.9]	+97.2 [+95.3, +98.5]	14.99 MB	319 KB
IoT-23 (twelve scenarios, Zeek connection logs)	local run	baseline	+61.9 [+61.5, +62.4]	+23.7 [+22.1, +26.3]	+51.3 [+44.7, +55.0]	+57.4 [+54.6, +58.9]	1.43 MB	21 KB
N-BaIoT (nine IoT devices)	local run	baseline	+97.3 [+97.0, +97.5]	+76.9 [+76.3, +77.6]	+98.7 [+98.5, +98.8]	+82.9 [+82.2, +83.7]	81.83 MB	2.43 MB
NF-ToN-IoT-v3 (2025 NetFlow)	local run	baseline	+51.0 [+45.8, +58.1]	+42.7 [+39.4, +45.3]	+55.3 [+50.8, +62.6]	+37.7 [+33.7, +42.4]	9.40 MB	397 KB
NSL-KDD (KDDTrain+ and KDDTest+)	local run	baseline	+80.2 [+78.3, +82.4]	+35.5 [+34.9, +36.1]	+81.7 [+79.7, +83.6]	+78.8 [+76.8, +80.9]	4.17 MB	454 KB
RT-IoT2022	local run	baseline	+94.5 [+93.5, +95.4]	+73.4 [+71.8, +75.0]	+90.8 [+89.3, +92.0]	+85.2 [+83.5, +86.8]	12.26 MB	893 KB
ToN_IoT network (Train_Test_Network)	local run	baseline	+25.6 [+24.9, +26.3]	+0.0 [+0.0, +0.0]	+16.8 [+16.1, +17.4]	+37.5 [+36.7, +38.4]	4.16 MB	94 KB
UNSW-NB15 (Kaggle)	local run	baseline	+66.4 [+59.0, +76.9]	+31.6 [+27.4, +36.3]	+66.3 [+58.3, +77.0]	+53.7 [+46.9, +62.6]	6.86 MB	297 KB
WUSTL-IIoT-2021 (Kaggle)	local run	baseline	+92.6 [+77.0, +97.6]	+66.5 [+66.4, +66.6]	+92.6 [+77.1, +97.9]	+66.7 [+66.7, +66.7]	2.13 MB	75 KB
X-IIoTID (Kaggle)	local run	baseline	+93.5 [+90.4, +95.8]	+53.4 [+48.1, +58.6]	+94.2 [+91.3, +96.3]	+89.6 [+85.7, +92.8]	8.75 MB	434 KB

Mean gain in attack-class recall on the withheld attack types against isolated training; local runs of the tool on the tool's own splits, which are optimistic where a dataset has no clock. Only DataSense carries the praxis claims, and the praxis has four training conditions; fingerprint sharing is product research, run with its own isolated baseline. What a fingerprint reveals about its sender has not been measured, so a gain here is half of an answer.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
