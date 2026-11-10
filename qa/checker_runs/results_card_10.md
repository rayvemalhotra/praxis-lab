# results_card_10

Open a scorecard
Edge-IIoTset (ranking check)

IoT and IIoT testbed, packet records, 38 cleaned features. The praxis run used three class-stratified random thirds of the records as organizations. Tracing (H3) was not repeated on this dataset: normal traffic gives no device-labelled examples for one of the two attacked hosts.

ranking check134,981 records38 behavior numbers kept1 columns removedorganizations by random thirds3 seedsprotocol budget
Run of record. The praxis run of record for Edge-IIoTset (Hex, 19 October 2026) reports H1 +70.8 [+69.6, +72.0] and H2 +61.5 [+60.4, +62.6]. The local run shown here was computed on another machine; the decimals differ and the H1 and H2 decisions are the same.

The table has no time column, so every record is its own event and the 95% ranges are optimistic.

The organizations are random thirds of the records, not groups of hosts; real organizations differ more from each other than these do.

STEPS 3 AND 4
Four training conditions, tested on the withheld attack type
Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
Fingerprint sharing (experimental, not a praxis condition)
Organization A
local run
trains on 20,225 records · 1,363 test records of the withheld type
withheld: DDoS_TCPDistributed denial of serviceT1498T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
69.6%
Federated learning
69.1%
Centralized training
69.5%
Fingerprint sharing (experimental)
72.6%
Sanitized attack-record sharing
gain met (tracing not tested)
Federated learning
not worth it (false-positive rate up more than 1 point)
False-positive rate. isolated 2.79%, sharing 2.79%, federated 3.91%, centralized 2.79%.
Tracing. not measured for this organization.
Organization B
local run
trains on 20,420 records · 1,246 test records of the withheld type
withheld: PasswordBrute force and credentialsT1110
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
44.8%
Federated learning
16.2%
Centralized training
41.6%
Fingerprint sharing (experimental)
35.1%
Sanitized attack-record sharing
gain met (tracing not tested)
Federated learning
gain met
False-positive rate. isolated 5.40%, sharing 5.40%, federated 4.84%, centralized 5.59%.
Tracing. not measured for this organization.
Organization C
local run
trains on 20,831 records · 999 test records of the withheld type
withheld: Port_ScanningReconnaissance and scanningT1595T1046T0846
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
98.8%
Federated learning
100.0%
Centralized training
100.0%
Fingerprint sharing (experimental)
99.3%
Sanitized attack-record sharing
gain met (tracing not tested)
Federated learning
gain met
False-positive rate. isolated 4.66%, sharing 4.66%, federated 5.03%, centralized 4.47%.
Tracing. not measured for this organization.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+70.8 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. Run of record (Hex, 19 October 2026), 95% range [+69.6, +72.0]. The local run on another machine gave +71.1 [+69.8, +72.3], not the run of record; the decision is the same.
5-point rule
100 points
H2 · FEDERATED
supported
+61.5 points
Federated learning: mean gain in attack-class recall over the three organizations. Run of record (Hex, 19 October 2026), 95% range [+60.4, +62.6]. The local run on another machine gave +61.8 [+60.7, +62.9], not the run of record; the decision is the same.
5-point rule
100 points
H3 · TRACING
not tested
n/a
not repeated on this dataset: normal traffic gives no device-labelled examples for one of the two attacked hosts.
FINGERPRINTS
experimental
+69.0 points
Fingerprint sharing: not a praxis training condition. 95% range [+67.9, +70.1], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type DDoS_TCP, 1,363 test records of that type (local run of the tool)

Attack family: Distributed denial of service. MITRE ATT&CK: T1498 Network Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	2.79%	baseline	0	9,943	baseline
Sanitized attack-record sharing	69.6%	100.0%	2.79%	+69.6 [+67.2, +71.9]	6.22 MB	9,943	gain met (tracing not tested)
Federated learning	69.1%	100.0%	3.91%	+69.1 [+66.8, +71.4]	569 KB	9,640	not worth it (false-positive rate up more than 1 point)
Centralized training	69.5%	100.0%	2.79%	+69.5 [+67.1, +71.8]	3.09 MB	9,943	reference
Fingerprint sharing (experimental, not a praxis condition)	72.6%	100.0%	2.79%	+72.6 [+70.3, +75.0]	199 KB	9,943	gain met (exposure of the fingerprint not measured)

Organization B, withheld attack type Password, 1,246 test records of that type (local run of the tool)

Attack family: Brute force and credentials. MITRE ATT&CK: T1110 Brute Force (Enterprise). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	5.40%	baseline	0	9,943	baseline
Sanitized attack-record sharing	44.8%	100.0%	5.40%	+44.8 [+42.2, +47.4]	6.19 MB	9,943	gain met (tracing not tested)
Federated learning	16.2%	100.0%	4.84%	+16.2 [+14.2, +18.4]	569 KB	9,640	gain met
Centralized training	41.6%	100.0%	5.59%	+41.6 [+39.0, +44.0]	3.12 MB	9,943	reference
Fingerprint sharing (experimental, not a praxis condition)	35.1%	100.0%	5.40%	+35.1 [+32.6, +37.5]	199 KB	9,943	gain met (exposure of the fingerprint not measured)

Organization C, withheld attack type Port_Scanning, 999 test records of that type (local run of the tool)

Attack family: Reconnaissance and scanning. MITRE ATT&CK: T1595 Active Scanning (Enterprise); T1046 Network Service Discovery (Enterprise); T0846 Remote System Discovery (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	4.66%	baseline	0	9,943	baseline
Sanitized attack-record sharing	98.8%	100.0%	4.66%	+98.8 [+98.3, +99.2]	6.13 MB	9,943	gain met (tracing not tested)
Federated learning	100.0%	100.0%	5.03%	+100.0 [+100.0, +100.0]	569 KB	9,640	gain met
Centralized training	100.0%	100.0%	4.47%	+100.0 [+99.9, +100.0]	3.19 MB	9,943	reference
Fingerprint sharing (experimental, not a praxis condition)	99.3%	100.0%	5.03%	+99.3 [+98.9, +99.6]	199 KB	9,943	gain met (exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	none in the table given to the tool	22,496	DDoS_TCP	2,271	20,225	298	19,927	1,363	1363
Organization B	none in the table given to the tool	22,497	Password	2,077	20,420	298	20,122	1,246	1246
Organization C	none in the table given to the tool	22,497	Port_Scanning	1,666	20,831	299	20,532	999	999

Organizations: organizations = three class-stratified random thirds of the records. Split: class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

40 columns in the table given to the tool. Kept: 38 behavior numbers and the attack type. Removed: 1 columns (identifiers, text, other labels). The publisher's raw file has 63 columns; the praxis uses a cleaned copy.

Kept
arp.opcodearp.hw.sizeicmp.seq_lehttp.content_lengthhttp.responsetcp.connection.fintcp.connection.rsttcp.connection.syntcp.connection.synacktcp.dstporttcp.flagstcp.flags.acktcp.lenudp.portudp.time_deltadns.qry.name.lendns.qry.qudns.retransmit_requestmqtt.conflag.cleansessmqtt.conflagsmqtt.hdrflagsmqtt.lenmqtt.msgtypemqtt.proto_lenmqtt.topic_lenmqtt.vermbtcp.lenmbtcp.unit_idhttp.request.method=GEThttp.request.method=POSThttp.request.method=TRACEhttp.request.method=OPTIONShttp.request.method=otherhttp.request.version=HTTP/1.1http.request.version=HTTP/1.0http.request.version=othermqtt.protoname_presentmqtt.topic_present
Removed
Attack_label
keyboard_arrow_down

How it was run, and the separate checks

Same network (38-128-64-15), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 5 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 100-tree forests. Budget: protocol.

Separate checks (local run of the tool). Centralized training against isolated training: +70.3 [+69.1, +71.5] points. Flagging only (attack or not, type ignored): sharing +0.0 [+0.0, +0.0], federated +0.0 [+0.0, +0.0]. Nothing withheld: sharing +0.6 [+0.2, +1.0], federated +2.4 [+1.9, +2.9]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +9.3 points, 95% range [+8.5, +10.1].

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

keyboard_arrow_down

About this dataset

Made by. Ferrag, Friha, Hamouda, Maglaras and Janicke (2022), IEEE Access

Year. 2022

What it is. An IoT and IIoT testbed with sensors, edge devices and cloud, recorded packet by packet. The praxis uses a cleaned copy (identifier and placeholder columns removed, 38 features) locked on 25 September.

Records used. 134,981 records used (the full cleaned file)

Attack types. 14 attack types, e.g. DDoS (TCP, UDP, HTTP, ICMP), password, port scanning, SQL injection, XSS, MITM, ransomware, backdoor

Host or device column. the dataset has host address columns; the cleaned copy given to the tool keeps none of them

Role in the praxis. Used to check that the ranking of the two approaches seen on DataSense holds on different data. The organizations are class-stratified random thirds of the records. Tracing (H3) was not repeated: normal traffic gives no device-labelled examples for one of the two attacked hosts.

Source. https://doi.org/10.1109/ACCESS.2022.3165809

keyboard_arrow_down

The decision rule behind the verdicts

The decision rule of 8 October, per organization and condition. Gain: the low end of the 95% range of the gain in attack-class recall must be above 5 points. False positives: the false-positive rate may rise by at most 1 point over isolated training. Privacy (sharing only): if the gain is met but the organization's own sent records are traced above the majority-host baseline, the result is a trade-off. Data sent is reported, not judged. In the rule's own words: not worth it (the gain is not met, or the false-positive rate rises by more than 1 point); trade-off (sharing, gain met, records traced); worth it (sharing, gain met, not traced); gain met (federated learning). The stored verdict strings keep their earlier wording; the pages show the rule's words.

Verdict words of the rule: not worth it (the gain is not met, or the false-positive rate rises by more than 1 point); trade-off (sanitized attack-record sharing: the gain is met and the organization's own sent records are traced above the baseline); worth it (sanitized attack-record sharing: the gain is met and they are not); gain met (federated learning).

Download the report (HTML, print to PDF)

Download the scorecard (JSON)

Download the tables (CSV)

keyboard_arrow_down

Summary table of all datasets

DATASET	ROLE	ISOLATED TRAINING	H1 SANITIZED ATTACK-RECORD SHARING (POINTS, 95% RANGE)	H2 FEDERATED LEARNING (POINTS, 95% RANGE)	CENTRALIZED TRAINING, THE REFERENCE (POINTS, 95% RANGE)	H3 RECORDS TRACED ABOVE THE MAJORITY-HOST BASELINE	SEEDS
DataSense CIC IIoT 2025 (the study)	the study, tool rerun	baseline	run of record +41.1 [+32.5, +49.6]; tool rerun +40.9 [+32.3, +49.5] supported	run of record +45.8 [+37.0, +53.9]; tool rerun +46.0 [+37.1, +54.1] supported	+44.4 [+36.7, +51.7]	observed, all organizations	3
Edge-IIoTset (ranking check)	ranking check, local run	baseline	run of record +70.8 [+69.6, +72.0]; local run +71.1 [+69.8, +72.3] supported	run of record +61.5 [+60.4, +62.6]; local run +61.8 [+60.7, +62.9] supported	+70.3 [+69.1, +71.5]	not tested	3
BoT-IoT 5% (Kaggle)	tool test, local run	baseline	+76.0 [+74.5, +77.3] supported	+92.1 [+87.3, +95.8] supported	+98.8 [+97.9, +99.6]	not all	3
BoT-IoT, 5% release (four files)	tool test, local run	baseline	+88.2 [+84.6, +92.0] supported	+57.5 [+52.3, +63.1] supported	+91.0 [+88.2, +93.8]	not all	3
CIC-IDS2017 (labelled flows)	tool test, local run	baseline	+98.7 [+98.5, +98.9] supported	+96.6 [+96.3, +97.0] supported	+99.0 [+98.8, +99.3]	not all	3
CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021)	tool test, local run	baseline	+97.2 [+96.2, +98.0] supported	+90.1 [+87.7, +92.6] supported	+96.6 [+95.6, +97.6]	not all	3
CICIoT2023 (merged flows)	tool test, local run	baseline	+69.0 [+68.3, +69.7] supported	+66.2 [+65.9, +66.5] supported	+75.1 [+74.2, +75.9]	not tested	3
CIDDS-001 (OpenStack and external server flows)	tool test, local run	baseline	+13.0 [+9.9, +16.3] supported	+0.8 [+0.3, +1.7] not supported	+12.9 [+9.8, +16.1]	not all	3
CSE-CIC-IDS2018 (seven days)	tool test, local run	baseline	+78.4 [+77.6, +79.2] supported	+70.1 [+68.9, +71.1] supported	+78.2 [+77.5, +79.0]	not tested	3
CTU-13 botnet families (NetTiSA flows)	tool test, local run	baseline	+92.4 [+88.8, +94.6] supported	+90.0 [+85.8, +92.8] supported	+91.3 [+87.4, +93.7]	not tested	3
DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout)	tool test, local run	baseline	+60.9 [+59.8, +62.0] supported	+33.3 [+33.2, +33.3] supported	+66.7 [+66.7, +66.7]	not all	3
Edge-IIoTset, ML subset (raw packet fields)	tool test, local run	baseline	+74.5 [+70.6, +78.6] supported	+62.8 [+62.2, +63.4] supported	+77.3 [+73.2, +81.1]	not all	3
Electra Modbus (electric traction substation)	tool test, local run	baseline	+50.8 [+49.7, +51.9] supported	+41.4 [+40.4, +42.2] supported	+50.6 [+49.6, +51.6]	not all	3
Electra S7comm (electric traction substation)	tool test, local run	baseline	+35.6 [+35.2, +36.0] supported	+33.3 [+33.3, +33.3] supported	+36.7 [+36.1, +37.3]	not all	3
IEC 60870-5-104 intrusion detection dataset (balanced flows)	tool test, local run	baseline	+45.2 [+39.6, +50.5] supported	+6.6 [+4.9, +8.6] not supported	+40.7 [+35.5, +45.8]	not all	3
InSDN (software-defined network)	tool test, local run	baseline	+99.5 [+98.7, +99.9] supported	+98.9 [+98.5, +99.2] supported	+99.5 [+98.8, +99.9]	not all	3
IoT-23 (twelve scenarios, Zeek connection logs)	tool test, local run	baseline	+61.9 [+61.5, +62.4] supported	+23.7 [+22.1, +26.3] supported	+51.3 [+44.7, +55.0]	not all	3
N-BaIoT (nine IoT devices)	tool test, local run	baseline	+97.3 [+97.0, +97.5] supported	+76.9 [+76.3, +77.6] supported	+98.7 [+98.5, +98.8]	not all	3
NF-ToN-IoT-v3 (2025 NetFlow)	tool test, local run	baseline	+51.0 [+45.8, +58.1] supported	+42.7 [+39.4, +45.3] supported	+55.3 [+50.8, +62.6]	observed, all organizations	3
NSL-KDD (KDDTrain+ and KDDTest+)	tool test, local run	baseline	+80.2 [+78.3, +82.4] supported	+35.5 [+34.9, +36.1] supported	+81.7 [+79.7, +83.6]	not tested	3
RT-IoT2022	tool test, local run	baseline	+94.5 [+93.5, +95.4] supported	+73.4 [+71.8, +75.0] supported	+90.8 [+89.3, +92.0]	not tested	3
ToN_IoT network (Train_Test_Network)	tool test, local run	baseline	+25.6 [+24.9, +26.3] supported	+0.0 [+0.0, +0.0] not supported	+16.8 [+16.1, +17.4]	not all	3
UNSW-NB15 (Kaggle)	tool test, local run	baseline	+66.4 [+59.0, +76.9] supported	+31.6 [+27.4, +36.3] supported	+66.3 [+58.3, +77.0]	not all	3
WUSTL-IIoT-2021 (Kaggle)	tool test, local run	baseline	+92.6 [+77.0, +97.6] supported	+66.5 [+66.4, +66.6] supported	+92.6 [+77.1, +97.9]	not all	3
X-IIoTID (Kaggle)	tool test, local run	baseline	+93.5 [+90.4, +95.8] supported	+53.4 [+48.1, +58.6] supported	+94.2 [+91.3, +96.3]	not all	3

All four training conditions: isolated training is the baseline of every gain; H1 and H2 are the mean gains of sanitized attack-record sharing and federated learning in attack-class recall on the withheld attack types over the three organizations, supported when the whole 95% range is above 5 points; centralized training is the reference. Local run = this tool's run on another machine; the praxis runs of record are DataSense H1 +41.1 [+32.5, +49.6], H2 +45.8 [+37.0, +53.9] and Edge-IIoTset H1 +70.8 [+69.6, +72.0], H2 +61.5 [+60.4, +62.6], with the same H1 and H2 decisions. H3 is shown as observed, not as a settled statistical result. The hypotheses of the praxis are tested on DataSense alone; every other row is a tool test.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
