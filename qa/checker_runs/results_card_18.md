# results_card_18

Open a scorecard
NF-ToN-IoT-v3 (2025 NetFlow)

IoT and IIoT testbed, NetFlow records with 9 attack types. Destination host is the organization asset. Working sample of 99,819 records.

tool test99,819 records46 behavior numbers kept8 columns removedorganizations by hosts3 seedsprotocol budget
STEPS 3 AND 4
Four training conditions, tested on the withheld attack type
Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
Fingerprint sharing (experimental, not a praxis condition)
Organization A
local run
165 hosts · trains on 18,336 records · 1,324 test records of the withheld type
withheld: scanningReconnaissance and scanningT1595T1046T0846
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
29.5%
Federated learning
0.2%
Centralized training
29.2%
Fingerprint sharing (experimental)
20.1%
Sanitized attack-record sharing
not worth it (false-positive rate up more than 1 point)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 3.92%, sharing 4.93%, federated 5.05%, centralized 4.40%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
49.7%
majority-host baseline
45.9%
Gain +3.8 points, 95% range between +3.3 and +4.4; 15 hosts; shuffle test p = 0.010.
Organization B
local run
165 hosts · trains on 14,204 records · 802 test records of the withheld type
withheld: xssWeb and injectionT1190T0819
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
47.0%
Federated learning
57.8%
Centralized training
60.0%
Fingerprint sharing (experimental)
23.1%
Sanitized attack-record sharing
not worth it (false-positive rate up more than 1 point)
Federated learning
not worth it (false-positive rate up more than 1 point)
False-positive rate. isolated 1.77%, sharing 3.00%, federated 6.58%, centralized 3.86%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
66.1%
majority-host baseline
54.7%
Gain +11.3 points, 95% range between +0.4 and +21.6; 90 hosts; shuffle test p = 0.005.
Organization C
local run
164 hosts · trains on 12,741 records · 420 test records of the withheld type
withheld: injectionWeb and injectionT1190T0819
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
76.3%
Federated learning
70.3%
Centralized training
76.8%
Fingerprint sharing (experimental)
70.0%
Sanitized attack-record sharing
trade-off (gain met, its sent records traced)
Federated learning
gain met
False-positive rate. isolated 5.20%, sharing 5.18%, federated 3.56%, centralized 5.20%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
85.6%
majority-host baseline
48.3%
Gain +37.4 points, 95% range between +30.9 and +44.0; 88 hosts; shuffle test p = 0.005.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+51.0 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. 95% range [+45.8, +58.1], local run, not the run of record.
5-point rule
100 points
H2 · FEDERATED
supported
+42.7 points
Federated learning: mean gain in attack-class recall over the three organizations. 95% range [+39.4, +45.3], local run, not the run of record.
5-point rule
100 points
H3 · TRACING
observed
All 3 organizations
Sanitized attack records traced above the majority-host baseline. Gain over the baseline from +3.8 to +37.4 points, local run. An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.
FINGERPRINTS
experimental
+37.7 points
Fingerprint sharing: not a praxis training condition. 95% range [+33.7, +42.4], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type scanning, 1,324 test records of that type (local run of the tool)

Attack family: Reconnaissance and scanning. MITRE ATT&CK: T1595 Active Scanning (Enterprise); T1046 Network Service Discovery (Enterprise); T0846 Remote System Discovery (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	7.9%	3.92%	baseline	0	8,784	baseline
Sanitized attack-record sharing	29.5%	29.5%	4.93%	+29.5 [+19.1, +49.4]	2.50 MB	8,784	not worth it (false-positive rate up more than 1 point)
Federated learning	0.2%	0.7%	5.05%	+0.2 [+0.0, +0.4]	716 KB	8,520	not worth it (gain not met)
Centralized training	29.2%	29.2%	4.40%	+29.2 [+19.1, +49.1]	3.39 MB	8,784	reference
Fingerprint sharing (experimental, not a praxis condition)	20.1%	20.3%	4.75%	+20.1 [+12.6, +33.0]	129 KB	8,784	not worth it (false-positive rate up more than 1 point; exposure of the fingerprint not measured)

Organization B, withheld attack type xss, 802 test records of that type (local run of the tool)

Attack family: Web and injection. MITRE ATT&CK: T1190 Exploit Public-Facing Application (Enterprise); T0819 Exploit Public-Facing Application (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	11.8%	1.77%	baseline	0	8,784	baseline
Sanitized attack-record sharing	47.0%	49.8%	3.00%	+47.0 [+41.2, +52.7]	3.51 MB	8,784	not worth it (false-positive rate up more than 1 point)
Federated learning	57.8%	96.2%	6.58%	+57.8 [+52.6, +62.4]	716 KB	8,520	not worth it (false-positive rate up more than 1 point)
Centralized training	60.0%	62.6%	3.86%	+60.0 [+53.9, +66.0]	2.63 MB	8,784	reference
Fingerprint sharing (experimental, not a praxis condition)	23.1%	26.4%	2.68%	+23.1 [+19.4, +26.8]	140 KB	8,784	gain met (exposure of the fingerprint not measured)

Organization C, withheld attack type injection, 420 test records of that type (local run of the tool)

Attack family: Web and injection. MITRE ATT&CK: T1190 Exploit Public-Facing Application (Enterprise); T0819 Exploit Public-Facing Application (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	72.7%	5.20%	baseline	0	8,784	baseline
Sanitized attack-record sharing	76.3%	95.2%	5.18%	+76.3 [+66.3, +82.0]	3.39 MB	8,784	trade-off (gain met, its sent records traced)
Federated learning	70.3%	83.5%	3.56%	+70.3 [+61.7, +76.0]	716 KB	8,520	gain met
Centralized training	76.8%	96.7%	5.20%	+76.8 [+68.5, +82.8]	2.36 MB	8,784	reference
Fingerprint sharing (experimental, not a praxis condition)	70.0%	93.3%	4.88%	+70.0 [+61.4, +75.4]	129 KB	8,784	gain met (exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	165	20,541	scanning	2,205	18,336	6,442	11,894	1,324	349
Organization B	165	15,536	xss	1,332	14,204	7,771	6,433	802	290
Organization C	164	13,432	injection	691	12,741	5,666	7,075	420	67

Organizations: organizations = groups of hosts (each host belongs to one organization). Split: by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

55 columns in the table given to the tool. Kept: 46 behavior numbers and the attack type. Removed: 8 columns (identifiers, text, other labels).

Kept
PROTOCOLL7_PROTOIN_BYTESIN_PKTSOUT_BYTESOUT_PKTSTCP_FLAGSCLIENT_TCP_FLAGSSERVER_TCP_FLAGSFLOW_DURATION_MILLISECONDSDURATION_INDURATION_OUTMIN_TTLMAX_TTLLONGEST_FLOW_PKTSHORTEST_FLOW_PKTMIN_IP_PKT_LENMAX_IP_PKT_LENSRC_TO_DST_SECOND_BYTESDST_TO_SRC_SECOND_BYTESRETRANSMITTED_IN_BYTESRETRANSMITTED_IN_PKTSRETRANSMITTED_OUT_BYTESRETRANSMITTED_OUT_PKTSSRC_TO_DST_AVG_THROUGHPUTDST_TO_SRC_AVG_THROUGHPUTNUM_PKTS_UP_TO_128_BYTESNUM_PKTS_128_TO_256_BYTESNUM_PKTS_256_TO_512_BYTESNUM_PKTS_512_TO_1024_BYTESNUM_PKTS_1024_TO_1514_BYTESTCP_WIN_MAX_INTCP_WIN_MAX_OUTICMP_TYPEICMP_IPV4_TYPEDNS_QUERY_TYPEDNS_TTL_ANSWERFTP_COMMAND_RET_CODESRC_TO_DST_IAT_MINSRC_TO_DST_IAT_MAXSRC_TO_DST_IAT_AVGSRC_TO_DST_IAT_STDDEVDST_TO_SRC_IAT_MINDST_TO_SRC_IAT_MAXDST_TO_SRC_IAT_AVGDST_TO_SRC_IAT_STDDEV
Removed
AttackDNS_QUERY_IDFLOW_END_MILLISECONDSFLOW_START_MILLISECONDSIPV4_DST_ADDRIPV4_SRC_ADDRL4_DST_PORTL4_SRC_PORTLabel
keyboard_arrow_down

How it was run, and the separate checks

Same network (46-128-64-10), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 6 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 100-tree forests. Budget: protocol.

Separate checks (local run of the tool). Centralized training against isolated training: +55.3 [+50.8, +62.6] points. Flagging only (attack or not, type ignored): sharing +27.3 [+23.5, +32.6], federated +29.3 [+25.1, +32.3]. Nothing withheld: sharing -1.3 [-2.3, -0.2], federated -4.8 [-7.3, -3.5]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +8.2 points, 95% range [+4.3, +15.6].

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

keyboard_arrow_down

About this dataset

Made by. UNSW Canberra Cyber Range (Moustafa); NetFlow v3 release by Sarhan, Layeghy and Portmann, 2025

Year. 2025

What it is. IoT and IIoT testbed traffic (smart home and industrial sensors, cloud and edge services) exported as NetFlow records with 46 behavior fields per flow.

Records used. 99,819 records used, a class-stratified sample of a 1.5% download

Attack types. 9 attack types: DDoS, DoS, scanning, XSS, password, injection, backdoor, MITM, ransomware

Host or device column. destination IP (the organization's asset)

Role in the praxis. Shows the system runs unchanged on new data from a settings file. Not study evidence: the split is the tool's own, not audited.

Source. https://research.unsw.edu.au/projects/toniot-datasets

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
