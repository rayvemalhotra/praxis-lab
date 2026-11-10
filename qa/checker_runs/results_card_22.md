# results_card_22

Open a scorecard
UNSW-NB15 (Kaggle)

Enterprise network testbed (not industrial), flow records, 9 attack categories. Destination host is the organization asset. Working sample of 103,617 records.

tool test103,617 records34 behavior numbers kept14 columns removedorganizations by hosts3 seedsprotocol budget
STEPS 3 AND 4
Four training conditions, tested on the withheld attack type
Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
Fingerprint sharing (experimental, not a praxis condition)
Organization A
local run
15 hosts · trains on 16,866 records · 1,335 test records of the withheld type
withheld: ExploitsExploitation and lateral movementT1210T1068T0866
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
37.5%
Federated learning
2.5%
Centralized training
38.8%
Fingerprint sharing (experimental)
29.3%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 4.75%, sharing 4.04%, federated 5.00%, centralized 3.72%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
33.8%
majority-host baseline
38.8%
Gain -5.0 points, 95% range between -10.8 and +5.1; 3 hosts; shuffle test p = 0.005.
Organization B
local run
14 hosts · trains on 15,295 records · 971 test records of the withheld type
withheld: FuzzersExploitation and lateral movementT1210T1068T0866
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
87.5%
Federated learning
44.8%
Centralized training
85.1%
Fingerprint sharing (experimental)
68.6%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 5.12%, sharing 4.57%, federated 4.53%, centralized 4.30%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
26.6%
majority-host baseline
51.8%
Gain -25.2 points, 95% range between -42.9 and -6.8; 3 hosts; shuffle test p = 0.005.
Organization C
local run
14 hosts · trains on 12,862 records · 1,327 test records of the withheld type
withheld: ReconnaissanceReconnaissance and scanningT1595T1046T0846
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
74.3%
Federated learning
47.5%
Centralized training
75.0%
Fingerprint sharing (experimental)
63.2%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 5.89%, sharing 5.31%, federated 5.51%, centralized 6.09%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
15.1%
majority-host baseline
45.3%
Gain -30.2 points, 95% range between -40.8 and -18.3; 4 hosts; shuffle test p = 0.005.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+66.4 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. 95% range [+59.0, +76.9], local run, not the run of record.
5-point rule
100 points
H2 · FEDERATED
supported
+31.6 points
Federated learning: mean gain in attack-class recall over the three organizations. 95% range [+27.4, +36.3], local run, not the run of record.
5-point rule
100 points
H3 · TRACING
not observed
Not all 3 organizations
Sanitized attack records traced above the majority-host baseline. Gain over the baseline from -30.2 to -5.0 points, local run. An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.
FINGERPRINTS
experimental
+53.7 points
Fingerprint sharing: not a praxis training condition. 95% range [+46.9, +62.6], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type Exploits, 1,335 test records of that type (local run of the tool)

Attack family: Exploitation and lateral movement. MITRE ATT&CK: T1210 Exploitation of Remote Services (Enterprise); T1068 Exploitation for Privilege Escalation (Enterprise); T0866 Exploitation of Remote Services (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	4.75%	baseline	0	8,052	baseline
Sanitized attack-record sharing	37.5%	100.0%	4.04%	+37.5 [+24.5, +63.6]	2.20 MB	8,052	worth it (gain met, its sent records not traced)
Federated learning	2.5%	100.0%	5.00%	+2.5 [+1.4, +4.5]	643 KB	8,472	not worth it (gain not met)
Centralized training	38.8%	100.0%	3.72%	+38.8 [+25.5, +65.7]	2.31 MB	8,052	reference
Fingerprint sharing (experimental, not a praxis condition)	29.3%	100.0%	4.72%	+29.3 [+19.2, +49.8]	94 KB	8,052	gain met (exposure of the fingerprint not measured)

Organization B, withheld attack type Fuzzers, 971 test records of that type (local run of the tool)

Attack family: Exploitation and lateral movement. MITRE ATT&CK: T1210 Exploitation of Remote Services (Enterprise); T1068 Exploitation for Privilege Escalation (Enterprise); T0866 Exploitation of Remote Services (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	99.2%	5.12%	baseline	0	8,052	baseline
Sanitized attack-record sharing	87.5%	100.0%	4.57%	+87.5 [+82.9, +91.1]	2.37 MB	8,052	worth it (gain met, its sent records not traced)
Federated learning	44.8%	99.3%	4.53%	+44.8 [+36.1, +54.5]	643 KB	8,472	gain met
Centralized training	85.1%	100.0%	4.30%	+85.1 [+80.8, +89.0]	2.10 MB	8,052	reference
Fingerprint sharing (experimental, not a praxis condition)	68.6%	99.9%	4.88%	+68.6 [+61.1, +75.2]	110 KB	8,052	gain met (exposure of the fingerprint not measured)

Organization C, withheld attack type Reconnaissance, 1,327 test records of that type (local run of the tool)

Attack family: Reconnaissance and scanning. MITRE ATT&CK: T1595 Active Scanning (Enterprise); T1046 Network Service Discovery (Enterprise); T0846 Remote System Discovery (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	99.9%	5.89%	baseline	0	8,052	baseline
Sanitized attack-record sharing	74.3%	99.9%	5.31%	+74.3 [+55.6, +90.3]	2.29 MB	8,052	worth it (gain met, its sent records not traced)
Federated learning	47.5%	100.0%	5.51%	+47.5 [+38.6, +56.2]	643 KB	8,472	gain met
Centralized training	75.0%	99.9%	6.09%	+75.0 [+56.6, +91.3]	1.76 MB	8,052	reference
Fingerprint sharing (experimental, not a praxis condition)	63.2%	99.9%	5.87%	+63.2 [+47.7, +77.3]	94 KB	8,052	gain met (exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	15	19,090	Exploits	2,224	16,866	7,871	8,995	1,335	511
Organization B	14	16,905	Fuzzers	1,610	15,295	7,566	7,729	971	116
Organization C	14	14,856	Reconnaissance	1,994	12,862	4,558	8,304	1,327	793

Organizations: organizations = groups of hosts (each host belongs to one organization). Split: by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

49 columns in the table given to the tool. Kept: 34 behavior numbers and the attack type. Removed: 14 columns (identifiers, text, other labels).

Kept
dursbytesdbytessttldttlslossdlossSloadDloadSpktsDpktsswindwinstcpbdtcpbsmeanszdmeansztrans_depthres_bdy_lenSjitDjitSintpktDintpkttcprttsynackackdatct_state_ttlct_srv_srcct_srv_dstct_dst_ltmct_src_ ltmct_src_dport_ltmct_dst_sport_ltmct_dst_src_ltm
Removed
LabelLtimeStimeattack_catct_flw_http_mthdct_ftp_cmddsportdstipis_ftp_loginis_sm_ips_portsprotoservicesportsrcipstate
keyboard_arrow_down

How it was run, and the separate checks

Same network (34-128-64-10), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 6 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 100-tree forests. Budget: protocol.

Separate checks (local run of the tool). Centralized training against isolated training: +66.3 [+58.3, +77.0] points. Flagging only (attack or not, type ignored): sharing +0.3 [+0.1, +0.5], federated +0.1 [-0.1, +0.2]. Nothing withheld: sharing +3.2 [+1.9, +4.6], federated +2.0 [+0.2, +3.8]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +34.8 points, 95% range [+28.4, +43.8].

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

keyboard_arrow_down

About this dataset

Made by. Moustafa and Slay (2015), UNSW Canberra Cyber Range

Year. 2015

What it is. An enterprise (office) network testbed, not industrial, recorded as network flows with 49 fields. Included to see whether the method holds outside IoT.

Records used. 103,617 records used, a class-stratified sample of 2,540,044

Attack types. 9 attack categories: exploits, fuzzers, generic, reconnaissance, DoS, analysis, backdoor, shellcode, worms

Host or device column. destination IP

Role in the praxis. Same system, new data, and the only non-industrial set. Not study evidence.

Source. https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15

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
