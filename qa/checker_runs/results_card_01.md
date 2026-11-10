# results_card_01

Open a scorecard
BoT-IoT, 5% release (four files)

IoT botnet testbed flows. The 5% release holds only 477 normal records, so the alarm threshold rests on a small normal sample. Working sample of 95,944 flows; attack type = category and subcategory.

tool test95,944 records32 behavior numbers kept14 columns removedorganizations by random thirds3 seedsprotocol budget

Organization A has only 36 normal validation records; its alarm threshold, and so its false-positive rate, is rough.

Organization B has only 32 normal validation records; its alarm threshold, and so its false-positive rate, is rough.

Organization C has only 32 normal validation records; its alarm threshold, and so its false-positive rate, is rough.

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
56 hosts · trains on 11,687 records · 2,510 test records of the withheld type
withheld: Reconnaissance_Service_ScanReconnaissance and scanningT1595T1046T0846
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
65.3%
Federated learning
34.1%
Centralized training
73.4%
Fingerprint sharing (experimental)
43.4%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 6.25%, sharing 5.56%, federated 3.47%, centralized 3.47%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
0.0%
majority-host baseline
33.8%
Gain -33.8 points, 95% range between -41.0 and -26.7; 8 hosts; shuffle test p = 1.000.
Organization B
local run
56 hosts · trains on 11,779 records · 2,413 test records of the withheld type
withheld: DoS_UDPDenial of serviceT1499T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
100.0%
Federated learning
57.3%
Centralized training
100.0%
Fingerprint sharing (experimental)
100.0%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 4.86%, sharing 1.39%, federated 4.86%, centralized 4.86%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
3.9%
majority-host baseline
40.9%
Gain -37.0 points, 95% range between -43.7 and -30.3; 8 hosts; shuffle test p = 0.532.
Organization C
local run
60 hosts · trains on 12,445 records · 2,096 test records of the withheld type
withheld: DoS_TCPDenial of serviceT1499T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
99.3%
Federated learning
81.0%
Centralized training
99.6%
Fingerprint sharing (experimental)
90.0%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 5.56%, sharing 4.86%, federated 5.56%, centralized 4.17%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
0.0%
majority-host baseline
43.7%
Gain -43.7 points, 95% range between -50.9 and -36.7; 8 hosts; shuffle test p = 1.000.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+88.2 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. 95% range [+84.6, +92.0], local run, not the run of record.
5-point rule
100 points
H2 · FEDERATED
supported
+57.5 points
Federated learning: mean gain in attack-class recall over the three organizations. 95% range [+52.3, +63.1], local run, not the run of record.
5-point rule
100 points
H3 · TRACING
not observed
Not all 3 organizations
Sanitized attack records traced above the majority-host baseline. Gain over the baseline from -43.7 to -33.8 points, local run. An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.
FINGERPRINTS
experimental
+77.8 points
Fingerprint sharing: not a praxis training condition. 95% range [+73.5, +82.3], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type Reconnaissance_Service_Scan, 2,510 test records of that type (local run of the tool)

Attack family: Reconnaissance and scanning. MITRE ATT&CK: T1595 Active Scanning (Enterprise); T1046 Network Service Discovery (Enterprise); T0846 Remote System Discovery (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	99.4%	6.25%	baseline	0	5,978	baseline
Sanitized attack-record sharing	65.3%	100.0%	5.56%	+65.3 [+54.4, +76.6]	3.10 MB	5,978	worth it (gain met, its sent records not traced)
Federated learning	34.1%	99.8%	3.47%	+34.1 [+23.0, +46.9]	528 KB	5,660	gain met
Centralized training	73.4%	100.0%	3.47%	+73.4 [+64.9, +81.9]	1.51 MB	5,978	reference
Fingerprint sharing (experimental, not a praxis condition)	43.4%	99.1%	4.17%	+43.4 [+31.5, +56.1]	101 KB	5,978	gain met (exposure of the fingerprint not measured)

Organization B, withheld attack type DoS_UDP, 2,413 test records of that type (local run of the tool)

Attack family: Denial of service. MITRE ATT&CK: T1499 Endpoint Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	97.3%	4.86%	baseline	0	5,978	baseline
Sanitized attack-record sharing	100.0%	100.0%	1.39%	+100.0 [+99.9, +100.0]	3.09 MB	5,978	worth it (gain met, its sent records not traced)
Federated learning	57.3%	100.0%	4.86%	+57.3 [+47.9, +66.5]	528 KB	5,660	gain met
Centralized training	100.0%	100.0%	4.86%	+100.0 [+100.0, +100.0]	1.52 MB	5,978	reference
Fingerprint sharing (experimental, not a praxis condition)	100.0%	100.0%	4.17%	+100.0 [+100.0, +100.0]	101 KB	5,978	gain met (exposure of the fingerprint not measured)

Organization C, withheld attack type DoS_TCP, 2,096 test records of that type (local run of the tool)

Attack family: Denial of service. MITRE ATT&CK: T1499 Endpoint Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	98.1%	5.56%	baseline	0	5,978	baseline
Sanitized attack-record sharing	99.3%	100.0%	4.86%	+99.3 [+98.7, +99.7]	3.01 MB	5,978	worth it (gain met, its sent records not traced)
Federated learning	81.0%	100.0%	5.56%	+81.0 [+74.3, +87.3]	528 KB	5,660	gain met
Centralized training	99.6%	100.0%	4.17%	+99.6 [+99.3, +99.9]	1.61 MB	5,978	reference
Fingerprint sharing (experimental, not a praxis condition)	90.0%	100.0%	6.94%	+90.0 [+83.6, +95.1]	101 KB	5,978	not worth it (false-positive rate up more than 1 point; exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	56	15,844	Reconnaissance_Service_Scan	4,157	11,687	75	11,612	2,510	70
Organization B	56	15,735	DoS_UDP	3,956	11,779	79	11,700	2,413	39
Organization C	60	15,811	DoS_TCP	3,366	12,445	79	12,366	2,096	35

Organizations: organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations). Split: by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

47 columns in the table given to the tool. Kept: 32 behavior numbers and the attack type. Removed: 14 columns (identifiers, text, other labels).

Kept
flgs_numberproto_numberpktsbytesstate_numberdurmeanstddevsumminmaxspktsdpktssbytesdbytesratesratedrateTnBPSrcIPTnBPDstIPTnP_PSrcIPTnP_PDstIPTnP_PerProtoTnP_Per_DportAR_P_Proto_P_SrcIPAR_P_Proto_P_DstIPN_IN_Conn_P_DstIPN_IN_Conn_P_SrcIPAR_P_Proto_P_SportAR_P_Proto_P_DportPkts_P_State_P_Protocol_P_DestIPPkts_P_State_P_Protocol_P_SrcIP
Removed
attackattack_typecategorydaddrdportflgsltimepkSeqIDprotosaddrseqsportstatestimesubcategory
keyboard_arrow_down

How it was run, and the separate checks

Same network (32-128-64-11), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 5 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 100-tree forests. Budget: protocol.

Separate checks (local run of the tool). Centralized training against isolated training: +91.0 [+88.2, +93.8] points. Flagging only (attack or not, type ignored): sharing +1.7 [+1.3, +2.1], federated +1.6 [+1.3, +2.0]. Nothing withheld: sharing +17.0 [+14.8, +19.1], federated +8.7 [+6.7, +10.7]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +30.7 points, 95% range [+25.9, +35.7].

computed by this tool on 08 November 2026 with the protocol budget on the working sample described above; the split is the tool's own

keyboard_arrow_down

About this dataset

Made by. UNSW Canberra Cyber Range (Koroniotis, Moustafa, Sitnikova and Turnbull, 2019)

Year. 2018

What it is. IoT testbed under DDoS, DoS, reconnaissance and theft attacks; Argus flow records with engineered rate features.

Records used. 95,944 flows sampled by attack type from the four 5% files

Attack types. DDoS and DoS (TCP, UDP, HTTP), service scan, OS fingerprint, keylogging, data exfiltration

Host or device column. destination IP

Source. https://research.unsw.edu.au/projects/bot-iot-dataset

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
