# results_card_21

Open a scorecard
ToN_IoT network (Train_Test_Network)

The original ToN_IoT network subset (Zeek logs): nine attack types, destination host as the organization asset, no clock column. Working sample of 119,994 records.

tool test119,994 records12 behavior numbers kept31 columns removedorganizations by hosts3 seedsprotocol budget

The table has no time column, so every record is its own event and the 95% ranges are optimistic.

STEPS 3 AND 4
Four training conditions, tested on the withheld attack type
Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
Fingerprint sharing (experimental, not a praxis condition)
Organization A
local run
190 hosts · trains on 22,645 records · 1,272 test records of the withheld type
withheld: ddosDistributed denial of serviceT1498T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
59.2%
Federated learning
0.0%
Centralized training
31.1%
Fingerprint sharing (experimental)
86.7%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 5.14%, sharing 4.94%, federated 4.83%, centralized 5.06%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
15.1%
majority-host baseline
35.1%
Gain -20.0 points, 95% range between -25.6 and -23.8; 48 hosts; shuffle test p = 1.000.
Organization B
local run
190 hosts · trains on 16,277 records · 1,496 test records of the withheld type
withheld: dosDenial of serviceT1499T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
3.6%
Federated learning
0.0%
Centralized training
5.1%
Fingerprint sharing (experimental)
4.3%
Sanitized attack-record sharing
not worth it (gain not met)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 1.88%, sharing 4.69%, federated 6.64%, centralized 3.95%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
0.1%
majority-host baseline
39.4%
Gain -39.3 points, 95% range between -40.1 and -38.6; 39 hosts; shuffle test p = 0.995.
Organization C
local run
189 hosts · trains on 12,928 records · 2,100 test records of the withheld type
withheld: xssWeb and injectionT1190T0819
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
14.0%
Federated learning
0.0%
Centralized training
14.1%
Fingerprint sharing (experimental)
21.6%
Sanitized attack-record sharing
not worth it (false-positive rate up more than 1 point)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 4.58%, sharing 6.07%, federated 1.94%, centralized 4.94%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
21.1%
majority-host baseline
37.5%
Gain -16.4 points, 95% range between -12.7 and -11.4; 47 hosts; shuffle test p = 1.000.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+25.6 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. 95% range [+24.9, +26.3], local run, not the run of record.
5-point rule
100 points
H2 · FEDERATED
not supported
+0.0 points
Federated learning: mean gain in attack-class recall over the three organizations. 95% range [+0.0, +0.0], local run, not the run of record.
5-point rule
100 points
H3 · TRACING
not observed
Not all 3 organizations
Sanitized attack records traced above the majority-host baseline. Gain over the baseline from -39.3 to -16.4 points, local run. An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.
FINGERPRINTS
experimental
+37.5 points
Fingerprint sharing: not a praxis training condition. 95% range [+36.7, +38.4], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type ddos, 1,272 test records of that type (local run of the tool)

Attack family: Distributed denial of service. MITRE ATT&CK: T1498 Network Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	99.9%	5.14%	baseline	0	10,797	baseline
Sanitized attack-record sharing	59.2%	100.0%	4.94%	+59.2 [+57.9, +60.5]	1.24 MB	10,797	worth it (gain met, its sent records not traced)
Federated learning	0.0%	99.8%	4.83%	+0.0 [+0.0, +0.0]	592 KB	11,368	not worth it (gain not met)
Centralized training	31.1%	99.9%	5.06%	+31.1 [+30.2, +32.0]	1.11 MB	10,797	reference
Fingerprint sharing (experimental, not a praxis condition)	86.7%	99.9%	5.26%	+86.7 [+84.9, +88.6]	29 KB	10,797	gain met (exposure of the fingerprint not measured)

Organization B, withheld attack type dos, 1,496 test records of that type (local run of the tool)

Attack family: Denial of service. MITRE ATT&CK: T1499 Endpoint Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	83.9%	1.88%	baseline	0	10,797	baseline
Sanitized attack-record sharing	3.6%	82.0%	4.69%	+3.6 [+2.9, +4.5]	1.35 MB	10,797	not worth it (gain not met)
Federated learning	0.0%	1.7%	6.64%	+0.0 [+0.0, +0.0]	592 KB	11,368	not worth it (gain not met)
Centralized training	5.1%	80.6%	3.95%	+5.1 [+4.2, +6.0]	798 KB	10,797	reference
Fingerprint sharing (experimental, not a praxis condition)	4.3%	83.2%	4.06%	+4.3 [+3.5, +5.2]	29 KB	10,797	not worth it (gain not met; exposure of the fingerprint not measured)

Organization C, withheld attack type xss, 2,100 test records of that type (local run of the tool)

Attack family: Web and injection. MITRE ATT&CK: T1190 Exploit Public-Facing Application (Enterprise); T0819 Exploit Public-Facing Application (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	4.58%	baseline	0	10,797	baseline
Sanitized attack-record sharing	14.0%	100.0%	6.07%	+14.0 [+12.5, +15.5]	1.57 MB	10,797	not worth it (false-positive rate up more than 1 point)
Federated learning	0.0%	83.2%	1.94%	+0.0 [+0.0, +0.0]	592 KB	11,368	not worth it (gain not met)
Centralized training	14.1%	100.0%	4.94%	+14.1 [+12.7, +15.5]	633 KB	10,797	reference
Fingerprint sharing (experimental, not a praxis condition)	21.6%	99.9%	5.64%	+21.6 [+19.9, +23.3]	36 KB	10,797	not worth it (false-positive rate up more than 1 point; exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	190	24,765	ddos	2,120	22,645	5,516	17,129	1,272	1272
Organization B	190	18,770	dos	2,493	16,277	1,422	14,855	1,496	1496
Organization C	189	16,461	xss	3,533	12,928	2,483	10,445	2,100	2100

Organizations: organizations = groups of hosts (each host belongs to one organization). Split: class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

44 columns in the table given to the tool. Kept: 12 behavior numbers and the attack type. Removed: 31 columns (identifiers, text, other labels).

Kept
durationsrc_bytesdst_bytesmissed_bytessrc_pktsdst_pktsdns_qclassdns_qtypedns_rcodehttp_request_body_lenhttp_response_body_lenhttp_status_code
Removed
conn_statedns_AAdns_RAdns_RDdns_querydns_rejecteddst_ipdst_ip_bytesdst_porthttp_methodhttp_orig_mime_typeshttp_resp_mime_typeshttp_trans_depthhttp_urihttp_user_agenthttp_versionlabelprotoservicesrc_ipsrc_ip_bytessrc_portssl_cipherssl_establishedssl_issuerssl_resumedssl_subjectssl_versiontypeweird_addlweird_nameweird_notice
keyboard_arrow_down

How it was run, and the separate checks

Same network (12-128-64-10), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 7 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 50-tree forests on at most 5,000 records per side. Budget: protocol (shuffle test on 5,000 records per side, 50-tree forests).

Separate checks (local run of the tool). Centralized training against isolated training: +16.8 [+16.1, +17.4] points. Flagging only (attack or not, type ignored): sharing -0.6 [-0.9, -0.3], federated -33.0 [-33.9, -32.2]. Nothing withheld: sharing -25.9 [-26.6, -25.1], federated -63.8 [-64.5, -63.2]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +25.6 points, 95% range [+24.9, +26.3].

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

keyboard_arrow_down

About this dataset

Made by. UNSW Canberra Cyber Range (Moustafa, 2021)

Year. 2019

What it is. IoT and IIoT testbed with cloud, fog and edge layers; Zeek connection records with DNS, SSL and HTTP fields.

Records used. 119,994 records sampled by attack type

Attack types. backdoor, DDoS, DoS, injection, MITM, password, ransomware, scanning, XSS

Host or device column. destination IP

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
