# results_card_17

Open a scorecard
N-BaIoT (nine IoT devices)

Nine commercial IoT devices infected with Mirai and BASHLITE (gafgyt); the device is the host, so organizations are device groups. Sampled per device and attack file.

tool test222,500 records115 behavior numbers kept1 columns removedorganizations by hosts3 seedsprotocol budget

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
3 hosts · trains on 37,500 records · 2,250 test records of the withheld type
withheld: gafgyt_comboDistributed denial of serviceT1498T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
92.8%
Federated learning
87.6%
Centralized training
99.5%
Fingerprint sharing (experimental)
61.2%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 5.41%, sharing 5.39%, federated 4.92%, centralized 5.11%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
33.0%
majority-host baseline
33.6%
Gain -0.6 points, 95% range between -1.5 and -0.1; 3 hosts; shuffle test p = 0.677.
Organization B
local run
3 hosts · trains on 31,250 records · 2,250 test records of the withheld type
withheld: gafgyt_junkDistributed denial of serviceT1498T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
99.3%
Federated learning
63.3%
Centralized training
96.8%
Fingerprint sharing (experimental)
88.9%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 4.59%, sharing 5.32%, federated 4.86%, centralized 6.07%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
32.6%
majority-host baseline
41.2%
Gain -8.6 points, 95% range between -10.1 and -7.8; 3 hosts; shuffle test p = 0.622.
Organization C
local run
3 hosts · trains on 31,250 records · 2,250 test records of the withheld type
withheld: gafgyt_scanReconnaissance and scanningT1595T1046T0846
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
99.7%
Federated learning
80.0%
Centralized training
99.7%
Fingerprint sharing (experimental)
98.8%
Sanitized attack-record sharing
worth it (gain met, its sent records not traced)
Federated learning
gain met
False-positive rate. isolated 4.67%, sharing 4.67%, federated 4.89%, centralized 4.49%.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
27.2%
majority-host baseline
41.0%
Gain -13.9 points, 95% range between -14.2 and -13.1; 3 hosts; shuffle test p = 0.891.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+97.3 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. 95% range [+97.0, +97.5], local run, not the run of record.
5-point rule
100 points
H2 · FEDERATED
supported
+76.9 points
Federated learning: mean gain in attack-class recall over the three organizations. 95% range [+76.3, +77.6], local run, not the run of record.
5-point rule
100 points
H3 · TRACING
not observed
Not all 3 organizations
Sanitized attack records traced above the majority-host baseline. Gain over the baseline from -13.9 to -0.6 points, local run. An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.
FINGERPRINTS
experimental
+82.9 points
Fingerprint sharing: not a praxis training condition. 95% range [+82.2, +83.7], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

Organization A, withheld attack type gafgyt_combo, 2,250 test records of that type (local run of the tool)

Attack family: Distributed denial of service. MITRE ATT&CK: T1498 Network Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	5.41%	baseline	0	17,873	baseline
Sanitized attack-record sharing	92.8%	100.0%	5.39%	+92.8 [+92.1, +93.4]	25.36 MB	17,873	worth it (gain met, its sent records not traced)
Federated learning	87.6%	100.0%	4.92%	+87.6 [+86.7, +88.4]	1.14 MB	18,792	gain met
Centralized training	99.5%	100.0%	5.11%	+99.5 [+99.3, +99.7]	17.29 MB	17,873	reference
Fingerprint sharing (experimental, not a praxis condition)	61.2%	100.0%	4.00%	+61.2 [+59.2, +63.1]	812 KB	17,873	gain met (exposure of the fingerprint not measured)

Organization B, withheld attack type gafgyt_junk, 2,250 test records of that type (local run of the tool)

Attack family: Distributed denial of service. MITRE ATT&CK: T1498 Network Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	100.0%	4.59%	baseline	0	17,873	baseline
Sanitized attack-record sharing	99.3%	100.0%	5.32%	+99.3 [+99.0, +99.5]	28.24 MB	17,873	worth it (gain met, its sent records not traced)
Federated learning	63.3%	100.0%	4.86%	+63.3 [+61.6, +65.0]	1.14 MB	18,792	gain met
Centralized training	96.8%	100.0%	6.07%	+96.8 [+96.3, +97.2]	14.41 MB	17,873	reference
Fingerprint sharing (experimental, not a praxis condition)	88.9%	100.0%	5.76%	+88.9 [+87.8, +90.0]	812 KB	17,873	not worth it (false-positive rate up more than 1 point; exposure of the fingerprint not measured)

Organization C, withheld attack type gafgyt_scan, 2,250 test records of that type (local run of the tool)

Attack family: Reconnaissance and scanning. MITRE ATT&CK: T1595 Active Scanning (Enterprise); T1046 Network Service Discovery (Enterprise); T0846 Remote System Discovery (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a local run of the tool.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT
Isolated training	0.0%	98.3%	4.67%	baseline	0	17,873	baseline
Sanitized attack-record sharing	99.7%	100.0%	4.67%	+99.7 [+99.5, +99.9]	28.24 MB	17,873	worth it (gain met, its sent records not traced)
Federated learning	80.0%	100.0%	4.89%	+80.0 [+79.3, +80.7]	1.14 MB	18,792	gain met
Centralized training	99.7%	100.0%	4.49%	+99.7 [+99.5, +99.9]	14.41 MB	17,873	reference
Fingerprint sharing (experimental, not a praxis condition)	98.8%	99.6%	5.07%	+98.8 [+98.4, +99.1]	812 KB	17,873	gain met (exposure of the fingerprint not measured)
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
Organization A	3	41,250	gafgyt_combo	3,750	37,500	3,750	33,750	2,250	2250
Organization B	3	35,000	gafgyt_junk	3,750	31,250	3,750	27,500	2,250	2250
Organization C	3	35,000	gafgyt_scan	3,750	31,250	3,750	27,500	2,250	2250

Organizations: organizations = groups of hosts (each host belongs to one organization). Split: class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

117 columns in the table given to the tool. Kept: 115 behavior numbers and the attack type. Removed: 1 columns (identifiers, text, other labels).

Kept
MI_dir_L5_weightMI_dir_L5_meanMI_dir_L5_varianceMI_dir_L3_weightMI_dir_L3_meanMI_dir_L3_varianceMI_dir_L1_weightMI_dir_L1_meanMI_dir_L1_varianceMI_dir_L0.1_weightMI_dir_L0.1_meanMI_dir_L0.1_varianceMI_dir_L0.01_weightMI_dir_L0.01_meanMI_dir_L0.01_varianceH_L5_weightH_L5_meanH_L5_varianceH_L3_weightH_L3_meanH_L3_varianceH_L1_weightH_L1_meanH_L1_varianceH_L0.1_weightH_L0.1_meanH_L0.1_varianceH_L0.01_weightH_L0.01_meanH_L0.01_varianceHH_L5_weightHH_L5_meanHH_L5_stdHH_L5_magnitudeHH_L5_radiusHH_L5_covarianceHH_L5_pccHH_L3_weightHH_L3_meanHH_L3_stdHH_L3_magnitudeHH_L3_radiusHH_L3_covarianceHH_L3_pccHH_L1_weightHH_L1_meanHH_L1_stdHH_L1_magnitudeHH_L1_radiusHH_L1_covarianceHH_L1_pccHH_L0.1_weightHH_L0.1_meanHH_L0.1_stdHH_L0.1_magnitudeHH_L0.1_radiusHH_L0.1_covarianceHH_L0.1_pccHH_L0.01_weightHH_L0.01_meanHH_L0.01_stdHH_L0.01_magnitudeHH_L0.01_radiusHH_L0.01_covarianceHH_L0.01_pccHH_jit_L5_weightHH_jit_L5_meanHH_jit_L5_varianceHH_jit_L3_weightHH_jit_L3_meanHH_jit_L3_varianceHH_jit_L1_weightHH_jit_L1_meanHH_jit_L1_varianceHH_jit_L0.1_weightHH_jit_L0.1_meanHH_jit_L0.1_varianceHH_jit_L0.01_weightHH_jit_L0.01_meanHH_jit_L0.01_varianceHpHp_L5_weightHpHp_L5_meanHpHp_L5_stdHpHp_L5_magnitudeHpHp_L5_radiusHpHp_L5_covarianceHpHp_L5_pccHpHp_L3_weightHpHp_L3_meanHpHp_L3_stdHpHp_L3_magnitudeHpHp_L3_radiusHpHp_L3_covarianceHpHp_L3_pccHpHp_L1_weightHpHp_L1_meanHpHp_L1_stdHpHp_L1_magnitudeHpHp_L1_radiusHpHp_L1_covarianceHpHp_L1_pccHpHp_L0.1_weightHpHp_L0.1_meanHpHp_L0.1_stdHpHp_L0.1_magnitudeHpHp_L0.1_radiusHpHp_L0.1_covarianceHpHp_L0.1_pccHpHp_L0.01_weightHpHp_L0.01_meanHpHp_L0.01_stdHpHp_L0.01_magnitudeHpHp_L0.01_radiusHpHp_L0.01_covarianceHpHp_L0.01_pcc
Removed
attack_typedevice
keyboard_arrow_down

How it was run, and the separate checks

Same network (115-128-64-11), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 6 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 50-tree forests on at most 5,000 records per side. Budget: protocol (shuffle test on 5,000 records per side, 50-tree forests).

Separate checks (local run of the tool). Centralized training against isolated training: +98.7 [+98.5, +98.8] points. Flagging only (attack or not, type ignored): sharing +0.6 [+0.4, +0.7], federated +0.6 [+0.4, +0.7]. Nothing withheld: sharing +0.9 [+0.8, +1.1], federated -12.8 [-13.6, -12.0]. Membership test on model weights: not measured in this tool.

Sharing minus federated, same test events, local run: +20.3 points, 95% range [+19.6, +21.0].

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

keyboard_arrow_down

About this dataset

Made by. Meidan, Bohadana, Mathov, Mirsky, Breitenbacher, Shabtai and Elovici (2018), UCI 442

Year. 2018

What it is. Traffic statistics (115 features over several time windows) of nine IoT devices, benign and under ten botnet attack types.

Records used. sampled per device and file

Attack types. gafgyt combo, junk, scan, tcp, udp; mirai ack, scan, syn, udp, udpplain

Host or device column. device

Source. https://doi.org/10.24432/C5RC8J

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
