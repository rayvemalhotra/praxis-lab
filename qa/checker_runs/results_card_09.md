# results_card_09

Open a scorecard
DataSense CIC IIoT 2025 (the study)

Industrial IoT testbed, 38 devices in the files analyzed, one record per 10 seconds per device: 59 behavior numbers (52 network, 7 log) and the attack type. The organizations are simulated: device groups by role.

the study29,574 records59 behavior numbers kept34 columns removedorganizations by hosts3 seedsprotocol budget
Run of record. The praxis run of record for DataSense (Hex, 11 October 2026, three seeds) reports H1 +41.1 points [32.5, 49.6] and H2 +45.8 points [37.0, 53.9]. The rerun shown here was computed on another machine; the decimals differ and every decision is the same.
STEPS 3 AND 4
Four training conditions, tested on the withheld attack type
Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
Fingerprint sharing (experimental, not a praxis condition)
A, network gear
tool rerun
7 hosts · trains on 3,567 records · 240 test records of the withheld type
withheld: dosDenial of serviceT1499T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
59.7%
Federated learning
57.6%
Centralized training
65.6%
Fingerprint sharing (experimental)
50.1%
Sanitized attack-record sharing
trade-off (gain met, its sent records traced)
Federated learning
gain met
False-positive rate. isolated 6.99%, sharing 6.10%, federated 4.32%, centralized 6.99%.
Run of record, recall: isolated 0.0%, sharing 59.9%, federated 57.6%, centralized 65.3%. The bars above are a tool rerun, not the run of record.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
55.3%
majority-device baseline
34.5%
Gain +20.7 points, 95% range between +11.8 and +29.1; 7 hosts; shuffle test p = 0.005.
B, cameras
tool rerun
10 hosts · trains on 3,284 records · 242 test records of the withheld type
withheld: ddosDistributed denial of serviceT1498T0814
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
63.1%
Federated learning
80.3%
Centralized training
67.6%
Fingerprint sharing (experimental)
62.8%
Sanitized attack-record sharing
trade-off (gain met, its sent records traced)
Federated learning
gain met
False-positive rate. isolated 6.32%, sharing 6.18%, federated 5.49%, centralized 7.22%.
Run of record, recall: isolated 0.0%, sharing 63.5%, federated 79.9%, centralized 67.8%. The bars above are a tool rerun, not the run of record.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
41.2%
majority-device baseline
16.9%
Gain +24.3 points, 95% range between +17.6 and +32.2; 10 hosts; shuffle test p = 0.005.
C, sensors and plugs
tool rerun
21 hosts · trains on 7,576 records · 140 test records of the withheld type
withheld: mitmAdversary in the middleT1557T0830
ATTACK-CLASS RECALL ON THE WITHHELD TYPE
Isolated training
0.0%
Sanitized attack-record sharing
0.0%
Federated learning
0.0%
Centralized training
0.0%
Fingerprint sharing (experimental)
0.0%
Sanitized attack-record sharing
not worth it (gain not met)
Federated learning
not worth it (gain not met)
False-positive rate. isolated 4.65%, sharing 4.99%, federated 6.42%, centralized 5.41%.
Run of record, recall: isolated 0.0%, sharing 0.0%, federated 0.0%, centralized 0.0%. The bars above are a tool rerun, not the run of record.
Tracing. A peer traced this organization's sanitized attack records to their source host:
traced to the source host
41.1%
majority-device baseline
7.3%
Gain +33.8 points, 95% range between +23.9 and +41.1; 21 hosts; shuffle test p = 0.005.

The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis. What a fingerprint reveals about its sender has not been measured.

STEP 5
Scorecard
H1 · SANITIZED SHARING
supported
+41.1 points
Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations. Run of record (Hex, 11 October 2026), 95% range [+32.5, +49.6]. The tool rerun on another machine gave +40.9 [+32.3, +49.5], not the run of record; the decision is the same.
5-point rule
100 points
H2 · FEDERATED
supported
+45.8 points
Federated learning: mean gain in attack-class recall over the three organizations. Run of record (Hex, 11 October 2026), 95% range [+37.0, +53.9]. The tool rerun on another machine gave +46.0 [+37.1, +54.1], not the run of record; the decision is the same.
5-point rule
100 points
H3 · TRACING
observed
All 3 organizations
Sanitized attack records traced above the majority-device baseline. Gain over the baseline from +20.7 to +33.8 points, tool rerun. Observed finding: tracing exceeded the majority-device baseline for every sender under the labelled-reference assumption. The statistical support is not called settled yet: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings. This is an open item of the praxis.
FINGERPRINTS
experimental
+37.6 points
Fingerprint sharing: not a praxis training condition. 95% range [+30.3, +44.7], local run. What a fingerprint reveals about its sender has not been measured.
5-point rule
100 points
keyboard_arrow_down

All numbers: every training condition for each organization

A, network gear, withheld attack type dos, 240 test records of that type (tool rerun; the run of record is in the last two columns)

Attack family: Denial of service. MITRE ATT&CK: T1499 Endpoint Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a tool rerun, not the run of record.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT	RUN OF RECORD, RECALL	RUN OF RECORD, FALSE-POSITIVE RATE
Isolated training	0.0%	95.8%	6.99%	baseline	0	3,660	baseline	0.0%	6.99%
Sanitized attack-record sharing	59.7%	96.9%	6.10%	+59.7 [+40.2, +78.0]	1.25 MB	3,660	trade-off (gain met, its sent records traced)	59.9%	6.15%
Federated learning	57.6%	98.1%	4.32%	+57.6 [+37.6, +76.5]	1.05 MB	3,648	gain met	57.6%	4.37%
Centralized training	65.6%	97.6%	6.99%	+65.6 [+48.6, +81.1]	845 KB	3,660	reference	65.3%	7.14%
Fingerprint sharing (experimental, not a praxis condition)	50.1%	95.8%	8.33%	+50.1 [+35.0, +65.0]	132 KB	3,660	not worth it (false-positive rate up more than 1 point; exposure of the fingerprint not measured)	not part of the praxis	not part of the praxis

B, cameras, withheld attack type ddos, 242 test records of that type (tool rerun; the run of record is in the last two columns)

Attack family: Distributed denial of service. MITRE ATT&CK: T1498 Network Denial of Service (Enterprise); T0814 Denial of Service (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a tool rerun, not the run of record.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT	RUN OF RECORD, RECALL	RUN OF RECORD, FALSE-POSITIVE RATE
Isolated training	0.0%	98.8%	6.32%	baseline	0	3,660	baseline	0.0%	6.32%
Sanitized attack-record sharing	63.1%	98.1%	6.18%	+63.1 [+45.2, +79.6]	1.45 MB	3,660	trade-off (gain met, its sent records traced)	63.5%	6.53%
Federated learning	80.3%	98.1%	5.49%	+80.3 [+63.1, +93.9]	1.05 MB	3,648	gain met	79.9%	5.45%
Centralized training	67.6%	98.2%	7.22%	+67.6 [+51.5, +83.3]	778 KB	3,660	reference	67.8%	6.67%
Fingerprint sharing (experimental, not a praxis condition)	62.8%	98.5%	5.49%	+62.8 [+46.6, +77.8]	165 KB	3,660	gain met (exposure of the fingerprint not measured)	not part of the praxis	not part of the praxis

C, sensors and plugs, withheld attack type mitm, 140 test records of that type (tool rerun; the run of record is in the last two columns)

Attack family: Adversary in the middle. MITRE ATT&CK: T1557 Adversary-in-the-Middle (Enterprise); T0830 Adversary-in-the-Middle (ICS). The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it. The table below is a tool rerun, not the run of record.

TRAINING CONDITION	RECALL, WITHHELD TYPE	FLAGGED	FALSE-POSITIVE RATE	GAIN VS ISOLATED, THIS LOCAL RUN [95% RANGE]	DATA SENT	STEPS	VERDICT	RUN OF RECORD, RECALL	RUN OF RECORD, FALSE-POSITIVE RATE
Isolated training	0.0%	61.9%	4.65%	baseline	0	3,660	baseline	0.0%	4.68%
Sanitized attack-record sharing	0.0%	50.2%	4.99%	+0.0 [+0.0, +0.0]	898 KB	3,660	not worth it (gain not met)	0.0%	4.98%
Federated learning	0.0%	47.1%	6.42%	+0.0 [+0.0, +0.0]	1.05 MB	3,648	not worth it (gain not met)	0.0%	6.53%
Centralized training	0.0%	49.3%	5.41%	+0.0 [+0.0, +0.0]	1.80 MB	3,660	reference	0.0%	5.47%
Fingerprint sharing (experimental, not a praxis condition)	0.0%	55.2%	4.68%	+0.0 [+0.0, +0.0]	165 KB	3,660	not worth it (gain not met; exposure of the fingerprint not measured)	not part of the praxis	not part of the praxis
keyboard_arrow_down

Step 1: the three organizations and their withheld attack types

ORGANIZATION	HOSTS	TRAINING RECORDS	WITHHELD ATTACK TYPE	TAKEN OUT	TRAINS ON	OF WHICH NORMAL	OF WHICH ATTACK	TEST RECORDS OF THE WITHHELD TYPE	ATTACK EVENTS IN THOSE
A, network gear	7	3,959	dos	392	3,567	1,260	2,307	240	24
B, cameras	10	3,680	ddos	396	3,284	1,800	1,484	242	22
C, sensors and plugs	21	7,868	mitm	292	7,576	3,780	3,796	140	11

Organizations: organizations = device groups by role (network gear, cameras, sensors). Split: audited event split of the study (train/validation/test by attack event and by time).

keyboard_arrow_down

Step 2: sanitizing, which columns were kept and which were removed

94 columns in the table given to the tool. Kept: 59 behavior numbers and the attack type. Removed: 34 columns (identifiers, text, other labels).

Kept
log_data-ranges_avglog_data-ranges_maxlog_data-ranges_minlog_data-ranges_std_deviationlog_data-types_countlog_interval-messageslog_messages_countnetwork_fragmentation-scorenetwork_fragmented-packetsnetwork_header-length_avgnetwork_header-length_maxnetwork_header-length_minnetwork_header-length_std_deviationnetwork_interval-packetsnetwork_ip-flags_avgnetwork_ip-flags_maxnetwork_ip-flags_minnetwork_ip-flags_std_deviationnetwork_ip-length_avgnetwork_ip-length_maxnetwork_ip-length_minnetwork_ip-length_std_deviationnetwork_mss_avgnetwork_mss_maxnetwork_mss_minnetwork_mss_std_deviationnetwork_packet-size_avgnetwork_packet-size_maxnetwork_packet-size_minnetwork_packet-size_std_deviationnetwork_packets_all_countnetwork_packets_dst_countnetwork_packets_src_countnetwork_payload-length_avgnetwork_payload-length_maxnetwork_payload-length_minnetwork_payload-length_std_deviationnetwork_tcp-flags-ack_countnetwork_tcp-flags-fin_countnetwork_tcp-flags-psh_countnetwork_tcp-flags-rst_countnetwork_tcp-flags-syn_countnetwork_tcp-flags-urg_countnetwork_tcp-flags_avgnetwork_tcp-flags_maxnetwork_tcp-flags_minnetwork_tcp-flags_std_deviationnetwork_time-delta_avgnetwork_time-delta_maxnetwork_time-delta_minnetwork_time-delta_std_deviationnetwork_ttl_avgnetwork_ttl_maxnetwork_ttl_minnetwork_ttl_std_deviationnetwork_window-size_avgnetwork_window-size_maxnetwork_window-size_minnetwork_window-size_std_deviation
Removed
device_macdevice_namelabel1label3label4label_fulllog_data-typesnetwork_ips_allnetwork_ips_all_countnetwork_ips_dstnetwork_ips_dst_countnetwork_ips_srcnetwork_ips_src_countnetwork_macs_allnetwork_macs_all_countnetwork_macs_dstnetwork_macs_dst_countnetwork_macs_srcnetwork_macs_src_countnetwork_ports_allnetwork_ports_all_countnetwork_ports_dstnetwork_ports_dst_countnetwork_ports_srcnetwork_ports_src_countnetwork_protocols_allnetwork_protocols_all_countnetwork_protocols_dstnetwork_protocols_dst_countnetwork_protocols_srcnetwork_protocols_src_counttimestamptimestamp_endtimestamp_start
keyboard_arrow_down

How it was run, and the separate checks

Same network (59-128-64-8), the same step budget per tested detector (61 passes of the largest organization at batch 128; the steps of each training condition are in the tables above), same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: 8 rounds, 4 local passes per round. Seeds: 3.

Tracing test: 5 random forests of 300 trees on at most 15,000 records per side; shuffle test 200 shuffles with 100-tree forests. Budget: protocol.

Separate checks (local run of the tool). Centralized training against isolated training: +44.4 [+36.7, +51.7] points. Flagging only (attack or not, type ignored): sharing -3.7 [-8.9, +0.5], federated -4.4 [-10.6, +1.0]. Nothing withheld: sharing +0.9 [-4.6, +6.5], federated +0.4 [-6.1, +7.4]. Membership test on model weights: not measured in this tool.

Tool rerun above. Run of record for the same checks: centralized +44.4 [+36.6, +51.7]; flagging only sharing -3.5 [-8.9, +0.5], federated -4.1 [-10.2, +0.8]; nothing withheld sharing +2.3 [-3.9, +8.2], federated +0.8 [-6.0, +7.7]; membership test (separate 10-round run) no clear signal, all six 95% ranges include 0.5.

Sharing minus federated, same test events, local run: -5.0 points, 95% range [-14.9, +4.6].

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

keyboard_arrow_down

About this dataset

Made by. Canadian Institute for Cybersecurity, University of New Brunswick (Firouzi, Dadkhah, Maret and Ghorbani, 2025)

Year. 2025

What it is. An industrial IoT testbed. The files analyzed hold 38 devices (routers, an MQTT broker, cameras, sensors, smart plugs) recorded under normal use and under attack. Each record summarizes 10 seconds of one device as 59 numbers (52 about its network traffic, 7 about its log messages) plus the attack name.

Records used. 29,574 records used (the audited split of the praxis)

Attack types. 7 attack types: DoS, DDoS, MITM, reconnaissance, malware, brute force, web

Host or device column. device name (38 devices in the files analyzed)

Role in the praxis. The praxis claims about H1, H2 and H3 rest on this dataset alone. The three organizations are simulated: groups of the testbed's devices by role. The train/validation/test split was audited on 23 September.

Source. https://doi.org/10.3390/electronics14204095

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
