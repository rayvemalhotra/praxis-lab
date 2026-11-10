# text_of_the_result_card_files

## bot_iot.json

BoT-IoT 5% (Kaggle)

IoT botnet testbed, flow records. Very few benign records in the 5% release, so the alarm threshold rests on a small benign sample. Working sample of 18,556 records.

08 Nov 2026, 21:10

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

gain met, false-positive limit breached

gain met

gain met, false-positive limit breached

tool test

BoT-IoT (5% release)

Koroniotis, Moustafa, Sitnikova and Turnbull (2019), UNSW Canberra Cyber Range

A smart-home IoT testbed under botnet attack, recorded as network flows. The public 5% release is almost entirely attack traffic: only 477 normal records in the sample.

18,556 records used, a class-stratified sample of the 5% release

4 attack types: DDoS, DoS, reconnaissance, theft

destination address

Tool check

Same system, new data. Not study evidence. The alarm threshold rests on very few normal records, so false alarms run high.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## bot_iot_5pct.json

BoT-IoT, 5% release (four files)

IoT botnet testbed flows. The 5% release holds only 477 normal records, so the alarm threshold rests on a small normal sample. Working sample of 95,944 flows; attack type = category and subcategory.

08 Nov 2026, 22:47

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

gain met

gain met

gain met

tool test

BoT-IoT 5%

UNSW Canberra Cyber Range (Koroniotis, Moustafa, Sitnikova and Turnbull, 2019)

IoT testbed under DDoS, DoS, reconnaissance and theft attacks; Argus flow records with engineered rate features.

95,944 flows sampled by attack type from the four 5% files

DDoS and DoS (TCP, UDP, HTTP), service scan, OS fingerprint, keylogging, data exfiltration

destination IP

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met, false-positive limit breached

09 November 2026

## cic_ids2017.json

CIC-IDS2017 (labelled flows)

University network testbed, five days of flows with 14 attack types. Destination host is the organization asset. Working sample of 120,013 flows from 3,119,345 (unlabelled rows left out).

08 Nov 2026, 23:02

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

DoS Hulk

Flow Duration

Total Fwd Packets

Total Backward Packets

Total Length of Fwd Packets

Total Length of Bwd Packets

Fwd Packet Length Max

Fwd Packet Length Min

Fwd Packet Length Mean

Fwd Packet Length Std

Bwd Packet Length Max

Bwd Packet Length Min

Bwd Packet Length Mean

Bwd Packet Length Std

Flow Bytes/s

Flow Packets/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Total

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Total

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Fwd PSH Flags

Fwd URG Flags

Fwd Header Length

Bwd Header Length

Fwd Packets/s

Bwd Packets/s

Min Packet Length

Max Packet Length

Packet Length Mean

Packet Length Std

Packet Length Variance

FIN Flag Count

SYN Flag Count

RST Flag Count

PSH Flag Count

ACK Flag Count

URG Flag Count

CWE Flag Count

ECE Flag Count

Down/Up Ratio

Average Packet Size

Avg Fwd Segment Size

Avg Bwd Segment Size

Fwd Header Length.1

Subflow Fwd Packets

Subflow Fwd Bytes

Subflow Bwd Packets

Subflow Bwd Bytes

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

Bwd Avg Bulk Rate

Bwd Avg Bytes/Bulk

Bwd Avg Packets/Bulk

Bwd PSH Flags

Bwd URG Flags

Destination IP

Destination Port

Flow ID

Fwd Avg Bulk Rate

Fwd Avg Bytes/Bulk

Fwd Avg Packets/Bulk

Source IP

Source Port

DoS GoldenEye

DoS Hulk

DoS Slowhttptest

DoS slowloris

Web Attack Brute Force

Web Attack SQL Injection

Web Attack XSS

Organization A

the sender has 1,004 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 969 hosts; the test covers its 50 busiest hosts only

Organization C

DoS Hulk

the sender has 992 hosts; the test covers its 50 busiest hosts only

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Canadian Institute for Cybersecurity, University of New Brunswick (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)

Five working days of traffic on a small enterprise network: normal use plus brute force, DoS, DDoS, web attacks, infiltration, botnet and port scanning, as CICFlowMeter flows.

120,013 flows sampled by attack type

14 attack types

destination IP

Tool test: a public dataset run unchanged through the procedure

Cite the makers; analysis use. The raw files are not re-hosted here.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## cic_ids2017_improved.json

CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021)

The same five days re-extracted with a corrected CICFlowMeter and relabelled; 'Attempted' labels mark attacks that did not complete. Working sample of 120,069 flows.

08 Nov 2026, 23:05

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Infiltration - Portscan

Organization B

Organization C

DoS Hulk

Flow Duration

Total Fwd Packet

Total Bwd packets

Total Length of Fwd Packet

Total Length of Bwd Packet

Fwd Packet Length Max

Fwd Packet Length Min

Fwd Packet Length Mean

Fwd Packet Length Std

Bwd Packet Length Max

Bwd Packet Length Min

Bwd Packet Length Mean

Bwd Packet Length Std

Flow Bytes/s

Flow Packets/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Total

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Total

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Fwd PSH Flags

Bwd PSH Flags

Fwd URG Flags

Fwd RST Flags

Bwd RST Flags

Fwd Header Length

Bwd Header Length

Fwd Packets/s

Bwd Packets/s

Packet Length Min

Packet Length Max

Packet Length Mean

Packet Length Std

Packet Length Variance

FIN Flag Count

SYN Flag Count

RST Flag Count

PSH Flag Count

ACK Flag Count

URG Flag Count

CWR Flag Count

ECE Flag Count

Down/Up Ratio

Average Packet Size

Fwd Segment Size Avg

Bwd Segment Size Avg

Fwd Bytes/Bulk Avg

Fwd Packet/Bulk Avg

Fwd Bulk Rate Avg

Bwd Bytes/Bulk Avg

Bwd Packet/Bulk Avg

Bwd Bulk Rate Avg

Subflow Fwd Packets

Subflow Fwd Bytes

Subflow Bwd Packets

Subflow Bwd Bytes

FWD Init Win Bytes

Bwd Init Win Bytes

Fwd Act Data Pkts

Fwd Seg Size Min

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

ICMP Code

ICMP Type

Total TCP Flow Time

Attempted Category

Bwd URG Flags

Dst IP

Dst Port

Flow ID

Src IP

Src Port

Botnet - Attempted

DoS GoldenEye

DoS GoldenEye - Attempted

DoS Hulk

DoS Hulk - Attempted

DoS Slowhttptest

DoS Slowhttptest - Attempted

DoS Slowloris

DoS Slowloris - Attempted

FTP-Patator - Attempted

Infiltration - Attempted

Infiltration - Portscan

SSH-Patator - Attempted

Web Attack - Brute Force

Web Attack - Brute Force - Attempted

Web Attack - SQL Injection

Web Attack - SQL Injection - Attempted

Web Attack - XSS

Web Attack - XSS - Attempted

Organization A

Infiltration - Portscan

the sender has 852 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 839 hosts; the test covers its 50 busiest hosts only

Organization C

DoS Hulk

the sender has 905 hosts; the test covers its 50 busiest hosts only

gain met

gain met

gain met

gain met

gain met

gain met

tool test

CIC-IDS2017 improved

DistriNet, KU Leuven (Engelen, Troia and Vanhoef, 2021; Liu, Engelen, Lynar, Essam and Joosen, 2022)

CIC-IDS2017 traffic re-extracted after fixing CICFlowMeter errors (flow termination, TCP flags, duplicates) and relabelled flow by flow.

120,069 flows sampled by label

13 attack types, each also as an 'Attempted' variant

destination IP

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## ciciot2023.json

CICIoT2023 (merged flows)

105 real IoT devices under 33 attacks, aggregated packet windows. The published CSV files carry no addresses or clock, so organizations are random thirds and tracing cannot be tested. Working sample of 120,624 records from three merged files.

08 Nov 2026, 23:07

protocol (shuffle test on 5,000 records per side, 50-tree forests)

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = three random thirds of the records (no host column in this data)

Organization A

Organization B

Organization C

Protocol Type

Tot sum

Tot size

Organization A

Organization B

Organization C

this data has no device or host column, so tracing cannot be tested

gain met

gain met

gain met

gain met

gain met

not worth it (gain not met)

tool test

Canadian Institute for Cybersecurity (Neto, Dadkhah, Ferreira, Zohourian, Lu and Ghorbani, 2023)

A smart-home testbed of 105 IoT devices attacked by other IoT devices: DDoS, DoS, reconnaissance, web, brute force, spoofing and Mirai.

120,624 records sampled by label from Merged01, Merged25 and Merged50

33 attack types

none in the CSV release

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## cidds001.json

CIDDS-001 (OpenStack and external server flows)

Flow records from an emulated small business network (OpenStack) and an external server, four attack types; destination host as the organization asset. Working sample of 95,753 flows from two internal and two external weeks.; the makers' date column is named Timestamp in the sample

08 Nov 2026, 23:09

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Dst Pt

Dst IP Addr

Src IP Addr

Src Pt

Organization A

the sender has 800 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 720 hosts; the test covers its 50 busiest hosts only

Organization C

the sender has 843 hosts; the test covers its 50 busiest hosts only

gain met

not worth it (gain not met)

gain met, privacy trade-off

not worth it (gain not met)

not worth it (gain not met)

not worth it (gain not met)

tool test

Coburg University of Applied Sciences (Ring, Wunderlich, Grudl, Landes and Hotho, 2017)

NetFlow records of an emulated company network with clients, servers and an external server exposed to the Internet; attacks are DoS, port scans, ping scans and brute force.

95,753 flows sampled by attack type

dos, portScan, pingScan, bruteForce

destination IP

Tool test (few features)

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

not worth it (gain not met)

09 November 2026

## cse_cic_ids2018.json

CSE-CIC-IDS2018 (seven days)

Large enterprise testbed on AWS, flows from seven attack days: brute force, DoS, DDoS, web attacks and botnet. No host column in these day files, so organizations are random thirds. Working sample of up to 120,000 flows.

08 Nov 2026, 23:11

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (no host column in this data)

Organization A

Organization B

Organization C

DoS attacks-SlowHTTPTest

Flow Duration

Tot Fwd Pkts

Tot Bwd Pkts

TotLen Fwd Pkts

TotLen Bwd Pkts

Fwd Pkt Len Max

Fwd Pkt Len Min

Fwd Pkt Len Mean

Fwd Pkt Len Std

Bwd Pkt Len Max

Bwd Pkt Len Min

Bwd Pkt Len Mean

Bwd Pkt Len Std

Flow Byts/s

Flow Pkts/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Tot

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Tot

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Fwd PSH Flags

Fwd Header Len

Bwd Header Len

Fwd Pkts/s

Bwd Pkts/s

Pkt Len Min

Pkt Len Max

Pkt Len Mean

Pkt Len Std

Pkt Len Var

FIN Flag Cnt

SYN Flag Cnt

RST Flag Cnt

PSH Flag Cnt

ACK Flag Cnt

URG Flag Cnt

ECE Flag Cnt

Down/Up Ratio

Pkt Size Avg

Fwd Seg Size Avg

Bwd Seg Size Avg

Subflow Fwd Pkts

Subflow Fwd Byts

Subflow Bwd Pkts

Subflow Bwd Byts

Init Fwd Win Byts

Init Bwd Win Byts

Fwd Act Data Pkts

Fwd Seg Size Min

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

Bwd Blk Rate Avg

Bwd Byts/b Avg

Bwd PSH Flags

Bwd Pkts/b Avg

Bwd URG Flags

CWE Flag Count

Dst IP

Dst Port

Flow ID

Fwd Blk Rate Avg

Fwd Byts/b Avg

Fwd Pkts/b Avg

Fwd URG Flags

Src IP

Src Port

Brute Force -Web

Brute Force -XSS

DDOS attack-HOIC

DDOS attack-LOIC-UDP

DoS attacks-GoldenEye

DoS attacks-Hulk

DoS attacks-SlowHTTPTest

DoS attacks-Slowloris

SQL Injection

Organization A

Organization B

Organization C

DoS attacks-SlowHTTPTest

this data has no device or host column, so tracing cannot be tested

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Communications Security Establishment and the Canadian Institute for Cybersecurity (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)

An AWS testbed of 420 machines and 30 servers attacked over ten days; this sample uses seven day files of CICFlowMeter flows.

up to 120,000 flows sampled by label

brute force (FTP, SSH), DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest), DDoS (LOIC-UDP, HOIC), web attacks, botnet

none in the day files

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met, false-positive limit breached

gain met (exposure of the fingerprint not measured)

09 November 2026

## ctu13_nettisa.json

CTU-13 botnet families (NetTiSA flows)

Botnet traffic of the CTU-13 captures as NetTiSA extended flows, labelled by botnet family; few attack families with enough records. Source host as the organization asset. 41,070 flows.

08 Nov 2026, 23:12

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Unnamed: 0

Organization A

not enough source hosts or records to test tracing

Organization B

not enough source hosts or records to test tracing

Organization C

not enough source hosts or records to test tracing

gain met

gain met

gain met

gain met

gain met

gain met

tool test

CTU-13 (NetTiSA)

CESNET and CTU Prague (Koumar, Hynek, Cejka and Siska, 2023), Zenodo 8301043; original captures by Garcia et al. (2014)

Botnet captures (Neris, Rbot, Donbot, fast flux and others) re-extracted as NetTiSA flows with time-series statistics.

41,070 flows (the whole botnet_multiclass file, normal capped)

botnet families: neris, fast_flux, qvod, rbot, donbot

source IP

Tool test (few attack families)

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## datasense.json

DataSense CIC IIoT 2025 (the study)

Industrial IoT testbed, 38 devices in the files analyzed, one record per 10 seconds per device: 59 behavior numbers (52 network, 7 log) and the attack type. The organizations are simulated: device groups by role.

08 Nov 2026, 21:10

audited event split of the study (train/validation/test by attack event and by time)

organizations = device groups by role (network gear, cameras, sensors)

A, infrastructure

B, cameras

C, sensors

A, infrastructure

B, cameras

C, sensors

gain met, privacy trade-off

gain met

gain met, privacy trade-off

gain met

not worth it (gain not met)

not worth it (gain not met)

the study

DataSense CIC IIoT 2025

Canadian Institute for Cybersecurity, University of New Brunswick (Firouzi, Dadkhah, Maret and Ghorbani, 2025)

An industrial IoT testbed. The files analyzed hold 38 devices (routers, an MQTT broker, cameras, sensors, smart plugs) recorded under normal use and under attack. Each record summarizes 10 seconds of one device as 59 numbers (52 about its network traffic, 7 about its log messages) plus the attack name.

29,574 records used (the audited split of the praxis)

7 attack types: DoS, DDoS, MITM, reconnaissance, malware, brute force, web

device name (38 devices in the files analyzed)

Primary study dataset

The praxis claims about H1, H2 and H3 rest on this dataset alone. The three organizations are simulated: groups of the testbed's devices by role. The train/validation/test split was audited on 23 September.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met, false-positive limit breached

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## dnp3.json

DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout)

Power-grid SCADA traffic (DNP3) from nine attack captures, as CICFlowMeter flows; destination host as the organization asset. 41,596 flows.

08 Nov 2026, 23:14

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Flow Duration

Tot Fwd Pkts

Tot Bwd Pkts

TotLen Fwd Pkts

TotLen Bwd Pkts

Fwd Pkt Len Max

Fwd Pkt Len Min

Fwd Pkt Len Mean

Fwd Pkt Len Std

Bwd Pkt Len Max

Bwd Pkt Len Min

Bwd Pkt Len Mean

Bwd Pkt Len Std

Flow Byts/s

Flow Pkts/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Tot

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Tot

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Fwd PSH Flags

Bwd PSH Flags

Fwd Header Len

Bwd Header Len

Fwd Pkts/s

Bwd Pkts/s

Pkt Len Min

Pkt Len Max

Pkt Len Mean

Pkt Len Std

Pkt Len Var

SYN Flag Cnt

PSH Flag Cnt

ACK Flag Cnt

Down/Up Ratio

Pkt Size Avg

Fwd Seg Size Avg

Bwd Seg Size Avg

Bwd Pkts/b Avg

Bwd Blk Rate Avg

Subflow Fwd Pkts

Subflow Fwd Byts

Subflow Bwd Pkts

Subflow Bwd Byts

Init Fwd Win Byts

Init Bwd Win Byts

Fwd Act Data Pkts

Fwd Seg Size Min

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

 Label

Bwd Byts/b Avg

Bwd URG Flags

CWE Flag Count

Dst IP

Dst Port

ECE Flag Cnt

FIN Flag Cnt

Flow ID

Fwd Blk Rate Avg

Fwd Byts/b Avg

Fwd Pkts/b Avg

Fwd URG Flags

RST Flag Cnt

Src IP

Src Port

URG Flag Cnt

Organization A

Organization B

Organization C

gain met

not worth it (gain not met)

gain met, privacy trade-off

not worth it (gain not met)

not worth it (gain not met)

gain met

tool test

DNP3 IDS

University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7348493

Attacks against DNP3 SCADA communication: disable unsolicited messages, cold and warm restart, enumerate, info, initialize data, stop application, replay, MITM DoS, ARP poisoning.

41,596 flows (all CIC flows at the 120 s timeout)

10 attack types

destination IP

Tool test

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## edge_iiotset.json

Edge-IIoTset (ranking check)

IoT and IIoT testbed, packet records, 38 cleaned features. The praxis run used three class-stratified random thirds of the records as organizations. Tracing (H3) was not repeated on this dataset: normal traffic gives no device-labelled examples for one of the two attacked hosts.

08 Nov 2026, 21:10

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = three class-stratified random thirds of the records

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

not repeated on this dataset: normal traffic gives no device-labelled examples for one of the two attacked hosts

gain met

gain met, false-positive limit breached

gain met

gain met

gain met

gain met

ranking check

Ferrag, Friha, Hamouda, Maglaras and Janicke (2022), IEEE Access

An IoT and IIoT testbed with sensors, edge devices and cloud, recorded packet by packet. The praxis uses a cleaned copy (identifier and placeholder columns removed, 38 features) locked on 25 September.

134,981 records used (the full cleaned file)

14 attack types, e.g. DDoS (TCP, UDP, HTTP, ICMP), password, port scanning, SQL injection, XSS, MITM, ransomware, backdoor

the dataset has host address columns; the cleaned copy given to the tool keeps none of them

Second dataset: ranking check

Used to check that the ranking of the two approaches seen on DataSense holds on different data. The organizations are class-stratified random thirds of the records. Tracing (H3) was not repeated: normal traffic gives no device-labelled examples for one of the two attacked hosts.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## edge_iiotset_ml.json

Edge-IIoTset, ML subset (raw packet fields)

The makers' machine-learning subset with the raw packet fields, including the destination host and a clock. Working sample of 119,994 records.

08 Nov 2026, 23:16

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

the sender has 962 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 701 hosts; the test covers its 50 busiest hosts only

Organization C

the sender has 1,016 hosts; the test covers its 50 busiest hosts only

gain met

gain met

gain met

gain met

gain met

not worth it (gain not met)

tool test

Edge-IIoTset (ML subset)

Ferrag, Friha, Hamouda, Maglaras and Janicke (2022), IEEE Access

The same IoT and IIoT testbed as the praxis ranking check, in the makers' ML-ready CSV with packet fields, host columns and a clock.

119,994 records sampled by attack type

14 attack types

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## electra_modbus.json

Electra Modbus (electric traction substation)

Modbus TCP traffic of an electric traction substation with seven attack types; only five numbers per record (function code, error, address, data, request), so the detector has little to work with. Working sample of 119,994 records.

08 Nov 2026, 23:18

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

not worth it (gain not met)

gain met

gain met

tool test

Electra Modbus

University of Murcia (Gomez, Maimo, Celdran, Clemente, Sarmiento, Masa and Nistal, 2019)

Modbus packets in a railway traction substation under reconnaissance, read, write, replay, response, force-error and MITM attacks.

119,994 packets sampled by label from 16 million

7 attack types

destination IP

Tool test (few features)

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## electra_s7comm.json

Electra S7comm (electric traction substation)

S7comm traffic of the same substation with the same attack families as the Modbus set; few numbers per record. Working sample of up to 120,000 records.

08 Nov 2026, 23:21

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

not worth it (gain not met)

not worth it (gain not met)

not worth it (gain not met)

tool test

Electra S7comm

University of Murcia (Gomez et al., 2019)

S7comm packets in a railway traction substation under attack.

up to 120,000 packets sampled by label

see label values

destination IP

Tool test (few features)

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## iec104.json

IEC 60870-5-104 intrusion detection dataset (balanced flows)

Power-grid control traffic (IEC 104) with eleven attack types, as CICFlowMeter flows; the balanced release is small (6,828 flows, 569 per label). Destination host as the organization asset.

08 Nov 2026, 23:21

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Flow Duration

Tot Fwd Pkts

Tot Bwd Pkts

TotLen Fwd Pkts

TotLen Bwd Pkts

Fwd Pkt Len Max

Fwd Pkt Len Min

Fwd Pkt Len Mean

Fwd Pkt Len Std

Bwd Pkt Len Max

Bwd Pkt Len Min

Bwd Pkt Len Mean

Bwd Pkt Len Std

Flow Byts/s

Flow Pkts/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Tot

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Tot

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Fwd Header Len

Bwd Header Len

Fwd Pkts/s

Bwd Pkts/s

Pkt Len Min

Pkt Len Max

Pkt Len Mean

Pkt Len Std

Pkt Len Var

Down/Up Ratio

Pkt Size Avg

Fwd Seg Size Avg

Bwd Seg Size Avg

Subflow Fwd Pkts

Subflow Fwd Byts

Subflow Bwd Pkts

Subflow Bwd Byts

Init Bwd Win Byts

Fwd Act Data Pkts

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

ACK Flag Cnt

Bwd Blk Rate Avg

Bwd Byts/b Avg

Bwd PSH Flags

Bwd Pkts/b Avg

Bwd URG Flags

CWE Flag Count

Dst IP

Dst Port

ECE Flag Cnt

FIN Flag Cnt

Flow ID

Fwd Blk Rate Avg

Fwd Byts/b Avg

Fwd PSH Flags

Fwd Pkts/b Avg

Fwd Seg Size Min

Fwd URG Flags

Init Fwd Win Byts

PSH Flag Cnt

RST Flag Cnt

SYN Flag Cnt

Src IP

Src Port

URG Flag Cnt

Organization A

Organization B

Organization C

gain met, false-positive limit breached

not worth it (gain not met)

gain met

gain met

not worth it (gain not met)

not worth it (gain not met)

tool test

IEC 104 IDS

University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7108614

Attacks against the IEC 60870-5-104 protocol used in electrical substations: unauthorized commands, DoS variants, MITM.

6,828 flows (all of the balanced release)

11 attack types

destination IP

Tool test (small data)

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

not worth it (gain not met)

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## insdn.json

InSDN (software-defined network)

SDN testbed flows from three capture points with seven attack types; destination host as the organization asset. Working sample of 120,001 flows.

08 Nov 2026, 23:24

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Flow Duration

Tot Fwd Pkts

Tot Bwd Pkts

TotLen Fwd Pkts

TotLen Bwd Pkts

Fwd Pkt Len Max

Fwd Pkt Len Min

Fwd Pkt Len Mean

Fwd Pkt Len Std

Bwd Pkt Len Max

Bwd Pkt Len Min

Bwd Pkt Len Mean

Bwd Pkt Len Std

Flow Byts/s

Flow Pkts/s

Flow IAT Mean

Flow IAT Std

Flow IAT Max

Flow IAT Min

Fwd IAT Tot

Fwd IAT Mean

Fwd IAT Std

Fwd IAT Max

Fwd IAT Min

Bwd IAT Tot

Bwd IAT Mean

Bwd IAT Std

Bwd IAT Max

Bwd IAT Min

Bwd PSH Flags

Fwd Header Len

Bwd Header Len

Fwd Pkts/s

Bwd Pkts/s

Pkt Len Min

Pkt Len Max

Pkt Len Mean

Pkt Len Std

Pkt Len Var

FIN Flag Cnt

SYN Flag Cnt

RST Flag Cnt

PSH Flag Cnt

ACK Flag Cnt

Down/Up Ratio

Pkt Size Avg

Fwd Seg Size Avg

Bwd Seg Size Avg

Subflow Fwd Pkts

Subflow Fwd Byts

Subflow Bwd Pkts

Subflow Bwd Byts

Init Bwd Win Byts

Fwd Act Data Pkts

Active Mean

Active Std

Active Max

Active Min

Idle Mean

Idle Std

Idle Max

Idle Min

Bwd Blk Rate Avg

Bwd Byts/b Avg

Bwd Pkts/b Avg

Bwd URG Flags

CWE Flag Count

Dst IP

Dst Port

ECE Flag Cnt

Flow ID

Fwd Blk Rate Avg

Fwd Byts/b Avg

Fwd PSH Flags

Fwd Pkts/b Avg

Fwd Seg Size Min

Fwd URG Flags

Init Fwd Win Byts

Src IP

Src Port

URG Flag Cnt

Organization A

the sender has 404 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 387 hosts; the test covers its 50 busiest hosts only

Organization C

the sender has 381 hosts; the test covers its 50 busiest hosts only

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Elsayed, Le-Khac and Jurcut (2020), University College Dublin

Attacks on a software-defined network from inside and outside: DoS, DDoS, probe, brute force, web attack, botnet, U2R.

120,001 flows sampled by label

7 attack types

destination IP

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## iot23.json

IoT-23 (twelve scenarios, Zeek connection logs)

Real IoT malware captures and honeypots from the Stratosphere laboratory; attack types from the detailed label. Responding host as the organization asset. Working sample of 102,373 connections.

08 Nov 2026, 23:26

protocol (shuffle test on 5,000 records per side, 50-tree forests)

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Organization A

the sender has 4,292 hosts; the test covers its 50 busiest hosts only

Organization B

the sender has 8,478 hosts; the test covers its 50 busiest hosts only

Organization C

the sender has 7,865 hosts; the test covers its 50 busiest hosts only

gain met

not worth it (gain not met)

not worth it (gain not met)

gain met

gain met

gain met

tool test

Stratosphere Laboratory, CTU Prague (Garcia, Parmisano and Erquiaga, 2020)

Twenty IoT malware captures (Mirai, Torii, Okiru, Hajime and others) and three benign device captures; this sample uses twelve of them.

102,373 connections sampled by detailed label

C&C, DDoS, horizontal port scan, attack, heartbeat and file-download variants

responding IP

Tool test

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

gain met (exposure of the fingerprint not measured)

09 November 2026

## n_baiot.json

N-BaIoT (nine IoT devices)

Nine commercial IoT devices infected with Mirai and BASHLITE (gafgyt); the device is the host, so organizations are device groups. Sampled per device and attack file.

08 Nov 2026, 23:39

protocol (shuffle test on 5,000 records per side, 50-tree forests)

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Meidan, Bohadana, Mathov, Mirsky, Breitenbacher, Shabtai and Elovici (2018), UCI 442

Traffic statistics (115 features over several time windows) of nine IoT devices, benign and under ten botnet attack types.

sampled per device and file

gafgyt combo, junk, scan, tcp, udp; mirai ack, scan, syn, udp, udpplain

Tool test

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met, false-positive limit breached

gain met (exposure of the fingerprint not measured)

09 November 2026

## nsl_kdd.json

NSL-KDD (KDDTrain+ and KDDTest+)

The cleaned successor of KDD Cup 1999: connection records with 38 attack names and no host or clock, so organizations are random thirds. Working sample of 85,592 records.

08 Nov 2026, 23:28

protocol (shuffle test on 5,000 records per side, 50-tree forests)

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = three random thirds of the records (no host column in this data)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

this data has no device or host column, so tracing cannot be tested

gain met

gain met

gain met

not worth it (gain not met)

gain met

not worth it (gain not met)

tool test

Tavallaee, Bagheri, Lu and Ghorbani (2009), from the DARPA 1998 and KDD Cup 1999 data

Connection records with 41 features; the classic benchmark, old traffic.

85,592 records sampled by attack name

38 attack names (DoS, probe, R2L, U2R)

Tool test

Public benchmark; cite the makers.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## rt_iot2022.json

Real-time IoT testbed (ThingSpeak, Wipro bulb, MQTT) with attacks; the three normal device patterns are mapped to one normal label. No host column. Working sample of 68,458 records.

08 Nov 2026, 23:29

protocol (shuffle test on 5,000 records per side, 50-tree forests)

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = three random thirds of the records (no host column in this data)

Organization A

Organization B

Organization C

Unnamed: 0

Organization A

Organization B

Organization C

this data has no device or host column, so tracing cannot be tested

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Sharmila and Nagapadma (2023), UCI Machine Learning Repository 942

IoT devices recorded in real time under normal use and under DoS, DDoS, ARP poisoning, scans and brute force; Zeek-style flow features.

68,458 records sampled by attack type

DoS SYN, DDoS Slowloris, ARP poisoning, five NMAP scans, SSH brute force

Tool test

CC BY 4.0.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## ton_iot.json

NF-ToN-IoT-v3 (2025 NetFlow)

IoT and IIoT testbed, NetFlow records with 9 attack types. Destination host is the company asset. Working sample of 99,819 records.

08 Nov 2026, 21:10

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met, false-positive limit breached

not worth it (gain not met)

gain met, false-positive limit breached

gain met, false-positive limit breached

gain met, privacy trade-off

gain met

tool test

NF-ToN-IoT-v3 (2025)

UNSW Canberra Cyber Range (Moustafa); NetFlow v3 release by Sarhan, Layeghy and Portmann, 2025

IoT and IIoT testbed traffic (smart home and industrial sensors, cloud and edge services) exported as NetFlow records with 46 behavior fields per flow.

99,819 records used, a class-stratified sample of a 1.5% download

9 attack types: DDoS, DoS, scanning, XSS, password, injection, backdoor, MITM, ransomware

destination IP (the company's asset)

Tool check

Shows the system runs unchanged on new data from a settings file. Not study evidence: the split is the tool's own, not audited.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met, false-positive limit breached

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## ton_iot_network.json

ToN_IoT network (Train_Test_Network)

The original ToN_IoT network subset (Zeek logs): nine attack types, destination host as the organization asset, no clock column. Working sample of 119,994 records.

08 Nov 2026, 23:32

protocol (shuffle test on 5,000 records per side, 50-tree forests)

class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

not worth it (gain not met)

not worth it (gain not met)

not worth it (gain not met)

gain met, false-positive limit breached

not worth it (gain not met)

tool test

ToN_IoT network

UNSW Canberra Cyber Range (Moustafa, 2021)

IoT and IIoT testbed with cloud, fog and edge layers; Zeek connection records with DNS, SSL and HTTP fields.

119,994 records sampled by attack type

backdoor, DDoS, DoS, injection, MITM, password, ransomware, scanning, XSS

destination IP

Tool test

Cite the makers; analysis use.

computed by this tool on 08 November 2026 with the protocol (shuffle test on 5,000 records per side, 50-tree forests) budget on the working sample described above; the split is the tool's own

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

gain met, false-positive limit breached

09 November 2026

## unsw_nb15.json

UNSW-NB15 (Kaggle)

Enterprise network testbed (not industrial), flow records, 9 attack categories. Destination host is the company asset. Working sample of 103,617 records.

08 Nov 2026, 21:10

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = groups of hosts (each host belongs to one organization)

Organization A

Organization B

Organization C

ct_src_ ltm

Organization A

Organization B

Organization C

gain met

not worth it (gain not met)

gain met

gain met

gain met

gain met

tool test

Moustafa and Slay (2015), UNSW Canberra Cyber Range

An enterprise (office) network testbed, not industrial, recorded as network flows with 49 fields. Included to see whether the method holds outside IoT.

103,617 records used, a class-stratified sample of 2,540,044

9 attack categories: exploits, fuzzers, generic, reconnaissance, DoS, analysis, backdoor, shellcode, worms

destination IP

Tool check

Same system, new data, and the only non-industrial set. Not study evidence.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026

## wustl_iiot.json

WUSTL-IIoT-2021 (Kaggle)

Water-tank industrial testbed, flow records, 4 attack types. Destination host is the company asset. Working sample of 60,711 records.

08 Nov 2026, 21:10

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

Organization A

Organization B

Organization C

gain met

gain met

gain met

gain met

gain met

not worth it (gain not met)

tool test

Zolanvari and colleagues, Washington University in St. Louis (2021)

An industrial control testbed (water storage tanks with PLCs and sensors) recorded as network flows, 49 fields per flow.

60,711 records used, a class-stratified sample of 1,194,464

4 attack types: DoS, reconnaissance, command injection, backdoor

destination address

Tool check

Same system, new data. Not study evidence. Few attacked hosts, so companies are random thirds.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

not worth it (gain not met)

09 November 2026

## xiiotid.json

X-IIoTID (Kaggle)

Industrial IoT testbed with network, host and log features. Attack sub-categories as the attack name; the destination host is the company asset. Working sample of 109,576 records.

08 Nov 2026, 21:10

by event inside each organization (records of one attack on one host under 15 s apart stay together; 50/20/30 train/validation/test by record count)

organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)

Organization A

Organization B

Organization C

FIN or RST

Organization A

Organization B

Organization C

gain met

gain met

gain met

gain met

gain met

gain met

tool test

Al-Hawawreh, Sitnikova and Aboutorab (2022), IEEE Internet of Things Journal

An industrial IoT testbed that records network traffic, host resources and logs together, with attack labels at three levels (attack or not, sub-category, sub-sub-category).

109,576 records used, a class-stratified sample of 820,834

9 attack sub-categories: reconnaissance, weaponization, exploitation, lateral movement, command and control, exfiltration, tampering, resource DoS, crypto-ransomware

destination IP

Tool check

Same system, new data. Not study evidence. Also an early candidate for the praxis that went to future work on 29 September.

training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool

Fingerprint sharing

experimental; not one of the four training conditions of the praxis

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

gain met (exposure of the fingerprint not measured)

09 November 2026
