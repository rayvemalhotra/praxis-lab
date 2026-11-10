# page_students

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

STUDENTS
A one-hour exercise

You need one labeled intrusion dataset: a CSV with one row per record and a column that names the attack type or says normal. The list at the bottom gives public datasets with direct downloads; the results page shows what the tool found on each of them. No dataset yet? The Live demo runs sample files, and Evaluate offers the same samples.

1
Look at the data

Open Evaluate and upload your file. Read the opening rows. Check the columns the tool proposes: which one is the label, which value means normal, which column names the host or device, which column is the clock. Fix anything it got wrong. Open the record shown before and after sanitizing and write down what a peer would receive and what stays home.

10 minutes
2
Make the organizations

Note how the tool formed organizations A, B and C (groups of hosts, or random thirds when there is no host column), and which attack type each organization has withheld. Write one sentence per organization: what it trains on, and which attack type it has withheld.

5 minutes
3
Run a quick look

Choose Quick look and run. Read the bars of each organization. Which training condition named the withheld attack type best? Which one raised the false-positive rate? What did each condition send, in bytes?

5 minutes
4
Read the verdicts

For each organization and each of the two approaches, write whether the gain was met, whether the false-positive limit held, and whether the sanitized records could be traced back to their host above the majority-host baseline. Is the verdict the same for all three organizations? If not, why not?

10 minutes
5
Run the protocol budget

Repeat with Protocol run. Compare the 95% ranges with the quick look. Did any verdict change? A quick look is a check; only the protocol run is a result.

20 minutes or more
6
Write five sentences

Dataset, organizations, the best condition for each organization, what it cost (false positives, bytes, tracing), and what you would tell an organization that asked whether to share.

10 minutes

What to be careful about. The split is the tool's own when a dataset has no clock (random split, optimistic ranges). A dataset with few normal records gives an unreliable alarm threshold. A dataset with few behavior numbers gives the detector little to work with. The tool reports all of this on the result page; read it before you trust a number.

DATA
Public datasets with a direct download
DATASET	MADE BY	ATTACK TYPES	HOST COLUMN	SOURCE	LICENCE	RUNS IN THE TOOL
BoT-IoT, 5% release (four files)	UNSW Canberra Cyber Range (Koroniotis, Moustafa, Sitnikova and Turnbull, 2019)	DDoS and DoS (TCP, UDP, HTTP), service scan, OS fingerprint, keylogging, data exfiltration	destination IP	https://research.unsw.edu.au/projects/bot-iot-dataset	Cite the makers; analysis use.	yes, see its card on the Results page
CIC-IDS2017 (labelled flows)	Canadian Institute for Cybersecurity, University of New Brunswick (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)	14 attack types	destination IP	https://www.unb.ca/cic/datasets/ids-2017.html	Cite the makers; analysis use. The raw files are not re-hosted here.	yes, see its card on the Results page
CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021)	DistriNet, KU Leuven (Engelen, Troia and Vanhoef, 2021; Liu, Engelen, Lynar, Essam and Joosen, 2022)	13 attack types, each also as an 'Attempted' variant	destination IP	https://intrusion-detection.distrinet-research.be/CNS2022/	Cite the makers; analysis use.	yes, see its card on the Results page
CICIoT2023 (merged flows)	Canadian Institute for Cybersecurity (Neto, Dadkhah, Ferreira, Zohourian, Lu and Ghorbani, 2023)	33 attack types	none in the CSV release	https://www.unb.ca/cic/datasets/iotdataset-2023.html	Cite the makers; analysis use.	yes, see its card on the Results page
CIDDS-001 (OpenStack and external server flows)	Coburg University of Applied Sciences (Ring, Wunderlich, Grudl, Landes and Hotho, 2017)	dos, portScan, pingScan, bruteForce	destination IP	https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/	Cite the makers; analysis use.	yes, see its card on the Results page
CIDDS-002 (port scans)	Coburg University of Applied Sciences (Ring, Wunderlich, Grudl, Landes and Hotho, 2017)	portScan	destination IP	https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/	Cite the makers; analysis use.	no: at least three attack types are needed so that each organization can withhold a different one
CSE-CIC-IDS2018 (seven days)	Communications Security Establishment and the Canadian Institute for Cybersecurity (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)	brute force (FTP, SSH), DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest), DDoS (LOIC-UDP, HOIC), web attacks, botnet	none in the day files	https://www.unb.ca/cic/datasets/ids-2018.html	Cite the makers; analysis use.	yes, see its card on the Results page
CTU-13 botnet families (NetTiSA flows)	CESNET and CTU Prague (Koumar, Hynek, Cejka and Siska, 2023), Zenodo 8301043; original captures by Garcia et al. (2014)	botnet families: neris, fast_flux, qvod, rbot, donbot	source IP	https://zenodo.org/records/8301043	CC BY 4.0.	yes, see its card on the Results page
DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout)	University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7348493	10 attack types	destination IP	https://zenodo.org/records/7348493	CC BY 4.0.	yes, see its card on the Results page
Edge-IIoTset, ML subset (raw packet fields)	Ferrag, Friha, Hamouda, Maglaras and Janicke (2022), IEEE Access	14 attack types	ip.dst_host	https://doi.org/10.1109/ACCESS.2022.3165809	Cite the makers; analysis use.	yes, see its card on the Results page
Electra Modbus (electric traction substation)	University of Murcia (Gomez, Maimo, Celdran, Clemente, Sarmiento, Masa and Nistal, 2019)	7 attack types	destination IP	http://perception.inf.um.es/ICS-datasets/	Cite the makers; analysis use.	yes, see its card on the Results page
Electra S7comm (electric traction substation)	University of Murcia (Gomez et al., 2019)	see label values	destination IP	http://perception.inf.um.es/ICS-datasets/	Cite the makers; analysis use.	yes, see its card on the Results page
IEC 60870-5-104 intrusion detection dataset (balanced flows)	University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7108614	11 attack types	destination IP	https://zenodo.org/records/7108614	CC BY 4.0.	yes, see its card on the Results page
InSDN (software-defined network)	Elsayed, Le-Khac and Jurcut (2020), University College Dublin	7 attack types	destination IP	https://aseados.ucd.ie/datasets/SDN/	Cite the makers; analysis use.	yes, see its card on the Results page
IoT-23 (twelve scenarios, Zeek connection logs)	Stratosphere Laboratory, CTU Prague (Garcia, Parmisano and Erquiaga, 2020)	C&C, DDoS, horizontal port scan, attack, heartbeat and file-download variants	responding IP	https://www.stratosphereips.org/datasets-iot23	CC BY 4.0.	yes, see its card on the Results page
N-BaIoT (nine IoT devices)	Meidan, Bohadana, Mathov, Mirsky, Breitenbacher, Shabtai and Elovici (2018), UCI 442	gafgyt combo, junk, scan, tcp, udp; mirai ack, scan, syn, udp, udpplain	device	https://doi.org/10.24432/C5RC8J	CC BY 4.0.	yes, see its card on the Results page
NSL-KDD (KDDTrain+ and KDDTest+)	Tavallaee, Bagheri, Lu and Ghorbani (2009), from the DARPA 1998 and KDD Cup 1999 data	38 attack names (DoS, probe, R2L, U2R)	none	https://www.unb.ca/cic/datasets/nsl.html	Public benchmark; cite the makers.	yes, see its card on the Results page
RT-IoT2022	Sharmila and Nagapadma (2023), UCI Machine Learning Repository 942	DoS SYN, DDoS Slowloris, ARP poisoning, five NMAP scans, SSH brute force	none	https://doi.org/10.24432/C5P338	CC BY 4.0.	yes, see its card on the Results page
ToN_IoT network (Train_Test_Network)	UNSW Canberra Cyber Range (Moustafa, 2021)	backdoor, DDoS, DoS, injection, MITM, password, ransomware, scanning, XSS	destination IP	https://research.unsw.edu.au/projects/toniot-datasets	Cite the makers; analysis use.	yes, see its card on the Results page

Kaggle and IEEE DataPort releases need a sign-in and are not listed. Every dataset keeps its makers' licence; cite them in anything you write.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
