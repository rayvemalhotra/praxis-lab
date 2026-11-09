"""Write one settings file per working sample in ../Praxis_Lab_Datasets/settings/.
Each entry was checked by hand against the sample's columns (label, normal value, host, time, identifiers).
    python3 tools/make_settings.py
"""
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(HERE, "..", "Praxis_Lab_Datasets")
OUT = os.path.join(DS, "settings")
os.makedirs(OUT, exist_ok=True)

CIC_FLOW_DROP = ["Flow ID", "Src IP", "Src Port", "Dst Port", "Protocol"]

SETTINGS = {
    "cic_ids2017": dict(
        name="CIC-IDS2017 (labelled flows)", study_role="tool test",
        about="University network testbed, five days of flows with 14 attack types. Destination host is the organization asset. Working sample of 120,013 flows from 3,119,345 (unlabelled rows left out).",
        paths=["cic_ids2017.csv"], label_col="Label", benign_label="BENIGN", source_col="Destination IP", time_col="Timestamp",
        drop=["Flow ID", "Source IP", "Source Port", "Destination Port", "Protocol"],
        label_map={"Web Attack � Brute Force": "Web Attack Brute Force", "Web Attack � XSS": "Web Attack XSS", "Web Attack � Sql Injection": "Web Attack SQL Injection"},
        info=dict(short="CIC-IDS2017", maker="Canadian Institute for Cybersecurity, University of New Brunswick (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)", year=2017,
                  what="Five working days of traffic on a small enterprise network: normal use plus brute force, DoS, DDoS, web attacks, infiltration, botnet and port scanning, as CICFlowMeter flows.",
                  records="120,013 flows sampled by attack type", attacks="14 attack types", host="destination IP",
                  role="Tool test: a public dataset run unchanged through the procedure", source="https://www.unb.ca/cic/datasets/ids-2017.html",
                  licence="Cite the makers; analysis use. The raw files are not re-hosted here.")),
    "cic_ids2017_improved": dict(
        name="CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021)", study_role="tool test",
        about="The same five days re-extracted with a corrected CICFlowMeter and relabelled; 'Attempted' labels mark attacks that did not complete. Working sample of 120,069 flows.",
        paths=["cic_ids2017_improved.csv"], label_col="Label", benign_label="BENIGN", source_col="Dst IP", time_col="Timestamp",
        drop=["id"] + CIC_FLOW_DROP, label_cols=["Attempted Category"],
        info=dict(short="CIC-IDS2017 improved", maker="DistriNet, KU Leuven (Engelen, Troia and Vanhoef, 2021; Liu, Engelen, Lynar, Essam and Joosen, 2022)", year=2021,
                  what="CIC-IDS2017 traffic re-extracted after fixing CICFlowMeter errors (flow termination, TCP flags, duplicates) and relabelled flow by flow.",
                  records="120,069 flows sampled by label", attacks="13 attack types, each also as an 'Attempted' variant", host="destination IP",
                  role="Tool test", source="https://intrusion-detection.distrinet-research.be/CNS2022/",
                  licence="Cite the makers; analysis use.")),
    "cse_cic_ids2018": dict(
        name="CSE-CIC-IDS2018 (seven days)", study_role="tool test",
        about="Large enterprise testbed on AWS, flows from seven attack days: brute force, DoS, DDoS, web attacks and botnet. No host column in these day files, so organizations are random thirds. Working sample of up to 120,000 flows.",
        paths=["cse_cic_ids2018.csv"], label_col="Label", benign_label="Benign", source_col=None, time_col="Timestamp",
        drop=["Dst Port", "Protocol", "Flow ID", "Src IP", "Dst IP", "Src Port"], drop_labels=["Label"],
        info=dict(short="CSE-CIC-IDS2018", maker="Communications Security Establishment and the Canadian Institute for Cybersecurity (Sharafaldin, Habibi Lashkari and Ghorbani, 2018)", year=2018,
                  what="An AWS testbed of 420 machines and 30 servers attacked over ten days; this sample uses seven day files of CICFlowMeter flows.",
                  records="up to 120,000 flows sampled by label", attacks="brute force (FTP, SSH), DoS (GoldenEye, Slowloris, Hulk, SlowHTTPTest), DDoS (LOIC-UDP, HOIC), web attacks, botnet", host="none in the day files",
                  role="Tool test", source="https://www.unb.ca/cic/datasets/ids-2018.html", licence="Cite the makers; analysis use.")),
    "ciciot2023": dict(
        name="CICIoT2023 (merged flows)", study_role="tool test",
        about="105 real IoT devices under 33 attacks, aggregated packet windows. The published CSV files carry no addresses or clock, so organizations are random thirds and tracing cannot be tested. Working sample of 120,624 records from three merged files.",
        paths=["ciciot2023.csv"], label_col="Label", benign_label="BENIGN", source_col=None, time_col=None, drop=[], drop_labels=["nan"],
        info=dict(short="CICIoT2023", maker="Canadian Institute for Cybersecurity (Neto, Dadkhah, Ferreira, Zohourian, Lu and Ghorbani, 2023)", year=2023,
                  what="A smart-home testbed of 105 IoT devices attacked by other IoT devices: DDoS, DoS, reconnaissance, web, brute force, spoofing and Mirai.",
                  records="120,624 records sampled by label from Merged01, Merged25 and Merged50", attacks="33 attack types", host="none in the CSV release",
                  role="Tool test", source="https://www.unb.ca/cic/datasets/iotdataset-2023.html", licence="Cite the makers; analysis use.")),
    "ton_iot_network": dict(
        name="ToN_IoT network (Train_Test_Network)", study_role="tool test",
        about="The original ToN_IoT network subset (Zeek logs): nine attack types, destination host as the organization asset, no clock column. Working sample of 119,994 records.",
        paths=["ton_iot_network.csv"], label_col="type", benign_label="normal", source_col="dst_ip", time_col=None,
        drop=["src_ip", "src_port", "dst_port", "proto", "service", "conn_state", "weird_name", "weird_addl", "weird_notice"], label_cols=["label"],
        info=dict(short="ToN_IoT network", maker="UNSW Canberra Cyber Range (Moustafa, 2021)", year=2019,
                  what="IoT and IIoT testbed with cloud, fog and edge layers; Zeek connection records with DNS, SSL and HTTP fields.",
                  records="119,994 records sampled by attack type", attacks="backdoor, DDoS, DoS, injection, MITM, password, ransomware, scanning, XSS", host="destination IP",
                  role="Tool test", source="https://research.unsw.edu.au/projects/toniot-datasets", licence="Cite the makers; analysis use.")),
    "edge_iiotset_ml": dict(
        name="Edge-IIoTset, ML subset (raw packet fields)", study_role="tool test",
        about="The makers' machine-learning subset with the raw packet fields, including the destination host and a clock. Working sample of 119,994 records.",
        paths=["edge_iiotset_ml.csv"], label_col="Attack_type", benign_label="Normal", source_col="ip.dst_host", time_col="frame.time",
        drop=["ip.src_host", "arp.dst.proto_ipv4", "arp.src.proto_ipv4", "http.file_data", "http.request.uri.query", "http.request.method", "http.referer", "http.request.full_uri",
              "http.request.version", "tcp.options", "tcp.payload", "tcp.srcport", "dns.qry.name", "mqtt.conack.flags", "mqtt.msg", "mqtt.protoname", "mqtt.topic", "tcp.flags"],
        keep=["tcp.dstport", "udp.port", "mbtcp.unit_id", "tcp.ack", "tcp.ack_raw", "tcp.seq", "icmp.seq_le"], label_cols=["Attack_label"],
        info=dict(short="Edge-IIoTset (ML subset)", maker="Ferrag, Friha, Hamouda, Maglaras and Janicke (2022), IEEE Access", year=2022,
                  what="The same IoT and IIoT testbed as the praxis ranking check, in the makers' ML-ready CSV with packet fields, host columns and a clock.",
                  records="119,994 records sampled by attack type", attacks="14 attack types", host="ip.dst_host",
                  role="Tool test", source="https://doi.org/10.1109/ACCESS.2022.3165809", licence="Cite the makers; analysis use.")),
    "bot_iot_5pct": dict(
        name="BoT-IoT, 5% release (four files)", study_role="tool test",
        about="IoT botnet testbed flows. The 5% release holds only 477 normal records, so the alarm threshold rests on a small normal sample. Working sample of 95,944 flows; attack type = category and subcategory.",
        paths=["bot_iot_5pct.csv"], label_col="attack_type", benign_label="Normal", source_col="daddr", time_col="stime",
        drop=["pkSeqID", "flgs", "proto", "saddr", "sport", "dport", "state", "ltime", "seq"], label_cols=["attack", "category", "subcategory"],
        info=dict(short="BoT-IoT 5%", maker="UNSW Canberra Cyber Range (Koroniotis, Moustafa, Sitnikova and Turnbull, 2019)", year=2018,
                  what="IoT testbed under DDoS, DoS, reconnaissance and theft attacks; Argus flow records with engineered rate features.",
                  records="95,944 flows sampled by attack type from the four 5% files", attacks="DDoS and DoS (TCP, UDP, HTTP), service scan, OS fingerprint, keylogging, data exfiltration", host="destination IP",
                  role="Tool test", source="https://research.unsw.edu.au/projects/bot-iot-dataset", licence="Cite the makers; analysis use.")),
    "nsl_kdd": dict(
        name="NSL-KDD (KDDTrain+ and KDDTest+)", study_role="tool test",
        about="The cleaned successor of KDD Cup 1999: connection records with 38 attack names and no host or clock, so organizations are random thirds. Working sample of 85,592 records.",
        paths=["nsl_kdd.csv"], label_col="attack", benign_label="normal", source_col=None, time_col=None,
        drop=["protocol_type", "service", "flag", "difficulty"],
        info=dict(short="NSL-KDD", maker="Tavallaee, Bagheri, Lu and Ghorbani (2009), from the DARPA 1998 and KDD Cup 1999 data", year=2009,
                  what="Connection records with 41 features; the classic benchmark, old traffic.",
                  records="85,592 records sampled by attack name", attacks="38 attack names (DoS, probe, R2L, U2R)", host="none",
                  role="Tool test", source="https://www.unb.ca/cic/datasets/nsl.html", licence="Public benchmark; cite the makers.")),
    "rt_iot2022": dict(
        name="RT-IoT2022", study_role="tool test",
        about="Real-time IoT testbed (ThingSpeak, Wipro bulb, MQTT) with attacks; the three normal device patterns are mapped to one normal label. No host column. Working sample of 68,458 records.",
        paths=["rt_iot2022.csv"], label_col="Attack_type", benign_label="Normal", source_col=None, time_col=None,
        drop=["Unnamed: 0", "id.orig_p", "id.resp_p", "proto", "service"],
        label_map={"Thing_Speak": "Normal", "MQTT_Publish": "Normal", "Wipro_bulb": "Normal"},
        info=dict(short="RT-IoT2022", maker="Sharmila and Nagapadma (2023), UCI Machine Learning Repository 942", year=2022,
                  what="IoT devices recorded in real time under normal use and under DoS, DDoS, ARP poisoning, scans and brute force; Zeek-style flow features.",
                  records="68,458 records sampled by attack type", attacks="DoS SYN, DDoS Slowloris, ARP poisoning, five NMAP scans, SSH brute force", host="none",
                  role="Tool test", source="https://doi.org/10.24432/C5P338", licence="CC BY 4.0.")),
    "insdn": dict(
        name="InSDN (software-defined network)", study_role="tool test",
        about="SDN testbed flows from three capture points with seven attack types; destination host as the organization asset. Working sample of 120,001 flows.",
        paths=["insdn.csv"], label_col="Label", benign_label="Normal", source_col="Dst IP", time_col="Timestamp", drop=CIC_FLOW_DROP,
        info=dict(short="InSDN", maker="Elsayed, Le-Khac and Jurcut (2020), University College Dublin", year=2020,
                  what="Attacks on a software-defined network from inside and outside: DoS, DDoS, probe, brute force, web attack, botnet, U2R.",
                  records="120,001 flows sampled by label", attacks="7 attack types", host="destination IP",
                  role="Tool test", source="https://aseados.ucd.ie/datasets/SDN/", licence="Cite the makers; analysis use.")),
    "iec104": dict(
        name="IEC 60870-5-104 intrusion detection dataset (balanced flows)", study_role="tool test",
        about="Power-grid control traffic (IEC 104) with eleven attack types, as CICFlowMeter flows; the balanced release is small (6,828 flows, 569 per label). Destination host as the organization asset.",
        paths=["iec104.csv"], label_col="Label", benign_label="NORMAL", source_col="Dst IP", time_col="Timestamp", drop=CIC_FLOW_DROP,
        info=dict(short="IEC 104 IDS", maker="University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7108614", year=2020,
                  what="Attacks against the IEC 60870-5-104 protocol used in electrical substations: unauthorized commands, DoS variants, MITM.",
                  records="6,828 flows (all of the balanced release)", attacks="11 attack types", host="destination IP",
                  role="Tool test (small data)", source="https://zenodo.org/records/7108614", licence="CC BY 4.0.")),
    "dnp3": dict(
        name="DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout)", study_role="tool test",
        about="Power-grid SCADA traffic (DNP3) from nine attack captures, as CICFlowMeter flows; destination host as the organization asset. 41,596 flows.",
        paths=["dnp3.csv"], label_col="Label", benign_label="NORMAL", source_col="Dst IP", time_col="Timestamp", drop=CIC_FLOW_DROP + ["capture"],
        info=dict(short="DNP3 IDS", maker="University of Western Macedonia (Radoglou-Grammatikis et al., 2022), Zenodo 7348493", year=2020,
                  what="Attacks against DNP3 SCADA communication: disable unsolicited messages, cold and warm restart, enumerate, info, initialize data, stop application, replay, MITM DoS, ARP poisoning.",
                  records="41,596 flows (all CIC flows at the 120 s timeout)", attacks="10 attack types", host="destination IP",
                  role="Tool test", source="https://zenodo.org/records/7348493", licence="CC BY 4.0.")),
    "electra_modbus": dict(
        name="Electra Modbus (electric traction substation)", study_role="tool test",
        about="Modbus TCP traffic of an electric traction substation with seven attack types; only five numbers per record (function code, error, address, data, request), so the detector has little to work with. Working sample of 119,994 records.",
        paths=["electra_modbus.csv"], label_col="label", benign_label="NORMAL", source_col="dip", time_col="Time",
        drop=["smac", "dmac", "sip"], keep=["address", "data", "fc", "error", "request"],
        info=dict(short="Electra Modbus", maker="University of Murcia (Gomez, Maimo, Celdran, Clemente, Sarmiento, Masa and Nistal, 2019)", year=2019,
                  what="Modbus packets in a railway traction substation under reconnaissance, read, write, replay, response, force-error and MITM attacks.",
                  records="119,994 packets sampled by label from 16 million", attacks="7 attack types", host="destination IP",
                  role="Tool test (few features)", source="http://perception.inf.um.es/ICS-datasets/", licence="Cite the makers; analysis use.")),
    "iot23": dict(
        name="IoT-23 (twelve scenarios, Zeek connection logs)", study_role="tool test",
        about="Real IoT malware captures and honeypots from the Stratosphere laboratory; attack types from the detailed label. Responding host as the organization asset. Working sample of 102,373 connections.",
        paths=["iot23.csv"], label_col="attack_type", benign_label="Benign", source_col="id.resp_h", time_col="ts",
        drop=["id.orig_h", "id.orig_p", "id.resp_p", "proto", "service", "conn_state", "history", "scenario"], label_cols=["label"],
        keep=["duration", "orig_bytes", "resp_bytes"], min_class_rows=30,
        info=dict(short="IoT-23", maker="Stratosphere Laboratory, CTU Prague (Garcia, Parmisano and Erquiaga, 2020)", year=2020,
                  what="Twenty IoT malware captures (Mirai, Torii, Okiru, Hajime and others) and three benign device captures; this sample uses twelve of them.",
                  records="102,373 connections sampled by detailed label", attacks="C&C, DDoS, horizontal port scan, attack, heartbeat and file-download variants", host="responding IP",
                  role="Tool test", source="https://www.stratosphereips.org/datasets-iot23", licence="CC BY 4.0.")),
    "cidds001": dict(
        name="CIDDS-001 (OpenStack and external server flows)", study_role="tool test",
        about="Flow records from an emulated small business network (OpenStack) and an external server, four attack types; destination host as the organization asset. Working sample of 95,753 flows from two internal and two external weeks; the makers' date column is named Timestamp in the sample.",
        paths=["cidds001.csv"], label_col="attackType", benign_label="---", source_col="Dst IP Addr", time_col="Timestamp",
        drop=["Proto", "Src IP Addr", "Src Pt", "Flags", "Flows", "Tos"], keep=["Dst Pt"], label_cols=["class", "attackID", "attackDescription"],
        label_map={"---": "normal"}, benign_label_after_map="normal",
        info=dict(short="CIDDS-001", maker="Coburg University of Applied Sciences (Ring, Wunderlich, Grudl, Landes and Hotho, 2017)", year=2017,
                  what="NetFlow records of an emulated company network with clients, servers and an external server exposed to the Internet; attacks are DoS, port scans, ping scans and brute force.",
                  records="95,753 flows sampled by attack type", attacks="dos, portScan, pingScan, bruteForce", host="destination IP",
                  role="Tool test (few features)", source="https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/", licence="Cite the makers; analysis use.")),
    "ctu13_nettisa": dict(
        name="CTU-13 botnet families (NetTiSA flows)", study_role="tool test",
        about="Botnet traffic of the CTU-13 captures as NetTiSA extended flows, labelled by botnet family; few attack families with enough records. Source host as the organization asset. 41,070 flows.",
        paths=["ctu13_nettisa.csv"], label_col="LABEL", benign_label="clear", source_col="SRC_IP", time_col="TIME_FIRST",
        drop=["Unnamed: 0", "DST_IP", "SRC_PORT", "DST_PORT", "TIME_LAST"], min_class_rows=30,
        info=dict(short="CTU-13 (NetTiSA)", maker="CESNET and CTU Prague (Koumar, Hynek, Cejka and Siska, 2023), Zenodo 8301043; original captures by Garcia et al. (2014)", year=2023,
                  what="Botnet captures (Neris, Rbot, Donbot, fast flux and others) re-extracted as NetTiSA flows with time-series statistics.",
                  records="41,070 flows (the whole botnet_multiclass file, normal capped)", attacks="botnet families: neris, fast_flux, qvod, rbot, donbot", host="source IP",
                  role="Tool test (few attack families)", source="https://zenodo.org/records/8301043", licence="CC BY 4.0.")),
    "n_baiot": dict(
        name="N-BaIoT (nine IoT devices)", study_role="tool test",
        about="Nine commercial IoT devices infected with Mirai and BASHLITE (gafgyt); the device is the host, so organizations are device groups. Sampled per device and attack file.",
        paths=["n_baiot.csv"], label_col="attack_type", benign_label="benign", source_col="device", time_col=None, drop=[],
        info=dict(short="N-BaIoT", maker="Meidan, Bohadana, Mathov, Mirsky, Breitenbacher, Shabtai and Elovici (2018), UCI 442", year=2018,
                  what="Traffic statistics (115 features over several time windows) of nine IoT devices, benign and under ten botnet attack types.",
                  records="sampled per device and file", attacks="gafgyt combo, junk, scan, tcp, udp; mirai ack, scan, syn, udp, udpplain", host="device",
                  role="Tool test", source="https://doi.org/10.24432/C5RC8J", licence="CC BY 4.0.")),
    "electra_s7comm": dict(
        name="Electra S7comm (electric traction substation)", study_role="tool test",
        about="S7comm traffic of the same substation with the same attack families as the Modbus set; few numbers per record. Working sample of up to 120,000 records.",
        paths=["electra_s7comm.csv"], label_col="label", benign_label="NORMAL", source_col="dip", time_col="Time", drop=["smac", "dmac", "sip"],
        info=dict(short="Electra S7comm", maker="University of Murcia (Gomez et al., 2019)", year=2019, what="S7comm packets in a railway traction substation under attack.",
                  records="up to 120,000 packets sampled by label", attacks="see label values", host="destination IP", role="Tool test (few features)",
                  source="http://perception.inf.um.es/ICS-datasets/", licence="Cite the makers; analysis use.")),
    "cidds002": dict(
        name="CIDDS-002 (port scans)", study_role="tool test",
        about="Flow records of an emulated company network with port-scan attacks only; included to show what the tool does when there are too few attack types.",
        paths=["cidds002.csv"], label_col="attackType", benign_label="---", source_col="Dst IP Addr", time_col="Timestamp",
        drop=["Proto", "Src IP Addr", "Src Pt", "Flags", "Flows", "Tos"], keep=["Dst Pt"], label_cols=["class", "attackID", "attackDescription"], label_map={"---": "normal"},
        info=dict(short="CIDDS-002", maker="Coburg University of Applied Sciences (Ring, Wunderlich, Grudl, Landes and Hotho, 2017)", year=2017,
                  what="NetFlow records with port scan attacks of several kinds.", records="sampled", attacks="portScan", host="destination IP", role="Tool test (too few attack types)",
                  source="https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/", licence="Cite the makers; analysis use.")),
}

for did, s in SETTINGS.items():
    s = dict(s)
    s["id"] = did
    if "benign_label_after_map" in s:
        s["benign_label"] = s.pop("benign_label_after_map")
    json.dump(s, open(os.path.join(OUT, f"{did}.json"), "w"), indent=1, ensure_ascii=False)
print("wrote", len(SETTINGS), "settings files to", OUT)
