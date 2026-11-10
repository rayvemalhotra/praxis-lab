"""Make two more SYNTHETIC sample organization files for trying ThreatPrint, in other sectors and with other column names
than the water utility (tools/make_sample_org.py), so that the automatic column detection is exercised:

    samples/sample_organization_hospital_SYNTHETIC.csv              a fictional hospital: medical and building devices
    samples/sample_organization_manufacturing_plant_SYNTHETIC.csv   a fictional plant: PLCs, HMIs, robots, historians

    python tools/make_sample_orgs_more.py

Everything in the files is made up by this script: device names, addresses, wards, lines and traffic numbers. The files
have the shape of real monitoring data (identifier columns, a clock, bursts of attack records on one device) so that the
upload, the sanitizer, the local agent and the evaluation can be tried end to end. They say nothing about real attacks.
The seed is fixed: the script writes the same files every time.
"""
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMOOTH = ("duration_s", "pkt_size_mean", "iat_ms_mean", "iat_ms_std", "entropy")


def make(out, seed, sector):
    rng = np.random.default_rng(seed)
    u = rng.uniform
    F = sector["features"]

    def attack(kind, x, role):
        if kind in ("dos_syn_flood", "DoS_SYN_Flood"):
            x["pkts_in"] *= u(25, 60); x["bytes_in"] *= u(8, 20); x["syn"] += u(800, 3000); x["ack"] *= u(0.1, 0.4)
            x["iat_ms_mean"] *= u(0.02, 0.06); x["iat_ms_std"] *= u(0.05, 0.2); x["pkt_size_mean"] = u(58, 70); x["rst"] += u(5, 60)
        elif kind in ("ddos_udp_flood", "DDoS_UDP_Flood"):
            x["pkts_in"] *= u(40, 90); x["bytes_in"] *= u(30, 80); x["peers"] += u(200, 900); x["syn"] *= u(0, 0.3)
            x["iat_ms_mean"] *= u(0.01, 0.04); x["pkt_size_mean"] = u(380, 620); x["entropy"] = u(6.8, 7.9)
        elif kind in ("port_scan", "Network_Scan"):
            x["ports"] += u(100, 800); x["syn"] += u(100, 800); x["rst"] += u(90, 700); x["pkts_in"] += u(100, 900)
            x["pkt_size_mean"] = u(56, 66); x["ack"] *= u(0.6, 1.2)
        elif kind in ("arp_mitm", "ARP_Spoofing"):                # subtle on purpose
            x["pkts_out"] *= u(1.1, 1.6); x["pkts_in"] *= u(1.1, 1.6); x["iat_ms_std"] *= u(1.5, 3.0)
            x["iat_ms_mean"] *= u(1.1, 1.5); x["peers"] += u(1, 3); x["rst"] += u(0, 3)
        elif kind in ("password_brute_force", "Brute_Force_Login"):
            x["failed_auth"] += u(20, 200); x["syn"] += u(20, 200); x["fin"] += u(15, 180); x["pkts_in"] += u(200, 1500)
            x["pkt_size_mean"] = u(96, 150); x["entropy"] = u(6.9, 7.8)
        elif kind in ("ransomware_smb", "Ransomware"):
            x["bytes_out"] *= u(8, 30); x["pkts_out"] *= u(5, 14); x["entropy"] = u(7.6, 7.99); x["ports"] += u(5, 30)
            x["peers"] += u(4, 40); x["pkt_size_mean"] = u(900, 1400)
        elif kind == "data_exfiltration":
            x["bytes_out"] *= u(15, 60); x["pkts_out"] *= u(4, 10); x["peers"] += u(0, 2); x["entropy"] = u(7.5, 7.99); x["duration_s"] = u(8.5, 10.0)
        elif kind == "Modbus_Command_Injection":
            k = 1.0 if role in ("plc", "robot") else 0.35
            x["ctrl_writes"] += k * u(12, 80); x["ctrl_reads"] *= u(0.5, 1.4); x["pkts_in"] += k * u(15, 90); x["peers"] += u(0, 2)
        elif kind == "Firmware_Exploit":
            x["bytes_in"] *= u(6, 25); x["pkt_size_mean"] = u(1100, 1460); x["rst"] += u(2, 20); x["ctrl_writes"] += u(0, 6); x["entropy"] = u(7.2, 7.95)
        return x

    rows, T0 = [], pd.Timestamp(sector["start"])
    for role, spec in sector["roles"].items():
        for i in range(1, spec["n"] + 1):
            name = f"{spec['name']}-{i:02d}"
            ip = f"{sector['net']}.{spec['subnet']}.{10 + i}"
            mac = sector["oui"] + ":" + ":".join(f"{b:02x}" for b in rng.integers(0, 256, 3))
            place = sector["places"][i % len(sector["places"])]
            offset = {f: float(rng.lognormal(0, 0.22)) for f in F}          # this device's own habits

            def window(kind, t):
                x = {f: max(0.0, spec.get(f, 0) * offset[f] * float(rng.lognormal(0, 0.30))) for f in F}
                x["entropy"] = min(7.99, x["entropy"])
                x["duration_s"] = min(10.0, x["duration_s"])
                if kind != sector["normal"]:
                    x = attack(kind, x, role)
                for f in F:
                    x[f] = round(x[f], 3) if f in SMOOTH else float(int(round(x[f])))
                inside = kind in (sector["normal"], "arp_mitm", "ARP_Spoofing", "Modbus_Command_Injection")
                peer = f"{sector['net']}.{int(rng.integers(10, 60))}.{int(rng.integers(2, 250))}" if inside else f"198.51.100.{int(rng.integers(2, 250))}"
                return sector["row"](T0, t, place, name, ip, mac, peer, rng, role, x, kind)

            for t in np.sort(rng.uniform(0, 14 * 86400, sector["normal_windows"])):
                rows.append(window(sector["normal"], t))
            for kind in sector["attacks"]:                                    # each attack arrives as a few bursts on this device
                for _ in range(int(rng.integers(3, 6))):
                    t = float(rng.uniform(0, 14 * 86400))
                    for _ in range(int(rng.integers(12, 36))):
                        rows.append(window(kind, t))
                        t += float(rng.uniform(2, 9))
    df = pd.DataFrame(rows).sort_values(sector["time"]).reset_index(drop=True)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    df.to_csv(out, index=False)
    print(f"wrote {out}: {len(df):,} records, {df.shape[1]} columns, {df[sector['host']].nunique()} devices")
    print(df[sector["label"]].value_counts().to_dict())
    return df


COMMON = ["duration_s", "pkts_out", "pkts_in", "bytes_out", "bytes_in", "pkt_size_mean", "pkt_size_max", "syn", "ack", "rst", "fin", "ports", "peers",
          "failed_auth", "iat_ms_mean", "iat_ms_std", "entropy"]

HOSPITAL = dict(
    start="2026-04-06 00:00:00", net="10.60", oui="00:09:fb", places=["Ward 3 East", "Ward 5 West", "Radiology", "Emergency"], normal="benign", normal_windows=240,
    label="attack_category", host="asset_name", time="event_time", features=COMMON + ["dicom_transfers", "hl7_messages"],
    attacks=["dos_syn_flood", "port_scan", "arp_mitm", "password_brute_force", "ransomware_smb", "data_exfiltration"],
    roles={
        "pump": dict(n=6, name="infusion-pump", subnet=11, duration_s=9.6, pkts_out=22, pkts_in=20, bytes_out=1900, bytes_in=1700, pkt_size_mean=84, pkt_size_max=220, syn=0.6, ack=19,
                     rst=0.1, fin=0.6, ports=1.5, peers=2, failed_auth=0.01, iat_ms_mean=440, iat_ms_std=60, entropy=3.4, dicom_transfers=0, hl7_messages=6),
        "monitor": dict(n=6, name="patient-monitor", subnet=12, duration_s=9.9, pkts_out=260, pkts_in=60, bytes_out=41000, bytes_in=5200, pkt_size_mean=158, pkt_size_max=600, syn=0.4, ack=58,
                        rst=0.1, fin=0.4, ports=1.5, peers=2, failed_auth=0.01, iat_ms_mean=38, iat_ms_std=9, entropy=4.6, dicom_transfers=0, hl7_messages=22),
        "imaging": dict(n=4, name="imaging-ws", subnet=21, duration_s=9.2, pkts_out=1400, pkts_in=420, bytes_out=1900000, bytes_in=31000, pkt_size_mean=1320, pkt_size_max=1460, syn=3, ack=410,
                        rst=0.4, fin=3, ports=4, peers=5, failed_auth=0.08, iat_ms_mean=7, iat_ms_std=5, entropy=7.1, dicom_transfers=3, hl7_messages=4),
        "nurse": dict(n=4, name="nurse-station", subnet=31, duration_s=8.8, pkts_out=180, pkts_in=260, bytes_out=26000, bytes_in=210000, pkt_size_mean=560, pkt_size_max=1460, syn=6, ack=250,
                      rst=0.8, fin=6, ports=9, peers=12, failed_auth=0.2, iat_ms_mean=40, iat_ms_std=44, entropy=5.6, dicom_transfers=0.2, hl7_messages=14),
        "hvac": dict(n=4, name="bms-controller", subnet=41, duration_s=9.7, pkts_out=48, pkts_in=50, bytes_out=4100, bytes_in=4300, pkt_size_mean=86, pkt_size_max=240, syn=0.8, ack=47,
                     rst=0.1, fin=0.8, ports=2, peers=3, failed_auth=0.02, iat_ms_mean=200, iat_ms_std=30, entropy=3.0, dicom_transfers=0, hl7_messages=0),
    },
    row=lambda T0, t, place, name, ip, mac, peer, rng, role, x, kind: dict(
        event_time=(T0 + pd.to_timedelta(float(t), unit="s")).strftime("%Y-%m-%dT%H:%M:%S"), ward=place, asset_name=name, asset_ip=ip, asset_mac=mac, remote_ip=peer,
        local_port=int(rng.integers(1024, 65535)), remote_port=int(rng.choice([104, 2575, 22, 80, 443, 445, 3389])), transport=str(rng.choice(["tcp", "udp"], p=[0.85, 0.15])),
        badge_id=(f"rn-{int(rng.integers(2000, 2090))}" if role == "nurse" else "-"), **x, attack_category=kind, malicious=int(kind != "benign")),
)

PLANT = dict(
    start="2026-05-04 00:00:00", net="172.20", oui="00:0e:8c", places=["Line 1", "Line 2", "Paint shop", "Packaging"], normal="Normal", normal_windows=230,
    label="Label", host="station", time="ts", features=COMMON + ["ctrl_writes", "ctrl_reads"],
    attacks=["DoS_SYN_Flood", "DDoS_UDP_Flood", "Network_Scan", "ARP_Spoofing", "Brute_Force_Login", "Modbus_Command_Injection", "Firmware_Exploit", "Ransomware"],
    roles={
        "plc": dict(n=8, name="plc-cell", subnet=10, duration_s=9.5, pkts_out=70, pkts_in=72, bytes_out=6100, bytes_in=6300, pkt_size_mean=88, pkt_size_max=260, syn=1, ack=68,
                    rst=0.2, fin=1, ports=2, peers=3, failed_auth=0.02, iat_ms_mean=140, iat_ms_std=30, entropy=3.2, ctrl_writes=3, ctrl_reads=48),
        "hmi": dict(n=5, name="hmi-panel", subnet=20, duration_s=9.0, pkts_out=150, pkts_in=190, bytes_out=23000, bytes_in=99000, pkt_size_mean=430, pkt_size_max=1460, syn=4, ack=180,
                    rst=0.6, fin=4, ports=6, peers=9, failed_auth=0.1, iat_ms_mean=58, iat_ms_std=46, entropy=5.3, ctrl_writes=1, ctrl_reads=14),
        "robot": dict(n=5, name="robot-arm", subnet=30, duration_s=9.8, pkts_out=420, pkts_in=410, bytes_out=52000, bytes_in=50000, pkt_size_mean=124, pkt_size_max=320, syn=0.5, ack=400,
                      rst=0.1, fin=0.5, ports=1.5, peers=2, failed_auth=0.01, iat_ms_mean=23, iat_ms_std=4, entropy=3.8, ctrl_writes=9, ctrl_reads=120),
        "hist": dict(n=3, name="historian", subnet=40, duration_s=9.9, pkts_out=300, pkts_in=900, bytes_out=42000, bytes_in=610000, pkt_size_mean=680, pkt_size_max=1460, syn=5, ack=880,
                     rst=0.5, fin=5, ports=7, peers=22, failed_auth=0.05, iat_ms_mean=11, iat_ms_std=8, entropy=5.9, ctrl_writes=0, ctrl_reads=260),
    },
    row=lambda T0, t, place, name, ip, mac, peer, rng, role, x, kind: dict(
        ts=round(T0.timestamp() + float(t), 3), line=place, station=name, station_ip=ip, mac_address=mac, dst_ip=peer,
        sport=int(rng.integers(1024, 65535)), dport=int(rng.choice([502, 102, 44818, 22, 80, 443, 445])), proto=str(rng.choice(["tcp", "udp"], p=[0.8, 0.2])),
        operator=(f"shift-{int(rng.integers(1, 4))}-op{int(rng.integers(10, 40))}" if role == "hmi" else "-"), **x, Label=kind),
)

if __name__ == "__main__":
    make(os.path.join(HERE, "samples", "sample_organization_hospital_SYNTHETIC.csv"), 20261110, HOSPITAL)
    make(os.path.join(HERE, "samples", "sample_organization_manufacturing_plant_SYNTHETIC.csv"), 20261111, PLANT)
