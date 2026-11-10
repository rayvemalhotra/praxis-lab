"""Make a SYNTHETIC sample organization file for trying Praxis Lab: a fictional water utility with 24 devices.

    python tools/make_sample_org.py            -> samples/sample_organization_water_utility_SYNTHETIC.csv

Everything in the file is made up by this script: device names, addresses, operators and traffic numbers. It has the
shape of real monitoring data (identifier columns, a clock, bursts of attack records on one device) so that the
upload, the sanitizer, the local agent and the evaluation can be tried end to end. It says nothing about real attacks.
"""
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "samples", "sample_organization_water_utility_SYNTHETIC.csv")
rng = np.random.default_rng(20261109)

FEATS = ["duration_s", "packets_out", "packets_in", "bytes_out", "bytes_in", "packet_size_mean", "packet_size_max", "syn_count", "ack_count",
         "rst_count", "fin_count", "channel_spread", "peer_spread", "modbus_write_count", "modbus_read_count", "failed_logins",
         "inter_arrival_ms_mean", "inter_arrival_ms_std", "payload_entropy"]
ROLES = {  # typical 10-second window of normal traffic per device role
    "plc": dict(n=8, name="plc-pump", duration_s=9.5, packets_out=60, packets_in=62, bytes_out=5200, bytes_in=5400, packet_size_mean=86, packet_size_max=260,
                syn_count=1, ack_count=58, rst_count=0.2, fin_count=1, channel_spread=2, peer_spread=3, modbus_write_count=2, modbus_read_count=40,
                failed_logins=0.02, inter_arrival_ms_mean=160, inter_arrival_ms_std=35, payload_entropy=3.1),
    "hmi": dict(n=6, name="hmi-control", duration_s=9.0, packets_out=140, packets_in=180, bytes_out=21000, bytes_in=96000, packet_size_mean=420, packet_size_max=1460,
                syn_count=4, ack_count=170, rst_count=0.6, fin_count=4, channel_spread=6, peer_spread=9, modbus_write_count=1, modbus_read_count=12,
                failed_logins=0.1, inter_arrival_ms_mean=62, inter_arrival_ms_std=48, payload_entropy=5.2),
    "cam": dict(n=6, name="cam-gate", duration_s=10.0, packets_out=900, packets_in=110, bytes_out=1100000, bytes_in=7000, packet_size_mean=1180, packet_size_max=1460,
                syn_count=0.5, ack_count=105, rst_count=0.1, fin_count=0.5, channel_spread=1.5, peer_spread=2, modbus_write_count=0, modbus_read_count=0,
                failed_logins=0.05, inter_arrival_ms_mean=11, inter_arrival_ms_std=6, payload_entropy=7.4),
    "gw": dict(n=4, name="gw-telemetry", duration_s=9.8, packets_out=220, packets_in=240, bytes_out=38000, bytes_in=41000, packet_size_mean=170, packet_size_max=900,
               syn_count=3, ack_count=225, rst_count=0.4, fin_count=3, channel_spread=5, peer_spread=14, modbus_write_count=4, modbus_read_count=90,
               failed_logins=0.05, inter_arrival_ms_mean=44, inter_arrival_ms_std=20, payload_entropy=4.0),
}


def attack(kind, x, role):
    """Change a normal window x (dict of feature values) into a window under one attack type."""
    u = rng.uniform
    if kind == "dos_syn_flood":
        x["packets_in"] *= u(25, 60); x["bytes_in"] *= u(8, 20); x["syn_count"] += u(800, 3000); x["ack_count"] *= u(0.1, 0.4)
        x["inter_arrival_ms_mean"] *= u(0.02, 0.06); x["inter_arrival_ms_std"] *= u(0.05, 0.2); x["packet_size_mean"] = u(58, 70); x["rst_count"] += u(5, 60)
    elif kind == "ddos_udp_flood":
        x["packets_in"] *= u(40, 90); x["bytes_in"] *= u(30, 80); x["peer_spread"] += u(200, 900); x["syn_count"] *= u(0, 0.3)
        x["inter_arrival_ms_mean"] *= u(0.01, 0.04); x["packet_size_mean"] = u(380, 620); x["payload_entropy"] = u(6.8, 7.9)
    elif kind == "port_scan":
        x["channel_spread"] += u(100, 800); x["syn_count"] += u(100, 800); x["rst_count"] += u(90, 700); x["packets_in"] += u(100, 900)
        x["packet_size_mean"] = u(56, 66); x["ack_count"] *= u(0.6, 1.2); x["bytes_in"] *= u(1.0, 1.6)
    elif kind == "arp_mitm":                       # subtle on purpose: traffic still flows, a little slower and more irregular
        x["duration_s"] = min(10.0, x["duration_s"] * u(1.0, 1.05)); x["packets_out"] *= u(1.1, 1.6); x["packets_in"] *= u(1.1, 1.6)
        x["inter_arrival_ms_std"] *= u(1.5, 3.0); x["inter_arrival_ms_mean"] *= u(1.1, 1.5); x["peer_spread"] += u(1, 3); x["rst_count"] += u(0, 3)
    elif kind == "ssh_brute_force":
        x["failed_logins"] += u(20, 200); x["syn_count"] += u(20, 200); x["fin_count"] += u(15, 180); x["packets_in"] += u(200, 1500)
        x["packet_size_mean"] = u(96, 150); x["payload_entropy"] = u(6.9, 7.8)
    elif kind == "modbus_write_injection":
        k = 1.0 if role in ("plc", "gw") else 0.35
        x["modbus_write_count"] += k * u(12, 80); x["modbus_read_count"] *= u(0.5, 1.4); x["packets_in"] += k * u(15, 90); x["peer_spread"] += u(0, 2)
    elif kind == "ransomware_smb":
        x["bytes_out"] *= u(8, 30); x["packets_out"] *= u(5, 14); x["payload_entropy"] = u(7.6, 7.99); x["channel_spread"] += u(5, 30)
        x["peer_spread"] += u(4, 40); x["packet_size_mean"] = u(900, 1400)
    return x


ATTACKS = ["dos_syn_flood", "ddos_udp_flood", "port_scan", "arp_mitm", "ssh_brute_force", "modbus_write_injection", "ransomware_smb"]
T0 = pd.Timestamp("2026-03-02 00:00:00")
rows = []
dev_id = 0
for role, spec in ROLES.items():
    for i in range(1, spec["n"] + 1):
        dev_id += 1
        name = f"{spec['name']}-{i:02d}"
        ip = f"10.20.{ {'plc': 10, 'hmi': 20, 'cam': 30, 'gw': 40}[role] }.{10 + i}"
        mac = "00:1d:9c:" + ":".join(f"{b:02x}" for b in rng.integers(0, 256, 3))
        site = "North Plant" if i % 2 else "South Plant"
        offset = {f: float(rng.lognormal(0, 0.22)) for f in FEATS}          # this device's own habits

        def window(kind, t):
            x = {f: max(0.0, spec[f] * offset[f] * float(rng.lognormal(0, 0.30))) for f in FEATS}
            x["payload_entropy"] = min(7.99, x["payload_entropy"])
            x["duration_s"] = min(10.0, x["duration_s"])
            if kind != "normal":
                x = attack(kind, x, role)
            for f in FEATS:                                                   # counts are whole numbers
                if f not in ("duration_s", "packet_size_mean", "inter_arrival_ms_mean", "inter_arrival_ms_std", "payload_entropy"):
                    x[f] = float(int(round(x[f])))
                else:
                    x[f] = round(x[f], 3)
            peer = f"10.20.{int(rng.integers(10, 50))}.{int(rng.integers(2, 250))}" if kind in ("normal", "arp_mitm", "modbus_write_injection") else f"203.0.113.{int(rng.integers(2, 250))}"
            return dict(timestamp=(T0 + pd.to_timedelta(float(t), unit="s")).strftime("%Y-%m-%d %H:%M:%S"), site=site, device_name=name, device_ip=ip, device_mac=mac,
                        peer_ip=peer, src_port=int(rng.integers(1024, 65535)), dst_port=int(rng.choice([502, 22, 80, 443, 445, 554, 1883])),
                        protocol=str(rng.choice(["tcp", "udp"], p=[0.8, 0.2])), operator_id=(f"op-{int(rng.integers(100, 140))}" if role == "hmi" else "-"),
                        **x, attack_type=kind, is_attack=int(kind != "normal"))

        for t in np.sort(rng.uniform(0, 14 * 86400, 260)):                    # normal windows over two weeks
            rows.append(window("normal", t))
        for kind in ATTACKS:                                                  # each attack arrives as a few bursts on this device
            for _ in range(int(rng.integers(3, 6))):
                t = float(rng.uniform(0, 14 * 86400))
                for _ in range(int(rng.integers(12, 36))):
                    rows.append(window(kind, t))
                    t += float(rng.uniform(2, 9))
df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
df.to_csv(OUT, index=False)
print(f"wrote {OUT}: {len(df):,} records, {df.shape[1]} columns, {df.device_name.nunique()} devices")
print(df.attack_type.value_counts().to_dict())
