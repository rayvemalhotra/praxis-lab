| Dataset | Role | Records (train+val+test) | Organizations | Numbers kept | H1 sharing | H2 federated | H3 traced above guessing | Verdicts sharing A/B/C | Verdicts federated A/B/C |
|---|---|---|---|---|---|---|---|---|---|
| DataSense CIC IIoT 2025 (the study) | the study | 29,574 | hosts | 59 | +40.9 [+32.3, +49.5] yes | +46.0 [+37.1, +54.1] yes | all 3 | trade-off/trade-off/no gain | gain/gain/no gain |
| Edge-IIoTset (ranking check) | ranking check | 134,981 | random thirds | 38 | +71.1 [+69.8, +72.3] yes | +61.8 [+60.7, +62.9] yes | not tested | gain/gain/gain | FP breach/gain/gain |
| BoT-IoT 5% (Kaggle) | tool test | 18,556 | random thirds | 32 | +76.0 [+74.5, +77.3] yes | +92.1 [+87.3, +95.8] yes | not all | gain/gain/gain | gain/FP breach/FP breach |
| BoT-IoT, 5% release (four files) | tool test | 95,944 | random thirds | 32 | +88.2 [+84.6, +92.0] yes | +57.5 [+52.3, +63.1] yes | not all | gain/gain/gain | gain/gain/gain |
| CIC-IDS2017 (labelled flows) | tool test | 120,013 | random thirds | 69 | +98.7 [+98.5, +98.9] yes | +96.6 [+96.3, +97.0] yes | not all | gain/gain/gain | gain/gain/gain |
| CIC-IDS2017 improved (Engelen, Troia and Vanhoef, 2021) | tool test | 120,069 | random thirds | 80 | +97.2 [+96.2, +98.0] yes | +90.1 [+87.7, +92.6] yes | not all | gain/gain/gain | gain/gain/gain |
| CICIoT2023 (merged flows) | tool test | 120,623 | random thirds | 39 | +69.0 [+68.3, +69.7] yes | +66.2 [+65.9, +66.5] yes | not tested | gain/gain/gain | gain/gain/no gain |
| CIDDS-001 (OpenStack and external server flows) | tool test | 95,753 | hosts | 4 | +13.0 [+9.9, +16.3] yes | +0.8 [+0.3, +1.7] no | not all | gain/trade-off/no gain | no gain/no gain/no gain |
| CSE-CIC-IDS2018 (seven days) | tool test | 120,088 | random thirds | 66 | +78.4 [+77.6, +79.2] yes | +70.1 [+68.9, +71.1] yes | not tested | gain/gain/gain | gain/gain/gain |
| CTU-13 botnet families (NetTiSA flows) | tool test | 41,040 | random thirds | 24 | +92.4 [+88.8, +94.6] yes | +90.0 [+85.8, +92.8] yes | not tested | gain/gain/gain | gain/gain/gain |
| DNP3 intrusion detection dataset (CICFlowMeter flows, 120 s timeout) | tool test | 41,596 | hosts | 65 | +60.9 [+59.8, +62.0] yes | +33.3 [+33.2, +33.3] yes | not all | gain/trade-off/no gain | no gain/no gain/gain |
| Edge-IIoTset, ML subset (raw packet fields) | tool test | 119,994 | random thirds | 32 | +74.5 [+70.6, +78.6] yes | +62.8 [+62.2, +63.4] yes | not all | gain/gain/gain | gain/gain/no gain |
| Electra Modbus (electric traction substation) | tool test | 119,994 | random thirds | 5 | +50.8 [+49.7, +51.9] yes | +41.4 [+40.4, +42.2] yes | not all | gain/gain/gain | gain/no gain/gain |
| Electra S7comm (electric traction substation) | tool test | 119,996 | random thirds | 4 | +35.6 [+35.2, +36.0] yes | +33.3 [+33.3, +33.3] yes | not all | gain/gain/no gain | gain/no gain/no gain |
| IEC 60870-5-104 intrusion detection dataset (balanced flows) | tool test | 6,828 | random thirds | 56 | +45.2 [+39.6, +50.5] yes | +6.6 [+4.9, +8.6] no | not all | FP breach/gain/no gain | no gain/gain/no gain |
| InSDN (software-defined network) | tool test | 120,001 | random thirds | 62 | +99.5 [+98.7, +99.9] yes | +98.9 [+98.5, +99.2] yes | not all | gain/gain/gain | gain/gain/gain |
| IoT-23 (twelve scenarios, Zeek connection logs) | tool test | 102,345 | hosts | 6 | +61.9 [+61.5, +62.4] yes | +23.7 [+22.1, +26.3] yes | not all | gain/no gain/gain | no gain/gain/gain |
| N-BaIoT (nine IoT devices) | tool test | 222,500 | hosts | 115 | +97.3 [+97.0, +97.5] yes | +76.9 [+76.3, +77.6] yes | not all | gain/gain/gain | gain/gain/gain |
| NF-ToN-IoT-v3 (2025 NetFlow) | tool test | 99,819 | hosts | 46 | +51.0 [+45.8, +58.1] yes | +42.7 [+39.4, +45.3] yes | all 3 | FP breach/FP breach/trade-off | no gain/FP breach/gain |
| NSL-KDD (KDDTrain+ and KDDTest+) | tool test | 85,592 | random thirds | 24 | +80.2 [+78.3, +82.4] yes | +35.5 [+34.9, +36.1] yes | not tested | gain/gain/gain | gain/no gain/no gain |
| RT-IoT2022 | tool test | 68,458 | random thirds | 78 | +94.5 [+93.5, +95.4] yes | +73.4 [+71.8, +75.0] yes | not tested | gain/gain/gain | gain/gain/gain |
| ToN_IoT network (Train_Test_Network) | tool test | 119,994 | hosts | 12 | +25.6 [+24.9, +26.3] yes | +0.0 [+0.0, +0.0] no | not all | gain/no gain/FP breach | no gain/no gain/no gain |
| UNSW-NB15 (Kaggle) | tool test | 103,617 | hosts | 34 | +66.4 [+59.0, +76.9] yes | +31.6 [+27.4, +36.3] yes | not all | gain/gain/gain | no gain/gain/gain |
| WUSTL-IIoT-2021 (Kaggle) | tool test | 60,711 | random thirds | 39 | +92.6 [+77.0, +97.6] yes | +66.5 [+66.4, +66.6] yes | not all | gain/gain/gain | gain/gain/no gain |
| X-IIoTID (Kaggle) | tool test | 109,576 | random thirds | 38 | +93.5 [+90.4, +95.8] yes | +53.4 [+48.1, +58.6] yes | not all | gain/gain/gain | gain/gain/gain |
| cidds002 | failed | | | | at least three attack types are needed so that each organization can withhold a different one | | | | |
