# page_definitions

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

GLOSSARY
The words, defined once

Every term, as this tool uses it. Where the praxis applies a different rule on DataSense, the entry says so.

Record
One row of the table: one flow, one packet summary or one time window at one host, described by numbers, with a label.
Attack type
The label of a record: normal, or the kind of attack it belongs to (for example DoS, DDoS, MITM, scanning).
Organization
One of three groups of hosts or devices, each running its own intrusion detector on its own records.
Withheld attack type
The attack type taken out of an organization's own training records. It is still in the other two organizations' training records and in the organization's own test records.
Sanitized
Direct identifiers removed (device names, addresses, ports, time stamps, other labels), nothing more. The behavior numbers and the attack type stay.
Training condition
One way of training the same detector, defined by what it learns from. Four are run: isolated training, sanitized attack-record sharing, federated learning, centralized training.
Isolated training
The baseline. The detector learns from the organization's own records only.
Sanitized attack-record sharing
The organization adds the sanitized attack records of its two peers to its own training records and trains again.
Federated learning
Each organization trains on its own records; after each round the model weights are averaged into one shared detector (FedAvg, McMahan et al., 2017). No records travel.
Centralized training
The reference. One detector trained on the training records every organization keeps after withholding, in one place.
Attack-class recall
Of the test records of the withheld attack type, the share that the detector flagged as an attack and named with the right attack type.
Flagged
Of the test records of the withheld attack type, the share the detector called an attack, whatever name it gave.
False-positive rate
Of the normal test records, the share the detector called an attack. The alarm threshold is set so that about 5% of the organization's own normal validation records are flagged.
Gain
Attack-class recall under a condition minus attack-class recall under isolated training, in percentage points.
95% range
The range of the gain over 2,000 resamples of the attack events (bootstrap), so that records of one attack stay together. See Attack event for how events are formed.
Attack event
For uploads and public datasets: a run of records of one attack type on one host with gaps under 15 seconds, cut at 300 seconds or 200 records. On DataSense the praxis groups records of the same attack type and subtype, no more than 15 seconds apart, across devices (936 reconstructed events; these are reconstructed groups, not confirmed independent attacks).
Tracing (H3)
A receiving peer that holds the sender's normal traffic labeled by host trains a random forest to name the source host of each sanitized attack record. Scored against the majority-host baseline: always naming the sender's busiest host (on DataSense, the majority-device baseline). The peer's labelled reference traffic is a test assumption.
Data sent
Sharing: received records times (4 bytes per number plus 1 byte for the label). Federated learning: model weights, 4 bytes each, two directions, every round. Centralized: each organization's training records sent once.
Decision rule
Gain: the low end of the 95% range above 5 points. False positives: a rise of at most 1 point over isolated training. Privacy (sharing): if the gain is met but the organization's own sent records are traced above the majority-host baseline, the result is a trade-off. Data sent is reported, not judged. Verdict words of the rule: not worth it (the gain is not met, or the false-positive rate rises by more than 1 point); trade-off (sanitized attack-record sharing: the gain is met and the organization's own sent records are traced above the baseline); worth it (sanitized attack-record sharing: the gain is met and they are not); gain met (federated learning).
Fingerprint
A file of summary statistics per attack type written by the local agent: quantiles and rank correlations of the behavior numbers for groups of at least 50 records. No records, no identifier columns. A summary, not a formal privacy protection.
Run of record
The praxis run whose numbers the study reports. DataSense: Hex, 11 October 2026, three seeds, the protocol budget. Edge-IIoTset, the ranking check: Hex, 19 October 2026. Every other run shown by this tool is a local run or a tool rerun and is labelled so.
Quick look and protocol budget
A quick look trains with one seed, fewer passes and fewer resamples: it shows that a file works in the tool. The protocol budget (three seeds, 61 passes, 2,000 resamples) is the praxis budget and the one to report.
Column role
What a column is used for: the label, the host or device, the clock, an identifier to remove, or a behavior number to keep. The tool proposes the roles; a person confirms them.
MITRE ATT&CK
A public catalogue of adversary techniques kept by MITRE. The tool maps each dataset's own attack labels to a common attack family and to the closest techniques (v20.1, Enterprise and ICS); a suggestion, not a ruling.
SOURCES
Where the procedure comes from

The procedure is the frozen protocol of a George Washington University Doctor of Engineering praxis: Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and Federated Learning for Intrusion Detection on Industrial Network Data (Rayve Malhotra, in progress). The study dataset is DataSense CIC IIoT 2025 (Firouzi, Dadkhah, Maret and Ghorbani, 2025; Canadian Institute for Cybersecurity). The ranking check uses Edge-IIoTset (Ferrag, Friha, Hamouda, Maglaras and Janicke, 2022). Federated averaging follows McMahan et al. (2017). The other datasets are public intrusion datasets used to show that the procedure runs on new data; their makers are named on each result page.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
