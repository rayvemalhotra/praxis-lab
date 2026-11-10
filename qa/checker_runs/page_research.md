# page_research

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

THE RESEARCH BEHIND THREATPRINT
Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and Federated Learning for Intrusion Detection on Industrial Network Data

Doctor of Engineering praxis, George Washington University, SEAS 8499. Author: Rayve Malhotra. Praxis in progress; not reviewed or endorsed by the university or the advisor.

PROBLEM STATEMENT
The problem
Deploying collaborative intrusion detection across industrial networks creates conflicts between privacy and reliability, leaving organizations unable to determine whether the benefits of collaboration outweigh its costs (Hernandez-Ramos et al., 2025; Zibak & Simpson, 2018).
THESIS
Thesis (proposed, awaiting advisor approval)
Sanitized attack-record sharing and federated learning improve mean attack-class recall compared with isolated training across the withheld attack types evaluated in the study.
QUESTIONS AND ANSWERS
Research questions, hypotheses and what the study found

Findings are the DataSense run of record (Hex, 11 October 2026, three seeds).

RQ1
To what extent does receiving sanitized attack records from peers improve attack-class recall for withheld attack types compared with isolated training?
H1
Sharing sanitized attack records improves mean attack-class recall for withheld attack types by at least 5 percentage points compared with isolated training.
+41.1
points, 95% range [32.5, 49.6]
supported
RQ2
To what extent does federated learning improve attack-class recall for withheld attack types compared with isolated training?
H2
Federated learning improves mean attack-class recall for withheld attack types by at least 5 percentage points compared with isolated training.
+45.8
points, 95% range [37.0, 53.9]
supported
RQ3
To what extent can the source device of a sanitized attack record be inferred after direct identifiers are removed?
H3
After direct identifiers are removed, a receiving peer with device-labelled reference traffic identifies the source device of shared attack records more accurately than the majority-device baseline.
41% to 55%
traced, against a majority-device baseline of 7% to 35%
observed

H3. Observed finding: tracing exceeded the majority-device baseline for every sender under the labelled-reference assumption. The statistical support is not called settled yet: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings. This is an open item of the praxis.

RUN OF RECORD
What the study found on DataSense, organization by organization

Attack-class recall on the withheld attack type under the four training conditions, and how often a receiving peer traced sanitized attack records to their source device.

Isolated training
Sanitized attack-record sharing
Federated learning
Centralized training
A, network gear
run of record
7 devices
withheld: DoS
Isolated training
0.0%
Sanitized attack-record sharing
59.9%
Federated learning
57.6%
Centralized training
65.3%
traced to the source device
55.3%
majority-device baseline
34.5%
B, cameras
run of record
10 devices
withheld: DDoS
Isolated training
0.0%
Sanitized attack-record sharing
63.5%
Federated learning
79.9%
Centralized training
67.8%
traced to the source device
41.2%
majority-device baseline
16.9%
C, sensors and plugs
run of record
21 devices
withheld: MITM
Isolated training
0.0%
Sanitized attack-record sharing
0.0%
Federated learning
0.0%
Centralized training
0.0%
traced to the source device
41.1%
majority-device baseline
7.3%
+41.1
H1: mean gain, sanitized attack-record sharing [32.5, 49.6]
+45.8
H2: mean gain, federated learning [37.0, 53.9]
41% to 55%
H3, observed: sanitized records traced to their device (majority-device baseline 7% to 35%)
0.499 to 0.513
membership test on model weights (separate 10-round run): AUC, all six 95% ranges include 0.5, no clear signal

Three organizations were made from the DataSense CIC IIoT 2025 testbed by device role: A, network gear (7 devices, DoS withheld); B, cameras (10 devices, DDoS withheld); C, sensors and plugs (21 devices, MITM withheld). Each organization trained one detector under the four training conditions with the same network, the same step budget per tested detector and the same alarm rule, and was tested on its withheld attack type. H1 and H2 were supported: the whole 95% range of the mean gain lies above 5 points. For H3 the observed finding is that a receiving peer holding device-labelled reference traffic traced the sanitized attack records to their source device above the majority-device baseline for every sender, so removing identifiers is not enough on its own; the statistical support for H3 is not called settled yet (see the note above). Organization C named none of its withheld MITM records under any condition, which the study reports as it is.

FROM STUDY TO PRODUCT
What ThreatPrint adds

The same procedure, as a service: any organization can run it on its own records without sending them anywhere, and read the answer in the terms of the study, with the decision rule applied. The results page shows the procedure on the praxis dataset, on the ranking check (Edge-IIoTset) and on public intrusion datasets, so that the procedure is seen on more than one source of data. The study claims rest on DataSense alone; every other run is a tool test with the tool's own split.

The problem statement, research questions and hypotheses above are quoted as recorded in the praxis; the thesis is a proposal until the advisor approves it. The local agent, the MITRE ATT&CK mapping and fingerprint sharing are product research built on the praxis procedure; they are not part of the praxis. The paragraphs on this page that are not quoted were written with AI assistance for this site; they are not text from the praxis document.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
