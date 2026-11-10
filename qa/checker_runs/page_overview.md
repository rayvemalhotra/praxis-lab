# page_overview

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

COLLABORATIVE DEFENSE, MEASURED

Know what sharing buys.
Know what it exposes.

ThreatPrint measures, on your own intrusion records, what working with other organizations would add to your detection of attack types you have not trained on, and what it would give away. Four training conditions, one scorecard, one decision rule.

Watch the live demo

See the 25 result cards

BUILT ON A GWU DOCTORAL PRAXIS, IN PROGRESS
MITRE ATT&CK V20.1 MAPPING (PRODUCT RESEARCH)
RUNS INSIDE YOUR NETWORK
DATASENSE · RUN OF RECORD
Organization B, cameras · DDoS withheld
Isolated training
0.0%
Sanitized attack-record sharing
63.5%
Federated learning
79.9%
Centralized training
67.8%
sharing: trade-off (gain met, its sent records traced) · federated: gain met
Tracing, run of record: 41.2% of B's sanitized records traced to their device, against the majority-device baseline of 16.9%
25
result cards run with the protocol budget, the praxis dataset and its ranking check among them
4
training conditions: same network, same step budget per tested detector, same alarm rule
11
attack families mapped to MITRE ATT&CK v20.1, Enterprise and ICS (the tool's mapping, product research)
0
records leave your network when you use the local agent (product research, not part of the praxis)
HOW IT WORKS
Five steps on any labeled table of network or device records

Three organizations each run an intrusion detector. Each one has an attack type it has not trained on: its withheld attack type. The other two have seen it. Does working together let each organization catch and name that attack, and what does it give away in return?

1
Make three organizations

Hosts or devices are split into organizations A, B and C. One attack type is withheld from each organization's own training records.

2
Sanitize

Keep the behavior numbers and the attack type. Remove device names, addresses, ports, time stamps and other labels. Sanitized means direct identifiers removed, nothing more.

3
Train under four training conditions

Isolated training, sanitized attack-record sharing, federated learning and centralized training, with the same network, budget and alarm rule.

4
Test on the withheld attack type

Was it flagged as an attack, and was it named with the right attack type? That share is the attack-class recall.

5
Read the scorecard

Gain against isolated training with a 95% range, false-positive rate, data sent, and whether sanitized records can be traced to their source host.

See these steps happen on a sample file
The live demo reads a file, shows which columns it removes and why, forms the three organizations, trains the four training conditions and draws the scorecard, in under a minute.

Open the live demo

THE COMPARISON
Four training conditions, one detector design

Every organization trains the same detector four times. Only what it learns from changes.

1 OF 4
A
B
C
Isolated training

The baseline. The detector learns from the organization's own records only. Nothing travels.

2 OF 4
A
B
C
Sanitized attack-record sharing

Own records plus the peers' sanitized attack records. Records travel; identifiers do not.

3 OF 4
A
B
C
Federated learning

Own records only. After each round the model weights are averaged into one shared detector. No records travel.

4 OF 4
one place
A
B
C
Centralized training

The reference. One detector trained on the training records every organization keeps after withholding, in one place.

THE VERDICT
A decision rule, not an opinion

The rule judges each of the two approaches for each organization. Sanitized attack-record sharing is worth it when the gain and the false-positive checks pass and its sent records are not traced; if they are traced it is a trade-off. Federated learning is judged on the gain and the false-positive checks. Data sent is reported, not judged.

GAIN
5
points

The low end of the 95% range of the recall gain must be above 5 points.

FALSE POSITIVES
1
point

The false-positive rate may rise by at most 1 point over isolated training.

PRIVACY
trade-off

If sanitized records can be traced to their source host above the majority-host guess, the gain comes with a privacy trade-off.

START ANYWHERE
Three ways in
01
Watch it work

Pick a sample file and watch the product take it in, stage by stage: read, detect column roles, sanitize, organize, train under the four training conditions, score.

Open the live demo

02
Evaluate your own data

Upload a CSV with a label column. The tool suggests which columns are identifiers, you confirm, and it runs the four training conditions and draws the scorecard.

Evaluate your data

03
Share only a fingerprint

Run the local agent on your own machine. It sanitizes, maps your attack types to MITRE ATT&CK and writes a fingerprint: summary statistics, no records. Product research, not part of the praxis.

Get the agent

The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis. The praxis itself is the comparison of the four training conditions on DataSense, with Edge-IIoTset as the ranking check.

LIMITS
Stated plainly

The study claims rest on the DataSense dataset alone. Every other dataset, and every upload, shows that the procedure runs on new data; the splits are the tool's own and are not audited.

Removing identifiers does not stop tracing. On DataSense, sanitized attack records were traced to their source device 41% to 55% of the time against a majority-device baseline of 7% to 35%. The tool measures this for your data when a host column exists.

A quick look uses a smaller training budget than the protocol. It shows whether your data works in the tool; the protocol run is the one to report.

The tool does not store uploads: everything runs in the session and is gone when the page closes. A fingerprint is kept only if you choose to contribute it on the Agent page. Do not upload data you are not allowed to process.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
