# page_organizations

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

FOR ORGANIZATIONS
An evaluation, not a promise

Information-sharing groups ask members to contribute attack data. Federated learning vendors ask them to contribute model updates. ThreatPrint measures, on your own records, what each would gain in detecting the attack types you have not trained on, what it would cost in false alarms, how many bytes would leave, and whether a sanitized record could still be traced back to one of your devices.

WHO IT IS FOR
Three kinds of organization ask this question
Operators of industrial and IoT networks

Utilities, manufacturing, building systems, healthcare devices. You are asked to share attack data or to join a federated program, and you need to know what it would add to your own detection and what it would expose.

Groups that ask members to share

ISACs, sector CERTs and consortia. Each member gets its own evidence of the gain and of the exposure, in the same terms as every other member: for this member, with this data, is sharing worth it?

Builders and researchers of federated detection

One test bench for every approach: the same detector, the same step budget per tested detector and the same alarm rule, on the customer's own records, with the decision rule applied.

WHAT YOU GET
Before you share, know what it buys and what it exposes
1
A scorecard in your own terms

Four training conditions on your data, one withheld attack type per organization, gains with 95% ranges, false-positive rates, data sent, tracing. A report you can hand to a security committee.

2
A rule, not an opinion

The decision rule says when an approach is worth it: gain low end above 5 points, false positives up by at most 1 point, and a tracing check on what sharing exposes.

3
Coverage by MITRE ATT&CK

The local agent maps your attack labels to common families and techniques and shows which families the library holds that you do not.

4
Run it where your records are

Run the tool on your own machine or inside your network (one container) and nothing leaves it. Uploads to a hosted copy live in the browser session only and are not stored; a fingerprint is kept only if you choose to contribute it.

HOW TO USE IT
Three ways to deploy

Free during the review period.

01
On this site

Watch a sample file go through the product, then upload a labeled sample of your own, run a quick look, read the scorecard and download the report. The table you upload is not stored.

Open the live demo

02
With the local agent

Run the agent on your records and upload only the fingerprint: no records leave your network. You get your MITRE ATT&CK coverage, the gaps against the library and a readiness check.

Get the agent

03
Inside your network

The same tool as a container or a local install (the repository and the Dockerfile are public). Protocol-budget runs on your full records, reports for your records only.

Read the research

DEPLOYMENT ACROSS SITES
From one machine to separate sites

In this tool the federated learning condition runs in one process: the three organizations are simulated on one machine and their model weights are averaged with FedAvg. Running the same condition across separate sites needs a federated runtime. This section reports only what has been run and tested.

NVIDIA FLARE job export
tested

The federated learning condition ran as an NVIDIA FLARE 2.9.0 FedAvg job in the FLARE simulator on CPU (6 runs, three sites each, no NVIDIA hardware); product research, not part of the praxis.

NVIDIA FLARE 2.9.0, simulator, CPU only (Linux aarch64); no NVIDIA GPU was used and none is claimed.
Three sites, one per organization. Each site read only its own training records; model weights travelled, records did not.
Same detector, training loop, batch size, learning rate, local passes, rounds and record-count weighting as the engine's federated condition, read from the engine.
Check of FLARE's arithmetic: from the same starting weights and shuffling seeds, a plain loop without FLARE gave the same shared detector, to within 6e-08 after one round (float rounding) and 5e-05 at the end, with identical scores in 6 of 6 runs.
built-in example, quick budget, seed 0, attack-class recall on the withheld type (local run of the tool): engine A 100.0%, B 44.8%, C 93.5%; FLARE A 100.0%, B 38.8%, C 96.8%. The two differ only in their random draws.
sample_organization_water_utility_SYNTHETIC.csv, quick budget, seed 0, attack-class recall on the withheld type (local run of the tool): engine A 100.0%, B 100.0%, C 59.9%; FLARE A 100.0%, B 100.0%, C 58.4%. The two differ only in their random draws.
Largest difference between engine and FLARE at the same seed over the 6 runs: 9.0 points (organization B of built-in example, 67 test records of the withheld type). Between seeds the engine itself moved by up to 11.9 points there.
Not shown: real separate sites, FLARE provisioning and secured channels, training on NVIDIA GPUs.
Product research. The praxis federated condition is the engine's own loop and is unchanged.

Product research built on the praxis procedure. It is not part of the praxis, which compares the four training conditions inside one process.

STATUS
What is built, and what is designed
Built
Evaluation of four training conditions on your data, with the decision rule
Live demo: a sample file through every stage, with the numbers of that run
Sanitizer with one record shown before and after
Local agent: sanitize at home, fingerprint file, SHA3-256 integrity digest
Attack labels mapped to common families and MITRE ATT&CK v20.1 (Enterprise and ICS), identifiers checked against MITRE's published data
Library of public datasets run with the protocol budget, with a table of which attack families transfer
Fingerprint sharing as an experimental fifth arm
Designed or not built
Measuring what a fingerprint reveals about its sender (tracing and membership tests on fingerprints) designed, not built
Post-quantum signature on fingerprints (ML-DSA, FIPS 204) and post-quantum key exchange for uploads (ML-KEM, FIPS 203) designed, not built
Differential privacy or other formal protection on what is shared not built
Accounts, saved runs, payments not built
LOOKING AHEAD
Why post-quantum matters here
AUGUST 2024
Standards published
FIPS 203, 204 and 205
(ML-KEM, ML-DSA, SLH-DSA)
TODAY
Harvest now, decrypt later
Traffic captured today can be stored
and decrypted once the machines exist
2030
Deprecated
Today's public-key algorithms, as reported
from NIST's transition report IR 8547
2035
Disallowed
The same algorithms,
as reported from the same report

The 2030 and 2035 dates are as reported from NIST IR 8547; whether that report is final was not confirmed on nist.gov when this page was written.

Attack records, model updates and fingerprints describe the weak points of industrial equipment that stays in service for fifteen or twenty years, so what organizations exchange about their defenses needs protection with a long life. In this tool the fingerprint already carries a hash-based integrity digest (SHA3-256) and a signature field built to take ML-DSA; the signing itself and a post-quantum upload channel are designed, not built. Quantum machine learning for detection is not part of the plan: the value is in protecting what is shared, not in a quantum detector.

LIMITS
Honest limits

The procedure needs labeled records with at least three attack types, a normal label, and ideally a host or device column and a clock. It evaluates detectors of the study's design; it is not an intrusion detection product itself.

Sanitized means direct identifiers removed, nothing more. The tracing test shows what that leaves exposed; it does not apply differential privacy or any other control.

Results on a quick look are a check; the protocol budget is the one to decide on. The study claims rest on DataSense; your data gets its own evidence.

CONTACT
Talk to the author

Open an issue or a discussion on the project repository.

ThreatPrint
Know what sharing buys. Know what it exposes. Built on the procedure of a George Washington University doctoral praxis by Rayve Malhotra (SEAS 8499). Praxis in progress; not reviewed or endorsed by the university or the advisor. The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. The study design, protocol, hypotheses and decisions are the author's. The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis.
ThreatPrint 0.4 (10 November 2026)
Uploads are not stored. A fingerprint is kept only if you choose to contribute it.
Sanitized means direct identifiers removed, nothing more.
