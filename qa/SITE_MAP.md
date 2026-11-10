# ThreatPrint site map

Written 10 November 2026 for the build that follows the layout, design and audit rounds. One bar at the top holds nine pages, in this order. Every page opens with what it is for.
"Praxis" below means the doctoral praxis of Rayve Malhotra (four training conditions on DataSense, Edge-IIoTset as the ranking check). "Product research" means work built on the praxis procedure that is not part of the praxis.

## The route of a new visitor

1. Sign-in screen: one password field. Nothing of the site is shown before it.
2. Overview: what the product does, in five steps, and the button "Watch the live demo".
3. Live demo: pick a sample, press one button, watch six stages.
4. Results: the 25 result cards.
5. Evaluate: the same run on the visitor's own file.
6. Agent, Research, Organizations, Glossary, Students: reference pages, in any order.

## The pages

| # | Page (address) | Purpose | Sections, in order | What a visitor can do | Praxis or product research |
|---|---|---|---|---|---|
| 0 | Sign-in screen (any address, before the password) | Keep the site to the people who were given the password | Art panel with the three things the product does; the password card | Enter the access password | Neither: access only. The panel names the praxis as in progress and labels the agent, the fingerprint and the ATT&CK mapping as product research |
| 1 | Overview (`/`) | Say what the product is and send the visitor to the Live demo | Hero with the DataSense run of record for organization B; four headline numbers; How it works (five steps); The comparison (four training conditions); The verdict (the decision rule); Start anywhere (three ways in); Limits | Go to the Live demo, the Results, Evaluate or the Agent | The hero card and the four training conditions are praxis (run of record). The agent, the fingerprint and the ATT&CK numbers are product research and are labelled so |
| 2 | Live demo (`/demo`) | Show ingestion, stage by stage, on a sample file | Hero; Samples (four sample files and the built-in example); The run: stage rail and six stage cards (Ingest, Detect column roles, Sanitize, Organize, Train and test, Scorecard) | Run a quick look on any sample with one button; read what happened at each stage; download the report | Product. Every run is labelled "quick look, local run of the tool, not the run of record" |
| 3 | Results (`/results`) | Show the procedure on the praxis dataset, the ranking check and public datasets | Hero; four counts and a note on what the 25 cards are (21 source datasets; one dataset did not run); Gain against isolated training (all four training conditions: isolated is the zero line); Fingerprint sharing on its own chart (experimental); Which attack families transfer; Open a scorecard (one dataset at a time, with downloads); Summary table of all datasets | Hover the marks; open any scorecard; download a report, the scorecard or the tables | DataSense and Edge-IIoTset rows show the praxis runs of record beside the tool's local runs. Every other card is a tool test. The fingerprint chart and the attack families are product research |
| 4 | Evaluate (`/evaluate`) | Run the evaluation on the visitor's own table, or only sanitize it | Hero; tab "Run the evaluation": bring a table (upload or a sample), confirm the columns, choose the budget and run, read the scorecard; tab "Sanitize a file only": see and download what would leave | Upload a CSV or Parquet file up to 200 MB, confirm column roles, run a quick look or a protocol run, download the report and the sanitized table | Product. The procedure is the praxis procedure; a visitor's run is a local run, never a praxis result |
| 5 | Agent (`/agent`) | Offer the local agent and read a fingerprint | Hero with the agent's real output; three steps; downloads (the agent, an example fingerprint, the four sample files); Upload a fingerprint: integrity check, Readiness, Coverage by MITRE ATT&CK, Gaps against the library, Contribute (optional); What a fingerprint is and is not; Experiment: does a fingerprint carry enough to help | Download the agent and samples; upload the example fingerprint without a terminal; contribute a fingerprint after consent | Product research, all of it. Not part of the praxis |
| 6 | Research (`/research`) | The praxis on one page | Title and author; The problem; Thesis (proposed, awaiting advisor approval); Research questions, hypotheses and what the study found; H3 note (observed finding); Run of record on DataSense, organization by organization; What the product adds | Read | Praxis: the title, problem statement, thesis, research questions and hypotheses are quoted word for word; the numbers are the run of record. The connecting paragraphs were written with AI assistance for the site and say so |
| 7 | Organizations (`/organizations`) | The commercial page: who it is for and how to use it | Hero; Who it is for; What you get; Three ways to deploy (free during the review period, no prices); Deployment across sites (the NVIDIA FLARE job, as tested in the simulator); What is built and what is designed; Why post-quantum matters here; Honest limits; Contact | Go to Evaluate, the Agent or the Research page; open the project repository | Product and product research. No praxis claim is made here |
| 8 | Glossary (`/definitions`) | One definition per term, as this tool uses it | Search box; the terms; Sources | Search | Terms of the praxis, defined for the tool; where the praxis applies a different rule on DataSense (attack events), the entry says so |
| 9 | Students (`/students`) | A one-hour exercise with the tool | Six steps; what to be careful about; public datasets with a direct download (from the tracked file `results/_datasets.json`, with whether each one runs in the tool) | Follow the exercise with a sample or a public dataset | Product. The exercise uses the praxis procedure; results are local runs |

## Parts that appear on more than one page

- The scorecard (`show_card`): header with the dataset and its budget; the run-of-record note on the two praxis datasets; three organization panels with all four training conditions as bars (the experimental fingerprint bar hatched under them); the verdicts in the words of the decision rule; the hypothesis tiles (H1 and H2 lead with the run of record on the praxis datasets; H3 is shown as observed); "All numbers" tables; the three organizations; sanitizing; how it was run; the decision rule.
- The downloadable report (`report_html`): the same content as one self-contained HTML file.
- The footer: the praxis credit (in progress, not reviewed or endorsed by the university or the advisor), the AI-assistance line, the storage line and "Sanitized means direct identifiers removed, nothing more".
