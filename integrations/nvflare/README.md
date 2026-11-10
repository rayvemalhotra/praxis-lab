# ThreatPrint on NVIDIA FLARE

This folder runs the federated learning condition of ThreatPrint as an NVIDIA FLARE job. NVIDIA FLARE (NVFlare) is NVIDIA's open-source federated learning software (Apache License 2.0). The job trains the same detector, with the same settings, as the engine's own federated learning condition, and the result is scored with the engine's own test.

Three things to know before reading further.

1. This is product research. It is not part of the praxis. The praxis federated learning condition is the engine's own loop (`engine.Bench.run`), and nothing here changes a praxis number or a praxis sentence.
2. It ran in the FLARE simulator on a CPU. No NVIDIA hardware was used, and no claim is made about NVIDIA GPUs.
3. It uses NVIDIA FLARE as published. NVIDIA has not reviewed or endorsed this work, and there is no partnership.

## Run it in three commands

```
pip install -r requirements.txt -r requirements-nvflare.txt
python integrations/nvflare/run_simulator.py
python -m pytest integrations/nvflare -q
```

The second command runs the built-in example and the water utility sample, three seeds each, prints the comparison and rewrites `STATUS.json`. The third runs five tests (they are skipped when NVIDIA FLARE is not installed).

Other ways to run it:

```
python integrations/nvflare/run_simulator.py --table my_records.csv        # any labeled table the web tool can read
python integrations/nvflare/run_simulator.py --budget protocol --seeds 0   # the larger training budget
python integrations/nvflare/export_job.py --table water_utility --out /tmp/threatprint_flare   # write the job folder and the site folders
```

## What is in the folder

| File | What it does |
|---|---|
| `site_train.py` | What one organization does in one round: reads its own folder, fits its own scaling, trains with the engine's loop. Travels with the job. |
| `flare_client.py` | The script FLARE runs at each site (FLARE Client API): receive the shared detector, train, send the weights back. |
| `tp_flare.py` | Makes the three organizations as the engine does, writes the site folders, builds the FLARE job (FLARE Recipe API, `FedAvgRecipe`), runs it in the simulator (`SimEnv`), loads and scores the result, and repeats the job without FLARE as a check. |
| `run_simulator.py` | Runs everything, compares with the engine, writes `STATUS.json`. |
| `export_job.py` | Writes a standard FLARE job folder (`meta.json`, `app/config`, `app/custom`) and one data folder per site. The job carries `engine.py`, so a site needs FLARE and the Python packages, not a ThreatPrint install. |
| `test_nvflare_job.py` | Five tests: the plan matches the engine, each site folder holds only its own sanitized training records, the simulator finishes and the engine can score the model, FLARE does the arithmetic of the engine's loop, and the exported job runs under the `nvflare simulator` command from another folder. |
| `STATUS.json` | Written by `run_simulator.py`, never by hand. The Organizations page of the web tool reads it. |

## What was run, and on what

The numbers below are from `STATUS.json` of the run of 10 November 2026, 00:56 EST: NVIDIA FLARE 2.9.0, Python 3.12.13, PyTorch 2.6.0 (CPU build), Linux on ARM (aarch64), 4 processors, no GPU. Six runs: two tables, seeds 0, 1 and 2, the quick budget (24 passes of training, 2 local passes per round, which the engine's rule turns into 4 rounds). Each run took 20 to 24 seconds in the simulator; the whole command took 2 minutes 19 seconds. One run held about 2.6 GB of memory, summed over the orchestrator, the simulated server and the three simulated sites (shared pages are counted more than once in that sum).

Each run did the following. It made three organizations and their withheld attack types with `engine.Data`. It ran the engine's own federated learning condition. It wrote each organization's own training records (behavior numbers and attack type, withheld type taken out, no identifiers) to its own site folder. It ran FedAvg in the FLARE simulator with three sites. It scored FLARE's shared detector with `engine.Bench.test`: the alarm threshold from each organization's own normal validation records, then attack-class recall on the withheld attack type.

## The numbers

Attack-class recall on the withheld attack type. These are local runs of the tool with the quick budget, not the run of record and not praxis results. Both tables are made up or synthetic and say nothing about real attacks.

Built-in example (6,600 records, 12 behavior numbers, about 980 to 1,000 own training records per organization, 62 to 73 test records of the withheld type):

| Seed | Engine A | Engine B | Engine C | FLARE A | FLARE B | FLARE C |
|---|---|---|---|---|---|---|
| 0 | 100.0% | 44.8% | 93.5% | 100.0% | 38.8% | 96.8% |
| 1 | 100.0% | 52.2% | 91.9% | 100.0% | 55.2% | 98.4% |
| 2 | 100.0% | 56.7% | 95.2% | 100.0% | 47.8% | 93.5% |
| Mean | 100.0% | 51.2% | 93.5% | 100.0% | 47.3% | 96.2% |

Water utility sample, synthetic (22,073 records, 19 behavior numbers, 3,150 to 3,237 own training records per organization):

| Seed | Engine A | Engine B | Engine C | FLARE A | FLARE B | FLARE C |
|---|---|---|---|---|---|---|
| 0 | 100.0% | 100.0% | 59.9% | 100.0% | 100.0% | 58.4% |
| 1 | 100.0% | 100.0% | 59.5% | 100.0% | 100.0% | 58.8% |
| 2 | 100.0% | 100.0% | 58.4% | 100.0% | 100.0% | 58.4% |
| Mean | 100.0% | 100.0% | 59.3% | 100.0% | 100.0% | 58.5% |

The largest difference between the engine and FLARE at the same seed was 9.0 points (organization B of the built-in example, where one test record is worth 1.5 points). Between seeds the engine itself moved by up to 11.9 points on that organization, and FLARE by up to 16.4 points. On the water utility sample the two stayed within 1.6 points of each other. The false-positive rates of every run are in `STATUS.json`.

A separate run with the larger training budget (`--budget protocol`, built-in example, seed 0, one site at a time in the simulator) also finished: 5 rounds of 4 local passes; engine A 100.0%, B 61.2%, C 95.2%; FLARE A 100.0%, B 64.2%, C 96.8%. It is not in `STATUS.json`.

## What is the same as the engine, and what differs

The same, read from the engine and not copied by hand: the detector (`engine.Detector`), the training loop (`engine.Bench.train`), the batch size and learning rate (`engine.BATCH`, `engine.LR`), the local passes per round and the training budget (`engine.Budget`), the rule for the number of rounds (checked in every run against the number of rounds the engine itself reports), scaling fitted on each organization's own records, weighting each organization by its number of own training records, the alarm rule and the scoring (`engine.Bench.test`).

What differs, and why:

1. **The random draws.** The engine draws the starting weights and the shuffling order from one random stream that its four training conditions share, so by the time federated learning starts the stream has already been used by isolated training and by sanitized attack-record sharing. A federation has no such shared stream. Here the starting weights come from `torch.manual_seed(seed)` and each site shuffles with its own seed for each round. This is the whole reason the two columns above are not equal.
2. **Who computes the weighted mean.** In the engine it is one line of Python. In FLARE it is FLARE's FedAvg controller, which adds the sites' weights in the order their results arrive.
3. **How the weighting is set.** FLARE weights a site by an aggregation weight times the number of optimizer steps the site reports. The job sets the aggregation weight of each site to its records divided by its steps, so each site counts by its number of records, as in the engine. The server therefore learns each site's record count, as FedAvg requires.
4. **What sites must agree on beforehand.** The engine takes the list of behavior numbers and the list of attack types from the whole table. In a federation the sites must agree on both before training (`contract.json`), and that list names every attack type any site has seen.

To separate point 1 from points 2 and 3, every run repeats the job without FLARE: the engine's loop, fed with the same starting weights, the same shuffling seeds and the same site folders. If FLARE does the same arithmetic, the two shared detectors must agree to rounding error. They did. After one round the largest difference in any weight was at most 6e-08 in every run, which is float rounding in the weighted mean. Later rounds train on from those weights, so the rounding grows; at the end of these six runs it was between 2e-07 and 7e-05, and it changes from run to run with the order in which results arrive (an earlier run of the same command reached 3e-04). The scores of FLARE's detector and of the loop without FLARE (recall, share flagged, false-positive rate) were identical in 6 of 6 runs. The arithmetic was not tuned to make the engine and FLARE columns match, and they do not match.

## What this does not show

- No NVIDIA hardware. The simulator ran on a CPU. Nothing here says how fast this would be on a GPU. The detector has about 10,000 to 11,000 weights and trains in seconds on a CPU at these sizes, so a GPU matters only for much larger tables or models. The engine trains on the CPU today; moving it to CUDA is a code change that was not made or tested here.
- No real separate sites. The three sites were simulated on one machine, with their folders side by side. No network, no firewall, no second organization was involved.
- No provisioning and no secured channels. The simulator does not use FLARE's startup kits or certificates.
- No protection of the weights. The simulated server saw every site's weights in every round. No secure aggregation, homomorphic encryption or differential privacy was used. What model weights reveal about a site was not measured here.
- The exported job is tied to this machine: it holds the path of the site folders and of the starting weights. Each real site would set its own data path.
- Only the federated learning condition. Isolated training, sanitized attack-record sharing, centralized training and the tracing test stay in the engine.
- Two tables, both made up or synthetic, with the quick budget. No real attack data and no praxis dataset was run through FLARE.

## Next real steps for a consortium

These are steps NVIDIA FLARE 2.9.0 has commands or modules for. None of them was run here.

1. Try a local FLARE system before real sites: `nvflare poc prepare` and `nvflare poc start` set up a server and sites on one machine (the Recipe API has `PocEnv` for this).
2. Provision the real federation: `nvflare provision` writes a startup kit with certificates for the server and for each site, and `nvflare preflight-check` checks a kit before deployment. Each organization then runs its site on its own machine with its own data folder.
3. Submit the job to the provisioned system: `nvflare job submit -j <job folder>`, or the Recipe API with `ProdEnv`. Give each site its own `--data_root` with the recipe's per-site configuration.
4. Decide how the weights are protected. FLARE ships FedAvg with homomorphic encryption (`nvflare.app_opt.pt.recipes.fedavg_he`, which needs provisioned kits and does not run in the simulator) and privacy filters for what a site sends (`nvflare.app_common.filters`, for example `svt_privacy`, `percentile_privacy` and `exclude_vars`). Each has a cost in accuracy or time that would have to be measured with the same scorecard.
5. Measure what leaves a site. The praxis measures what sanitized attack records give away (the tracing test). The same question for model weights in a FLARE federation is open.
6. Only then, GPUs: larger detectors or much larger tables at each site, trained with CUDA, with the same job.

In NVIDIA FLARE 2.9.0 the `nvflare simulator` command is marked deprecated in favor of the Recipe API with `SimEnv`, which `run_simulator.py` uses. The command still works in 2.9.0 and one test uses it to check the exported job.
