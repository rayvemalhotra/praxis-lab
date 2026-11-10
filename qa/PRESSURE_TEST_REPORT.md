# ThreatPrint pressure test report

Built by `tests/pressure/report.py` on 10 November 2026, 04:37 from the result files in `qa/`. Every number below was produced by a run of the suite;
the file and the machine of each part are listed at the end. Rerun: `python tests/pressure/run_all.py` (about 12 minutes on the Mac with the library datasets,
`--quick` about 5 minutes without them). The patches that `app.py` needed (`qa/APP_PATCHES.md`, P1 to P11) were applied on 10 November 2026; that file is kept as the record of what was found.

## Summary

- Checks in this report: 190. Passed: 180. Failed: 0. Open, waiting for a patch in `app.py`: 0. Notes (measurements, no pass or fail): 10. The last table of this report shows how the total is counted, section by section.
- As found, before any fix: the ingestion matrix ran 19 of 21 files and matched the hand-made column roles on 15; of 32 malformed or hostile tables 20 ended well and 2 ended the Python process; two evaluations at once changed each other's numbers.
- Now: the matrix runs 22 of 23 files and matches the hand-made roles on 20; the others are explained in the table. All 34 malformed or hostile tables end in a run or in one sentence for the person. Runs at once give the serial numbers.
- The engine changes did not move a result. On the Linux test machine the built-in example gives the identical scorecard before and after the changes (SHA-256 of all its numbers: f5610472a743d620...; the baseline was saved before the changes). On the Mac, 7 library cards were recomputed from their data with today's engine and the budget written in each card: 0 differing values out of 2472.

## The worst findings

1. **A 13-byte cell ends the whole site on Linux.** A CSV cell such as `1e2147483648` (or the hex string `32342e33302037352e37350d0a`, which the Edge-IIoTset payload column holds) makes the number parser of pandas 2.3.3 end the Python process on Linux (segmentation fault in `read_csv` and `to_numeric`; macOS is not affected). Through the real page, as found: server alive: False; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: False; page said: nothing special. Fixed in the engine and the agent (`read_table`, `defuse`); the page reads every upload and every sample file through `read_table` (patch P1, applied). Through the real page now: server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: Note: 3 cells look like numbers with an impossible exponent (for example 1e2147483648); they are kept as text with a ~ in front..
2. **Two visitors at once got numbers that no single run gives.** PyTorch's global random generator is shared by every visitor thread. As found: 2 of 2 runs at once differed from the serial result (22.9 s); 6 of 6 runs at once differed from the serial result (96.7 s). Fixed with one run at a time in the process (`engine.RUN_LOCK`): 0 of 2 differ (15.0 s); 0 of 6 differ (45.8 s).
3. **A hostile fingerprint file broke the page and put its own markup into it.** 26 files; before the check 13 ended in a traceback or put markup from the file into the page; now 0 do. Through the real page: image tag with a script handler as removed_columns_count: scripts that ran: 0; elements from the file in the page: 0 (with its script handler still attached: 0); tracebacks: 0; page said: This file could not be used: the file is not a valid fingerprint: removed_columns_count or payload_bytes.; a JSON list: scripts that ran: 0; elements from the file in the page: 0 (with its script handler still attached: 0); tracebacks: 0; page said: This file could not be used: the file is not a valid fingerprint: it is not a JSON object.. Streamlit's own filter removed the script handler, so markup was injected but no script ran. The contribute button built its file name from a field of the upload (a path in that field resolves outside the folder; only the disabled state of a button stood in the way, and forcing that button was not tried). Fixed in `threatprint_agent.load_fingerprint` and `engine.save_contribution`; the page uses both (patches P2 and P3, applied), so the file name of a kept fingerprint is the digest the server computes itself.
4. **The sign-in delay was not a limit.** As found, a fresh session started with a clean count: 231 to 262 password guesses a minute from one machine over four runs of the probe (recorded in `qa/APP_PATCHES.md`). Nothing behind the gate was reachable without the password, and forged messages did not open it. The page now counts wrong passwords for the whole site (`engine.GATE_LIMITER`, patch P4, applied): of 10 guesses sent at once from fresh sessions, 9 were turned away by the limit; of 30 guesses sent at once from fresh sessions, 30 were turned away by the limit.
5. **The automatic column detection was wrong on real datasets, silently.** As found it chose a sub-category, an attacker/victim flag or an attack identifier as the attack type on three library datasets, missed the host column of Zeek logs, and one quick look stopped on a table with little normal traffic. Detection rules fixed; where a person is needed (no value that means normal) the tool now says so on the page (`benign_guess`, patch P6, applied).

## A and H. Ingestion matrix, automatic path (result file: 2026-11-10 03:04, Darwin arm64, 18 cores)

Every file goes through what the upload page does: read, `engine.inspect` with no settings, every suggestion accepted, `engine.run` with the quick budget.
Four sample files ship with the tool (two of them new: a hospital and a manufacturing plant, both synthetic, made by `tools/make_sample_orgs_more.py` with a fixed seed).

| File | Records x columns | Result | Detected roles against the hand-made settings | Evidence |
|---|---|---|---|---|
| sample_organization_hospital_SYNTHETIC.csv | 19,507 x 31 | ran | all four as a person would pick | H1 +78.1 points (above the 5-point rule), H2 +74.9; 8.7 s; peak memory 492 MB; groups of hosts (each host belongs to one or |
| sample_organization_manufacturing_plant_SYNTHETIC.csv | 21,198 x 30 | ran | all four as a person would pick | H1 +98.2 points (above the 5-point rule), H2 +98.8; 8.9 s; peak memory 499 MB; groups of hosts (each host belongs to one or |
| sample_organization_water_utility_SYNTHETIC.csv | 22,073 x 31 | ran | all four as a person would pick | H1 +86.8 points (above the 5-point rule), H2 +86.6; 8.8 s; peak memory 501 MB; groups of hosts (each host belongs to one or |
| sample_power_grid_dnp3_REAL_CC-BY-4.0.csv | 10,952 x 85 | ran | all four as a person would pick | H1 +20.5 points (above the 5-point rule), H2 +0.0; 7.7 s; peak memory 537 MB; groups of hosts (each host belongs to one or |
| bot_iot_5pct.csv | 95,944 x 47 | ran | all four as a person would pick | H1 +99.9 points (above the 5-point rule), H2 +99.0; 8.7 s; peak memory 736 MB; three random thirds of the records (the host |
| cic_ids2017.csv | 120,013 x 85 | ran | all four as a person would pick | H1 +95.6 points (above the 5-point rule), H2 +79.5; 10.1 s; peak memory 1146 MB; three random thirds of the records (the host |
| cic_ids2017_improved.csv | 120,069 x 91 | ran | all four as a person would pick | H1 +97.8 points (above the 5-point rule), H2 +85.2; 9.9 s; peak memory 1045 MB; three random thirds of the records (the host |
| ciciot2023.csv | 120,624 x 40 | ran | all four as a person would pick | H1 +52.2 points (above the 5-point rule), H2 +33.3; 3.1 s; peak memory 662 MB; three random thirds of the records (no host  |
| cidds001.csv | 95,753 x 16 | ran | all four as a person would pick | H1 +38.8 points (above the 5-point rule), H2 +9.2; 9.7 s; peak memory 661 MB; groups of hosts (each host belongs to one or |
| cidds002.csv | 60,000 x 16 | refused | differs: label, normal value, time | DataProblem: the label column holds 2 attack types besides the normal value 'normal' (attacker, victim); at least three are needed so that each organization can withhold a different one. Pick another label column, or add records o NOTE: The file holds one attack type (scan) in attackType; the hand-made settings built attack types from the nmap arguments and name a time column the file does not have. Without that hand work the table cannot support an evaluation, and the tool says so in one sentence. |
| cse_cic_ids2018.csv | 120,089 x 80 | ran | all four as a person would pick | H1 +81.4 points (above the 5-point rule), H2 +81.9; 4.6 s; peak memory 1145 MB; three random thirds of the records (no host  |
| ctu13_nettisa.csv | 41,070 x 32 | ran | all four as a person would pick | H1 +90.8 points (above the 5-point rule), H2 +88.4; 2.9 s; peak memory 583 MB; three random thirds of the records (the host |
| dnp3.csv | 41,596 x 86 | ran | all four as a person would pick | H1 +66.7 points (above the 5-point rule), H2 +33.3; 11.4 s; peak memory 753 MB; groups of hosts (each host belongs to one or |
| edge_iiotset_ml.csv | 119,994 x 63 | ran | all four as a person would pick | H1 +77.0 points (above the 5-point rule), H2 +62.8; 11.1 s; peak memory 799 MB; three random thirds of the records (the host |
| electra_modbus.csv | 119,994 x 11 | ran | all four as a person would pick | H1 +40.4 points (above the 5-point rule), H2 +39.7; 8.2 s; peak memory 537 MB; three random thirds of the records (the host |
| electra_s7comm.csv | 119,996 x 11 | ran | all four as a person would pick | H1 +33.3 points (above the 5-point rule), H2 +33.3; 8.6 s; peak memory 537 MB; three random thirds of the records (the host |
| iec104.csv | 6,828 x 84 | ran | all four as a person would pick | H1 +27.5 points (above the 5-point rule), H2 +0.0; 6.8 s; peak memory 500 MB; three random thirds of the records (the host |
| insdn.csv | 120,001 x 84 | ran | all four as a person would pick | H1 +99.6 points (above the 5-point rule), H2 +99.3; 10.2 s; peak memory 1126 MB; three random thirds of the records (the host |
| iot23.csv | 102,373 x 20 | ran | differs: source | H1 +49.4 points (above the 5-point rule), H2 +15.1; 8.8 s; peak memory 597 MB; three random thirds of the records (the host NOTE: The tool picks the originating host (987 hosts); the hand-made settings used the responding host (50,267 values, one for every second record). Either way the hosts cannot form three organizations and the tool uses random thirds. |
| n_baiot.csv | 222,500 x 117 | ran (file is over the 200 MB upload limit; engine only) | all four as a person would pick | H1 +37.1 points (above the 5-point rule), H2 +33.8; 10.5 s; peak memory 1739 MB; groups of hosts (each host belongs to one or |
| nsl_kdd.csv | 85,592 x 42 | ran | all four as a person would pick | H1 +99.3 points (above the 5-point rule), H2 +76.8; 3.1 s; peak memory 652 MB; three random thirds of the records (no host  |
| rt_iot2022.csv | 68,458 x 85 | ran | differs: normal value | H1 +96.7 points (above the 5-point rule), H2 +86.2; 3.1 s; peak memory 813 MB; three random thirds of the records (no host  NOTE: No label value means normal (the normal traffic is labeled by device: Thing_Speak, MQTT_Publish, Wipro_bulb, Amazon-Alexa). The tool takes the most frequent value and flags it as a guess (benign_guess) for the person to correct; the hand-made settings merge the four values. |
| ton_iot_network.csv | 119,994 x 44 | ran | all four as a person would pick | H1 +4.1 points (not above the 5-point rule), H2 +0.3; 10.0 s; peak memory 797 MB; groups of hosts (each host belongs to one or |

Quick-look time over the files that ran: 2.9 to 11.4 seconds. Peak memory of one evaluation (files under the upload limit): 492 to 1146 MB.

## B. Malformed and hostile tables (result file: 2026-11-10 03:11, Darwin arm64, 18 cores)

Pass = the table runs, or the person gets one sentence that says what to change. A traceback, an error not written for a person, a dead process or no answer in 120 seconds fails.

| Case | Should | Result | What the person is told (or what ran) |
|---|---|---|---|
| well-formed base table | run | pass | ran; 6 behavior numbers kept |
| labels with stray spaces and mixed case (' Normal ', 'DoS ') | run | pass | ran; 6 behavior numbers kept |
| constant column and all-empty column among the numbers | run | pass | ran; 6 behavior numbers kept |
| infinite values in a number column | run | pass | ran; 5 behavior numbers kept |
| unicode, emoji and very long headers | run | pass | ran; 6 behavior numbers kept |
| 2,000 number columns | run | pass | ran; 2006 behavior numbers kept |
| numeric labels (0 = normal, 1..4 = attack types) | run | pass | ran; 6 behavior numbers kept |
| mixed types in one number column (numbers and words) | run | pass | ran; 6 behavior numbers kept |
| no host column and no clock | run | pass | ran; 6 behavior numbers kept |
| file: UTF-8 byte order mark at the start | run | pass | ran; 6 behavior numbers kept |
| file: semicolon delimiter | run | pass | ran; 6 behavior numbers kept |
| file: tab delimiter | run | pass | ran; 6 behavior numbers kept |
| file: Latin-1 bytes in a header (not UTF-8) | run | pass | ran; 6 behavior numbers kept |
| file: duplicate column names | run | pass | ran; 6 behavior numbers kept |
| file: a cell '1e2147483648' (a number with an impossible exponent; pandas 2.3 on Linux dies on it) | run | pass | ran; 7 behavior numbers kept |
| table: the same impossible-exponent cell inside a DataFrame (Parquet path) | run | pass | ran; 6 behavior numbers kept |
| file: Parquet with a nested (list) column | run | pass | ran; 6 behavior numbers kept |
| file: script and image tags in column names, label values and host names | run | pass | ran; 6 behavior numbers kept |
| file: empty (0 bytes) | refuse | pass | DataProblem: the file is empty |
| file: header only, no records | refuse | pass | DataProblem: the table has column names but no records |
| file: one record | refuse | pass | No label column was recognized (the page asks the person to pick it). |
| file: not a table at all (random bytes) | refuse | pass | DataProblem: the file is not a text table; it looks like a binary file with a .csv name |
| file: a PDF named .csv (wrong extension) | refuse | pass | DataProblem: the file is a PDF document, not a CSV table; export the records as CSV (one header row, one record per row) |
| file: a CSV named .parquet (wrong extension) | refuse | pass | DataProblem: the file is named as a Parquet file but is not one; if it is a CSV, give it a name that ends in .csv |
| no label column | refuse | pass | No label column was recognized (the page asks the person to pick it). |
| one class only (all normal) | refuse | pass | No label column was recognized (the page asks the person to pick it). |
| all attack, no normal records | refuse | pass | DataProblem: organization A has only 13 normal validation records; the alarm threshold needs at least 25. The table needs more records labeled 'dos' (about 300 per organization), or 'dos' is not the value that means normal traffic |
| two classes (normal and one attack type) | refuse | pass | DataProblem: the label column holds 1 attack type besides the normal value 'normal' (dos); at least three are needed so that each organization can withhold a different one. Pick another label column, or add records of more attack types |
| columns named like the tool's own working columns (y, org, part, event, source) | run | pass | ran; 9 behavior numbers kept |
| missing labels in some records | run | pass | ran; 6 behavior numbers kept |
| three attack types with 5 records each (runs, with a warning in the scorecard) | run | pass | ran; 6 behavior numbers kept |
| no number columns (text only) | refuse | pass | DataProblem: only 0 usable number columns were found; the detector needs at least 3 columns of behavior numbers (a column counts when at least 95% of its cells are numbers and it has more than one value) |
| every number column empty | refuse | pass | DataProblem: only 0 usable number columns were found; the detector needs at least 3 columns of behavior numbers (a column counts when at least 95% of its cells are numbers and it has more than one value) |
| 20 records in all | refuse | pass | No label column was recognized (the page asks the person to pick it). |

A table at the upload limit (2026-11-10 03:04, Darwin arm64, 18 cores): 200 MB, 362,170 records x 85 columns; read 8.7 s, column detection 1.8 s, quick look 10.4 s, peak memory 1832 MB.

## C. Injection (result files: 2026-11-10 03:11, Darwin arm64, 18 cores; browser: 2026-11-10 04:34, Linux aarch64, 4 cores)

| Test | Result | Evidence |
|---|---|---|
| the payloads survive into the scorecard data (so the rendering is really tested) | pass | attack types in the card: ['<b>scan</b>**md**', "<script>alert('dos')</script>"]; kept columns with a tag: ['<script>alert(1)</script>', '<img src=x onerror=alert(2)>'] |
| app.report_html (the downloadable report) | pass | 12,822 characters of HTML, every payload escaped |
| app.org_panel (organization panels of the scorecard) | pass | 11,334 characters of HTML, every payload escaped |
| app.show_card (the whole scorecard, expanders included) | pass | 21,810 characters of HTML, every payload escaped |
| app.org_table through ui.table | pass | 4,014 characters of HTML, every payload escaped |
| app._before_after (one record before and after sanitizing) | pass | 1,418 characters of HTML, every payload escaped |
| ui.table on the raw table (column names and cells) | pass | 2,102 characters of HTML, every payload escaped |
| ui.chip on every column name | pass | 453 characters of HTML, every payload escaped |
| app.role_reasons (why each column got its role, live demo) | pass | 852 characters of HTML, every payload escaped |
| the download written by pandas with no helper (what the page did): cells a spreadsheet would run as formulas | note | 961 cells start with = + - @ (label values and one column name came from the sender) |
| threatprint_agent.csv_safe: no cell of the downloaded table starts a formula, and no number changes | pass | 0 formula cells after csv_safe; numbers identical: True |
| app.py: every CSV download goes through csv_safe | pass | 3 to_csv calls in app.py, 3 csv_safe calls (see qa/APP_PATCHES.md when they differ) |

The same files through the real page in a headless browser (a dialog that opens means a script ran):

| Test | Result | Evidence |
|---|---|---|
| browser upload: script_tags.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: nothing special |
| browser upload: impossible_exponent.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: Note: 3 cells look like numbers with an impossible exponent (for example 1e2147483648); they are kept as text with a ~ in front. |
| browser upload: binary.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: False; page said: The file could not be read: the file is not a text table; it looks like a binary file with a .csv name |
| browser upload: semicolons.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: Note: the columns are separated by semicolons, not commas; the file was read that way. |

The same four uploads against a copy of the page with patch P1 of `qa/APP_PATCHES.md` applied in memory (`ui_upload.py --patched`, run before P1 was applied to `app.py` itself; 2026-11-10 04:37, Linux aarch64, 4 cores):

| Test | Result | Evidence |
|---|---|---|
| browser upload: script_tags.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: nothing special |
| browser upload: impossible_exponent.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: Note: 3 cells look like numbers with an impossible exponent (for example 1e2147483648); they are kept as text with a ~ in front. |
| browser upload: binary.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: False; page said: The file could not be read: the file is not a text table; it looks like a binary file with a .csv name |
| browser upload: semicolons.csv | pass | server alive: True; tracebacks on the page: 0; scripts that ran: 0; injected elements: 0; evaluation started: True; page said: Note: the columns are separated by semicolons, not commas; the file was read that way. |

## D. Fingerprint and agent (result file: 2026-11-10 03:11, Darwin arm64, 18 cores)

| Test | Result | Evidence |
|---|---|---|
| agent on sample_organization_hospital_SYNTHETIC.csv: fingerprint written and its digest verifies | pass | 6 attack types, 19 behavior numbers, 38 KB on disk |
| fingerprint of sample_organization_hospital_SYNTHETIC.csv: no identifier value of the source file | pass | 25,654 distinct identifier values from 8 columns searched in the file; found: none |
| fingerprint of sample_organization_hospital_SYNTHETIC.csv: how often the lowest or highest stored quantile equals the true smallest or largest value | note | of 114 attack-type and number pairs, the 1% quantile equals the smallest value in 32 (28%) and the 99% quantile equals the largest in 9 (8%) |
| agent on sample_organization_manufacturing_plant_SYNTHETIC.csv: fingerprint written and its digest verifies | pass | 8 attack types, 19 behavior numbers, 51 KB on disk |
| fingerprint of sample_organization_manufacturing_plant_SYNTHETIC.csv: no identifier value of the source file | pass | 6,705 distinct identifier values from 7 columns searched in the file; found: none |
| fingerprint of sample_organization_manufacturing_plant_SYNTHETIC.csv: how often the lowest or highest stored quantile equals the true smallest or largest value | note | of 152 attack-type and number pairs, the 1% quantile equals the smallest value in 36 (24%) and the 99% quantile equals the largest in 25 (16%) |
| agent on sample_organization_water_utility_SYNTHETIC.csv: fingerprint written and its digest verifies | pass | 7 attack types, 19 behavior numbers, 45 KB on disk |
| fingerprint of sample_organization_water_utility_SYNTHETIC.csv: no identifier value of the source file | pass | 28,785 distinct identifier values from 8 columns searched in the file; found: none |
| fingerprint of sample_organization_water_utility_SYNTHETIC.csv: how often the lowest or highest stored quantile equals the true smallest or largest value | note | of 133 attack-type and number pairs, the 1% quantile equals the smallest value in 42 (32%) and the 99% quantile equals the largest in 18 (14%) |
| agent on sample_power_grid_dnp3_REAL_CC-BY-4.0.csv: fingerprint written and its digest verifies | pass | 10 attack types, 65 behavior numbers, 280 KB on disk |
| fingerprint of sample_power_grid_dnp3_REAL_CC-BY-4.0.csv: no identifier value of the source file | pass | 8,619 distinct identifier values from 4 columns searched in the file; found: none |
| fingerprint of sample_power_grid_dnp3_REAL_CC-BY-4.0.csv: how often the lowest or highest stored quantile equals the true smallest or largest value | note | of 650 attack-type and number pairs, the 1% quantile equals the smallest value in 394 (61%) and the 99% quantile equals the largest in 351 (54%) |
| hostile fingerprint: not JSON (random bytes) | pass | before: TRACEBACK UnicodeDecodeError / now: refused: the file is not a fingerprint (it is not UTF-8 text) |
| hostile fingerprint: not JSON (a CSV file) | pass | before: TRACEBACK JSONDecodeError / now: refused: the file is not a fingerprint (it is not JSON, or it holds values that are not numbers) |
| hostile fingerprint: JSON list instead of an object | pass | before: TRACEBACK AttributeError / now: refused: the file is not a valid fingerprint: it is not a JSON object |
| hostile fingerprint: JSON string | pass | before: TRACEBACK AttributeError / now: refused: the file is not a valid fingerprint: it is not a JSON object |
| hostile fingerprint: empty file | pass | before: TRACEBACK JSONDecodeError / now: refused: the file is not a fingerprint (it is not JSON, or it holds values that are not numbers) |
| hostile fingerprint: wrong format name | pass | before: refused: not a fingerprint / now: refused: the file is not a valid fingerprint: its format field is not a ThreatPrint fingerprint |
| hostile fingerprint: format only, every other key missing | pass | before: shown / now: refused: the file is not a valid fingerprint: version |
| hostile fingerprint: classes is a list | pass | before: TRACEBACK AttributeError / now: refused: the file is not a valid fingerprint: classes |
| hostile fingerprint: classes missing | pass | before: shown / now: refused: the file is not a valid fingerprint: classes |
| hostile fingerprint: features is a number | pass | before: TRACEBACK TypeError / now: refused: the file is not a valid fingerprint: features |
| hostile fingerprint: records is a string | pass | before: TRACEBACK ValueError / now: refused: the file is not a valid fingerprint: attack type 'ransomware_smb': records |
| hostile fingerprint: records is 10**400 | pass | before: shown / now: refused: the file is not a valid fingerprint: normal.records |
| hostile fingerprint: NaN among the quantiles | pass | before: shown / now: refused: the file is not a fingerprint (it is not JSON, or it holds values that are not numbers) |
| hostile fingerprint: Infinity as payload size | pass | before: shown / now: refused: the file is not a fingerprint (it is not JSON, or it holds values that are not numbers) |
| hostile fingerprint: image tag as removed_columns_count (ui.stats puts its values into the page unescaped) | pass | before: shown (markup from the file put into the page unescaped) / now: refused: the file is not a valid fingerprint: removed_columns_count or payload_bytes |
| hostile fingerprint: script tag as payload_bytes | pass | before: TRACEBACK TypeError / now: refused: the file is not a valid fingerprint: removed_columns_count or payload_bytes |
| hostile fingerprint: script tag as a technique name | pass | before: shown / now: refused: the file is not a valid fingerprint: attack type 'ransomware_smb': techniques |
| hostile fingerprint: normal.records is a list | pass | before: TRACEBACK TypeError / now: refused: the file is not a valid fingerprint: normal.records |
| hostile fingerprint: hosts is a dict | pass | before: TRACEBACK TypeError / now: refused: the file is not a valid fingerprint: hosts |
| hostile fingerprint: integrity missing | pass | before: shown / now: refused: the file is not a valid fingerprint: integrity |
| hostile fingerprint: integrity.digest is a path (../../../etc/passwd) | pass | before: shown / now: refused: the file is not a valid fingerprint: integrity |
| hostile fingerprint: integrity.digest is a number | pass | before: shown / now: refused: the file is not a valid fingerprint: integrity |
| hostile fingerprint: quantiles of the wrong shape | pass | before: shown / now: refused: the file is not a valid fingerprint: attack type 'ransomware_smb': quantiles |
| hostile fingerprint: 100,000 features | pass | before: shown / now: refused: the file is not a valid fingerprint: features |
| hostile fingerprint: deeply nested JSON (100,000 levels) | pass | before: TRACEBACK RecursionError / now: refused: the file is not a fingerprint (it is nested too deeply) |
| hostile fingerprint: 50 MB of JSON | pass | before: shown / now: refused: a fingerprint is a small file (tens of kilobytes); this file is 50.0 MB and was not read |
| hostile fingerprints, total | pass | 26 files; before the check 13 ended in a traceback or put markup from the file into the page; now 0 do |
| tampered fingerprint (one count changed): well-formed, and the digest check refuses it | pass | verify = False |
| the genuine fingerprint still loads and verifies; a file of the old format name is still read | pass | load_fingerprint + verify on the agent's own output |
| contribute, as the page did it: the file name came from the uploaded digest field | note | a digest of '../../../../tmp/tp_pwned' gives the file name '../../../../tmp/.json', which resolves to /tmp/.json (outside the folder: True); only the disabled state of a button stood in the way |
| engine.save_contribution refuses a fingerprint whose digest is a path | pass | refused: the file is not a valid fingerprint: integrity |
| engine.save_contribution names the file from the digest it computes itself | pass | file 2f3b78a5361c8d10.json |
| contributions have an upper limit (here 5 files): a flood cannot fill the disk | pass | 8 more contributions sent: 4 kept, 4 refused, 5 files in the folder |
| agent command line on 8 hostile inputs: one line for the person, no traceback, no dead process | pass | empty file, binary file, no label, a PDF, the cell that ends pandas, a missing file, a wrong --label, --verify on a binary file |
| the agent file has no network code and starts no other program | pass | none of: socket, urllib, requests, http, ftplib, smtplib, subprocess |

Two of the hostile fingerprints through the real page as it stands now, with patch P2 applied (2026-11-10 04:33, Linux aarch64, 4 cores). As found, before the patch, both gave a traceback or put their own markup into the page:

| Test | Result | Evidence |
|---|---|---|
| hostile fingerprint through the real page: image tag with a script handler as removed_columns_count | pass | scripts that ran: 0; elements from the file in the page: 0 (with its script handler still attached: 0); tracebacks: 0; page said: This file could not be used: the file is not a valid fingerprint: removed_columns_count or payload_bytes. |
| hostile fingerprint through the real page: a JSON list | pass | scripts that ran: 0; elements from the file in the page: 0 (with its script handler still attached: 0); tracebacks: 0; page said: This file could not be used: the file is not a valid fingerprint: it is not a JSON object. |

## E. Access gate and server (result file: 2026-11-10 03:03, Linux aarch64, 4 cores)

A raw client that speaks Streamlit's websocket protocol, against a copy of the site started with a test password.

| Test | Result | Evidence |
|---|---|---|
| without the password: GET /_stcore/health | pass | HTTP 200; Streamlit's own health answer ('ok'); no content of the site |
| without the password: GET /_stcore/host-config | pass | HTTP 200; Streamlit's own settings for the browser; no content of the site |
| without the password: GET /app/static/inter-latin-wght-normal.woff2 | pass | HTTP 200; a typeface; the static folder is public by design and must hold nothing else |
| without the password: 13 tries to read files of the site (secrets, the password file, code, results, .git) through the web server | pass | none of them returned a file |
| the public static folder holds only typefaces and their licence texts | pass | ['Inter-LICENSE-OFL.txt', 'JetBrainsMono-LICENSE-OFL.txt', 'SourceSerif4-LICENSE-OFL.txt', 'inter-latin-wght-normal.woff2', 'jetbrains-mono-latin-wght-normal.woff2', 'source-serif-4-latin-wght-italic.woff2', 'source-serif-4-latin-wght-normal.woff2'] |
| without the password: a websocket session is sent the sign-in screen and nothing of the pages | pass | 7 elements sent; page content found: none |
| without the password: asking for five pages by name over the websocket | pass | each time only the sign-in screen came back |
| without the password: forged session values sent over the websocket (_access_ok, _left, _access_attempts) do not open the site | pass | 5 forgeries, no page content came back |
| the same forgeries leave the sign-in screen working (no error box) | pass | the sign-in form came back each time |
| cookie: a made-up cookie | pass | sign-in screen |
| cookie: the cookie of another password | pass | sign-in screen |
| cookie: an empty cookie | pass | sign-in screen |
| cookie: a cookie of 100,000 characters | pass | connection refused (HTTPTimeoutError) |
| cookie: the genuine cookie of today | pass | admitted |
| cookie: the genuine cookie of yesterday | pass | admitted |
| cookie: the genuine cookie of two days ago | pass | sign-in screen |
| without the password: sending a 1 MB file to Streamlit's upload address from a session that only saw the sign-in screen | note | HTTP 204 (204 = the server took the bytes into memory). Session obtained: True; anti-forgery token obtained: True. Nothing reads such a file, but the gate does not stop it: the per-file upload limit (200 MB) is the only bound, so a front door before Streamlit is needed for customers |
| the right password over the websocket admits (so the probe can tell the two states apart) | pass | after the password: 35 elements, navigation links present: True |
| wrong guesses in ONE session are slowed down more each time | pass | seconds per guess: [2.05, 4.05, 8.04, 10.04] |
| guessing with 10 fresh sessions at once | note | 10 guesses answered in 4.3 s = 140 guesses a minute from one machine; 9 were turned away by a server-side limit |
| guessing with 30 fresh sessions at once | note | 30 guesses answered in 6.2 s = 291 guesses a minute from one machine; 30 were turned away by a server-side limit |
| after the owner changes the password, a cookie made with the old password no longer admits | pass | sign-in screen |
| a server-side limit on password guesses across sessions | pass | guesses from fresh sessions are turned away after a few failures |

The sign-in path in a real browser, on the pages as they are now (2026-11-10 04:32, Linux aarch64, 4 cores):

| Test | Result | Evidence |
|---|---|---|
| the sign-in screen is what a new browser gets | pass | password field shown, no navigation bar |
| a wrong password is refused | pass | the page says the password did not match |
| the right password admits and the remembering cookie is set | pass | cookie tp_access present: True; the server runs Streamlit 1.67.0 and sets the cookie through st.iframe |
| a reload stays signed in | pass | navigation bar shown, no password field |
| a direct page address opens for the signed-in browser | pass | /results shows the results page |
| a browser without the cookie meets the sign-in screen at a direct page address | pass | /results shows the password field only |
| Leave the site signs out and clears the cookie | pass | cookie with a value after leaving: 0; a reload shows the sign-in screen |

What the shared password does: it keeps the pages, the results and the upload form away from anybody who does not have it, and a wrong or forged cookie does not help. What it does not do: it is one password for everybody (no accounts, nobody can be removed without changing it for all), a stolen cookie works until the next day or until the password changes, and anybody on the internet can still open a session, see the sign-in screen and keep the server busy. For customers the site needs a real front door before Streamlit: an identity-aware proxy (for example Cloudflare Access or an OAuth proxy) with one account per person, and a rate limit at that proxy.

## F. Concurrency, determinism, load (result files: 2026-11-10 03:04, Linux aarch64, 4 cores; Mac: 2026-11-10 03:09, Darwin arm64, 18 cores)

| When | Runs | Result | Evidence |
|---|---|---|---|
| as found, before the lock (Linux test box, 4 cores) | one run, twice | identical | 7.9 s a run; H1 85.57 points; peak memory 455 MB |
| as found, before the lock (Linux test box, 4 cores) | 2 at once | 2 of 2 differ from the serial result | 22.9 s in all; H1 of each: [86.53, 86.03]; peak memory 503 MB; errors: 0 |
| as found, before the lock (Linux test box, 4 cores) | 6 at once | 6 of 6 differ from the serial result | 96.7 s in all; H1 of each: [87.44, 86.03, 88.56, 86.53, 87.52, 86.53]; peak memory 592 MB; errors: 0 |
| after the lock (Linux test box, 4 cores) | one run, twice | identical | 7.3 s a run; H1 85.57 points; peak memory 456 MB |
| after the lock (Linux test box, 4 cores) | 2 at once | 0 of 2 differ from the serial result | 15.0 s in all; H1 of each: [85.57, 85.57]; peak memory 478 MB; errors: 0 |
| after the lock (Linux test box, 4 cores) | 6 at once | 0 of 6 differ from the serial result | 45.8 s in all; H1 of each: [85.57, 85.57, 85.57, 85.57, 85.57, 85.57]; peak memory 524 MB; errors: 0 |
| after the lock (the Mac, 18 cores) | one run, twice | identical | 6.9 s a run; H1 85.57 points; peak memory 448 MB |
| after the lock (the Mac, 18 cores) | 2 at once | 0 of 2 differ from the serial result | 12.9 s in all; H1 of each: [85.57, 85.57]; peak memory 455 MB; errors: 0 |
| after the lock (the Mac, 18 cores) | 6 at once | 0 of 6 differ from the serial result | 38.5 s in all; H1 of each: [85.57, 85.57, 85.57, 85.57, 85.57, 85.57]; peak memory 485 MB; errors: 0 |
| latest run of the suite | one run, twice | identical | 7.8 s a run; H1 85.57 points; peak memory 457 MB |
| latest run of the suite | 2 at once | 0 of 2 differ from the serial result | 15.2 s in all; H1 of each: [85.57, 85.57]; peak memory 485 MB; errors: 0 |

Library cards recomputed with today's engine (2026-11-10 03:08, Darwin arm64, 18 cores):

| Library dataset | Budget of the stored card | Stored card made | Values compared | Differences | Largest difference | Minutes |
|---|---|---|---|---|---|---|
| edge_iiotset_ml | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:16 | 358 | 0 | 0.0 | 2.3 |
| cic_ids2017 | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:02 | 380 | 0 | 0.0 | 2.3 |
| rt_iot2022 | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:29 | 345 | 0 | 0.0 | 1.0 |
| bot_iot_5pct | protocol | 08 Nov 2026, 22:47 | 335 | 0 | 0.0 | 2.0 |
| iec104 | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:21 | 376 | 0 | 0.0 | 0.6 |
| dnp3 | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:14 | 377 | 0 | 0.0 | 1.5 |
| cidds001 | protocol (shuffle test on 5,000 records per side, 50-tree forests) | 08 Nov 2026, 23:09 | 301 | 0 | 0.0 | 2.1 |

Real browser sessions on the real page at once, each signing in and starting a quick look of the built-in example (2026-11-10 04:35, Linux aarch64, 4 cores):

| Test | Result | Evidence |
|---|---|---|
| 5 browser sessions sign in with the password and reach the Live demo | pass | sign-in and page ready in 3.1 to 3.6 s per session, one after another |
| 5 quick looks started together through the page all finish | pass | 5 of 5 finished; seconds from the click to the finished scorecard, in order of finishing: [12.7, 20.8, 29.9, 38.0, 47.0] (one evaluation runs at a time; the others wait in line) |
| every session shows the same result for the same file | pass | H1 tile of each session: ['+85.6 points', '+85.6 points', '+85.6 points', '+85.6 points', '+85.6 points'] |
| no page showed an error or a traceback during the load | pass | 0 pages with an error box, of 6 |
| a visitor who arrives during the runs can sign in and open the Results page | pass | sign-in 5.0 s, Results page ready in 1.3 s while 5 runs were in line |
| memory of the server during the load | note | server process 60 MB before, peak 564 MB during 5 sessions (resident memory of the server and its children; 0 means not measurable on this system) |
| the server is alive after the load | pass | health answer after the last session |

One protocol-budget run on the largest sample upload, through the upload path (2026-11-10 03:01, Darwin arm64, 18 cores): sample_power_grid_dnp3_REAL_CC-BY-4.0.csv, 10,952 records x 85 columns: ran in 57 s, peak memory 557 MB, three seeds; a local run of the tool, not the run of record.

## G. Supply chain and repository (result files: 2026-11-10 03:03, Linux aarch64, 4 cores; audit: 2026-11-10 03:04, Linux aarch64, 4 cores)

| Test | Result | Evidence |
|---|---|---|
| the whole history was read | pass | 7 commits, 13.4 MB of patches |
| the access password of the site is nowhere in the git history | pass | 0 occurrences (the password itself is not shown) |
| the access password is in no tracked file | pass | no tracked file holds it |
| history: GitHub token | pass | 0 lines match (test and example values set aside) |
| history: AWS access key | pass | 0 lines match (test and example values set aside) |
| history: private key block | pass | 0 lines match (test and example values set aside) |
| history: Slack token | pass | 0 lines match (test and example values set aside) |
| history: API key assignment | pass | 0 lines match (test and example values set aside) |
| history: password assignment | pass | 0 lines match (test and example values set aside) |
| no private file is tracked (secrets, password file, tunnel address, logs, contributions, virtual environment) | pass | 68 tracked files checked |
| .gitignore names every private path | pass | secrets, password file, tunnel address, contributions, logs, virtual environment, cache |
| git itself confirms the two password files are ignored | pass | git check-ignore |
| the container runs as an ordinary user, and .dockerignore keeps the password files out of the image | pass | USER line in the Dockerfile; .dockerignore lists the secrets |
| every dependency is pinned to an exact version | pass | requirements.txt and requirements-mac.txt |

Known advisories (pip-audit):

| Environment | Package | Known advisories | Clean from version | Examples |
|---|---|---|---|---|
| the environment that ran the suite (Linux aarch64; it also holds test-only packages) | 81 packages | 0 |  |  |
| the pinned versions of requirements-mac.txt and requirements.txt (the packages named there, without their dependencies) | 6 packages | 0 |  |  |
| the Mac that serves the site, BEFORE the update to the new pins (pip freeze of its virtual environment at 96b832c; to be rerun after the update at release) | pillow 11.3.0 | 56 | 13.0.0 | CVE-2026-112390, CVE-2026-112391, CVE-2026-112393 |
| the Mac that serves the site, BEFORE the update to the new pins (pip freeze of its virtual environment at 96b832c; to be rerun after the update at release) | streamlit 1.50.0 | 2 | 1.54.0 | PYSEC-2026-212, PYSEC-2026-2285 |

Not checked by pip-audit: torch (the CPU build is not on PyPI under that version name). For those packages the statement "no known advisory" does not apply; the publisher's own notes are the place to look.

Streamlit 1.50.0 required Pillow below 12, and Pillow is clean only from 13.0.0, so both were moved together: the pinned set is now Streamlit 1.67.0 with Pillow 13.0.0 (10 November 2026). On that set the app tests, this suite and a browser pass over every page were run again, and pip-audit shows no known advisory for the environment that ran the suite or for the pinned versions. The row of the Mac above is its install from before the update; it is updated at release and audited again then. For the old set, as the app was written, no uploaded file is given to Pillow (uploads are CSV, Parquet and JSON; the only image it opens is its own icon), and the two Streamlit advisories concern Windows hosts and a local attacker. That is a reading of the code and of the advisory texts, not a test.

## Bugs fixed in this session (files the pressure agent owns)

| File | What was wrong | Fix | How it was verified |
|---|---|---|---|
| `engine.py` | Runs at once shared PyTorch's global random generator and changed each other's results | `RUN_LOCK`: one evaluation at a time in the process; a waiting run says so in its log and gives up with one sentence after 30 minutes | section F; example scorecard identical; library cards identical |
| `threatprint_agent.py`, `engine.py` | A cell with an impossible exponent ended the process on Linux | `read_table` neutralizes such cells before pandas sees them; `defuse` does the same for tables that arrive another way (Parquet, a DataFrame) | section B (two cases), agent command line in section D |
| `threatprint_agent.py` | The reader gave raw pandas errors (empty file, PDF, binary, Latin-1), read semicolon and tab files as one column | `read_table`: one sentence per problem, encoding fallback, delimiter detection, duplicate column names numbered | section B |
| `threatprint_agent.py` | Label detection: a sub-category, a yes/no flag, an attack identifier or a free-text column could win; a count column that contains 0 could be taken for a label | Columns with three or more values come before yes/no columns, the usual attack-type names come before the others, identifiers and descriptions are set back, a number column needs a label-like name | section A (BoT-IoT, CIDDS-001, CIDDS-002), section B ("no label column") |
| `threatprint_agent.py` | Host detection missed Zeek names (`id.orig_h`), took an address before the device name, took a column that is one value in 95% of the records | Zeek pattern, name before address, the 95% rule, upper bound of distinct hosts raised to a tenth of the records | section A (IoT-23, Edge-IIoTset subset, the plant sample) |
| `engine.py` | Quick look: the class-stratified cap left a table with little normal traffic with too few normal validation records and stopped | Normal traffic keeps at least 1,500 records under the cap; when grouping by host starves one organization, three random thirds are used and the scorecard says so | section A (BoT-IoT 5%) |
| `engine.py` | Errors were ValueError with half a sentence, or raw library errors | `DataProblem`: one sentence that names the column, the values found and what to change; anything unforeseen is wrapped so that no page shows a traceback | section B |
| `engine.py` | A column named `y`, `org`, `part`, `event` or `source` was silently overwritten by the tool's own working columns | Such columns are renamed on the way in | section B |
| `threatprint_agent.py` | A hostile fingerprint gave tracebacks; `verify` could raise | `load_fingerprint` and `check_fingerprint` check every field; `verify` never raises | section D |
| `engine.py` | No safe way to keep a contributed fingerprint | `save_contribution`: checked, digest must match, file name from the computed digest, upper limit of 500 files or 50 MB | section D |
| `engine.py` | No count of wrong passwords across sessions | `AttemptLimiter` and `GATE_LIMITER` (in memory, per client and for the whole site) | unit check in the suite's history; the page test turns green with patch P4 |
| `threatprint_agent.py` | A downloaded CSV could carry formula cells to a peer | `csv_safe`; the agent's `--sanitized` output uses it | section C |
| `threatprint_agent.py` | The docstring said the fingerprint holds no minimum or maximum values | Reworded: the 1% and 99% quantiles can equal the extremes for numbers with few distinct values | section D (measured shares) |
| `requirements.txt`, `requirements-mac.txt` | Version ranges | Exact versions of the tested sets | section G |
| `Dockerfile`, `.dockerignore` | The container ran as root; `docker build` in the working folder copied the password files into the image | Ordinary user, health check; `.dockerignore` lists the secrets | section G |
| `samples/`, `tools/make_sample_orgs_more.py` | Two sample files, one sector each | Two more synthetic organizations (hospital, manufacturing plant) with their own column names; `samples/manifest.json` lists four | section A, section D |

## Patches to `app.py` from `qa/APP_PATCHES.md`: all applied on 10 November 2026

| Patch | Severity | What was applied | The check that now passes |
|---|---|---|---|
| P1 | critical | `_read_upload` and the sample loader use `engine.read_table` | browser upload of `impossible_exponent.csv`, `binary.csv`, `semicolons.csv` (section C) |
| P2 | high | the fingerprint upload uses `agent.load_fingerprint`; values shown in the headline boxes are escaped | hostile fingerprints through the real page (section D) |
| P3 | high | contribute uses `engine.save_contribution`; the folder can be set with `TP_CONTRIB_DIR` | contribute checks of section D |
| P4 | high | sign-in uses `engine.GATE_LIMITER` and safe session reads; a form that Streamlit cannot draw after a forged message ends in one sentence; cookie with the Secure flag on https | "a server-side limit on password guesses across sessions" and "no error box" (section E) |
| P5 | high | the three CSV downloads go through `engine.csv_safe` | "every CSV download goes through csv_safe" (section C) |
| P6 | medium | the confirmation form warns when the normal value was only a guess (`benign_guess`) | page test in `tests/test_app.py` |
| P7 | medium | a scorecard shows `card["warnings"]`; library cards made before the key existed get the same sentences without a rerun | page test in `tests/test_app.py` |
| P8 | medium | records with an empty label are left out (`drop_labels`), and the page says how many | page test in `tests/test_app.py` |
| P9 | low | nothing to change: the page already shows the engine's "in line" message | section F |
| P10 | text | the agent page and the README say what the lowest and highest stored points are | wording check in `tests/test_app.py` |
| P11 | repository | `qa/_*` ignored; Streamlit 1.67.0 and Pillow 13.0.0 pinned | section G |

## Limits that are real and should be said to a customer

- One evaluation runs at a time on a server. A quick look takes 2.9 to 11.4 seconds on the Mac, so a class of thirty waits several minutes for the last scorecard; a protocol run on a large table holds the line for much longer. More capacity means more processes behind a queue, not more threads.
- Memory: one evaluation of a table under the upload limit peaked at 1146 MB in the matrix, and a 200 MB file at 1832 MB. A free host with 1 GB cannot take the large library tables or an upload near the limit; the Mac can.
- The tool needs labeled records: at least three attack types besides normal traffic, about 300 normal records per organization, and numbers that describe behavior. When a table falls short the tool says which of these is missing; it cannot make up for it.
- Automatic column roles are suggestions. On 20 of 23 files they equal what a person chose by hand; where no label value means normal, or the attack types live in free text, a person has to decide.
- The shared password is a door for reviewers, not customer-grade access control (section E). A visitor who has only seen the sign-in screen can still send files to Streamlit's own upload address (1 MB was accepted in the test); nothing reads them, but they use the server's memory, so customers need a front door before Streamlit.
- A fingerprint is a summary, not a formal privacy protection. What it reveals about its sender has not been measured; its lowest and highest stored quantiles can equal the true extremes (section D).
- Scratch files of this test whose names start with an underscore are in `qa/` (logs, a frozen package list, two small scripts). They are not needed; they were left in place because nothing in this folder is deleted without Rayve's yes.

## How the total is counted

| Section | Checks | Passed | Failed | Open | Notes (no pass or fail) |
|---|---|---|---|---|---|
| A and H. Ingestion matrix (one check per file) | 23 | 23 | 0 | 0 | 0 |
| B. Malformed and hostile tables (one check per case) | 34 | 34 | 0 | 0 | 0 |
| C. Browser uploads on a patched copy of the page (kept as the record of patch P1) | 4 | 4 | 0 | 0 | 0 |
| C. Injection | 12 | 11 | 0 | 0 | 1 |
| C. Hostile files through the real page (browser) | 4 | 4 | 0 | 0 | 0 |
| D. Fingerprint and agent | 47 | 42 | 0 | 0 | 5 |
| E. Access gate and server | 23 | 20 | 0 | 0 | 3 |
| G. Repository | 14 | 14 | 0 | 0 | 0 |
| D. Hostile fingerprints through the real page (browser) | 2 | 2 | 0 | 0 | 0 |
| E. Sign-in path in a real browser | 7 | 7 | 0 | 0 | 0 |
| F. Browser sessions under load | 7 | 6 | 0 | 0 | 1 |
| F. Protocol run on the largest sample upload | 1 | 1 | 0 | 0 | 0 |
| F. Concurrency and determinism (engine level, each machine) | 5 | 5 | 0 | 0 | 0 |
| F. Library cards recomputed | 7 | 7 | 0 | 0 | 0 |
| Total | 190 | 180 | 0 | 0 | 10 |

## Where each part ran

| Result file | When | Machine | Python |
|---|---|---|---|
| audit_results.json | 2026-11-10 03:04 | Linux aarch64, 4 cores | 3.12.13 |
| bigfile_results.json | 2026-11-10 03:04 | Darwin arm64, 18 cores | 3.12.13 |
| browser_load_results.json | 2026-11-10 04:35 | Linux aarch64, 4 cores | 3.10.12 |
| concurrency_results.json | 2026-11-10 03:04 | Linux aarch64, 4 cores | 3.12.13 |
| concurrency_results_mac.json | 2026-11-10 03:09 | Darwin arm64, 18 cores | 3.12.13 |
| fingerprint_results.json | 2026-11-10 03:11 | Darwin arm64, 18 cores | 3.12.13 |
| fp_page_results.json | 2026-11-10 04:33 | Linux aarch64, 4 cores | 3.10.12 |
| gate_results.json | 2026-11-10 03:03 | Linux aarch64, 4 cores | 3.12.13 |
| hostile_results.json | 2026-11-10 03:11 | Darwin arm64, 18 cores | 3.12.13 |
| injection_results.json | 2026-11-10 03:11 | Darwin arm64, 18 cores | 3.12.13 |
| matrix_results.json | 2026-11-10 03:04 | Darwin arm64, 18 cores | 3.12.13 |
| protocol_sample_results.json | 2026-11-10 03:01 | Darwin arm64, 18 cores | 3.12.13 |
| repo_results.json | 2026-11-10 03:03 | Linux aarch64, 4 cores | 3.12.13 |
| reproduce_results.json | 2026-11-10 03:08 | Darwin arm64, 18 cores | 3.12.13 |
| reproduce_results_last_commit.json | 2026-11-09 23:53 | Darwin arm64, 18 cores | 3.12.13 |
| signin_flow_results.json | 2026-11-10 04:32 | Linux aarch64, 4 cores | 3.10.12 |
| ui_upload_results.json | 2026-11-10 04:34 | Linux aarch64, 4 cores | 3.10.12 |
| ui_upload_results_patched.json | 2026-11-10 04:37 | Linux aarch64, 4 cores | 3.10.12 |
