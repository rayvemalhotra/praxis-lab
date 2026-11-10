# Sample organization files

Two files for trying ThreatPrint (the upload page, the sanitizer, the local agent).

- `sample_organization_water_utility_SYNTHETIC.csv`: made up by `tools/make_sample_org.py`. A fictional water utility with 24 devices, 7 attack types, 22,073 records. Device names, addresses, operators and traffic numbers are invented. It has the shape of real monitoring data and says nothing about real attacks.
- `sample_power_grid_dnp3_REAL_CC-BY-4.0.csv`: 10,952 real flows sampled by label from the DNP3 Intrusion Detection Dataset (Zenodo record 7348493, https://zenodo.org/records/7348493; the makers ask users to cite V. Kelli et al., "Attacking and Defending DNP3 ICS/SCADA Systems", DCOSS 2022, doi 10.1109/DCOSS54816.2022.00041), CICFlowMeter flows at the 120 s timeout. Licence: Creative Commons Attribution 4.0. Changes made here: a sample of at most 3,000 normal flows and 1,000 flows per attack type, the capture-folder column removed, rows sorted by time.
