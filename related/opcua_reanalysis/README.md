# Re-analysis of Lo et al. (IEEE SNGC 2026), OPC UA anomaly detection

Separate from CADENCE; kept here so one branch holds today's work. Move it to its own repo whenever you like.

Data and notebook come from github.com/carolsworld/FactoryIOOPCUA (zipped CSVs under `datasets/`).

```bash
git clone --depth 1 https://github.com/carolsworld/FactoryIOOPCUA /tmp/opcua_repo
mkdir -p data/opcua && for z in /tmp/opcua_repo/datasets/*/*.zip; do unzip -o -q "$z" -d data/opcua; done
python related/opcua_reanalysis/opcua_baselines.py \
  data/opcua/opcua_instance1-60_sliced_1min.csv \
  data/opcua/20250903_Network_OPCUA_enriched_features_instanced_file1.csv \
  data/opcua/20250903_Network_OPCUA_enriched_features_instanced_file2.csv
```

`results_reproduction.txt` is the script's output. Rerun on 19 Nov 2026 against the public repo, it matched line for line.
