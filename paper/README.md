# CADENCE paper (IEA/AIE 2027 target, Springer LNCS)

Build:

```bash
python paper/make_numbers.py        # regenerate paper/generated/* from experiment outputs
cd paper && latexmk -pdf main.tex
```

Every number in the text and tables comes from `paper/generated/numbers.tex`. Do not type numbers into `main.tex`. Red `TBD` or `[...]` text marks real-data content still to be filled.

| Source | Produced by |
|---|---|
| `paper/data/synthetic_{fixed,original,none}.json` | `python paper/experiments/synthetic_eval.py --out DIR --seeds 42 0 1 2 3 4 5 6 7 8 9 --spectral VARIANT` |
| `paper/data/synthetic_h2.json` | `python paper/experiments/h2_stats.py DIR paper/data/synthetic_h2.json` |
| `results/real_data/<run>/` | `run_real_data.py` (see README "Running on real Zeek data") |

Things to check before submission:
- The IEA/AIE 2027 page limit and review mode (blind or not). The draft assumes 12 pages including references and keeps the author block.
- `refs.bib` entries were checked on 19 Nov 2026. `[7]` in the earlier IEEE draft (Schwartz et al. 2023) could not be found anywhere and was dropped.
