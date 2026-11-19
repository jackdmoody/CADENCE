#!/usr/bin/env bash
# One command on a Mac with normal internet:
#   git checkout real-data-eval && ./scripts/run_real_data_mac.sh
# Extra arguments go to scripts/real_data_eval.py (e.g. --ctu13 7 11 --iot23 CTU-IoT-Malware-Capture-1-1).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v brew >/dev/null || { echo "Install Homebrew first: https://brew.sh"; exit 1; }
command -v zeek >/dev/null || brew install zeek
python3 -m venv .venv-real
source .venv-real/bin/activate
pip install -q --upgrade pip
pip install -q pandas numpy scikit-learn scipy statsmodels matplotlib seaborn pytest
python -m pytest analytic_pipeline -q -p no:warnings
caffeinate -i python scripts/real_data_eval.py "$@"
python paper/make_numbers.py
if command -v latexmk >/dev/null; then (cd paper && latexmk -pdf -interaction=nonstopmode main.tex >/dev/null) || true; fi
git add results/real_data paper/generated paper/main.pdf 2>/dev/null || true
git commit -m "Real-data results from scripts/real_data_eval.py" || true
echo "Done. Review results/real_data and paper/main.pdf, then: git push origin real-data-eval"
