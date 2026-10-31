import subprocess
import sys

QUICK = "--quick" in sys.argv
PY = sys.executable

STEPS = [
    ("Unit tests", [PY, "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py"]),
    ("Decision matrix", [PY, "-m", "experiments.run_matrix", "--runs", "3" if QUICK else "20"]),
    ("Timing benchmark", [PY, "-m", "experiments.benchmark"] + (["--quick"] if QUICK else [])),
]
if not QUICK:   # figures are built only from a full benchmark run
    STEPS.append(("Figures and tables", [PY, "-m", "experiments.make_figures"]))

for name, cmd in STEPS:
    print(f"\n=== {name} ===", flush=True)
    if subprocess.run(cmd).returncode != 0:
        sys.exit(f"Step failed: {name}")

print("\nDone. Copy results/paper/fig_*.pdf to the Overleaf figures/ folder and the"
      "\nrows of results/paper/tab_*.tex into the matching tables in main.tex.")
