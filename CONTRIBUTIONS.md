# Contribution record

Lizë Syla, Rinesa Saraçi and Yllka Syla. Information Security seminar project,
Faculty of Electrical and Computer Engineering, University of Prishtina.
Every member reviewed the whole project and can explain all of its parts.

## Lizë Syla

- **Code:** key generation and testbed settings (`app/keys.py`), the six
  validation configurations C0–C5 (`app/policies.py`), the `run_all.py`
  script, and the full experiment run whose results are in `results/`
  (Windows 11, Python 3.14).
- **Paper:** Introduction and Conclusion; checked the RFC references;
  updated the results and timing tables; compiled the paper in Overleaf.
- **Presentation:** slides 1–5 (problem, research gap, testbed, configurations).
- **Coordination:** repository review and final submission.

## Rinesa Saraçi

- **Code:** project scaffold (`.gitignore`, `requirements.txt`, `README.md`),
  the FastAPI prototype (`app/main.py`), the validator-level and API-level
  test suites (`tests/`), and the API usage and results sections of the README.
- **Paper:** Background and Method; checked them against the code; checked
  the CVE and web references; wrote the AI-use declaration.
- **Presentation:** slides 6–10 (token scenarios, procedure, headline result,
  findings 1 and 2).

## Yllka Syla

- **Code:** the 26 labelled token scenarios (`experiments/scenarios.py`), the
  decision matrix with its stability check (`experiments/run_matrix.py`), the
  timing benchmark and figure/table generation (`experiments/benchmark.py`,
  `experiments/make_figures.py`), and the CI workflow.
- **Paper:** Results and Discussion; checked every reported number against
  `results/`; checked the conference-paper references.
- **Presentation:** slides 11–15 (finding 3, performance, recommendations,
  limitations, conclusion); exported the slides and organised the rehearsal.

## Use of generative AI

Generative AI (Claude, Anthropic) was used to draft the initial code, parts
of the paper text and the presentation slides. The group divided, reviewed,
tested and committed the code, ran all experiments reported in the paper on
our own machine, checked every number and reference against the results and
sources, and remains fully responsible for the content.