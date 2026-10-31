"""Turn results/*.json into the figures and LaTeX tables used in the paper.

Usage:  python -m experiments.make_figures [output_dir]
Default output_dir: results/paper
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from app.policies import POLICY_LABELS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else RES / "paper"
PIDS = list(POLICY_LABELS)
BLUE, ORANGE = "#2a78d6", "#eb6834"      # categorical slots 1 and 2
INK, MUTED = "#222222", "#8a8a8a"

plt.rcParams.update({
    "font.family": "serif", "font.size": 8, "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
    "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42,
})


def fig_outcomes(summary):
    fig, ax = plt.subplots(figsize=(3.45, 1.9))
    w = 0.38
    xs = range(len(PIDS))
    for i, (mode, col, hatch) in enumerate((("RS256", BLUE, ""), ("HS256", ORANGE, "///"))):
        s = summary[mode]["summary"]
        vals = [s[p]["invalid_accepted"] for p in PIDS]
        bars = ax.bar([x + (i - 0.5) * w for x in xs], vals, w - 0.04, color=col,
                      hatch=hatch, edgecolor="white", linewidth=0.6, label=mode)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.3, str(v),
                    ha="center", va="bottom", fontsize=6.5, color=INK)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(PIDS)
    ax.set_ylabel("Invalid tokens accepted")
    ax.set_ylim(0, 25)
    ax.yaxis.grid(True, color="#e6e6e6", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "fig_outcomes.pdf")
    plt.close(fig)


def fig_timing(timing):
    fig, ax = plt.subplots(figsize=(3.45, 2.0))
    w = 0.38
    xs = range(len(PIDS))
    for i, (mode, col, hatch) in enumerate((("RS256", BLUE, ""), ("HS256", ORANGE, "///"))):
        t = timing["modes"][mode]
        means = [t[p]["mixed_mean_us"] for p in PIDS]
        sds = [t[p]["mixed_sd_us"] for p in PIDS]
        ax.bar([x + (i - 0.5) * w for x in xs], means, w - 0.04, yerr=sds,
               color=col, hatch=hatch, edgecolor="white", linewidth=0.6,
               error_kw=dict(ecolor=INK, elinewidth=0.6, capsize=1.5), label=mode)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(PIDS)
    ax.set_ylabel(r"Mean time per token ($\mu$s)")
    ax.yaxis.grid(True, color="#e6e6e6", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "fig_timing.pdf")
    plt.close(fig)


MARK = {"accept": r"\cmark", "reject": r"\xmark", "n/a": "--"}


def tex_matrix(summary):
    rows = summary["RS256"]["rows"]
    hs = {r["sid"]: r for r in summary["HS256"]["rows"]}
    lines = []
    cat = None
    for r in rows:
        if r["category"] != cat:
            if cat is not None:
                lines.append(r"\midrule")
            cat = r["category"]
        cells = []
        for p in PIDS:
            d = r[p]
            wrong = (d == "accept") != (r["expected"] == "accept") and d != "n/a"
            cell = MARK[d]
            if hs[r["sid"]][p] not in (d, "n/a"):
                cell += r"$^\dagger$"     # RS256 and HS256 decisions differ
            cells.append(r"\cellcolor{bad}" + cell if wrong else cell)
        exp = MARK[r["expected"]]
        desc = r["description"].replace("->", r"$\rightarrow$")
        lines.append(f"{r['sid']} & {desc} & {exp} & " +
                     " & ".join(cells) + r" \\")
    (OUT / "tab_matrix.tex").write_text("\n".join(lines) + "\n")


def tex_summary(summary):
    lines = []
    for mode in ("RS256", "HS256"):
        s = summary[mode]["summary"]
        n_inv = s["C5"]["invalid_rejected"] + s["C5"]["invalid_accepted"]
        lines.append(r"\multicolumn{7}{l}{\textit{" + mode +
                     f" ({n_inv} invalid, 2 valid tokens)" + r"}} \\")
        for label, key in (("Invalid rejected", "invalid_rejected"),
                           ("Invalid accepted", "invalid_accepted"),
                           ("Valid accepted", "valid_accepted"),
                           ("Valid rejected", "valid_rejected")):
            lines.append(label + " & " + " & ".join(str(s[p][key]) for p in PIDS) + r" \\")
        if mode == "RS256":
            lines.append(r"\midrule")
    (OUT / "tab_summary.tex").write_text("\n".join(lines) + "\n")


def tex_timing(timing):
    lines = []
    pids = PIDS + ["C4k"]
    for p in pids:
        rs = timing["modes"]["RS256"].get(p)
        hs = timing["modes"]["HS256"].get(p)
        name = POLICY_LABELS.get(p, "C4, key pre-parsed")

        def f(d, k):
            return "--" if d is None else f"{d[k + '_mean_us']:.1f} $\\pm$ {d[k + '_sd_us']:.1f}"
        lines.append(f"{p} & {name} & {f(rs, 'valid')} & {f(rs, 'mixed')} & "
                     f"{f(hs, 'valid')} & {f(hs, 'mixed')} " + r"\\")
    (OUT / "tab_timing.tex").write_text("\n".join(lines) + "\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary = json.loads((RES / "summary.json").read_text())["modes"]
    timing = json.loads((RES / "timing.json").read_text())
    fig_outcomes(summary)
    fig_timing(timing)
    tex_matrix(summary)
    tex_summary(summary)
    tex_timing(timing)
    print("written to", OUT)


if __name__ == "__main__":
    main()
