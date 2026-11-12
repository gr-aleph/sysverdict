"""Score SysVerdict on a folder of labelled Sysmon logs (a blind exam).

Run (cmd.exe):  .venv\\Scripts\\python evaluate.py <folder with .evtx files>

The expected verdict comes only from the start of each file name, so no answer key is opened:
    benign_... or baseline_...       -> Benign
    suspicious_... or suspicious2_... -> Suspicious
    malicious_..., incident_... or attack_... -> Malicious
Files with another name are skipped. Only verdicts and counts are printed, never event contents.
"""

import sys
from pathlib import Path

from triage.checks import make_verdict, run_checks
from triage.parse import read_evtx

LABELS = ["Benign", "Suspicious", "Malicious"]
PREFIXES = {"benign": "Benign", "baseline": "Benign",
            "suspicious": "Suspicious", "suspicious2": "Suspicious",
            "malicious": "Malicious", "incident": "Malicious", "attack": "Malicious"}


def expected_label(file_name):
    """'malicious_PC_Sysmon.evtx' -> 'Malicious', or None for an unknown prefix."""
    return PREFIXES.get(file_name.split("_")[0].lower())


def main(folder):
    # matrix[expected][got] = how many logs
    matrix = {e: {g: 0 for g in LABELS} for e in LABELS}
    print(f"{'file':45} {'expected':11} {'got':11}")
    for path in sorted(Path(folder).glob("*.evtx")):
        expected = expected_label(path.name)
        if expected is None:
            continue
        events = read_evtx(path)
        if not events:
            print(f"{path.name:45} {expected:11} (no Sysmon events: skipped)")
            continue
        got = make_verdict(run_checks(events))["label"]
        mark = "" if got == expected else "   <-- wrong"
        print(f"{path.name:45} {expected:11} {got:11}{mark}")
        matrix[expected][got] += 1

    print("\nConfusion matrix (rows = expected, columns = SysVerdict's verdict)")
    print(" " * 12 + "".join(f"{g:>12}" for g in LABELS))
    for e in LABELS:
        print(f"{e:12}" + "".join(f"{matrix[e][g]:>12}" for g in LABELS))

    print("\nPer verdict: precision = of the logs given this verdict, how many were right;"
          " recall = of the logs that should get it, how many got it")
    for label in LABELS:
        given = sum(matrix[e][label] for e in LABELS)
        should = sum(matrix[label].values())
        right = matrix[label][label]
        precision = f"{right}/{given}" if given else "-"
        recall = f"{right}/{should}" if should else "-"
        print(f"{label:12} precision {precision:6} recall {recall}")
    total = sum(sum(row.values()) for row in matrix.values())
    correct = sum(matrix[label][label] for label in LABELS)
    print(f"\nCorrect: {correct}/{total}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python evaluate.py <folder with .evtx files>")
        sys.exit(1)
    main(sys.argv[1])
