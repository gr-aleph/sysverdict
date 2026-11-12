"""Optional check against real lab logs in samples/ (git-ignored, so this is skipped on GitHub).

Expected results:
  attack_fake_fireeye.evtx      -> Malicious (fake FireEye installer: Run key, recon, lookalike domain)
  attack_leaked_video.evtx      -> Malicious (WordPad drops leaked_video.mp4.exe, service, ransom note)
  benign_before_infection.evtx  -> Suspicious (the same computer before the infection. Since
      Milestone 5 the policy is "unsure = Suspicious": its two new Run key entries and a script
      program going online are Low findings worth a look; nothing is High.)
"""

from pathlib import Path

import pytest

from triage.checks import make_verdict, run_checks
from triage.parse import read_evtx

SAMPLES = Path(__file__).parent.parent / "samples"
EXPECTED = {"attack_fake_fireeye.evtx": "Malicious",
            "attack_leaked_video.evtx": "Malicious",
            "benign_before_infection.evtx": "Suspicious"}


@pytest.mark.parametrize("name, label", EXPECTED.items())
def test_real_sample_verdict(name, label):
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"{name} is not on this computer (real logs are never committed)")
    findings = run_checks(read_evtx(path))
    assert make_verdict(findings)["label"] == label
    if label == "Benign":
        assert findings == []
