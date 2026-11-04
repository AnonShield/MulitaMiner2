"""Segmentation tests: synthetic fixtures for the rules, real PDFs for counts."""
import re
from pathlib import Path

import pytest

from mulitaminer.pdf_reader import extract_pdf
from mulitaminer.scanner_engine import get_scanner

OPENVAS_FIXTURE = """\
Scan Report
1.2.3.4
Host scan start Tue Jul 15 10:00:00 2026
High 443/tcp
High (CVSS: 7.5)
NVT: SSL/TLS: Certificate Expired
Summary:
The certificate expired.
Medium (CVSS: 5.3)
NVT: Weak Cipher Suites
Summary:
Weak ciphers are enabled.
Low 25/tcp
Low (CVSS: 3.1)
NVT: SMTP Banner Disclosure
Summary:
The banner reveals version information.
"""

TENABLE_FIXTURE = """\
Missing HTTP Strict Transport Security Policy
VULNERABILITY HIGH PLUGIN ID 98056
Description:
The remote web server does not send the HSTS header.
Solution:
Enable HSTS.
Reference Information:
CVE CVE-2021-33193, CVE-2021-40438
BID -
Missing HTTP Strict Transport Security Policy Instances (2)
VULNERABILITY HIGH PLUGIN ID 98056
Identification:
https://example.com/
HTTP Info:
GET / 200
"""


def test_openvas_marker_starts_each_block_with_severity_header():
    blocks = get_scanner("openvas").segment(OPENVAS_FIXTURE)
    assert len(blocks) == 3
    # The CVSS header line must be INSIDE its block, line one.
    for block in blocks:
        assert re.match(r"(Critical|High|Medium|Low|Log)\s+\(CVSS:", block.text.splitlines()[0])


def test_openvas_context_tracking():
    blocks = get_scanner("openvas").segment(OPENVAS_FIXTURE)
    assert [b.severity_hint for b in blocks] == ["HIGH", "MEDIUM", "LOW"]
    # Port headers apply to the blocks that follow them; state persists until
    # the next header ("Weak Cipher Suites" inherits 443/tcp).
    assert [(b.port, b.protocol) for b in blocks] == [(443, "tcp"), (443, "tcp"), (25, "tcp")]
    # Host recovered from the preamble (line above "Host scan start").
    assert all(b.host == "1.2.3.4" for b in blocks)


def test_openvas_preamble_yields_no_block():
    blocks = get_scanner("openvas").segment(OPENVAS_FIXTURE)
    assert "Scan Report" not in blocks[0].text


def test_openvas_discard_patterns_strip_noise_lines():
    # A "Results per Host" table cell wraps between the name and the first
    # section; discard_patterns drops it so it never pollutes the extracted name.
    fixture = """\
1.2.3.4
Host scan start Tue Jul 15 10:00:00 2026
High 80/tcp
High (CVSS: 7.5)
NVT: phpinfo() output Reporting
2 RESULTS PER HOST 7
Summary:
The file discloses info.
"""
    blocks = get_scanner("openvas").segment(fixture)
    assert len(blocks) == 1  # the noise line neither adds nor removes a block
    assert "RESULTS PER HOST" not in blocks[0].text.upper()
    assert blocks[0].text.splitlines()[1] == "NVT: phpinfo() output Reporting"


def test_tenable_name_walkback_pulls_name_into_block():
    blocks = get_scanner("tenable").segment(TENABLE_FIXTURE)
    assert len(blocks) == 2
    # The name line ABOVE the VULNERABILITY header belongs to this block.
    assert blocks[0].text.splitlines()[0] == "Missing HTTP Strict Transport Security Policy"
    assert blocks[1].text.splitlines()[0].endswith("Instances (2)")
    # And the previous block must NOT have swallowed the next block's name.
    assert "Instances (2)" not in blocks[0].text
    # The previous block's reference tail ('BID -') sits
    # directly above the name and must never be pulled in as name content.
    assert not blocks[1].text.startswith("BID")
    assert "BID -" in blocks[0].text  # it stays where it belongs


def test_tenable_wrapped_instances_title_is_fully_captured():
    """Long '<name> Instances (N)' titles wrap; the line
    above the marker is then only '(1)'; the walk-back must climb one more
    line, or pairing breaks."""
    fixture = """\
Apache 2.4.x < 2.4.25 Multiple Vulnerabilities (httpoxy)
VULNERABILITY HIGH PLUGIN ID 98910
Description:
Something.
Apache 2.4.x < 2.4.25 Multiple Vulnerabilities (httpoxy) Instances
(1)
VULNERABILITY HIGH PLUGIN ID 98910
Identification:
https://example.com/
"""
    blocks = get_scanner("tenable").segment(fixture)
    assert len(blocks) == 2
    first_line = blocks[1].text.splitlines()[0]
    assert first_line.endswith("Instances")
    assert "(1)" in blocks[1].text.splitlines()[1]
    assert "Instances" not in blocks[0].text  # nothing leaked backwards


def test_tenable_severity_hint():
    blocks = get_scanner("tenable").segment(TENABLE_FIXTURE)
    assert all(b.severity_hint == "HIGH" for b in blocks)


# --- Real baseline PDFs: block count == marker count (the count-parity core) --

REAL_CASES = [
    ("openvas", Path("resources/openvas/OpenVAS_JuiceShop.pdf"), 34),
    ("openvas", Path("resources/openvas/OpenVAS_Metasploitable2.pdf"), 59),
    ("tenable", Path("resources/tenable/TenableWAS_JuiceShop.pdf"), 128),
]


@pytest.mark.parametrize("scanner,pdf,expected", REAL_CASES)
def test_block_count_matches_marker_count_on_real_reports(scanner, pdf, expected):
    profile = get_scanner(scanner)
    doc = extract_pdf(pdf)
    blocks = profile.segment(doc.text)
    assert len(blocks) == expected
    assert [b.id for b in blocks] == list(range(expected))


def test_real_openvas_recovers_host():
    doc = extract_pdf(Path("resources/openvas/OpenVAS_JuiceShop.pdf"))
    blocks = get_scanner("openvas").segment(doc.text)
    assert blocks, "no blocks segmented"
    hosts = {b.host for b in blocks}
    assert hosts != {None}, "host was not recovered from the per-host preamble"
    for host in hosts - {None}:
        assert re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)


TENABLE_VM_FIXTURE = """\
Asset ID ecff72d7-10a5-463a-b3d8-793047ce70d5
Asset Details
IPv4 Address:
10.0.0.12
Asset ID:
ecff72d7-10a5-463a-b3d8-793047ce70d5
Vulnerabilities Detected
Plugin ID Plugin Name Severity
113044 GitLab 11.9.x < 13.8.8 / 13.9.x < 13.9.6 / 13.10.x <
13.10.3 Remote Code Execution
Critical
First Seen:
2026-04-24
Plugin Description:
An issue has been discovered in GitLab CE/EE.
Solution:
Update to GitLab version 13.8.8 / 13.9.6 / 13.10.3 or later.
10287 Traceroute Information Info
Plugin Description:
It was possible to obtain traceroute information.
Plugin Output:
Hop Count: 1
"""


def test_tenable_vm_rejoins_wrapped_rows_and_recovers_host():
    blocks = get_scanner("tenable-vm").segment(TENABLE_VM_FIXTURE)
    assert len(blocks) == 2
    first, second = blocks
    assert first.text.startswith(
        "113044 GitLab 11.9.x < 13.8.8 / 13.9.x < 13.9.6 / 13.10.x < 13.10.3 Remote Code Execution Critical")
    assert first.severity_hint == "CRITICAL" and second.severity_hint == "INFO"
    assert first.host == "10.0.0.12" and second.host == "10.0.0.12"
    assert "Hop Count: 1" in second.text and "Hop Count" not in first.text
