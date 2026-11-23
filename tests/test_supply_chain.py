# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
import datetime as dt
import json
from pathlib import Path
import pytest
from kubeflight.cli import main
from kubeflight.engine import assess
from kubeflight.images import ImagePolicy, image_findings, parse_image, parse_image_policy, merge_policies
from kubeflight.parser import parse_text
from kubeflight.plus import plus_findings
from kubeflight.registry import REGISTRY
from kubeflight.report import sarif_report, markdown_report, json_report
from kubeflight.vulns import (cvss3_score, compare_versions, parse_advisories, parse_sbom, load_sbom, load_advisories,
                              vulnerability_findings, MAX_FILE_BYTES)

ROOT = Path(__file__).parents[1]
SUP = ROOT / "examples" / "supply"
TODAY = dt.date(2026, 11, 23)


def dep(image, name="web"):
    return parse_text(f"""apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: default}}
spec:
  selector: {{matchLabels: {{app: {name}}}}}
  template:
    metadata: {{labels: {{app: {name}}}}}
    spec:
      containers:
      - {{name: c, image: "{image}"}}
""")

def ids(fs): return [f.id for f in fs]


# ---- image hygiene --------------------------------------------------------

def test_parse_image_variants():
    r = parse_image("nginx")
    assert (r.registry, r.repo, r.tag, r.digest) == ("docker.io", "library/nginx", None, None)
    r = parse_image("ghcr.io/acme/app:1.2@sha256:" + "a" * 64)
    assert (r.registry, r.repo, r.tag) == ("ghcr.io", "acme/app", "1.2") and r.digest
    assert parse_image("localhost:5000/x:1").registry == "localhost:5000"
    assert parse_image("index.docker.io/acme/x").registry == "docker.io"

@pytest.mark.parametrize("bad", ["", " nginx", "NGINX", "a b", "nginx:", "nginx@sha256:zz", "a" * 600, "-x", "x/-y", "reg.io/", "${IMAGE}", "x\ny", None, 5, ["x"]])
def test_parse_image_rejects_hostile(bad):
    assert parse_image(bad) is None

def test_digest_and_mutable_tag_findings():
    fs = image_findings(dep("ghcr.io/a/b:stable"))
    assert set(ids(fs)) == {"KF-IMG-001", "KF-IMG-002"}
    assert ids(image_findings(dep("ghcr.io/a/b:1.2@sha256:" + "b" * 64))) == []
    # a digest makes a floating tag immutable
    assert "KF-IMG-002" not in ids(image_findings(dep("ghcr.io/a/b:stable@sha256:" + "b" * 64)))

def test_require_digest_raises_severity():
    f = image_findings(dep("ghcr.io/a/b:1.2"), ImagePolicy(require_digest=True))[0]
    assert (f.id, f.severity) == ("KF-IMG-001", "medium")

def test_registry_allow_list():
    pol = ImagePolicy(("ghcr.io/acme/*", "registry.example.com", "*.corp.io"))
    assert not [f for f in image_findings(dep("ghcr.io/acme/app:1"), pol) if f.id == "KF-IMG-003"]
    assert not [f for f in image_findings(dep("registry.example.com/x/y:1"), pol) if f.id == "KF-IMG-003"]
    assert not [f for f in image_findings(dep("a.corp.io/x:1"), pol) if f.id == "KF-IMG-003"]
    bad = [f for f in image_findings(dep("ghcr.io/evil/app:1"), pol) if f.id == "KF-IMG-003"]
    assert bad and bad[0].severity == "high"
    assert [f for f in image_findings(dep("nginx:1.27"), pol) if f.id == "KF-IMG-003"]  # docker hub is not allowed
    assert not [f for f in image_findings(dep("ghcr.io/evil/app:1")) if f.id == "KF-IMG-003"]  # no allow-list, no finding

def test_malformed_image_does_not_crash_and_is_not_echoed_raw():
    fs = image_findings(dep("BAD IMAGE\\x1b[31m"))
    assert ids(fs) == ["KF-IMG-004"] and "\x1b" not in fs[0].evidence

def test_non_string_image_values():
    res = parse_text("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - {name: a, image: 123}\n  - {name: b, image: [x]}\n  - {name: c}\n")
    assert ids(image_findings(res)) == ["KF-IMG-004", "KF-IMG-004"]

def test_image_policy_validation():
    assert parse_image_policy({"allowed_registries": ["a.io"], "require_digest": True}).require_digest
    for bad in ([], {"allowed_registries": "x"}, {"allowed_registries": [1]}, {"allowed_registries": ["a b"]}, {"require_digest": "yes"}, {"typo": 1}):
        with pytest.raises(ValueError):
            parse_image_policy(bad)
    assert merge_policies(ImagePolicy(("a.io",)), ["b.io"]).allowed_registries == ("a.io", "b.io")


# ---- versions / CVSS ------------------------------------------------------

@pytest.mark.parametrize("a,b,expect", [("1.2.3", "1.2.3", 0), ("1.2.3", "1.10.0", -1), ("2.0", "1.9.9", 1), ("1.0.0-rc1", "1.0.0", -1),
                                        ("1.0", "1.0.1", -1), ("v1.2.3", "1.2.3", 0), ("1:2.0", "2.0", 0), ("1.1.1k", "1.1.1", 1), ("3.0.11-1~deb12u2", "3.0.13", -1)])
def test_compare_versions(a, b, expect):
    assert compare_versions(a, b) == expect

def test_cvss3_known_vectors():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_score("CVSS:4.0/AV:N") is None and cvss3_score("garbage") is None and cvss3_score(None) is None


# ---- advisory parsing -----------------------------------------------------

def test_simple_and_osv_formats_parse():
    s = load_advisories(SUP / "advisories.yaml")
    assert s.version == "2026-11-01" and s.expires == dt.date(2027, 1, 31) and len(s.advisories) == 2
    o = load_advisories(SUP / "advisories.osv.json")
    assert o.fmt == "osv" and o.advisories[0].severity == "critical" and "CVSS v3 base score 9.8" in o.advisories[0].severity_source

def test_severity_sources_are_ordered_and_transparent():
    def sev(entry):
        return parse_advisories({"advisories": [entry]}).advisories[0]
    a = sev({"id": "X", "package": "p", "affected": ["<2"], "severity": "high"})
    assert (a.severity, a.severity_source) == ("high", "advisory 'severity'")
    o = parse_advisories([{"id": "Y", "database_specific": {"severity": "MODERATE"}, "affected": [{"package": {"name": "p", "ecosystem": "npm"}, "versions": ["1.0.0"]}]}]).advisories[0]
    assert (o.severity, o.severity_source) == ("medium", "database_specific.severity")
    d = parse_advisories([{"id": "Z", "affected": [{"package": {"name": "p"}, "versions": ["1"]}]}]).advisories[0]
    assert d.severity == "medium" and d.severity_source.startswith("default")

@pytest.mark.parametrize("doc", [
    "just a string", 5, {"advisories": "x"}, {"advisories": [5]}, {"advisories": [{"id": "X"}]},
    {"advisories": [{"id": "X", "package": "p", "affected": ["<<1"]}]}, {"advisories": [{"id": "", "package": "p", "affected": ["<1"]}]},
    {"advisories": [{"id": "X", "package": 5, "affected": ["<1"]}]}, {"expires": "soon", "advisories": []}, {"nonsense": 1},
])
def test_advisory_hostile_input_is_rejected_cleanly(doc):
    with pytest.raises(ValueError):
        parse_advisories(doc)

def test_osv_git_ranges_ignored_and_open_ended_introduced():
    db = parse_advisories([{"id": "G", "affected": [{"package": {"name": "p", "ecosystem": "npm"}, "ranges": [
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}, {"type": "SEMVER", "events": [{"introduced": "1.5.0"}]}]}]}])
    aff = db.advisories[0].affected[0]
    assert aff.matches_version("1.6.0") and not aff.matches_version("1.4.0")

def test_osv_last_affected_inclusive():
    db = parse_advisories([{"id": "L", "affected": [{"package": {"name": "p"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.0"}]}]}]}])
    a = db.advisories[0].affected[0]
    assert a.matches_version("2.0") and not a.matches_version("2.0.1")


# ---- SBOM parsing ---------------------------------------------------------

def test_cyclonedx_and_spdx_parse():
    c = load_sbom(SUP / "sbom.cdx.json")
    assert c.fmt == "cyclonedx" and len(c.components) == 3 and c.subjects[0].canonical_repo == "ghcr.io/example/payments"
    s = load_sbom(SUP / "sbom.spdx.json")
    assert s.fmt == "spdx" and len(s.components) == 1 and s.subjects[0].canonical_repo == "docker.io/library/nginx"

def test_sbom_image_binding_syntax_and_property(tmp_path):
    p = tmp_path / "s.json"; p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    assert load_sbom(f"{p}=ghcr.io/a/b:1").subjects[0].raw == "ghcr.io/a/b:1"
    with pytest.raises(ValueError):
        load_sbom(f"{p}=NOT A REF")
    d = {"bomFormat": "CycloneDX", "metadata": {"properties": [{"name": "kubeflight:image", "value": "ghcr.io/x/y:2"}]}, "components": []}
    s = parse_sbom(d)
    assert s.explicit and s.subjects[0].repo == "x/y"

@pytest.mark.parametrize("doc", [[], "x", {}, {"bomFormat": "CycloneDX", "components": "x", "metadata": 5}, {"spdxVersion": "SPDX-3.0"}, {"spdxVersion": "SPDX-2.3"}])
def test_sbom_hostile_input(doc):
    try:
        s = parse_sbom(doc)
    except ValueError:
        return
    assert s.components == []  # lenient shapes must degrade to "no components", never crash

def test_sbom_nesting_and_size_bounds(tmp_path):
    deep = {"name": "a", "version": "1"}
    cur = deep
    for _ in range(20):
        cur["components"] = [{"name": "a", "version": "1"}]; cur = cur["components"][0]
    with pytest.raises(ValueError, match="nested"):
        parse_sbom({"bomFormat": "CycloneDX", "components": [deep]})
    big = tmp_path / "big.json"; big.write_text(" " * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="larger"):
        load_sbom(big)
    nest = tmp_path / "nest.json"; nest.write_text("[" * 100000)
    with pytest.raises(ValueError):
        load_sbom(nest)


# ---- matching -------------------------------------------------------------

def run(image="ghcr.io/example/payments:v4.9.0", sbom="sbom.cdx.json", adv="advisories.yaml", today=TODAY):
    return vulnerability_findings(dep(image), [load_sbom(SUP / sbom)], [load_advisories(SUP / adv)], today)

def test_matches_known_vulnerable_components_with_transparent_evidence():
    fs = [f for f in run() if f.id == "KF-VUL-001"]
    assert {f.severity for f in fs} == {"high", "medium"} and len(fs) == 2
    ev = next(f.evidence for f in fs if "0001" in f.title)
    assert "openssl@3.0.11" in ev and "<3.0.13" in ev and "advisory 'severity'" in ev and "version 2026-11-01" in ev and "expires 2027-01-31" in ev

def test_fixed_component_does_not_match_and_ecosystem_must_agree(tmp_path):
    adv = parse_advisories({"advisories": [{"id": "A", "package": "requests", "ecosystem": "npm", "affected": ["<9"], "severity": "high"}]})
    fs = vulnerability_findings(dep("ghcr.io/example/payments:v4.9.0"), [load_sbom(SUP / "sbom.cdx.json")], [adv], TODAY)
    assert "KF-VUL-001" not in ids(fs)  # requests is a pypi component

def test_tag_mismatch_means_sbom_not_applied():
    fs = run(image="ghcr.io/example/payments:v1.0.0")
    assert "KF-VUL-001" not in ids(fs) and "KF-VUL-004" in ids(fs) and "KF-VUL-005" in ids(fs)

def test_digest_mismatch_means_sbom_not_applied():
    d1, d2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    sbom = parse_sbom({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "ghcr.io/a/b", "version": d1}}, "components": [{"name": "p", "version": "1"}]})
    adv = parse_advisories({"advisories": [{"id": "A", "package": "p", "affected": ["<2"]}]})
    assert "KF-VUL-001" in ids(vulnerability_findings(dep(f"ghcr.io/a/b@{d1}"), [sbom], [adv], TODAY))
    assert "KF-VUL-001" not in ids(vulnerability_findings(dep(f"ghcr.io/a/b@{d2}"), [sbom], [adv], TODAY))

def test_stale_and_undated_advisories_are_called_out():
    assert "KF-VUL-002" in ids(run(today=dt.date(2027, 2, 1)))
    assert "KF-VUL-002" not in ids(run(today=TODAY))
    undated = parse_advisories({"advisories": [{"id": "A", "package": "p", "affected": ["<2"]}]})
    assert "KF-VUL-003" in ids(vulnerability_findings(dep("x"), [], [undated], TODAY))
    versioned = parse_advisories({"version": "7", "advisories": [{"id": "A", "package": "p", "affected": ["<2"]}]})
    assert "KF-VUL-003" not in ids(vulnerability_findings(dep("x"), [], [versioned], TODAY))

def test_spdx_osv_end_to_end():
    fs = run(image="nginx:1.27", sbom="sbom.spdx.json", adv="advisories.osv.json")
    v = [f for f in fs if f.id == "KF-VUL-001"]
    assert len(v) == 1 and v[0].severity == "critical" and "zlib@1.2.11" in v[0].evidence

def test_finding_cap_and_summary_finding():
    comps = [{"name": f"p{i}", "version": "1"} for i in range(600)]
    sbom = parse_sbom({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "ghcr.io/a/b", "version": "1"}}, "components": comps})
    adv = parse_advisories({"version": "1", "advisories": [{"id": f"A{i}", "package": f"p{i}", "affected": ["<2"]} for i in range(600)]})
    fs = vulnerability_findings(dep("ghcr.io/a/b:1"), [sbom], [adv], TODAY)
    assert ids(fs).count("KF-VUL-001") == 500 and "KF-VUL-006" in ids(fs)

def test_adversarial_names_do_not_inject_into_evidence():
    sbom = parse_sbom({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "ghcr.io/a/b", "version": "1"}},
                       "components": [{"name": "evil\x1b[31m|`<script>", "version": "1\n2"}]})
    adv = parse_advisories({"version": "1", "advisories": [{"id": "A\n1", "package": "evil\x1b[31m|`<script>", "affected": ["*"], "summary": "x\x00y"}]})
    f = vulnerability_findings(dep("ghcr.io/a/b:1"), [sbom], [adv], TODAY)[0]
    assert "\x1b" not in f.evidence and "\x00" not in f.evidence and "\n" not in f.evidence and "\n" not in f.title

def test_plus_requires_both_inputs():
    with pytest.raises(ValueError, match="both"):
        plus_findings(dep("x"), target="1.33", sboms=[load_sbom(SUP / "sbom.cdx.json")])
    with pytest.raises(ValueError, match="both"):
        plus_findings(dep("x"), target="1.33", advisories=[load_advisories(SUP / "advisories.yaml")])


# ---- outputs and registry -------------------------------------------------

def _assess_demo():
    res = parse_text((ROOT / "examples/demo/app.yaml").read_text())
    extra = plus_findings(res, target="1.33", image_policy=ImagePolicy(("registry.example.com",)), sboms=[load_sbom(SUP / "sbom.cdx.json")], advisories=[load_advisories(SUP / "advisories.yaml")])
    return assess(res, extra=extra)

def test_all_new_ids_registered_and_explainable(capsys):
    a = _assess_demo()
    got = {f.id for f in a.findings}
    assert {"KF-VUL-001", "KF-IMG-001", "KF-IMG-003"} <= got and got <= set(REGISTRY)
    for fid in ("KF-IMG-001", "KF-VUL-001", "KF-VUL-002", "KF-VUL-003", "KF-HLM-006"):
        assert main(["explain", fid]) == 0
    assert "not a scanner" in capsys.readouterr().out

def test_reports_cover_supply_findings():
    a = _assess_demo()
    sarif = json.loads(sarif_report(a))
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "KF-VUL-001" in rules and rules["KF-VUL-001"]["help"]["markdown"]
    assert any(r["ruleId"] == "KF-VUL-001" and r["level"] == "error" for r in sarif["runs"][0]["results"])
    assert "Known-vulnerable component" in markdown_report(a)
    assert any(f["id"] == "KF-VUL-001" for f in json.loads(json_report(a))["findings"])

def test_cli_flags_and_limitations(tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = main(["check", str(ROOT / "examples/demo/app.yaml"), "--sbom", str(SUP / "sbom.cdx.json"), "--advisories", str(SUP / "advisories.yaml"),
               "--image-policy", str(SUP / "image-policy.yaml"), "--allow-registry", "ghcr.io/example/*", "--format", "json", "--output", str(out), "--fail-on", "high"])
    d = json.loads(out.read_text())
    assert rc == 3 and any(f["id"] == "KF-VUL-001" for f in d["findings"]) and any("not a vulnerability scanner" in l for l in d["limitations"])

def test_cli_sbom_without_advisories_is_usage_error(capsys):
    rc = main(["check", str(ROOT / "examples/demo/app.yaml"), "--sbom", str(SUP / "sbom.cdx.json")])
    assert rc == 2 and "--advisories" in capsys.readouterr().err

def test_cli_bad_sbom_is_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"; bad.write_text("{not json")
    rc = main(["check", str(ROOT / "examples/demo/app.yaml"), "--sbom", str(bad), "--advisories", str(SUP / "advisories.yaml")])
    assert rc == 2 and "kubeflight:" in capsys.readouterr().err
