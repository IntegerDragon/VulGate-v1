import hashlib
import json

from tools.frontier.benchmark import run_corpus, main


def corpus(tmp_path):
    source = tmp_path / "source.c"
    source.write_text("int target(void) { return -EINVAL; }\nint caller(void) { int r = target(); if (r < 0) return r; return 0; }", encoding="utf-8")
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps({"cases": [{"id": "test", "dangerous_function": "target",
        "sources": [{"path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}],
        "expected_status": "found", "expected_candidates": [["target", "-EINVAL", "self"]]}]}), encoding="utf-8")
    return manifest, source


def test_replay_matches_reviewed_candidates(tmp_path):
    manifest, _ = corpus(tmp_path)
    report = run_corpus(manifest)
    assert report["matched"] == report["total"] == 1
    assert main([str(manifest), "--output", str(tmp_path / "report.json")]) == 0


def test_changed_source_cannot_reuse_review(tmp_path):
    manifest, source = corpus(tmp_path)
    source.write_text("int target(void) { return 0; }", encoding="utf-8")
    report = run_corpus(manifest)
    assert report["matched"] == 0
    assert report["cases"][0]["check"] == "input_error"


def test_new_candidate_requires_review(tmp_path):
    manifest, _ = corpus(tmp_path)
    data = json.loads(manifest.read_text())
    data["cases"][0]["expected_candidates"] = []
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = run_corpus(manifest)
    assert report["matched"] == 0
    assert report["cases"][0]["new_unreviewed_candidates"] == [("target", "-EINVAL", "self")]
