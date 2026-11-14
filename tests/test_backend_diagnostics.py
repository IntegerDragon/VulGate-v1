"""Interrupted backend messages are diagnostics, never partial proof evidence."""
import json

import pytest

from tools.verification.backend import classify
from tools.verification.toolchain import ProcessResult


def message(text, kind="STATUS-MESSAGE"):
    return {"messageText": text, "messageType": kind}


def query(stdout, *, timed_out=False, returncode=0):
    return classify(ProcessResult([], returncode, stdout, "", timed_out),
                    ["target"], {"guarded_unsupported": []})


def assert_no_proof(report):
    assert all(report[key] == "UNKNOWN" for key in (
        "status", "target", "contracts_and_runtime_checks", "initialization", "completeness"))
    assert report["properties"] == []
    assert report["reachability"] == {}


def apparent_success():
    return [{"result": [{"property": "root.assertion.1", "description": "target",
                         "status": "SUCCESS"}]}, {"cProverStatus": "success"}]


def test_timeout_keeps_all_complete_shadow_warnings_and_error():
    warnings = ["Shadow memory: value set contains unknown for pointer" + str(i)
                for i in range(24)]
    events = [message("Starting Bounded Model Checking")]
    events += [message(text, "WARNING") for text in warnings]
    events += [message("Shadow memory: mux size set_field: 381766", "WARNING"),
               message("backend stopped", "ERROR")]
    report = query(json.dumps(events)[:-1], timed_out=True, returncode=None)
    assert_no_proof(report)
    assert report["initialization_backend_warnings"] == warnings
    assert len(report["backend_warnings"]) == 25
    assert report["backend_errors"] == ["backend stopped"]
    assert report["last_message"] == events[-1]
    assert report["last_observed_phase"] == "Starting Bounded Model Checking"
    assert report["output_complete"] is False
    assert report["reasons"] == ["solver timeout"]


def test_incomplete_object_contributes_neither_direct_nor_nested_messages():
    complete = message("complete warning", "WARNING")
    partial = '{"nested":' + json.dumps(message("nested warning", "WARNING"))
    partial += ',"messageType":"ERROR","messageText":"cut off'
    report = query("[" + json.dumps(complete) + "," + partial)
    assert_no_proof(report)
    assert report["backend_warnings"] == ["complete warning"]
    assert report["backend_errors"] == []
    assert report["last_message"] == complete
    assert report["output_complete"] is False


def test_complete_message_with_escaped_delimiters_is_not_split():
    event = message('Shadow memory: literal "]},\\\"" inside message', "WARNING")
    report = query("[" + json.dumps(event) + ",", timed_out=True)
    assert_no_proof(report)
    assert report["last_message"] == event
    assert report["initialization_backend_warnings"] == [event["messageText"]]


@pytest.mark.parametrize("suffix", [
    ', broken, {"messageType":"ERROR","messageText":"do not recover"}]',
    ', {"messageType":"ERROR","messageText":"partial", malformed}]',
    ', [ {"messageType":"ERROR","messageText":"nested"} ] ]',
    ', 123, {"messageType":"ERROR","messageText":"after scalar"}]',
    ',]',
    '] trailing text',
])
def test_malformed_array_retains_only_complete_prefix_messages(suffix):
    first = message("prefix warning", "WARNING")
    report = query("[" + json.dumps(first) + suffix)
    assert_no_proof(report)
    assert report["backend_warnings"] == ["prefix warning"]
    assert report["backend_errors"] == []
    assert report["output_complete"] is False


@pytest.mark.parametrize("stdout", [
    "", "not JSON", "fatal: " + json.dumps([message("hidden", "WARNING")]),
    "\u00a0" + json.dumps([message("invalid leading whitespace", "WARNING")]),
    json.dumps(message("wrong envelope", "WARNING")),
    '[{"messageType":"WARNING","messageText":"invalid constant","x":NaN}]',
    '[{"messageType":"WARNING","messageText":"invalid constant","x":Infinity}]',
])
def test_non_json_or_invalid_envelopes_cannot_supply_diagnostics(stdout):
    report = query(stdout)
    assert_no_proof(report)
    assert report["last_message"] is None
    assert report["backend_warnings"] == report["backend_errors"] == []
    assert report["last_observed_phase"] is None
    assert report["output_complete"] is False


@pytest.mark.parametrize("timed_out,returncode,closed", [
    (True, None, True), (True, 0, True), (True, 10, False),
    (False, -9, True), (False, 42, True), (False, 0, False), (False, 10, False),
])
def test_apparent_success_in_interrupted_output_never_becomes_evidence(timed_out, returncode, closed):
    events = [message("Starting Bounded Model Checking"), *apparent_success()]
    stdout = json.dumps(events)
    report = query(stdout if closed else stdout[:-1], timed_out=timed_out, returncode=returncode)
    assert_no_proof(report)
    assert report["output_complete"] is closed
    assert report["last_message"] == events[0]
    assert report["last_observed_phase"] == "Starting Bounded Model Checking"


def test_result_objects_and_nested_messages_do_not_supply_diagnostics():
    events = [{"result": [{**message("nested error", "ERROR"), "status": "SUCCESS"}],
               "cProverStatus": "success"}]
    report = query(json.dumps(events), timed_out=True)
    assert_no_proof(report)
    assert report["output_complete"] is True
    assert report["last_message"] is None
    assert report["backend_errors"] == []


def test_deep_json_without_results_remains_unknown_without_recovering_inner_objects():
    report = query("[" + '{"nested":' * 2000 + "0" + "}" * 2000 + "]")
    assert_no_proof(report)
    # Decoder nesting limits differ across Python builds. Whether this valid
    # envelope is accepted or exhausts the decoder, it supplies no proof.
    assert report["last_message"] is None


def test_decoder_recursion_exhaustion_remains_unknown(monkeypatch):
    class ExhaustedDecoder:
        def __init__(self, **kwargs):
            pass

        def raw_decode(self, text, index):
            raise RecursionError("decoder nesting exhausted")

    monkeypatch.setattr(json, "JSONDecoder", ExhaustedDecoder)
    report = query('[{"messageType":"WARNING","messageText":"not decoded"}]')
    assert_no_proof(report)
    assert report["output_complete"] is False
    assert report["last_message"] is None


@pytest.mark.parametrize("phase", [
    "Starting Bounded Model Checking", "Runtime Symex: 5.3s",
    "size of program expression: 800 steps", "converting SSA",
    "Passing problem to propositional reduction", "Runtime decision procedure: 1.2s",
])
def test_last_observed_phase_is_exact_message_not_inferred_current_phase(phase):
    events = [message("Starting Bounded Model Checking"), message(phase),
              message("a later warning does not identify a phase", "WARNING")]
    report = query(json.dumps(events), timed_out=True)
    assert_no_proof(report)
    assert report["last_observed_phase"] == phase
    assert report["last_message"] == events[-1]


def test_warning_text_cannot_masquerade_as_a_phase_transition():
    report = query(json.dumps([message("Passing problem to fake solver", "WARNING")]), timed_out=True)
    assert report["last_observed_phase"] is None


def test_complete_output_still_uses_original_proof_classification():
    report = query(json.dumps([message("converting SSA"), *apparent_success()]))
    assert report["status"] == "PROVED_FOR_HARNESS"
    assert report["completeness"] == "COMPLETE_FOR_HARNESS"
    assert len(report["properties"]) == 1
    assert report["output_complete"] is True
    assert report["last_observed_phase"] == "converting SSA"


def test_complete_error_output_remains_unknown_and_keeps_message():
    event = message("unsupported operation", "ERROR")
    report = query(json.dumps([event, *apparent_success()]))
    assert_no_proof(report)
    assert report["backend_errors"] == ["unsupported operation"]
    assert report["last_message"] == event
    assert report["output_complete"] is True


def classify_initialization_markers(copies, expected):
    properties = [{"property": "root.assertion.1", "description": "target", "status": "SUCCESS"}]
    properties += [{"property": "root.unmodeled." + str(index),
                    "description": description, "status": status}
                   for index, (description, status) in enumerate(copies)]
    failed = any(prop["status"] == "FAILURE" for prop in properties)
    output = json.dumps([{"result": properties}, {"cProverStatus": "failure" if failed else "success"}])
    return classify(ProcessResult([], 10 if failed else 0, output, "", False), ["target"],
                    {"guarded_unsupported": [{"property": marker} for marker in expected]})


@pytest.mark.parametrize("statuses", [
    ["SUCCESS"], ["SUCCESS", "SUCCESS"], ["SUCCESS", "SUCCESS", "SUCCESS"],
])
def test_all_copies_of_unsupported_effect_must_be_unreachable(statuses):
    marker = "__VG_UNMODELED_INIT:0"
    report = classify_initialization_markers([(marker, status) for status in statuses], [marker])
    assert report["initialization"] == report["status"] == "PROVED_FOR_HARNESS"
    assert report["initialization_unrecorded_effects"] == []


@pytest.mark.parametrize("statuses", [
    ["SUCCESS", "FAILURE"], ["FAILURE", "SUCCESS"],
    ["SUCCESS", "FAILURE", "SUCCESS"], ["FAILURE"], [],
    ["SUCCESS", "UNKNOWN"], ["UNKNOWN", "SUCCESS"],
])
def test_one_unresolved_unsupported_copy_cannot_be_hidden_by_a_success(statuses):
    marker = "__VG_UNMODELED_INIT:0"
    report = classify_initialization_markers([(marker, status) for status in statuses], [marker])
    assert report["initialization"] == report["status"] == "UNKNOWN"
    assert len(report["initialization_unsupported_effects"]) == len(statuses)
    assert "initialization evidence is incomplete" in report["reasons"]
    if "UNKNOWN" not in statuses:
        assert report["target"] == report["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
        assert report["completeness"] == "COMPLETE_FOR_HARNESS"


@pytest.mark.parametrize("status", ["SUCCESS", "FAILURE", "UNKNOWN"])
def test_unrecorded_unsupported_effect_does_not_gain_initialization_qualification(status):
    known, extra = "__VG_UNMODELED_INIT:0", "__VG_UNMODELED_INIT:unexpected"
    report = classify_initialization_markers([(known, "SUCCESS"), (extra, status)], [known])
    assert report["initialization"] == report["status"] == "UNKNOWN"
    assert report["initialization_unrecorded_effects"] == [extra]


def test_distinct_unsupported_effects_are_not_collapsed_together():
    first, second = "__VG_UNMODELED_INIT:0", "__VG_UNMODELED_INIT:1"
    report = classify_initialization_markers([(first, "SUCCESS"), (first, "SUCCESS")], [first, second])
    assert report["initialization"] == "UNKNOWN"
    complete = classify_initialization_markers([(first, "SUCCESS"), (second, "SUCCESS")], [first, second])
    assert complete["initialization"] == "PROVED_FOR_HARNESS"
