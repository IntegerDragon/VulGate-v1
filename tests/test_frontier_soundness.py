"""Counterexamples to the source heuristic; these are not a kernel proof."""
import pytest

from tools.frontier import analyze_sources
from tools.frontier.__main__ import main


def analyze(tmp_path, source, dangerous="target"):
    path = tmp_path / "sample.c"
    path.write_text(source, encoding="utf-8")
    return analyze_sources([path], dangerous)


def values(result, function="target"):
    return {c["return_value"] for c in result["candidates"] if c["function"] == function}


@pytest.mark.parametrize("tail", [
    "if (r < 0) { if (flag) return r; } return 0;",
    "if (r < 0) {} return 0;",
    "{ int r = 0; if (r < 0) return r; } return 0;",
])
def test_real_paths_veto_regex_checks(tmp_path, tail):
    result = analyze(tmp_path, "int target(void) {return -EINVAL;} int caller(void) {int r=target(); " + tail + "}")
    assert not values(result)


def test_unchecked_dereference_vetoes_later_check(tmp_path):
    result = analyze(tmp_path, """
int *target(void) {return NULL;}
int caller(void) {int *p=target(); int x=*p; if(!p) return -1; return x;}
""")
    assert not values(result)


def test_inner_injection_does_not_skip_wrapper_output_effects(tmp_path):
    result = analyze(tmp_path, """
struct out {int n;};
int target(void) {return -EINVAL;}
int wrapper(struct out *o) {int r=target(); o->n=1; return r;}
int caller(void) {struct out o={0}; int r=wrapper(&o); if(o.n) r=0; if(r<0) return r; return 0;}
""")
    assert all(c["caller_contract"] != "confirmed_in_model" for c in result["candidates"] if c["function"] == "target")


def test_positive_http_error_is_not_a_negative_errno(tmp_path):
    result = analyze(tmp_path, """
#define NGX_HTTP_BAD_REQUEST 400
int target(void) {return NGX_HTTP_BAD_REQUEST;}
int caller(void) {int r=target(); if(r<0) return r; return 0;}
""")
    assert not values(result)


def test_positive_status_is_handled_by_actual_numeric_contract(tmp_path):
    result = analyze(tmp_path, """
#define HTTP_ERROR 400
#define SPECIAL_RESPONSE HTTP_ERROR
int target(void) {return HTTP_ERROR;}
int caller(void) {int r=target(); if(r>=SPECIAL_RESPONSE) return r; return 0;}
""")
    assert values(result) == {"HTTP_ERROR"}
    assert result["candidates"][0]["caller_contract"] == "confirmed_in_model"


def test_resolved_errno_does_not_take_other_sentinel_branch(tmp_path):
    result = analyze(tmp_path, """
#define EPERM 1
#define SENTINEL 500
int target(void) {return -EPERM;}
int caller(void) {int r=target(); if(r!=-SENTINEL) return r; return fallback();}
""")
    assert values(result) == {"-EPERM"}
    assert result["candidates"][0]["caller_contract"] == "confirmed_in_model"


def test_macro_meaning_does_not_change_when_return_crosses_files(tmp_path):
    a, b = tmp_path / "a.c", tmp_path / "b.c"
    a.write_text("#define RESULT 400\nint target(void) {return RESULT;}")
    b.write_text("#define RESULT -1\nint caller(void) {int r=target(); if(r==RESULT) return r; return 0;}")
    assert not values(analyze_sources([a, b], "target"))


@pytest.mark.parametrize("include,confirmed", [('#include "status.h"', True), ('/*\n#include "status.h"\n*/', False)])
def test_only_explicitly_included_headers_define_constants(tmp_path, include, confirmed):
    header, source = tmp_path / "status.h", tmp_path / "main.c"
    header.write_text("#define FAILURE 400\n#define LIMIT 300\n")
    source.write_text(include + "\nint target(void) {return FAILURE;} int caller(void) {int r=target(); if(r>=LIMIT) return r; return 0;}")
    result = analyze_sources([source, header], "target")
    assert bool(values(result)) is confirmed


@pytest.mark.parametrize("definition", ["#define FAILURE 400\n#undef FAILURE", "#if UNKNOWN\n#define FAILURE 400\n#else\n#define FAILURE -1\n#endif", "#if UNKNOWN\n#define FAILURE 400\n#endif"])
def test_undefined_or_conflicting_macro_is_unknown(tmp_path, definition):
    result = analyze(tmp_path, definition + "\nint target(void) {return FAILURE;} int caller(void) {int r=target(); if(r>=300) return r; return 0;}")
    assert not values(result)


def test_optional_macro_does_not_select_only_the_safe_configuration(tmp_path):
    result = analyze(tmp_path, '''#if OPTIONAL
#define FLAG 1
#endif
int target(void) {return -1;}
int caller(void) {int r=target();
#ifdef FLAG
if(r<0) return r;
#else
return 0;
#endif
return 0;}
''')
    assert all(c["caller_contract"] != "confirmed_in_model" for c in result["candidates"])
    assert all("FLAG" not in constants for constants in result["analysis"]["integer_macros"].values())


def test_optional_include_does_not_supply_unconditional_constants(tmp_path):
    from tools.frontier.constants import source_macro_contexts
    contexts = source_macro_contexts([
        ("main.c", '#if OPTIONAL\n#include "status.h"\n#endif\n'),
        ("status.h", '#ifndef STATUS_H\n#define STATUS_H\n#define FLAG 1\n#endif\n'),
    ])
    assert not dict(contexts["main.c"])
    assert dict(contexts["status.h"]) == {"FLAG": 1}


def test_only_whole_file_include_guard_is_a_configuration_container():
    from tools.frontier.constants import integer_macros
    assert integer_macros(['#ifndef H\n#define H\n#define FLAG 1\n#endif\n']) == {"FLAG": 1}
    assert integer_macros(['#ifndef H\n#define H\n#define FLAG 1\n#endif\nint x;']) == {}
    assert integer_macros(['#ifndef H\n#define H\n#define FLAG 1\n#else\nint x;\n#endif']) == {}
    assert integer_macros(['#if 0\n#define FLAG 3\n#elif 1\n#define FLAG 1\n#endif']) == {"FLAG": 1}


@pytest.mark.parametrize("value", ["NGX_DECLINED", "NGX_DONE"])
def test_continuation_sentinels_are_not_terminal_failures(tmp_path, value):
    result = analyze(tmp_path, f"int target(void) {{return {value};}} int caller(void) {{int r=target(); if(r) return r; return 0;}}")
    assert not values(result)


@pytest.mark.parametrize("expr", ["PTR_ERR(local)", "ERR_PTR(err)", "ERR_PTR(-EAGAIN)",
                                  "ERR_PTR(-EBUSY)", "-ENOIOCTLCMD"])
def test_return_must_be_entry_available_and_terminal(tmp_path, expr):
    result = analyze(tmp_path, f"""
int *target(void) {{ int err = -EINVAL; void *local = get(); return {expr}; }}
int caller(void) {{ int *p = target(); if (IS_ERR(p)) return -EINVAL; return 0; }}
""")
    assert not values(result)


def test_constant_error_pointer_is_retained(tmp_path):
    result = analyze(tmp_path, """
void *target(void) { return ERR_PTR(-EINVAL); }
int caller(void) { void *p = target(); if (IS_ERR(p)) return -EINVAL; return 0; }
""")
    assert values(result) == {"ERR_PTR(-EINVAL)"}


def test_ptr_err_local_is_not_available_at_entry(tmp_path):
    result = analyze(tmp_path, """
int target(void) { void *p = acquire(); return PTR_ERR(p); }
int caller(void) { int r = target(); if (r < 0) return r; return 0; }
""")
    assert not values(result)


def test_success_only_check_does_not_handle_negative_errno(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int caller(void) { int r = target(); if (!r) return 0; consume(r); return 0; }
""")
    assert not values(result)


def test_else_assignment_cannot_overwrite_the_taken_branch(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int wrapper(void) { int r; if (flag) { r = target(); } else { r = -EPERM; } return r; }
int caller(void) { int r = wrapper(); if (r < 0) return r; return 0; }
""")
    assert values(result) == {"-EINVAL"}


def test_balanced_unlock_before_call_is_not_a_held_lock(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int caller(void) {
    mutex_lock(&m);
    if (flag) { mutex_unlock(&m); prepare(); } else { mutex_unlock(&m); }
    int r = target();
    if (r < 0) return r;
    return 0;
}
""")
    assert values(result) == {"-EINVAL"}


def test_owner_field_cleanup_preserves_allocation_identity(tmp_path):
    result = analyze(tmp_path, """
void cleanup(struct owner *o) { kfree(o->data); }
int target(void) { return -EINVAL; }
int caller(struct owner *o) {
    void *data = kmalloc(8, 0);
    o->data = data;
    int r = target();
    if (r < 0) { cleanup(o); return r; }
    return 0;
}
""")
    assert values(result) == {"-EINVAL"}


def test_early_return_cannot_bypass_cleanup(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int caller(void) {
    void *p = kmalloc(8, 0);
    int r = target();
    if (r < 0) { if (flag) return r; kfree(p); return r; }
    return 0;
}
""")
    assert not values(result)


def test_constructor_setup_needed_by_destructor_is_not_skippable(tmp_path):
    result = analyze(tmp_path, """
struct ops { int (*init)(struct state *s); void (*destroy)(struct state *s); int (*run)(void); };
int setup(struct state *s) { qdisc_watchdog_init(&s->wd, s); if (bad()) return -EINVAL; return 0; }
void cleanup(struct state *s) { qdisc_watchdog_cancel(&s->wd); }
int target(void) { consume(); return 0; }
struct ops table = { .init = setup, .destroy = cleanup, .run = target };
int create(struct ops *o, struct state *s) { int r = o->init(s); if (r) { o->destroy(s); return r; } return 0; }
""")
    assert not values(result, "setup")
    assert any("qdisc_watchdog_init" in item for item in result["rejected"])


def test_overwritten_assignment_is_not_an_existing_return(tmp_path):
    result = analyze(tmp_path, """
int target(void) { int ret = -EINVAL; ret = 0; return ret; }
int caller(void) { int ret = target(); if (ret < 0) return ret; return 0; }
""")
    assert not values(result)


def test_unchecked_sibling_above_parent_stays_uncovered(tmp_path):
    result = analyze(tmp_path, """
void target(void) { consume(); }
void bridge(void) { target(); }
int good(void) { if (bad()) return -EINVAL; bridge(); return 0; }
void unchecked(void) { bridge(); }
int entry(void) { int r = good(); if (r < 0) return r; return 0; }
""")
    assert result["status"] == "partial"
    assert "bridge" in result["uncovered"]


def test_two_good_branches_cover_the_dangerous_entry(tmp_path):
    result = analyze(tmp_path, """
void target(void) { consume(); }
void bridge(void) { target(); }
int one(void) { if (bad()) return -EINVAL; bridge(); return 0; }
int two(void) { if (bad()) return -EPERM; bridge(); return 0; }
int entry1(void) { int r = one(); if (r < 0) return r; return 0; }
int entry2(void) { int r = two(); if (r < 0) return r; return 0; }
""")
    assert result["status"] == "found"
    assert result["uncovered"] == []


def test_unknown_transitive_caller_is_not_silently_confirmed(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int wrapper(void) { return target(); }
int checked(void) { int r = wrapper(); if (r < 0) return r; return 0; }
int unknown(void) { return wrapper(); }
""")
    assert result["status"] == "partial"
    assert result["candidates"][0]["caller_contract"] == "partial"
    assert "wrapper" in result["uncovered"]


@pytest.mark.parametrize("cleanup", ["kfree(other);", "kfree(a);", "if (flag) kfree(a); kfree(b);"])
def test_cleanup_must_release_each_actual_object(tmp_path, cleanup):
    result = analyze(tmp_path, f"""
int target(void) {{ return -EINVAL; }}
int caller(void) {{
    void *a = kmalloc(8, 0);
    void *b = kmalloc(8, 0);
    int r = target();
    if (r < 0) {{ {cleanup} return r; }}
    return 0;
}}
""")
    assert not values(result)


def test_matching_cleanup_for_two_objects(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int caller(void) {
    void *a = kmalloc(8, 0);
    void *b = kmalloc(8, 0);
    int r = target();
    if (r < 0) { kfree(a); kfree(b); return r; }
    return 0;
}
""")
    assert values(result) == {"-EINVAL"}


def test_helper_cleanup_binds_argument_to_parameter(tmp_path):
    result = analyze(tmp_path, """
void cleanup(void *p) { kfree(p); }
int target(void) { return -EINVAL; }
int caller(void) {
    void *a = kmalloc(8, 0);
    int r = target();
    if (r < 0) { cleanup(a); return r; }
    return 0;
}
""")
    assert values(result) == {"-EINVAL"}


@pytest.mark.parametrize("condition", ["if (r < 0 && flag)", "if (r == -ENOMEM)"])
def test_partial_error_check_does_not_accept_every_errno(tmp_path, condition):
    result = analyze(tmp_path, f"""
int target(void) {{ return -EINVAL; }}
int caller(void) {{ int r = target(); {condition} return r; consume(r); return 0; }}
""")
    assert not values(result)


def test_reassigned_call_result_is_not_a_check(tmp_path):
    result = analyze(tmp_path, """
int target(void) { return -EINVAL; }
int caller(void) { int r = target(); r = other(); if (r < 0) return r; return 0; }
""")
    assert not values(result)


def test_logging_only_branch_does_not_handle_failure(tmp_path):
    result = analyze(tmp_path, """
void *target(void) { return NULL; }
int caller(void) { void *p = target(); if (!p) log_error(); return p->value; }
""")
    assert not values(result)


def test_static_function_in_another_file_is_not_a_direct_target(tmp_path):
    a, b = tmp_path / "a.c", tmp_path / "b.c"
    a.write_text("static int target(void) { return -EINVAL; }", encoding="utf-8")
    b.write_text("int caller(void) { int r = target(); if (r < 0) return r; return 0; }", encoding="utf-8")
    result = analyze_sources([a, b], "target")
    assert result["status"] == "insufficient_input"


@pytest.mark.parametrize("directive", ["#if 0\nreturn -EINVAL;\n#elif 0\nreturn -ENOMEM;\n#else\nreturn -EPERM;\n#endif",
                                        "#if 1\nreturn -EPERM;\n#else\nreturn -EINVAL;\n#endif"])
def test_constant_preprocessor_branches(tmp_path, directive):
    result = analyze(tmp_path, "int target(void) {\n" + directive + "\n}\n"
                     "int caller(void) { int r = target(); if (r < 0) return r; return 0; }")
    assert values(result) == {"-EPERM"}


def test_source_locations_survive_macro_normalization(tmp_path):
    source = "// header\nint target(void)\n{\n#if 0\nreturn -ENOMEM;\n#endif\n    if (unlikely(bad()))\n        return -EINVAL;\n    return 0;\n}\nint caller(void) { int r = target(); if (r < 0) return r; return 0; }\n"
    result = analyze(tmp_path, source)
    candidate = result["candidates"][0]
    assert candidate["location"]["line"] == 2
    assert candidate["return_location"]["line"] == 8
    assert candidate["caller_evidence"][0]["location"]["line"] == 11
    assert result["analysis"]["enforceable"] is False


def test_unknown_configuration_is_reported(tmp_path):
    result = analyze(tmp_path, """
int target(void) {
#ifdef CONFIG_FEATURE
return -EINVAL;
#else
return 0;
#endif
}
int caller(void) { int r = target(); if (r < 0) return r; return 0; }
""")
    assert result["analysis"]["unresolved_conditionals"]


@pytest.mark.parametrize("contents", ["{bad", '[]', '{"dangerous_function": "f", "sources": "x.c"}'])
def test_bad_manifest_has_a_clean_cli_error(tmp_path, capsys, contents):
    manifest = tmp_path / "case.json"
    manifest.write_text(contents, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([str(manifest)])
    assert exc.value.code == 2
    assert "Traceback" not in capsys.readouterr().err
