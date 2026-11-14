import pytest


def test_vm_bounded_loop_and_safe_read_replay(tmp_path):
    import ctypes
    import os
    from pathlib import Path
    from tools.postdeploy.expressions import compile_guard
    from tools.postdeploy.monitors import VMReplay

    root = Path(__file__).resolve().parents[1]
    bridge = Path(os.environ.get('VULGATE_FRIDA_BUILD', root / 'build/frida-linux')) / 'vulgate_frida.so'
    if not bridge.exists():
        pytest.skip('build vulgate_frida.so first')

    dsl = """
dots = 0
for i in range(16):
    ch = read_u8(host_ptr, i)
    if ch == 0:
        break
    if ch == 46:
        dots += 1
if dots >= 3:
    BLOCK()
"""
    fields = {'host_ptr': {'source': 'arg', 'index': 0}}
    bytecode = compile_guard(dsl, fields)
    rule_path = tmp_path / 'loop_dots.bin'
    rule_path.write_bytes(bytecode)

    vm = VMReplay(bridge, {'vhost_guard': {'path': rule_path, 'step_limit': 4096, 'observations': []}})
    try:
        handle, limit = vm.handles['vhost_guard']
        max_steps = ctypes.c_uint64(0)
        vm.lib.vg_program_max_steps.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
        vm.lib.vg_program_max_steps.restype = ctypes.c_int
        assert vm.lib.vg_program_max_steps(handle, ctypes.byref(max_steps)) == 0
        assert 16 < max_steps.value < 2000

        buf_short = ctypes.create_string_buffer(b'a.b.org')
        stats = (ctypes.c_uint64 * 3)()
        dec_short = vm.lib.vg_run(
            handle,
            (ctypes.c_uint64 * 6)(ctypes.addressof(buf_short)),
            (ctypes.c_uint64 * 16)(),
            limit,
            stats,
        )
        assert dec_short == 0
        assert stats[1] == 8

        buf_deep = ctypes.create_string_buffer(b'a.b.c.org')
        dec_deep = vm.lib.vg_run(
            handle,
            (ctypes.c_uint64 * 6)(ctypes.addressof(buf_deep)),
            (ctypes.c_uint64 * 16)(),
            limit,
            stats,
        )
        assert dec_deep == 1

        vm.lib.vg_last_read_count.restype = ctypes.c_uint
        rcount = vm.lib.vg_last_read_count()
        assert rcount == 10
    finally:
        vm.close()


def test_paired_goto_catches_uninitialized_caller_continuation_and_approves_safe_action(tmp_path):
    import os
    from pathlib import Path
    from tools.postdeploy.expressions import compile_guard
    from tools.postdeploy.obligations import build_and_verify_paired_goto_slice, verify_vm_bytecode_equivalence

    cbmc = os.environ.get('VULGATE_CBMC')
    if not cbmc:
        pytest.skip('set VULGATE_CBMC')
    cbmc_bin = Path(cbmc)

    app_c = tmp_path / 'record_service.c'
    app_c.write_text('''
#include <stdint.h>
#include <stddef.h>

typedef struct Record {
    uint64_t length;
    uint64_t tag;
} Record;

static Record global_pool[2];

void release_record(Record *r) {
    if (r != NULL) {
        r->tag = 0;
    }
}

int decode_record(uint64_t raw_len, Record *dst) {
    if (raw_len > 64) {
        __CPROVER_assert(0, "vg.target.oob_sink");
    }
    dst->length = raw_len;
    dst->tag = 1;
    return 0;
}

int parse_record(uint64_t raw_len, Record **out) {
    *out = NULL;
    if (raw_len == 0) {
        return -1;
    }
    Record *rec = &global_pool[0];
    int rc = decode_record(raw_len, rec);
    if (rc != 0) {
        return rc;
    }
    *out = rec;
    return 0;
}

int handle_request(uint64_t raw_len, uint64_t *obs_tag) {
    Record *record;
    int rc = parse_record(raw_len, &record);
    if (rc < 0) {
        release_record(record);
        *obs_tag = 999;
        return rc;
    }
    *obs_tag = record->length;
    release_record(record);
    return 0;
}
''', encoding='utf-8')

    driver_c = tmp_path / 'driver.c'
    driver_c.write_text('''
#include <stdint.h>
extern _Bool __vulgate_any_blocked;
extern _Bool __vulgate_action_write_ok;
extern uint64_t __vulgate_nondet_u64(void);

int handle_request(uint64_t raw_len, uint64_t *obs_tag);

int __vg_run_world_0(uint64_t len, uint64_t *tag_out) {
    return handle_request(len, tag_out);
}

int __vg_run_world_1(uint64_t len, uint64_t *tag_out) {
    return handle_request(len, tag_out);
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_raw_len = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_raw_len <= 128ULL);
    uint64_t tag1 = 0;
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_raw_len, &tag1);
    (void)rc1;
    __CPROVER_assert(!__vulgate_any_blocked || __vulgate_action_write_ok, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(!(__vg_in_raw_len > 64ULL && !__vulgate_any_blocked), "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_raw_len = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_raw_len >= 1ULL && __vg_in_raw_len <= 64ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    uint64_t tag0 = 0, tag1 = 0;
    int rc0 = __vg_run_world_0(__vg_in_raw_len, &tag0);
    __vulgate_any_blocked = 0;
    int rc1 = __vg_run_world_1(__vg_in_raw_len, &tag1);
    _Bool __vg_obs_diff = (rc0 != rc1) || (tag0 != tag1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
''', encoding='utf-8')

    fields = {'raw_len': {'source': 'arg', 'index': 0}}
    rule_bin = tmp_path / 'parse_guard.bin'
    rule_bin.write_bytes(compile_guard('raw_len > 32', fields))

    def make_case_ir(with_null_init_write: bool):
        action = {'kind': 'return_int', 'value': -22}
        if with_null_init_write:
            action['writes'] = [{'arg': 1, 'offset': 0, 'type': 'pointer', 'value': 0}]
        return {
            'case_id': 'SYNTH-PARSE-RECORD',
            'app_profile': {
                'name': 'record-service',
                'operation_roots': ['handle_request'],
                'symbolic_slice': {
                    'slice_sources': [str(app_c)],
                    'slice_driver_c': str(driver_c),
                },
            },
            'maps': {},
            'observer_specs': [],
            'guards': [{
                'id': 'g_parse',
                'function': 'parse_record',
                'arg_types': ['uint64', 'pointer'],
                'return_type': 'int',
                'parameter_names': ['raw_len', 'out'],
                'selectors': {'raw_len': {'arg': 0, 'type': 'uint64'}},
                'resolved_vm_args': [{'arg': 0, 'type': 'uint64'}],
                'fields': fields,
                'map_reads': [],
                'policy_source': 'raw_len > 32',
                'extracted_predicates': ['raw_len > 32'],
                'rule_path': str(rule_bin),
                'resolved_action': action,
                'step_limit': 256,
            }],
            'defect_anchors': {
                'sink_site': {'function': 'decode_record', 'role': 'memory_write'},
            },
            'symbolization_scope': {
                'enable_uninitialized_shadow': True,
                'symbolic_inputs': [{'name': 'raw_len'}],
                'field_to_input_map': {'raw_len': 'raw_len'},
            },
            'budgets': {
                'loop_unwind': 16,
                'max_impact_regions': 4,
                'solver_timeout_sec': 90,
            },
        }

    bad_ir = make_case_ir(False)
    vmp = verify_vm_bytecode_equivalence(bad_ir['guards'][0], cbmc_bin, tmp_path / 'vm_eq')
    assert vmp['status'] == 'PROVED'

    bad_res = build_and_verify_paired_goto_slice(bad_ir, {'g_parse': vmp}, cbmc_bin, tmp_path / 'unsafe_action')
    assert bad_res['boundary_plan']['selected_cut_functions'] == ['handle_request']
    assert bad_res['action_and_caller_continuation']['status'] == 'VIOLATED', bad_res

    good_ir = make_case_ir(True)
    good_res = build_and_verify_paired_goto_slice(good_ir, {'g_parse': vmp}, cbmc_bin, tmp_path / 'safe_action')
    assert good_res['action_and_caller_continuation']['status'] == 'PROVED_IN_BOUNDED_DOMAIN', good_res
    assert good_res['target_vulnerability_elimination']['status'] == 'PROVED_IN_BOUNDED_DOMAIN', good_res
    reg_classes = {r['classification'] for r in good_res['impact_regions']['regions']}
    assert reg_classes == {'UNCHANGED', 'CHANGED_BY_BLOCK'}, good_res['impact_regions']


def test_outside_caller_gets_its_own_continuation_query(tmp_path):
    import os
    from pathlib import Path
    from tools.postdeploy.evaluate import verification_task_rows
    from tools.postdeploy.expressions import compile_guard
    from tools.postdeploy.obligations import build_and_verify_paired_goto_slice, verify_vm_bytecode_equivalence

    cbmc = os.environ.get('VULGATE_CBMC')
    if not cbmc:
        pytest.skip('set VULGATE_CBMC')
    cbmc_bin = Path(cbmc)
    app_c = tmp_path / 'record_service.c'
    app_c.write_text('''
#include <stdint.h>
#include <stddef.h>

typedef struct Record {
    uint64_t length;
    uint64_t tag;
} Record;

static Record global_pool[2];

void clear_tag(Record *r) {
    if (r != NULL) {
        r->tag = 0;
    }
}

int decode_record(uint64_t raw_len, Record *dst) {
    if (raw_len > 64) {
        __CPROVER_assert(0, "vg.target.oob_sink");
    }
    dst->length = raw_len;
    dst->tag = 1;
    return 0;
}

int parse_record(uint64_t raw_len, Record **out) {
    *out = NULL;
    if (raw_len == 0) {
        return -1;
    }
    Record *rec = &global_pool[0];
    int rc = decode_record(raw_len, rec);
    if (rc != 0) {
        return rc;
    }
    *out = rec;
    return 0;
}

int inside(uint64_t raw_len, uint64_t *obs_tag) {
    Record *record = 0;
    int rc = parse_record(raw_len, &record);
    if (rc < 0) {
        *obs_tag = 999;
        return rc;
    }
    *obs_tag = record->length;
    clear_tag(record);
    return 0;
}

int outside(uint64_t raw_len, uint64_t *obs_tag) {
    Record *record;
    int rc = parse_record(raw_len, &record);
    if (rc < 0) {
        clear_tag(record);
        *obs_tag = 999;
        return rc;
    }
    *obs_tag = record->length;
    clear_tag(record);
    return 0;
}
''', encoding='utf-8')
    driver_c = tmp_path / 'driver.c'
    driver_c.write_text('''
#include <stdint.h>
extern _Bool __vulgate_any_blocked;
extern _Bool __vulgate_action_write_ok;
extern uint64_t __vulgate_nondet_u64(void);

int inside(uint64_t raw_len, uint64_t *obs_tag);

int __vg_run_world_0(uint64_t len, uint64_t *tag_out) {
    return inside(len, tag_out);
}

int __vg_run_world_1(uint64_t len, uint64_t *tag_out) {
    return inside(len, tag_out);
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_raw_len = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_raw_len <= 128ULL);
    uint64_t tag1 = 0;
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_raw_len, &tag1);
    (void)rc1;
    __CPROVER_assert(!__vulgate_any_blocked || __vulgate_action_write_ok, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(!(__vg_in_raw_len > 64ULL && !__vulgate_any_blocked), "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_raw_len = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_raw_len >= 1ULL && __vg_in_raw_len <= 64ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    uint64_t tag0 = 0, tag1 = 0;
    int rc0 = __vg_run_world_0(__vg_in_raw_len, &tag0);
    __vulgate_any_blocked = 0;
    int rc1 = __vg_run_world_1(__vg_in_raw_len, &tag1);
    _Bool __vg_obs_diff = (rc0 != rc1) || (tag0 != tag1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
''', encoding='utf-8')
    fields = {'raw_len': {'source': 'arg', 'index': 0}}
    rule_bin = tmp_path / 'parse_guard.bin'
    rule_bin.write_bytes(compile_guard('raw_len > 32', fields))

    def make_case(with_null_init_write: bool):
        action = {'kind': 'return_int', 'value': -22}
        if with_null_init_write:
            action['writes'] = [{'arg': 1, 'offset': 0, 'type': 'pointer', 'value': 0}]
        return {
            'case_id': 'SYNTH-OUTSIDE-CALLER',
            'app_profile': {
                'name': 'record-service',
                'family': 'record',
                'operation_roots': ['inside'],
                'symbolic_slice': {
                    'slice_sources': [str(app_c)],
                    'slice_driver_c': str(driver_c),
                },
            },
            'maps': {},
            'observer_specs': [],
            'guards': [{
                'id': 'g_parse',
                'function': 'parse_record',
                'arg_types': ['uint64', 'pointer'],
                'return_type': 'int',
                'parameter_names': ['raw_len', 'out'],
                'selectors': {'raw_len': {'arg': 0, 'type': 'uint64'}},
                'resolved_vm_args': [{'arg': 0, 'type': 'uint64'}],
                'fields': fields,
                'map_reads': [],
                'policy_source': 'raw_len > 32',
                'extracted_predicates': ['raw_len > 32'],
                'rule_path': str(rule_bin),
                'resolved_action': action,
                'step_limit': 256,
            }],
            'defect_anchors': {
                'sink_site': {'function': 'decode_record', 'role': 'memory_write'},
            },
            'safety_oracle': {'kind': 'initialized_read_safety', 'bindings': {}},
            'symbolization_scope': {
                'enable_uninitialized_shadow': True,
                'input_bounds': {'raw_len': {'min': 0, 'max': 128}},
            },
            'dynamic_traces': [{
                'call_stacks': [['inside', 'parse_record']],
                'call_edges': [['inside', 'parse_record']],
            }],
            'budgets': {
                'loop_unwind': 8,
                'max_impact_regions': 4,
                'solver_timeout_sec': 120,
            },
        }

    bad_ir = make_case(False)
    vmp = verify_vm_bytecode_equivalence(bad_ir['guards'][0], cbmc_bin, tmp_path / 'vm_eq')
    assert vmp['status'] == 'PROVED'
    bad_res = build_and_verify_paired_goto_slice(bad_ir, {'g_parse': vmp}, cbmc_bin, tmp_path / 'unsafe_outside')
    assert bad_res['boundary_plan']['selected_cut_functions'] == ['inside'], bad_res['boundary_plan']
    bad_rows = verification_task_rows(bad_res)
    outside = next(row for row in bad_rows if row['cut_function'] == 'outside')
    assert outside['role'] == 'caller_local'
    assert outside['proof_entry'] == 'local_query', bad_res.get('local_caller_obligations')
    bad_local = bad_res['local_caller_obligations'][0]
    assert bad_local['status'] == 'VIOLATED', bad_local.get('failures')
    good_res = build_and_verify_paired_goto_slice(make_case(True), {'g_parse': vmp}, cbmc_bin, tmp_path / 'safe_outside')
    good_local = good_res['local_caller_obligations'][0]
    assert good_local['status'] == 'PROVED_IN_BOUNDED_DOMAIN', good_local.get('failures')
    good_outside = next(row for row in verification_task_rows(good_res) if row['cut_function'] == 'outside')
    assert good_outside['proof_entry'] == 'local_query'
