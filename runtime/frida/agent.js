'use strict';

// Explicit observations and catalog-bound returns; decisions remain in the VM.
// The policy is interpreted by runtime/vm.c, never by JavaScript predicates.
let installed = null;
const types = new Set(['int', 'uint', 'int64', 'uint64', 'pointer', 'float', 'double']);

function requireThat(condition, message) {
    if (!condition) throw new Error(message);
}

function index(value, length, label) {
    requireThat(Number.isInteger(value) && value >= 0 && value < length, label);
}

function address(spec) {
    requireThat(typeof spec.module === 'string', 'module is required');
    const module = Process.getModuleByName(spec.module);
    if (spec.offset !== undefined) {
        requireThat(Number.isSafeInteger(spec.offset) && spec.offset >= 0 && spec.offset < module.size,
            'invalid module offset');
        const location = module.base.add(spec.offset);
        const range = Process.findRangeByAddress(location);
        requireThat(range !== null && range.protection.includes('x'), 'hook must be executable');
        return location;
    }
    requireThat(typeof spec.symbol === 'string', 'exported symbol or offset is required');
    return module.getExportByName(spec.symbol);
}

// Typed, read-only selectors are trusted build bindings, separate from bytecode.
function select(source, args, context, raw = false) {
    if ('constant' in source) return uint64(source.constant.toString());
    let value;
    if ('arg' in source) value = bits(args[source.arg], source.type || 'pointer', raw);
    else if ('global' in source) {
        const module = Process.getModuleByName(source.global.module);
        requireThat(Number.isSafeInteger(source.global.offset) && source.global.offset >= 0 &&
            source.global.offset < module.size, 'invalid global selector');
        value = uint64(module.base.add(source.global.offset).toString());
    }
    else if ('register' in source) {
        requireThat(source.register in context, 'unknown context register');
        value = uint64(context[source.register].toString());
    } else throw new Error('selector needs constant, arg or register');
    for (const read of source.reads || []) {
        let offset = read.offset || 0;
        if (read.index) {
            const i = select(read.index, args, context, raw).toNumber();
            requireThat(Number.isSafeInteger(i) && i >= 0 && i < (read.index_limit || 4096),
                'selector index outside binding extent');
            offset += i * (read.stride || 8);
        }
        const p = ptr(value.toString()).add(offset);
        switch (read.type) {
        case 'u64': case 'pointer': value = p.readU64(); break;
        case 's64': value = uint64(p.readS64().toString()); break;
        case 'u32': value = uint64(p.readU32()); break;
        case 's32': value = uint64(p.readS32().toString()); break;
        case 'u16': value = uint64(p.readU16()); break;
        case 's16': value = uint64(p.readS16().toString()); break;
        case 'u8': value = uint64(p.readU8()); break;
        case 's8': value = uint64(p.readS8().toString()); break;
        default: throw new Error('unsupported selector read type');
        }
    }
    return value;
}

function signature(spec) {
    requireThat(Array.isArray(spec.arg_types) && spec.arg_types.length <= 6 &&
        spec.arg_types.every(t => types.has(t)), 'unsupported argument ABI');
}

function bits(value, type, raw = false) {
    if (raw && type === 'int') return uint64(value.toInt32().toString());
    if (raw && type === 'uint') return uint64(value.toUInt32().toString());
    if (type === 'float') {
        const single = new Float32Array(1);
        single[0] = Number(value);
        return uint64(new Uint32Array(single.buffer)[0].toString());
    }
    if (type === 'double') {
        const wide = new Float64Array(1);
        wide[0] = Number(value);
        return uint64(new BigUint64Array(wide.buffer)[0].toString());
    }
    return uint64(value.toString());
}

// Only the trusted action catalog supplies these values and field destinations.
function catalogAction(action, spec) {
    requireThat(action && typeof action === 'object', 'missing catalog action');
    let value;
    if (action.kind === 'return_int') {
        requireThat(['int', 'int64'].includes(spec.return_type) && Number.isSafeInteger(action.value) &&
            (spec.return_type === 'int64' || (action.value >= -2147483648 && action.value <= 2147483647)),
            'catalog integer return ABI mismatch');
        value = spec.return_type === 'int64' ? int64(action.value) : action.value;
    } else if (action.kind === 'return_void') {
        requireThat(spec.return_type === 'void', 'catalog void return ABI mismatch');
    } else if (action.kind === 'return_null') {
        requireThat(spec.return_type === 'pointer', 'catalog pointer return ABI mismatch');
        value = ptr(0);
    } else if (action.kind === 'return_string') {
        requireThat(spec.return_type === 'pointer' && typeof action.value === 'string' &&
            action.value.length <= 4096, 'invalid catalog string return');
        value = Memory.allocUtf8String(action.value); // Allocated once at installation.
    } else if (action.kind === 'return_float') {
        requireThat(spec.return_type === 'float' && typeof action.value === 'number' &&
            Number.isFinite(action.value), 'catalog float return ABI mismatch');
        value = Math.fround(action.value);
    } else if (action.kind === 'return_double') {
        requireThat(spec.return_type === 'double' && typeof action.value === 'number' &&
            Number.isFinite(action.value), 'catalog double return ABI mismatch');
        value = Number(action.value);
    } else throw new Error('unsupported catalog action');
    requireThat(action.errno === undefined || Number.isSafeInteger(action.errno),
        'catalog errno must be an integer');
    const writes = (action.writes || []).map(write => {
        index(write.arg, spec.arg_types.length, 'invalid action pointer argument');
        requireThat(spec.arg_types[write.arg] === 'pointer' && Number.isSafeInteger(write.offset) &&
            write.offset >= 0 && ['u32', 'u64', 'pointer'].includes(write.type), 'invalid catalog field write');
        let fixed = write.value;
        if (write.symbol) {
            const module = Process.getModuleByName(write.symbol.module);
            requireThat(Number.isSafeInteger(write.symbol.offset) && write.symbol.offset >= 0 &&
                write.symbol.offset < module.size, 'invalid catalog symbol offset');
            fixed = module.base.add(write.symbol.offset);
            const range = Process.findRangeByAddress(fixed);
            requireThat(range && range.protection.includes('r'), 'catalog symbol must be readable');
        }
        requireThat(write.symbol ? write.type === 'pointer' : Number.isSafeInteger(fixed), 'invalid fixed field value');
        return {arg: write.arg, offset: write.offset, type: write.type, value: fixed};
    });
    const apply = function (args) {
        for (const write of writes) {
            const destination = args[write.arg].add(write.offset);
            if (write.type === 'pointer') destination.writePointer(ptr(write.value));
            else if (write.type === 'u64') destination.writeU64(uint64(write.value));
            else destination.writeU32(write.value);
        }
        return value;
    };
    if (action.errno !== undefined) apply.errno = action.errno;
    return apply;
}

function remove(state) {
    requireThat(state.active === 0, 'callbacks active: quiesce target before uninstall');
    for (const hook of state.hooks.reverse()) {
        if (hook.listener) hook.listener.detach();
        else Interceptor.revert(hook.address);
    }
    Interceptor.flush();
    for (const handle of state.handles) state.destroy(handle);
    for (const map of state.maps.values()) state.mapDestroy(map.handle);
    state.hooks = [];
    state.handles = [];
}

function probeAction(action, spec, add) {
    if (!action) {
        add('E_ACTION_MISSING', 'action_id ' + spec.action_id + ' is not in the catalog', spec.id);
        return;
    }
    const ret = spec.return_type;
    if (action.kind === 'return_int') {
        if (!['int', 'int64'].includes(ret) || !Number.isSafeInteger(action.value)) {
            add('E_ACTION_ABI_MISMATCH', 'return_int requires int/int64 and an integer value', spec.id);
        } else if (ret === 'int' && (action.value < -2147483648 || action.value > 2147483647)) {
            add('E_ACTION_ABI_MISMATCH', 'return_int value does not fit int', spec.id);
        }
    } else if (action.kind === 'return_void') {
        if (ret !== 'void') add('E_ACTION_ABI_MISMATCH', 'return_void requires a void function', spec.id);
    } else if (action.kind === 'return_null') {
        if (ret !== 'pointer') add('E_ACTION_ABI_MISMATCH', 'return_null requires a pointer return', spec.id);
    } else if (action.kind === 'return_string') {
        if (ret !== 'pointer' || typeof action.value !== 'string' || action.value.length > 4096)
            add('E_ACTION_ABI_MISMATCH', 'return_string requires a pointer return and a short string', spec.id);
    } else if (action.kind === 'return_float') {
        if (ret !== 'float' || typeof action.value !== 'number' || !Number.isFinite(action.value))
            add('E_ACTION_ABI_MISMATCH', 'return_float requires a float return and a number', spec.id);
    } else if (action.kind === 'return_double') {
        if (ret !== 'double' || typeof action.value !== 'number' || !Number.isFinite(action.value))
            add('E_ACTION_ABI_MISMATCH', 'return_double requires a double return and a number', spec.id);
    } else {
        add('E_ACTION_ABI_MISMATCH', 'unsupported action kind', spec.id);
    }
    if (action.errno !== undefined && !Number.isSafeInteger(action.errno))
        add('E_ACTION_ABI_MISMATCH', 'action errno must be an integer', spec.id);
    for (const write of action.writes || []) {
        const valid = Number.isInteger(write.arg) && write.arg >= 0 &&
            write.arg < (spec.arg_types || []).length &&
            spec.arg_types[write.arg] === 'pointer' &&
            Number.isSafeInteger(write.offset) && write.offset >= 0 &&
            ['u32', 'u64', 'pointer'].includes(write.type);
        if (!valid) add('E_ACTION_WRITE_INVALID', 'invalid action field write', spec.id);
    }
}

// Resolve and validate a bundle without attaching any hook. Returns a per-hook
// error list with stable codes; install() still performs its own checks.
function probeBundle(config, catalog) {
    const errors = [];
    const add = (code, message, hook) => errors.push({code, message: String(message), hook: hook === undefined ? null : hook});
    const guards = [];
    const observers = [];
    if (installed !== null) {
        add('E_ALREADY_INSTALLED', 'a bundle is already installed in this process');
        return {ok: false, errors, guards, observers};
    }
    if (Process.arch !== 'x64') add('E_ARCH_UNSUPPORTED', 'only x64 targets are supported');
    if (!config || config.schema !== 1 || !catalog || catalog.schema !== 1) {
        add('E_SCHEMA_INVALID', 'unsupported bundle schema');
        return {ok: false, errors, guards, observers};
    }
    const maps = new Map();
    for (const [name, definition] of Object.entries(config.maps || {})) {
        if (!definition || !Number.isInteger(definition.capacity) || definition.capacity <= 0 ||
            definition.capacity > 65536) {
            add('E_MAP_INVALID', 'invalid capacity for map ' + name, name);
        }
        maps.set(name, definition || {});
    }
    const ids = new Set();
    const addresses = new Map();
    const resolve = (spec, kind) => {
        if (typeof spec.module !== 'string' || !spec.module) {
            add('E_MODULE_MISSING', 'module is required', spec.id);
            return null;
        }
        let module;
        try {
            module = Process.getModuleByName(spec.module);
        } catch (error) {
            add('E_MODULE_MISSING', 'module ' + spec.module + ' is not loaded', spec.id);
            return null;
        }
        if (spec.offset !== undefined) {
            if (!Number.isSafeInteger(spec.offset) || spec.offset < 0 || spec.offset >= module.size) {
                add('E_OFFSET_INVALID', 'offset is outside the module', spec.id);
                return null;
            }
            const target = module.base.add(spec.offset);
            const range = Process.findRangeByAddress(target);
            if (range === null || !range.protection.includes('x')) {
                add('E_OFFSET_INVALID', 'offset does not point at executable memory', spec.id);
                return null;
            }
            return {module: spec.module, target};
        }
        if (typeof spec.symbol === 'string') {
            try {
                return {module: spec.module, target: module.getExportByName(spec.symbol)};
            } catch (error) {
                add('E_SYMBOL_MISSING', 'exported symbol ' + spec.symbol + ' is missing', spec.id);
                return null;
            }
        }
        add('E_MODULE_MISSING', 'module + symbol or offset is required', spec.id);
        return null;
    };
    const noteAddress = (spec, resolved, out) => {
        if (resolved === null) return;
        const key = resolved.target.toString();
        if (addresses.has(key)) {
            add('E_DUPLICATE_HOOK', 'hook address already bound by ' + addresses.get(key), spec.id);
            return;
        }
        addresses.set(key, spec.id);
        out.push({id: spec.id, module: resolved.module, address: key, kind: spec.kind || 'guard'});
    };
    for (const spec of config.observers || []) {
        if (!spec || typeof spec.id !== 'string' || !spec.id) {
            add('E_HOOK_INVALID', 'observer without id', spec && spec.id);
            continue;
        }
        if (ids.has(spec.id)) {
            add('E_HOOK_INVALID', 'duplicate hook id', spec.id);
            continue;
        }
        ids.add(spec.id);
        if (spec.varargs) {
            add('E_ARITY_UNSUPPORTED', 'variadic functions are not supported', spec.id);
            continue;
        }
        try {
            signature(spec);
        } catch (error) {
            add('E_ARITY_UNSUPPORTED', error.message, spec.id);
            continue;
        }
        if (spec.operation !== 'set' && spec.operation !== 'delete') {
            add('E_OBSERVER_INVALID', 'operation must be set or delete', spec.id);
        }
        if (!maps.has(spec.map)) add('E_MAP_MISSING', 'unknown observation map ' + String(spec.map), spec.id);
        const resolved = resolve(spec, 'observer');
        if (resolved !== null) {
            spec.kind = 'observer';
            noteAddress(spec, resolved, observers);
        }
    }
    for (const spec of config.guards || []) {
        if (!spec || typeof spec.id !== 'string' || !spec.id) {
            add('E_HOOK_INVALID', 'guard without id', spec && spec.id);
            continue;
        }
        if (ids.has(spec.id)) {
            add('E_HOOK_INVALID', 'duplicate hook id', spec.id);
            continue;
        }
        ids.add(spec.id);
        if (spec.varargs) {
            add('E_ARITY_UNSUPPORTED', 'variadic functions are not supported', spec.id);
            continue;
        }
        try {
            signature(spec);
        } catch (error) {
            add('E_ARITY_UNSUPPORTED', error.message, spec.id);
            continue;
        }
        const isShim = spec.shim !== undefined;
        if (isShim) {
            if (!spec.shim || typeof spec.shim.path !== 'string' || typeof spec.shim.entry !== 'string') {
                add('E_SHIM_INVALID', 'invalid shim spec', spec.id);
            }
            if ((spec.observations || []).length) {
                add('E_SHIM_UNSUPPORTED', 'shim guards do not support observations', spec.id);
            }
        } else {
            if (!['int', 'int64', 'pointer', 'void', 'float', 'double'].includes(spec.return_type)) {
                add('E_RETURN_UNSUPPORTED', 'unsupported return ABI ' + String(spec.return_type), spec.id);
            }
            probeAction((catalog.actions || {})[spec.action_id], spec, add);
        }
        const code = spec.code;
        if (!Array.isArray(code) || code.length === 0 || code.length > 32768 || code.length % 8 !== 0 ||
            !code.every(x => Number.isInteger(x) && x >= 0 && x <= 255)) {
            add('E_RULE_INVALID', 'invalid bytecode buffer', spec.id);
        }
        const limit = spec.step_limit === undefined ? 4096 : spec.step_limit;
        if (!Number.isInteger(limit) || limit <= 0 || limit > 1000000) {
            add('E_RULE_INVALID', 'invalid step limit', spec.id);
        }
        for (const ref of spec.observations || []) {
            if (!maps.has(ref.map)) add('E_MAP_MISSING', 'unknown guard observation map ' + String(ref.map), spec.id);
            if (ref.key_arg !== undefined && !(Number.isInteger(ref.key_arg) && ref.key_arg >= 0 &&
                ref.key_arg < (spec.arg_types || []).length)) {
                add('E_OBSERVER_INVALID', 'invalid guard key argument', spec.id);
            }
            if (ref.slot !== undefined && !(Number.isInteger(ref.slot) && ref.slot >= 0 && ref.slot < 16)) {
                add('E_OBSERVER_INVALID', 'invalid guard observation slot', spec.id);
            }
        }
        const resolved = resolve(spec, 'guard');
        if (resolved !== null) {
            spec.kind = 'guard';
            noteAddress(spec, resolved, guards);
        }
    }
    return {ok: errors.length === 0, errors, guards, observers};
}

rpc.exports = {
    probe(config, catalog) {
        try {
            return probeBundle(config, catalog);
        } catch (error) {
            return {ok: false,
                errors: [{code: 'E_PROBE_INTERNAL', message: String(error), hook: null}],
                guards: [], observers: []};
        }
    },
    install(config, catalog) {
        requireThat(installed === null, 'hooks already installed');
        requireThat(Process.arch === 'x64', 'version 1 requires an x64 process');
        requireThat(config.schema === 1 && catalog.schema === 1, 'unsupported schema');
        requireThat(Array.isArray(config.guards) && config.guards.length > 0 &&
            Array.isArray(config.observers), 'guards and observers are required');
        const library = Module.load(config.bridge);
        const native = (name, ret, args) => new NativeFunction(
            library.getExportByName(name), ret, args, {scheduling: 'exclusive'});
        requireThat(native('vg_abi_version', 'uint', [])() === 1, 'bridge ABI mismatch');
        const create = native('vg_program_create', 'pointer', ['pointer', 'uint']);
        const run = native('vg_run', 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer']);
        const lastReadCount = native('vg_last_read_count', 'uint', []);
        const copyLastReads = native('vg_copy_last_reads', 'uint', ['pointer', 'uint']);
        const state = {hooks: [], handles: [], callbacks: [], active: 0, maps: new Map(),
            argStacks: new Map(),
            destroy: native('vg_program_destroy', 'void', ['pointer']), calls: 0};
        const mapCreate = native('vg_map_create', 'pointer', ['uint']);
        const mapSet = native('vg_map_set', 'int', ['pointer', 'uint64', 'uint64', 'uint64']);
        const mapGet = native('vg_map_get', 'int', ['pointer', 'uint64', 'uint64', 'pointer', 'int']);
        let mapGetWords = null;
        let mapSetWords = null;
        let mapDeleteWords = null;
        const mapDelete = native('vg_map_delete', 'void', ['pointer', 'uint64', 'uint64']);
        state.mapSize = native('vg_map_size', 'uint', ['pointer']);
        state.mapDestroy = native('vg_map_destroy', 'void', ['pointer']);
        try {
            for (const [name, definition] of Object.entries(config.maps || {})) {
                requireThat(Number.isInteger(definition.capacity) && definition.capacity > 0 &&
                    definition.capacity <= 65536, 'invalid observation map capacity');
                const handle = mapCreate(definition.capacity);
                requireThat(!handle.isNull(), 'cannot allocate observation map');
                state.maps.set(name, {
                    handle,
                    threadScoped: definition.thread_scoped === true || definition.scope === 'thread',
                    invalidScopes: new Set(),
                    fullScopes: new Set(),
                    onFull: definition.on_full === 'block' ? 'block' : 'drop',
                });
            }
            const used = new Set();
            const ids = new Set();
            const common = spec => {
                requireThat(typeof spec.id === 'string' && !ids.has(spec.id), 'duplicate/missing hook id');
                ids.add(spec.id);
                signature(spec);
                const target = address(spec);
                requireThat(!used.has(target.toString()), 'duplicate hook address');
                used.add(target.toString());
                return target;
            };
            // Resolve and validate the whole bundle before attaching any hooks.
            const observers = config.observers.map(spec => {
                const target = common(spec);
                requireThat(state.maps.has(spec.map), 'unknown observation map');
                requireThat(spec.operation === 'set' || spec.operation === 'delete', 'invalid observation operation');
                if (spec.key_components)
                    requireThat(Array.isArray(spec.key_components) && spec.key_components.length >= 1 &&
                        spec.key_components.length <= 4, 'invalid observation key words');
                else if (!spec.key) index(spec.key_arg, spec.arg_types.length, 'invalid observation key argument');
                if (spec.operation === 'set' && spec.value_words)
                    requireThat(Array.isArray(spec.value_words) && spec.value_words.length >= 1 &&
                        spec.value_words.length <= 4, 'invalid observation value words');
                else if (spec.operation === 'set' && !spec.value)
                    index(spec.value_arg, spec.arg_types.length, 'invalid observation value argument');
                return {spec, target};
            });
            const guards = config.guards.map(spec => {
                const target = common(spec);
                const isShim = spec.shim !== undefined;
                let action = null;
                if (isShim) {
                    requireThat(spec.shim && typeof spec.shim.path === 'string' &&
                        typeof spec.shim.entry === 'string', 'invalid shim spec');
                    requireThat(!(spec.observations || []).length,
                        'shim guards do not support observations');
                } else {
                    requireThat(['int', 'int64', 'pointer', 'void', 'float', 'double']
                        .includes(spec.return_type), 'unsupported return ABI');
                    action = catalogAction(catalog.actions[spec.action_id], spec);
                }
                requireThat(!('block_return' in spec) && !('action' in spec), 'guard must reference catalog action_id');
                requireThat(!spec.varargs, 'variadic functions are not supported');
                const slots = new Set();
                for (const ref of spec.observations || []) {
                    requireThat(state.maps.has(ref.map), 'unknown guard observation map');
                    if (!ref.key) index(ref.key_arg, spec.arg_types.length, 'invalid guard key argument');
                    index(ref.slot, 16, 'invalid observation slot');
                    requireThat(!slots.has(ref.slot), 'duplicate observation slot');
                    slots.add(ref.slot);
                    if (ref.present_slot !== undefined) {
                        index(ref.present_slot, 16, 'invalid presence slot');
                        requireThat(!slots.has(ref.present_slot), 'duplicate presence slot');
                        slots.add(ref.present_slot);
                    }
                }
                const limit = spec.step_limit === undefined ? 4096 : spec.step_limit;
                requireThat(Number.isInteger(limit) && limit > 0 && limit <= 1000000, 'invalid step limit');
                requireThat(Array.isArray(spec.code) && spec.code.length > 0 && spec.code.length <= 32768 &&
                    spec.code.every(x => Number.isInteger(x) && x >= 0 && x <= 255), 'invalid bytecode buffer');
                const bytes = Memory.alloc(spec.code.length);
                bytes.writeByteArray(spec.code);
                const handle = create(bytes, spec.code.length);
                requireThat(!handle.isNull(), 'VM rejected bytecode for ' + spec.id);
                state.handles.push(handle);
                let original = null;
                if (!isShim) {
                    original = new SystemFunction(target, spec.return_type, spec.arg_types);
                    if (spec.vm_args) requireThat(spec.vm_args.length <= 6, 'too many VM argument bindings');
                }
                const returnFilter = spec.return_offsets && new Set(spec.return_offsets.map(offset => {
                    requireThat(Number.isSafeInteger(offset) && offset >= 0, 'invalid return offset');
                    return Process.getModuleByName(spec.module).base.add(offset).toString();
                }));
                return {spec, target, action, handle, original, limit, returnFilter, isShim};
            });
            const recordObservation = (spec, args, context, threadId) => {
                        const map = state.maps.get(spec.map);
                        const scope = uint64(map.threadScoped ? threadId : 0);
                        let key = null;
                        let keyBuf = null;
                        let keyWordCount = 0;
                        const wordOf = (comp) => {
                            if (comp && comp.scope) return scope;
                            if (comp && comp.constant !== undefined) return uint64(String(comp.constant));
                            if (comp && comp.arg !== undefined)
                                return bits(args[comp.arg], spec.arg_types[comp.arg], true);
                            if (comp && (comp.register || comp.global || comp.reads))
                                return select(comp, args, context, true);
                            throw new Error('observation word unbound');
                        };
                        try {
                        const multi = (spec.key_components && spec.key_components.length > 1) ||
                            (spec.value_words && spec.value_words.length > 1);
                        if (multi) {
                            const components = spec.key_components;
                            keyBuf = Memory.alloc(components.length * 8);
                            keyWordCount = components.length;
                            components.forEach((comp, index) => {
                                keyBuf.add(index * 8).writeU64(wordOf(comp));
                            });
                            key = keyBuf.readU64();
                            if (spec.operation === 'delete') {
                                if (mapDeleteWords === null)
                                    mapDeleteWords = native('vg_map_delete_words', 'void',
                                        ['pointer', 'uint64', 'pointer', 'uint']);
                                mapDeleteWords(map.handle, scope, keyBuf, components.length);
                                map.fullScopes.delete(scope.toString());
                                if (config.telemetry) send({event: 'observation', hook: spec.id, map: spec.map,
                                    operation: 'delete', key: key.toString(), scope: scope.toString()});
                            } else {
                                const words = spec.value_words || [];
                                const out = Memory.alloc(Math.max(words.length, 1) * 8);
                                words.forEach((comp, index) => {
                                    out.add(index * 8).writeU64(wordOf(comp));
                                });
                                if (mapSetWords === null)
                                    mapSetWords = native('vg_map_set_words', 'int',
                                        ['pointer', 'uint64', 'pointer', 'uint', 'pointer', 'uint']);
                                const setResult = mapSetWords(map.handle, scope, keyBuf, components.length,
                                    out, words.length);
                                if (setResult !== 0 && map.onFull === 'block')
                                    map.fullScopes.add(scope.toString());
                                else if (setResult !== 0)
                                    send({event: 'diagnostic', hook: spec.id, reason: 'observation_map_full'});
                                if (config.telemetry)
                                    send({event: 'observation', hook: spec.id, map: spec.map, operation: 'set',
                                        key: key.toString(), scope: scope.toString(),
                                        value: words.length ? out.readU64().toString() : '0', result: setResult});
                            }
                        } else {
                        key = spec.key ? select(spec.key, args, context, true) :
                            bits(args[spec.key_arg], spec.arg_types[spec.key_arg], true);
                        if (spec.operation === 'delete') {
                            mapDelete(map.handle, scope, key);
                            map.fullScopes.delete(scope.toString());
                            if (config.telemetry) send({event: 'observation', hook: spec.id, map: spec.map,
                                operation: 'delete', key: key.toString(), scope: scope.toString()});
                        } else {
                            const value = spec.value ? select(spec.value, args, context, true) :
                                bits(args[spec.value_arg], spec.arg_types[spec.value_arg], true);
                            const setResult = mapSet(map.handle, scope, key, value);
                            if (setResult !== 0 && map.onFull === 'block')
                                map.fullScopes.add(scope.toString());
                            else if (setResult !== 0)
                                send({event: 'diagnostic', hook: spec.id, reason: 'observation_map_full'});
                            if (config.telemetry)
                                send({event: 'observation', hook: spec.id, map: spec.map, operation: 'set',
                                    key: key.toString(), scope: scope.toString(), value: value.toString(), result: setResult});
                        }
                        }
                        } catch (error) {
                            if (String(error).indexOf('observation word unbound') >= 0) {
                                send({event: 'diagnostic', hook: spec.id, reason: 'observation_anchor_unbound'});
                                return;
                            }
                            // A failed observation must never reuse an older sample.
                            if (keyBuf !== null) {
                                if (mapDeleteWords === null)
                                    mapDeleteWords = native('vg_map_delete_words', 'void',
                                        ['pointer', 'uint64', 'pointer', 'uint']);
                                mapDeleteWords(map.handle, scope, keyBuf, keyWordCount);
                                map.fullScopes.delete(scope.toString());
                            } else if (key !== null) {
                                mapDelete(map.handle, scope, key);
                                map.fullScopes.delete(scope.toString());
                                if (config.telemetry) send({event: 'observation', hook: spec.id, map: spec.map,
                                    operation: 'delete', key: key.toString(), scope: scope.toString()});
                            } else map.invalidScopes.add(scope.toString());
                            send({event: 'diagnostic', hook: spec.id, reason: 'observation_read_failed:' + error});
                        }
            };
            for (const {spec, target} of observers) {
                const anchorOffsets = Array.isArray(spec.anchor_offsets) ? spec.anchor_offsets : [];
                const listener = Interceptor.attach(target, {
                    onEnter(args) {
                        if (spec.anchor === 'function_exit' || anchorOffsets.length) {
                            const saved = [];
                            for (let i = 0; i < spec.arg_types.length; i++)
                                saved.push(ptr(args[i].toString()));
                            this.savedArgs = saved;
                            this.savedThread = this.threadId;
                            if (anchorOffsets.length) {
                                const key = String(this.threadId);
                                let stack = state.argStacks.get(key);
                                if (!stack) {
                                    stack = [];
                                    state.argStacks.set(key, stack);
                                }
                                stack.push(saved);
                            }
                            return;
                        }
                        recordObservation(spec, args, this.context, this.threadId);
                    },
                    onLeave() {
                        if (spec.anchor === 'function_exit' || spec.anchor_fallback_leave)
                            recordObservation(spec, this.savedArgs, this.context, this.savedThread);
                        if (anchorOffsets.length) {
                            const stack = state.argStacks.get(String(this.savedThread));
                            if (stack) stack.pop();
                        }
                    }
                });
                state.hooks.push({listener});
                const module = Process.getModuleByName(spec.module);
                let anchored = 0;
                for (const offset of anchorOffsets) {
                    requireThat(Number.isSafeInteger(offset) && offset >= 0 && offset < module.size,
                        'invalid anchor offset');
                    const site = module.base.add(offset);
                    requireThat(!used.has(site.toString()), 'duplicate hook address');
                    try {
                        const extra = Interceptor.attach(site, {
                            onEnter() {
                                const stack = state.argStacks.get(String(this.threadId)) || [];
                                const saved = stack[stack.length - 1];
                                if (!saved) {
                                    send({event: 'diagnostic', hook: spec.id, reason: 'observation_anchor_unbound'});
                                    return;
                                }
                                recordObservation(spec, saved, this.context, this.threadId);
                            }
                        });
                        used.add(site.toString());
                        state.hooks.push({listener: extra});
                        anchored++;
                    } catch (error) {
                        void error;
                    }
                }
                if (anchorOffsets.length && anchored === 0)
                    spec.anchor_fallback_leave = true;
            }
            for (const {spec, target, action, handle, original, limit, returnFilter, isShim} of guards) {
                if (isShim) {
                    // Struct-by-value / sret signatures: the bundle ships a native
                    // shim with the exact C signature; bind it to the VM and replace.
                    const shimModule = Module.load(spec.shim.path);
                    const bind = new NativeFunction(shimModule.getExportByName('__vg_shim_bind'),
                        'void', ['pointer', 'uint', 'pointer']);
                    const setOriginal = new NativeFunction(shimModule.getExportByName('__vg_shim_set_original'),
                        'void', ['pointer']);
                    bind(handle, limit, library.getExportByName('vg_run'));
                    setOriginal(target);
                    Interceptor.replace(target, shimModule.getExportByName(spec.shim.entry));
                    state.hooks.push({address: target, shim: shimModule});
                    continue;
                }
                const callback = new NativeCallback(function (...args) {
                    state.active++;
                    try {
                        if (returnFilter && !returnFilter.has(this.returnAddress.toString())) {
                            const result = original(...args);
                            if (Process.platform === 'windows') this.lastError = result.lastError;
                            else this.errno = result.errno;
                            return result.value;
                        }
                        let rawDecision = null;
                        let reason = null;
                        let inputSnapshot = null;
                        const stats = Memory.alloc(24);
                        stats.writeByteArray(new Uint8Array(24));
                        try {
                            const argv = Memory.alloc(6 * 8);
                            const slots = Memory.alloc(16 * 8);
                            const mapReads = [];
                            let mapFull = false;
                            for (let i = 0; i < 6; i++) {
                                const value = spec.vm_args ? (i < spec.vm_args.length ?
                                    select(spec.vm_args[i], args, this.context) : 0) :
                                    (i < args.length ? bits(args[i], spec.arg_types[i]) : 0);
                                argv.add(i * 8).writeU64(value);
                            }
                            for (let i = 0; i < 16; i++) slots.add(i * 8).writeU64(0);
                            for (const ref of spec.observations || []) {
                                const key = ref.key ? select(ref.key, args, this.context) :
                                    (ref.key_arg === undefined ? uint64(0) :
                                        bits(args[ref.key_arg], spec.arg_types[ref.key_arg]));
                                const map = state.maps.get(ref.map);
                                const scopeText = String(map.threadScoped ? this.threadId : 0);
                                if (map.invalidScopes.has(scopeText))
                                    throw new Error('observation_scope_invalid:' + ref.map);
                                if (map.fullScopes.has(scopeText)) mapFull = true;
                                const scopeWord = uint64(map.threadScoped ? this.threadId : 0);
                                let found;
                                let shown = '0';
                                if ((ref.words || 1) > 1) {
                                    if (mapGetWords === null)
                                        mapGetWords = native('vg_map_get_words', 'int',
                                            ['pointer', 'uint64', 'pointer', 'uint', 'pointer', 'uint', 'int']);
                                    const components = ref.key_components || [{arg: ref.key_arg}];
                                    const keyBuf = Memory.alloc(components.length * 8);
                                    components.forEach((comp, index) => {
                                        const word = comp.scope ? scopeWord :
                                            bits(args[comp.arg === undefined ? ref.key_arg : comp.arg],
                                                spec.arg_types[comp.arg === undefined ? ref.key_arg : comp.arg]);
                                        keyBuf.add(index * 8).writeU64(word);
                                    });
                                    const outBuf = Memory.alloc(ref.words * 8);
                                    found = mapGetWords(map.handle, scopeWord, keyBuf, components.length,
                                        outBuf, ref.words, ref.consume ? 1 : 0);
                                    for (let word = 0; word < ref.words; word++) {
                                        const value = found === 1 ? outBuf.add(word * 8).readU64() : uint64(0);
                                        slots.add(ref.word_slots[word] * 8).writeU64(value);
                                    }
                                    if (ref.present_slot !== undefined)
                                        slots.add(ref.present_slot * 8).writeU64(found === 1 ? 1 : 0);
                                    shown = found === 1 ? outBuf.readU64().toString() : '0';
                                } else {
                                    found = mapGet(map.handle, scopeWord, key, slots.add(ref.slot * 8), ref.consume ? 1 : 0);
                                    shown = slots.add(ref.slot * 8).readU64().toString();
                                }
                                mapReads.push({map: ref.map, key: key.toString(),
                                    slot: ref.slot, present_slot: ref.present_slot,
                                    scope: scopeText,
                                    found: found === 1, value: shown,
                                    consume: !!ref.consume});
                                if (ref.present_slot !== undefined)
                                    slots.add(ref.present_slot * 8).writeU64(found === 1 ? 1 : 0);
                                if (!found && !mapFull && ref.on_missing !== 'pass' &&
                                    ((ref.words || 1) > 1 || ref.present_slot === undefined))
                                    throw new Error('missing_observation:' + ref.map);
                            }
                            if (config.telemetry) inputSnapshot = {
                                map_reads: mapReads,
                                args: Array.from({length: 6}, (_, i) => argv.add(i * 8).readU64().toString()),
                                slots: Array.from({length: 16}, (_, i) => slots.add(i * 8).readU64().toString())};
                            if (mapFull) {
                                rawDecision = 1;
                                reason = 'observation_map_full';
                            } else rawDecision = run(handle, argv, slots, limit, stats);
                            if (config.telemetry && inputSnapshot && stats.add(8).readU64().toNumber() > 0) {
                                const count = lastReadCount();
                                if (count > 0 && count <= 512) {
                                    const buf = Memory.alloc(count * 24);
                                    const copied = copyLastReads(buf, count);
                                    const reads = [];
                                    for (let k = 0; k < copied; k++) {
                                        const base = buf.add(k * 24);
                                        reads.push({
                                            address: base.readU64().toString(),
                                            value: base.add(8).readU64().toString(),
                                            width: base.add(16).readU32(),
                                            rc: base.add(20).readS32()
                                        });
                                    }
                                    inputSnapshot.memory_reads = reads;
                                }
                            }
                            if (rawDecision !== 0 && rawDecision !== 1) reason = 'vm_diagnostic:' + rawDecision;
                        } catch (error) {
                            reason = String(error);
                        }
                        const pass = rawDecision === 0 && reason === null;
                        state.calls++;
                        send({event: 'decision', hook: spec.id, action: pass ? 'PASS' : 'BLOCK',
                            vm_decision: rawDecision, diagnostic: reason,
                            snapshot: inputSnapshot,
                            instructions: stats.readU64().toString(),
                            safe_reads: stats.add(8).readU64().toString(),
                            helper_calls: stats.add(16).readU64().toString()});
                        if (!pass) {
                            if (action.errno !== undefined) this.errno = action.errno;
                            return action(args);
                        }
                        const result = original(...args);
                        if (Process.platform === 'windows') this.lastError = result.lastError;
                        else this.errno = result.errno;
                        return result.value;
                    } finally {
                        state.active--;
                    }
                }, spec.return_type, spec.arg_types);
                state.callbacks.push(callback); // Keep replacement trampolines alive.
                Interceptor.replace(target, callback);
                state.hooks.push({address: target});
            }
            Interceptor.flush();
            installed = state;
            const receipt = {installed: true, guards: guards.length, observers: observers.length, arch: Process.arch};
            if (config.telemetry) receipt.bindings = [...guards, ...observers].map(x =>
                ({id: x.spec.id, address: x.target.toString(), module: x.spec.module}));
            return receipt;
        } catch (error) {
            remove(state);
            throw error;
        }
    },
    status() {
        return installed === null ? {installed: false} : {installed: true,
            calls: installed.calls, active: installed.active,
            map_sizes: Object.fromEntries([...installed.maps].map(([k, v]) => [k, installed.mapSize(v.handle)]))};
    },
    barrier(token) {
        send({event: 'barrier', token});
        return true;
    },
    uninstall() {
        if (installed !== null) {
            remove(installed);
            installed = null;
        }
        return {installed: false};
    }
};
