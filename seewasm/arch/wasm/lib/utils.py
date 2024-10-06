# this is the helper function which are only used in lib folder

from z3 import BitVecVal, is_bv, is_bv_value

from seewasm.arch.wasm.configuration import Configuration
from seewasm.arch.wasm.memory import (insert_symbolic_memory,
                                      lookup_symbolic_memory_data_section)

# A dictionary defining the functions modeled for different languages. 
# 'c', 'go', 'rust', and 'wasi' represent different language environments.
MODELED_FUNCS = {
    'c':
    {'__small_printf', 'abs', 'atof', 'atoi', 'exp', 'getchar',
     'iprintf', 'printf', 'putchar', 'puts', 'scanf', 'swap',
     'system', 'emscripten_resize_heap', 'fopen', 'vfprintf',
     'open', 'exit', 'setlocale', 'hard_locale', 'strstr'},
    'go': {'fmt.Scanf', 'fmt.Printf', 'runtime.divideByZeroPanic', 'runtime.lookupPanic', 'runtime.nilPanic'
      'runtime.slicePanic', 'runtime.sliceToArrayPointerPanic', 'runtime.unsafeSlicePanic', 'runtime.chanMakePanic',
      'runtime.negativeShiftPanic', 'runtime.blockingPanic', 'runtime.calculateHeapAddresses', 'memset', 'runtime.alloc', 'memcpy',
      'syscall/js.valueGet', 'runtime.putchar'},
    'rust': {},  # Currently no modeled Rust functions
    'wasi':
    {'args_sizes_get', 'args_get', 'environ_sizes_get',
     'fd_advise', 'fd_fdstat_get', 'fd_tell', 'fd_seek',
                  'fd_close', 'fd_read', 'fd_write', 'proc_exit',
                  'fd_prestat_get', 'fd_prestat_dir_name', 'path_open'}, }


def is_modeled(func_name, specify_lang=None):
    """
    Check if the function is modeled in the MODELED_FUNCS dictionary.
    If specify_lang is given, it checks for the function in that specific language.
    Otherwise, it checks for the function in 'wasi' or in the current source type.
    """
    if specify_lang:
        return func_name in MODELED_FUNCS[specify_lang]
    else:
        # Check if the function is in 'wasi' or matches the current configuration's source type
        return func_name in MODELED_FUNCS['wasi'] or func_name in MODELED_FUNCS[Configuration.get_source_type()]


def _extract_params(param_str, state):
    """
    Extract the parameters for a given imported function.
    The parameter string indicates the number of parameters, which are then popped from the symbolic stack.
    The order of the extracted parameters will be reversed.
    If a parameter is a bit-vector value (bv_value), it's concretized (converted to a concrete integer value).
    Otherwise, the symbolic representation is kept.
    Returns a list of the function's arguments.
    """
    param_cnt = len(param_str.split(" "))
    params = []
    for _ in range(param_cnt):
        params.append(state.symbolic_stack.pop())

    # concretize
    params_result = []
    for i in params:
        if is_bv_value(i):
            params_result.append(i.as_long())
        else:
            params_result.append(i)

    return params_result


def _storeN(state, dest, val, len_in_bytes):
    """
    Store a value into symbolic memory at the destination address.
    If the value is not a bit-vector (concrete), it will be converted to a bit-vector using `BitVecVal`.
    The size of the value is determined by len_in_bytes (converted to bits).
    """
    if not is_bv(val):
        state.symbolic_memory = insert_symbolic_memory(
            state.symbolic_memory, dest, len_in_bytes,
            BitVecVal(val, len_in_bytes * 8))
    else:
        state.symbolic_memory = insert_symbolic_memory(
            state.symbolic_memory, dest, len_in_bytes, val)


def _loadN(state, data_section, dest, len_in_bytes):
    """
    Load a value from the symbolic memory, given the destination address and the number of bytes (len_in_bytes).
    If the loaded value is a bit-vector value, it's converted into a concrete integer.
    Otherwise, it returns the symbolic value as-is.
    """
    val = lookup_symbolic_memory_data_section(
        state.symbolic_memory, data_section, dest, len_in_bytes)
    if is_bv_value(val):
        val = val.as_long()
    return val
