import copy
import logging
from collections import defaultdict

from z3 import (Not, Or, is_bool, is_bv, is_bv_value, is_false, is_true,
                simplify, unsat)

from seewasm.arch.wasm.configuration import Configuration
from seewasm.arch.wasm.exceptions import (ASSERT_FAIL, ProcFailTermination,
                                          ProcSuccessTermination,
                                          UnsupportInstructionError)
from eunomia.arch.wasm.lib.c_lib import CPredefinedFunction, C_extract_string_by_mem_pointer
from eunomia.arch.wasm.lib.go_lib import GoPredefinedFunction
from seewasm.arch.wasm.lib.utils import is_modeled
from seewasm.arch.wasm.lib.wasi import WASIImportFunction
from seewasm.arch.wasm.utils import (log_in_out, one_time_query_cache,
                                     readable_internal_func_name)

TERMINATED_FUNCS = {'__assert_fail', 'runtime.divideByZeroPanic'}


class ControlInstructions:
    def __init__(self, instr_name, instr_operand, instr_string):
        """
        Initialize with instruction name, operand, and string.
        `instr_name` - instruction type (e.g., call, br_if)
        `instr_operand` - additional data related to the instruction (e.g., branch targets)
        `instr_string` - full string representation of the instruction.
        """
        self.instr_name = instr_name
        self.instr_operand = instr_operand
        self.instr_string = instr_string
        self.skip_command = {'loop', 'end', 'br', 'else', 'block'}
        self.term_command = {'unreachable', 'return'}

    def store_context(self, param_str, return_str, state, callee_func_name):
        """
        Store the context of current stack and local.
        The sequence is:
        1. pop specific number of elements from stack, which will be used by callee
        2. store the current context, including (current_func, current_block, stack, local, require_return)
        3. assign popped elements in step 1 in local, change the current_func_name
        """
        logging.info(
            f"Call: {readable_internal_func_name(Configuration.get_func_index_to_func_name(), state.current_func_name)} -> {callee_func_name}")

        # Step 1: Pop arguments for the callee function from the symbolic stack
        num_arg = 0
        if param_str:
            num_arg = len(param_str.split(' '))
            arg = [state.symbolic_stack.pop() for _ in range(num_arg)]

        # Step 2: Store the current function's context
        state.context_stack.append((state.current_func_name,
                                    state.instr.cur_bb,
                                    [e for e in state.symbolic_stack],
                                    copy.copy(state.local_var),
                                    True if return_str else False))

        # Step 3: Assign arguments to local variables in the callee function
        for x in range(num_arg):
            state.local_var[num_arg - 1 - x] = arg[x]
        # Clear remaining local variables
        for x in range(num_arg, len(state.local_var)):
            try:
                state.local_var.pop(x)
            except KeyError:
                # If some locals are unused, continue
                # There is no need to pop it, thus continue the loop
                continue

        state.current_func_name = callee_func_name

    def restore_context(self, state):
        """
        Restore the context of the caller function after the callee returns.
        Steps:
        1. If necessary, pop the return value from the stack.
        2. Restore the caller's context (function, block, stack, locals).
        3. Push the return value back to the stack if required.
        """
        if len(state.context_stack) == 0:
            raise ProcSuccessTermination(0)

        caller_func_name, cur_bb, stack, local, require_return = state.context_stack.pop()

        logging.info(
            f"Return: {readable_internal_func_name(Configuration.get_func_index_to_func_name(), state.current_func_name)}")

        # Step 1: Pop the return value if necessary
        if require_return:
            return_val = state.symbolic_stack.pop()

        # Step 2: Restore the caller function's context
        state.current_func_name = caller_func_name
        state.current_bb_name = cur_bb
        state.symbolic_stack = stack
        state.local_var = local

        # Step 3: Push the return value back onto the stack if necessary
        if require_return:
            state.symbolic_stack.append(return_val)

    def deal_with_call(self, state, f_offset, data_section, analyzer, lvar):
        """
        Handle a function call by determining the callee function signature
        and preparing the appropriate context for the call.
        """
        # Get callee's function signature
        target_func = analyzer.func_prototypes[f_offset]
        callee_func_name, param_str, return_str, _ = target_func

        # Get human-readable callee function name
        readable_callee_func_name = readable_internal_func_name(
            Configuration.get_func_index_to_func_name(),
            callee_func_name)
        
        # Handle specific modeled functions (like library calls or assertions)
        if Configuration.get_dsl_flag() and readable_callee_func_name.startswith("checker"):
            # Handle instrumented functions starting with "checker"
            idx = int(readable_callee_func_name.split('$')[1])
            """
            if idx == -1:
                arg = _extract_params(param_str, state)[0]
                state.solver.add(arg > 0);
            elif idx == -2:
                arg = _extract_params(param_str, state)[0]
                state.solver.add(arg > 0);
            elif idx == 3:
                lvar['prior'] = abs(20 - lvar['rounds_i']) - 20
            elif idx == 4:
                lvar['prior'] = abs(3 - lvar['rounds_j'])
            """
            states = [state]
        elif Configuration.get_source_type() == 'c' and is_modeled(readable_callee_func_name, specify_lang='c'):
            # Handle C library functions
            func = CPredefinedFunction(
                readable_callee_func_name, state.current_func_name)
            states = log_in_out(
                readable_callee_func_name, "C Library")(
                func.emul)(
                state, param_str, return_str, data_section, analyzer)
        elif Configuration.get_source_type() == 'go' and is_modeled(readable_callee_func_name, specify_lang='go'):
            # Handle Go library functions (untested)
            # TODO Go library func modeling is not tested
            func = GoPredefinedFunction(
                readable_callee_func_name, state.current_func_name)
            states = log_in_out(
                readable_callee_func_name, "Go Library")(
                func.emul)(
                state, param_str, return_str, data_section, analyzer)
        elif Configuration.get_source_type() == 'rust' and is_modeled(readable_callee_func_name, specify_lang='rust'):
            # TODO may model some rust library funcs
            pass
        # if the callee is imported (WASI)
        elif is_modeled(readable_callee_func_name, specify_lang='wasi'):
            # Handle WASI-imported functions
            func = WASIImportFunction(
                readable_callee_func_name, state.current_func_name)
            states = log_in_out(
                readable_callee_func_name, "import")(
                func.emul)(
                state, param_str, return_str, data_section)
        elif readable_callee_func_name in TERMINATED_FUNCS:
            # Handle functions that result in termination (like runtime errors)
            logging.info(f"Termination: {readable_callee_func_name}")
            raise ProcFailTermination(ASSERT_FAIL)
        else:
            # Store the current context and proceed with the function call
            self.store_context(param_str, return_str, state,
                               readable_callee_func_name)
            states = [state]
        return states

    def emulate(self, state, data_section, analyzer, lvar):
        """
        Main function that handles the emulation of control instructions like
        `br`, `call`, `if`, `return`, etc.
        """
        # Handle instructions that we can skip or terminate early
        if self.instr_name in self.skip_command:
            return [state]
        if self.instr_name in self.term_command:
            return [state]

        # Handle a no-op instruction
        if self.instr_name == 'nop':
            if state.instr.xref:
                self.restore_context(state)
            return [state]
        # Handle branch instructions like `br_if`, `if`
        elif self.instr_name == 'br_if' or self.instr_name == 'if':
            op = state.symbolic_stack.pop()
            assert is_bv(op) or is_bool(
                op), f"the type of op popped from stack in `br_if`/`if` is {type(op)} instead of bv or bool"
            states = []
            if is_bv(op):
                op = simplify(op != 0)

            # | op      | branch              |
            # | ------- | ------------------- |
            # | False   | conditional_false_0 |
            # | True    | conditional_true_0  |
            # | BoolRef | both                |

            # Handle true/false or symbolic branch conditions
            if is_true(op):
                state.edge_type = 'conditional_true_0'
                states.append(state)
            elif is_false(op):
                state.edge_type = 'conditional_false_0'
                states.append(state)
            elif not is_true(op) and not is_false(op):
                # these two flags are used to jump over unnecessary deepcopy
                no_need_true, no_need_false = False, False
                if unsat == one_time_query_cache(state.solver, op):
                    no_need_true = True
                if unsat == one_time_query_cache(state.solver, Not(op)):
                    no_need_false = True

                if no_need_true and no_need_false:
                    pass
                elif not no_need_true and not no_need_false:
                    new_state = copy.deepcopy(state)
                    # conditional_true
                    state.edge_type = 'conditional_true_0'
                    state.solver.add(op)
                    # conditional_false
                    new_state.edge_type = 'conditional_false_0'
                    new_state.solver.add(Not(op))
                    # append
                    states.append(state)
                    states.append(new_state)
                else:
                    if no_need_true:
                        state.edge_type = 'conditional_false_0'
                        state.solver.add(Not(op))
                        states.append(state)
                    else:
                        state.edge_type = 'conditional_true_0'
                        state.solver.add(op)
                        states.append(state)
            else:
                exit(f"br_if/if instruction error. op is {op}")

            return states
        elif self.instr_name == 'call_indirect':
            # refer to: https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format#webassembly_tables
            # this instruction will pop an element out of the stack, and use this as an index in the table, i.e., elem section in Wasm module, to dynamically determine which fucntion will be invoked
            elem_index_to_func = Configuration.get_elem_index_to_func()

            # target function index
            op = state.symbolic_stack.pop()
            assert is_bv_value(
                op), f"in call_indirect, op is a symbol ({op}), not support yet"
            op = op.as_long()

            offset = analyzer.elements[0]['offset']

            callee_func_name = elem_index_to_func[op - offset]
            callee_func_offset = -1
            for func_offset, item in enumerate(analyzer.func_prototypes):
                if callee_func_name == readable_internal_func_name(
                        Configuration.get_func_index_to_func_name(),
                        item[0]):
                    state.call_indirect_callee = callee_func_name
                    callee_func_offset = func_offset
                    break

            if callee_func_offset == -1:
                exit("no valid callee in call_indirect")
            else:
                return self.deal_with_call(
                    state, callee_func_offset, data_section, analyzer, lvar)
        elif self.instr_name == 'br_table':
            # state.instr.xref indicates the destination instruction's offset
            # TODO examine br_table
            op = state.symbolic_stack.pop()

            # operands of br_table instruction
            ops = [i for i in self.instr_operand]
            n_br, br_lis = ops[0], ops[1:-1]

            # construct a dict to minimize the possible states
            target_branch2index = defaultdict(list)
            for index, target in enumerate(br_lis):
                target_branch2index[target].append(index)

            # construct possible state
            states = []
            for target, index_list in target_branch2index.items():
                index_list = [simplify(op == i) for i in index_list]
                cond = simplify(Or(index_list))
                if is_false(cond):
                    continue
                elif is_true(cond):
                    # we can omit the "True" apppended into the constraint
                    new_state = copy.deepcopy(state)
                    new_state.edge_type = f"conditional_true_{target}"
                    states.append(new_state)
                else:
                    # we have to query z3
                    new_state = copy.deepcopy(state)
                    new_state.solver.add(cond)
                    new_state.edge_type = f"conditional_true_{target}"
                    states.append(new_state)

            # determine if we need the default branch
            cond = simplify(Or(op >= n_br, op < 0))
            if is_false(cond):
                # we don't need it
                pass
            elif is_true(cond):
                state.edge_type = "conditional_false_0"
                states.append(state)
            else:
                state.solver.add(cond)
                state.edge_type = "conditional_false_0"
                states.append(state)

            assert len(states) != 0, f"in br_table, no branch is selected"
            return states
        elif self.instr_name == 'call':
            self.instr_operand = self.instr_string.split(' ')[1]
            # get the callee's function signature
            try:
                f_offset = int(self.instr_operand)
            except ValueError:
                # it's possible that the `call` operand is a hex
                f_offset = int(self.instr_operand, 16)
            return self.deal_with_call(
                state, f_offset, data_section, analyzer, lvar)
        else:
            raise UnsupportInstructionError
