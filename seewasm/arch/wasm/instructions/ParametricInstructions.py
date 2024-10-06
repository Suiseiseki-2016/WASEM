from copy import deepcopy

from seewasm.arch.wasm.exceptions import UnsupportInstructionError
from seewasm.arch.wasm.utils import one_time_query_cache
from z3 import Not, is_bool, is_bv, is_false, is_true, simplify, unsat


class ParametricInstructions:
    def __init__(self, instr_name, instr_operand, _):
        # Initialize the instruction with its name and operand
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    def emulate(self, state):
        # Handling the 'drop' instruction (removes the top element from the stack)
        if self.instr_name == 'drop':
            state.symbolic_stack.pop()
            return [state]
        
        # Handling the 'select' instruction (picks between two values based on a condition)
        elif self.instr_name == 'select':  # select instruction
            # Pop the top 3 elements from the symbolic stack
            # arg0 is the condition, arg1 and arg2 are the values to select from
            arg0, arg1, arg2 = state.symbolic_stack.pop(
            ), state.symbolic_stack.pop(), state.symbolic_stack.pop()
            # Ensure the condition (arg0) is either a bit-vector (bv) or a boolean
            assert is_bv(arg0) or is_bool(
                arg0), f"in select, arg0 type is {type(arg0)} instead of bv or bool"
            # mimic the br_if
            # If arg0 is a bit-vector (common in WebAssembly), check if it's equal to 0 (false)
            # Select between arg1 and arg2 based on whether arg0 is zero or non-zero
            if is_bv(arg0):
                # NOTE: if arg0 is zero, return arg1, or arg2
                # ref: https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Control_flow/Select
                op = simplify(arg0 == 0)

            # If condition is true (arg0 == 0), push arg1 to the stack (use arg1)
            if is_true(op):
                state.symbolic_stack.append(arg1)
                return [state]
            
            # If condition is false (arg0 != 0), push arg2 to the stack (use arg2)
            elif is_false(op):
                state.symbolic_stack.append(arg2)
                return [state]
            
            # If the condition is neither true nor false (arg0 is symbolic), handle both cases
            elif not is_true(op) and not is_false(op):
                # Flags to avoid unnecessary deepcopy if path constraints are unsatisfiable
                # these two flags are used to jump over unnecessary deepcopy
                no_need_true, no_need_false = False, False
                if unsat == one_time_query_cache(state.solver, op):
                    no_need_true = True
                    
                # Check if the condition (op) is unsatisfiable
                if unsat == one_time_query_cache(state.solver, Not(op)):
                    no_need_false = True

                # Check if the negation of the condition (Not(op)) is unsatisfiable
                if no_need_true and no_need_false:
                    pass
                
                # If neither are unsatisfiable, handle both true and false paths
                elif not no_need_true and not no_need_false:
                    # Create a new state for the false path by deep copying the current state
                    new_state = deepcopy(state)

                    # Add the condition to the solver for the true path and push arg1 to the stack
                    state.solver.add(op)
                    state.symbolic_stack.append(arg1)

                    # Add the negation of the condition for the false path and push arg2 to the stack
                    new_state.solver.add(Not(op))
                    new_state.symbolic_stack.append(arg2)

                    # Return both states (one for the true path, one for the false path)
                    return [state, new_state]
                # If only one path is satisfiable, follow that path
                else:
                    if no_need_true:
                        # Only the false path is possible (arg0 != 0)
                        state.solver.add(Not(op))
                        state.symbolic_stack.append(arg2)
                    else:
                        # Only the true path is possible (arg0 == 0)
                        state.solver.add(op)
                        state.symbolic_stack.append(arg1)
                    return [state]
                
            # If something went wrong, exit with an error
            else:
                exit(f"select instruction error. op is {op}")
        # Raise an error if the instruction is not supported
        else:
            raise UnsupportInstructionError
