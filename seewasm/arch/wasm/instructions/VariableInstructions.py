# emulate the variable related instructions

from seewasm.arch.wasm.exceptions import UnsupportInstructionError, UnsupportGlobalTypeError
from z3 import BitVecVal, is_bv, is_bv_value


class VariableInstructions:
    def __init__(self, instr_name, instr_operand, _):
        """
        Initialize the class with the instruction name and operand.
        instr_name: Name of the WebAssembly instruction (e.g., 'get_local', 'set_global').
        instr_operand: Operand associated with the instruction (e.g., local/global variable index).
        """
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    def emulate(self, state):
        """
        Emulates WebAssembly variable-related instructions (get_local, set_local, get_global, etc.).
        This method manipulates the symbolic execution state based on the instruction and operand.
        """
        # TODO
        # for go_samples.nosync/tinygo_main.wasm, the global.get operand would be prefixed by four \x80
        # If the operand is prefixed with \x80\x80\x80\x80, strip the first 4 bytes
        if self.instr_operand.startswith(b'\x80\x80\x80\x80'):
            self.instr_operand = self.instr_operand[4:]

        # Convert the operand from bytes to an integer, interpreted in little-endian byte order.
        op = int.from_bytes(self.instr_operand, byteorder='little')

        # Handle get_local: retrieve the value of a local variable and push it onto the symbolic stack.
        if self.instr_name == 'get_local':
            if state.local_var.get(op, None) is not None:
                # Push the local variable onto the symbolic stack.
                state.symbolic_stack.append(state.local_var[op])
            else:
                # If the local variable is uninitialized, raise an error or handle as needed.
                state.symbolic_stack.append(state.local_var[op])
                # raise UninitializedLocalVariableError
        # Handle set_local: pop a value from the stack and store it in a local variable.
        elif self.instr_name == 'set_local':
            var = state.symbolic_stack.pop()
            state.local_var[op] = var
        # Handle get_global: retrieve the value of a global variable and push it onto the symbolic stack.
        elif self.instr_name == 'get_global':
            global_index = op
            global_operand = state.globals[global_index]

            # If the global variable is a basic type (int or string), wrap it in a BitVec.
            if isinstance(
                    global_operand, str) or isinstance(
                    global_operand, int):
                state.symbolic_stack.append(BitVecVal(global_operand, 32))
            # If the global variable is already a BitVec or BitVec value, push it directly.
            elif is_bv(global_operand) or is_bv_value(global_operand):
                # the operand is a BitVecRef or BitVecNumRef
                state.symbolic_stack.append(global_operand)
            else:
                raise UnsupportGlobalTypeError
        # Handle set_global: pop a value from the stack and store it in a global variable.
        elif self.instr_name == 'set_global':
            global_operand = state.symbolic_stack.pop()
            global_index = op

            state.globals[global_index] = global_operand
        # Handle tee_local: copy the top of the stack and store it in a local variable without removing it from the stack.
        elif self.instr_name == 'tee_local':
            var = state.symbolic_stack[-1]
            state.local_var[op] = var
        else:
            raise UnsupportInstructionError
        return [state]
