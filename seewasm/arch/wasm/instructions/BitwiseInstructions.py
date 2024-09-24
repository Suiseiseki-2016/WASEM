# emulate the bitwise related instructions

import logging

from seewasm.arch.wasm.exceptions import UnsupportInstructionError
from z3 import (BitVec, BitVecVal, LShR, RotateLeft, RotateRight, is_bool,
                is_bv, is_false, is_true, simplify)

# Helper map for the bit sizes of different WebAssembly data types
helper_map = {
    'i32': 32,          # 32-bit integer
    'i64': 64,          # 64-bit integer
}


class BitwiseInstructions:
    """
    Class to emulate bitwise operations for WebAssembly instructions using Z3 symbolic execution.
    """
    def __init__(self, instr_name, instr_operand, _):
        """
        Initialize the instruction with its name and operand.
        
        :param instr_name: The WebAssembly instruction name (e.g., "i32.and")
        :param instr_operand: Operand for the instruction (not used in this implementation)
        """
        self.instr_name = instr_name
        self.instr_operand = instr_operand

    # TODO overflow check in this function?
    def emulate(self, state):
        """
        Emulate the bitwise instruction by performing symbolic operations on two arguments
        from the symbolic stack, and push the result back onto the stack.
        
        :param state: The current execution state, including the symbolic stack.
        :return: The modified state after emulation.
        """
        
        arg1, arg2 = state.symbolic_stack.pop(), state.symbolic_stack.pop()
        instr_type = self.instr_name[:3]

        # Handle the case where the arguments are BoolRef types (Boolean), converting them to BitVec
        if is_bool(arg1):
            arg1 = BitVec(str(arg1), helper_map[instr_type])
            logging.warning(
                f"[!] In `BitwiseInstructions.py`, arg1 is BoolRef, translated to BitVec which may lead to some information loss")
        if is_bool(arg2):
            arg2 = BitVec(str(arg2), helper_map[instr_type])
            logging.warning(
                f"[!] In `BitwiseInstructions.py`, arg2 is BoolRef, translated to BitVec which may lead to some information loss")

        # Ensure that both arguments match the expected size for the WebAssembly type (i32 or i64)
        assert arg1.size(
        ) == helper_map[instr_type], f'arg1 size is {arg1.size()} instead of {helper_map[instr_type]} in do_emulate_bitwise_instruction'
        assert arg2.size(
        ) == helper_map[instr_type], f'arg2 size is {arg2.size()} instead of {helper_map[instr_type]} in do_emulate_bitwise_instruction'

        # Determine the bitwise operation to perform based on the instruction name
        if '.and' in self.instr_name:
            result = simplify(arg1 & arg2)                  # Bitwise AND operation
        elif '.or' in self.instr_name:
            result = simplify(arg1 | arg2)                  # Bitwise OR operation
        elif '.xor' in self.instr_name:
            result = simplify(arg1 ^ arg2)                  # Bitwise XOR operation
        elif '.shr_s' in self.instr_name:
            result = simplify(arg2 >> arg1)                 # Signed right shift (arithmetic shift)
        elif '.shr_u' in self.instr_name:
            result = simplify(LShR(arg2, arg1))             # Unsigned right shift (logical shift)
        elif '.shl' in self.instr_name:
            result = simplify(arg2 << arg1)                 # Left shift
        elif '.rotl' in self.instr_name:
            result = simplify(RotateLeft(arg2, arg1))       # Rotate left
        elif '.rotr' in self.instr_name:
            result = simplify(RotateRight(arg2, arg1))      # Rotate right
        else:
            raise UnsupportInstructionError

        # Handle the case where the result is a boolean value
        if is_bool(result):
            if is_true(result):
                result = BitVecVal(1, 32)
            elif is_false(result):
                result = BitVecVal(0, 32)

        assert is_bv(result) or is_bool(
            result), f"in bitwise instruction, the value to be pushed is {type(result)} instead of BitVec or Bool"

        state.symbolic_stack.append(result)

        return [state]
