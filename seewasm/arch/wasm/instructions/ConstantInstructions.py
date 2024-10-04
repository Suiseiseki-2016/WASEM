# emulate the constant related instructions

import re
from struct import unpack

from seewasm.arch.wasm.exceptions import UnsupportInstructionError
from z3 import BitVecVal, Float32, Float64, FPVal


class ConstantInstructions:
    def __init__(self, instr_name, instr_operand, instr_string):
        # Initialize the ConstantInstructions class with the instruction name, operand, and string representation.
        self.instr_name = instr_name
        self.instr_operand = instr_operand
        self.instr_str = instr_string

    # TODO overflow check in this function?
    def emulate(self, state):
        """
        Emulate constant instructions for WebAssembly (WASM).
        These instructions could be either integer (i32, i64) or float (f32, f64) constants.
        
        Example instructions:
        - i32.const 0
        - f64.const 0x1.9p+6 (;=100;)

        This method handles the different scenarios for integer and float constants,
        and appends the corresponding symbolic value to the state's stack.
        """
        
        # Split the instruction string to get the mnemonic and constant value.
        mnemonic = self.instr_str.split(' ')[0]
        const_num = self.instr_str.split(' ')[-1]

        # The mnemonic gives the type of the constant (i32, i64, f32, f64).
        const_type_prefix, _ = mnemonic.split('.')

        # Handle integer constants (i32 and i64).
        if const_type_prefix == 'i32':
            # Append a 32-bit BitVec symbolic value to the stack.
            state.symbolic_stack.append(BitVecVal(const_num, 32))
        elif const_type_prefix == 'i64':
            # Append a 64-bit BitVec symbolic value to the stack.
            state.symbolic_stack.append(BitVecVal(const_num, 64))
        
        # Handle floating-point constants (f32 and f64).
        elif const_type_prefix == 'f32' or const_type_prefix == 'f64':
            # Try to find the float representaion within the annotation (;=100;)
            # TODO: need to be verified
            num_found = re.search(';=([0-9.-]+);', const_num)

            # If we find a match, extract the float number and handle it.
            if num_found:
                float_num = num_found.group(1)
                # Append an FPVal symbolic value for f32 or f64.
                if const_type_prefix == 'f32':
                    state.symbolic_stack.append(FPVal(float_num, Float32()))
                else:
                    state.symbolic_stack.append(FPVal(float_num, Float64()))
            
            # If the constant number is in hexadecimal format, handle it.
            elif const_num[:2] == '0x':
                # Remove the '0x' prefix
                const_num = const_num[2:]
                
                # Calculate how many zeros need to be added to reach the required length.
                # 8 hex digits for f32 (4 bytes), 16 hex digits for f64 (8 bytes).
                current_const_num_length = len(const_num)

                need_zero = (8 - current_const_num_length) if const_type_prefix == 'f32' else (
                    16 - current_const_num_length)
                
                # Padding with leading zero if necessary.
                const_num = '0' * need_zero + const_num

                # Unpack the hexadecimal string into a floating-point number.
                if const_type_prefix == 'f32':
                    # Interpret the hex string as a 4-byte float.
                    float_num = unpack('!f', bytes.fromhex(const_num))[0]
                    state.symbolic_stack.append(FPVal(float_num, Float32()))
                else:
                    # Interpret the hex string as an 8-byte double.
                    float_num = unpack('!d', bytes.fromhex(const_num))[0]
                    state.symbolic_stack.append(FPVal(float_num, Float64()))
            
            # Raise an error if the constant format is not recognized.
            else:
                raise UnsupportInstructionError
        
        # Raise an error if the constant type is not supported (e.g., types other than i32, i64, f32, f64).
        else:
            raise UnsupportInstructionError
        
        # Return the modified state after emulating the instruction.
        return [state]
    
