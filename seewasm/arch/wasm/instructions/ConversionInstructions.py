# emulate the conversion related instructions

from seewasm.arch.wasm.exceptions import UnsupportInstructionError
from z3 import (RNE, RTZ, BitVecSort, BitVecVal, Extract, Float32, Float64,
                SignExt, ZeroExt, fpBVToFP, fpFPToFP, fpSignedToFP, fpToIEEEBV,
                fpToSBV, fpToUBV, fpUnsignedToFP, simplify)

# Class to emulate WebAssembly (WASM) conversion instructions
class ConversionInstructions:
    # Initialize the conversion instruction
    def __init__(self, instr_name, instr_operand, _):
        self.instr_name = instr_name  # Instruction name
        self.instr_operand = instr_operand  # Operand of the instruction

    # Emulate the conversion instructions based on their type
    def emulate(self, state):
        # Pop the top element from the symbolic stack (i.e., the operand)
        arg0 = state.symbolic_stack.pop()

        # Handle each instruction based on its name
        if self.instr_name == 'i32.wrap/i64':
            # Wrap a 64-bit integer to a 32-bit by taking the modulus
            assert arg0.size() == 64, 'i32.wrap/i64 has wrong arg type'
            divisor = BitVecVal(2 ** 32, 64)
            # mod
            result = simplify(Extract(31, 0, arg0 % divisor))
        elif self.instr_name == 'i64.extend_s/i32':
            # Sign-extend a 32-bit integer to 64-bit
            assert arg0.size() == 32, 'i64.extend_s/i32 has wrong arg type'

            result = simplify(SignExt(32, arg0))
        elif self.instr_name == 'i64.extend_u/i32':
            # Zero-extend a 32-bit integer to 64-bit
            assert arg0.size() == 32, 'i64.extend_u/i32 has wrong arg type'

            result = simplify(ZeroExt(32, arg0))
        elif self.instr_name == 'i32.trunc_s/f32':
            # Convert a signed 32-bit float (f32) to a signed 32-bit integer
            assert arg0.ebits() == 8, 'i32.trunc_s/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'i32.trunc_s/f32 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToSBV(rm, arg0, BitVecSort(32)))
            assert result.size() == 32, 'i32.trunc_s/f32 convert fail'
        elif self.instr_name == 'i32.trunc_s/f64':
            # Convert a signed 64-bit float (f64) to a signed 32-bit integer
            assert arg0.ebits() == 11, 'i32.trunc_s/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'i32.trunc_s/f64 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToSBV(rm, arg0, BitVecSort(32)))
            assert result.size() == 32, 'i32.trunc_s/f64 convert fail'
        elif self.instr_name == 'i64.trunc_s/f32':
            # Convert a signed 32-bit float (f32) to a signed 64-bit integer
            assert arg0.ebits() == 8, 'i64.trunc_s/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'i64.trunc_s/f32 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToSBV(rm, arg0, BitVecSort(64)))
            assert result.size() == 64, 'i64.trunc_s/f32 convert fail'
        elif self.instr_name == 'i64.trunc_s/f64':
            # Convert a signed 64-bit float (f64) to a signed 64-bit integer
            assert arg0.ebits() == 11, 'i64.trunc_s/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'i64.trunc_s/f64 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToSBV(rm, arg0, BitVecSort(64)))
            assert result.size() == 64, 'i64.trunc_s/f64 convert fail'
        elif self.instr_name == 'i32.trunc_u/f32':
            # Convert an unsigned 32-bit float (f32) to an unsigned 32-bit integer
            assert arg0.ebits() == 8, 'i32.trunc_u/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'i32.trunc_u/f32 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToUBV(rm, arg0, BitVecSort(32)))
            assert result.size() == 32, 'i32.trunc_u/f32 convert fail'
        elif self.instr_name == 'i32.trunc_u/f64':
            # Convert an unsigned 64-bit float (f64) to an unsigned 32-bit integer
            assert arg0.ebits() == 11, 'i32.trunc_u/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'i32.trunc_u/f64 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToUBV(rm, arg0, BitVecSort(32)))
            assert result.size() == 32, 'i32.trunc_u/f64 convert fail'
        elif self.instr_name == 'i64.trunc_u/f32':
            # Convert an unsigned 32-bit float (f32) to an unsigned 64-bit integer
            assert arg0.ebits() == 8, 'i64.trunc_u/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'i64.trunc_u/f32 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToUBV(rm, arg0, BitVecSort(64)))
            assert result.size() == 64, 'i64.trunc_u/f32 convert fail'
        elif self.instr_name == 'i64.trunc_u/f64':
            # Convert an unsigned 64-bit float (f64) to an unsigned 64-bit integer
            assert arg0.ebits() == 11, 'i64.trunc_u/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'i64.trunc_u/f64 has wrong arg type'

            rm = RTZ()
            result = simplify(fpToUBV(rm, arg0, BitVecSort(64)))
            assert result.size() == 64, 'i64.trunc_u/f64 convert fail'
        elif self.instr_name == 'f32.demote/f64':
            # Demote a 64-bit float (f64) to a 32-bit float (f32)
            assert arg0.ebits() == 11, 'f32.demote/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'f32.demote/f64 has wrong arg type'

            rm = RNE()
            result = simplify(fpFPToFP(rm, arg0, Float32()))
            assert result.ebits() == 8, 'f32.demote/f64 conversion fail'
            assert result.sbits() == 24, 'f32.demote/f64 conversion fail'
        elif self.instr_name == 'f64.promote/f32':
            # Promote a 32-bit float (f32) to a 64-bit float (f64)
            assert arg0.ebits() == 8, 'f64.promote/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'f64.promote/f32 has wrong arg type'

            rm = RNE()
            result = simplify(fpFPToFP(rm, arg0, Float64()))
            assert result.ebits() == 11, 'f64.promote/f32 conversion fail'
            assert result.sbits() == 53, 'f64.promote/f32 conversion fail'
        elif self.instr_name == 'f32.convert_s/i32':
            # Convert a signed 32-bit integer to a 32-bit float (f32)
            assert arg0.size() == 32, 'f32.convert_s/i32 has wrong arg type'

            rm = RNE()
            result = simplify(fpSignedToFP(rm, arg0, Float32()))
            assert result.ebits() == 8, 'f32.convert_s/i32 conversion fail'
            assert result.sbits() == 24, 'f32.convert_s/i32 conversion fail'
        elif self.instr_name == 'f32.convert_s/i64':
            # Convert a signed 64-bit integer to a 32-bit float (f32)
            assert arg0.size() == 64, 'f32.convert_s/i64 has wrong arg type'

            rm = RNE()
            result = simplify(fpSignedToFP(rm, arg0, Float32()))
            assert result.ebits() == 8, 'f32.convert_s/i64 conversion fail'
            assert result.sbits() == 24, 'f32.convert_s/i64 conversion fail'
        elif self.instr_name == 'f64.convert_s/i32':
            # Convert a signed 32-bit integer to a 64-bit float (f64)
            assert arg0.size() == 32, 'f64.convert_s/i32 has wrong arg type'

            rm = RNE()
            result = simplify(fpSignedToFP(rm, arg0, Float64()))
            assert result.ebits() == 11, 'f64.convert_s/i32 conversion fail'
            assert result.sbits() == 53, 'f64.convert_s/i32 conversion fail'
        elif self.instr_name == 'f64.convert_s/i64':
            # Convert a signed 64-bit integer to a 64-bit float (f64)
            assert arg0.size() == 64, 'f64.convert_s/i64 has wrong arg type'

            rm = RNE()
            result = simplify(fpSignedToFP(rm, arg0, Float64()))
            assert result.ebits() == 11, 'f64.convert_s/i64 conversion fail'
            assert result.sbits() == 53, 'f64.convert_s/i64 conversion fail'
        elif self.instr_name == 'f32.convert_u/i32':
            # Convert an unsigned 32-bit integer to a 32-bit float (f32)
            assert arg0.size() == 32, 'f32.convert_u/i32 has wrong arg type'

            rm = RNE()
            result = simplify(fpUnsignedToFP(rm, arg0, Float32()))
            assert result.ebits() == 8, 'f32.convert_u/i32 conversion fail'
            assert result.sbits() == 24, 'f32.convert_u/i32 conversion fail'
        elif self.instr_name == 'f32.convert_u/i64':
            # Convert an unsigned 64-bit integer to a 32-bit float (f32)
            assert arg0.size() == 64, 'f32.convert_u/i64 has wrong arg type'

            rm = RNE()
            result = simplify(fpUnsignedToFP(rm, arg0, Float32()))
            assert result.ebits() == 8, 'f32.convert_u/i64 conversion fail'
            assert result.sbits() == 24, 'f32.convert_u/i64 conversion fail'
        elif self.instr_name == 'f64.convert_u/i32':
            # Convert an unsigned 32-bit integer to a 64-bit float (f64)
            assert arg0.size() == 32, 'f64.convert_u/i32 has wrong arg type'

            rm = RNE()
            result = simplify(fpUnsignedToFP(rm, arg0, Float64()))
            assert result.ebits() == 11, 'f64.convert_u/i32 conversion fail'
            assert result.sbits() == 53, 'f64.convert_u/i32 conversion fail'
        elif self.instr_name == 'f64.convert_u/i64':
            # Convert an unsigned 64-bit integer to a 64-bit float (f64)
            assert arg0.size() == 64, 'f64.convert_u/i64 has wrong arg type'

            rm = RNE()
            result = simplify(fpUnsignedToFP(rm, arg0, Float64()))
            assert result.ebits() == 11, 'f64.convert_u/i64 conversion fail'
            assert result.sbits() == 53, 'f64.convert_u/i64 conversion fail'
        elif self.instr_name == 'i32.reinterpret/f32':
            # Reinterpret the bit pattern of a 32-bit float (f32) as a 32-bit integer
            assert arg0.ebits() == 8, 'i32.reinterpret/f32 has wrong arg type'
            assert arg0.sbits() == 24, 'i32.reinterpret/f32 has wrong arg type'

            result = simplify(fpToIEEEBV(arg0))
            assert result.size() == 32, 'i32.reinterpret/f32 conversion fail'
        elif self.instr_name == 'i64.reinterpret/f64':
            # Reinterpret the bit pattern of a 64-bit float (f64) as a 64-bit integer
            assert arg0.ebits() == 11, 'i64.reinterpret/f64 has wrong arg type'
            assert arg0.sbits() == 53, 'i64.reinterpret/f64 has wrong arg type'

            result = simplify(fpToIEEEBV(arg0))
            assert result.size() == 64, 'i64.reinterpret/f64 conversion fail'
        elif self.instr_name == 'f32.reinterpret/i32':
            # Reinterpret the bit pattern of a 32-bit integer as a 32-bit float (f32)
            assert arg0.size() == 32, 'f32.reinterpret/i32 has wrong arg type'

            result = simplify(fpBVToFP(arg0, Float32()))
            assert result.ebits() == 8, 'f32.reinterpret/i32 conversion fail'
            assert result.sbits() == 24, 'f32.reinterpret/i32 conversion fail'
        elif self.instr_name == 'f64.reinterpret/i64':
            # Reinterpret the bit pattern of a 64-bit integer as a 64-bit float (f64)
            assert arg0.size() == 64, 'f64.reinterpret/i64 has wrong arg type'

            result = simplify(fpBVToFP(arg0, Float64()))
            assert result.ebits() == 11, 'f64.reinterpret/i64 conversion fail'
            assert result.sbits() == 53, 'f64.reinterpret/i64 conversion fail'
        elif self.instr_name == 'i32.extend_s/i8':
            # Sign-extend an 8-bit integer to a 32-bit integer
            assert arg0.size() == 8, 'i32.extend_s/i8 has wrong arg type'

            result = simplify(SignExt(24, arg0))
        else:
            # Raise an error for unsupported instructions
            print('\nErr:\nUnsupported instruction: %s\n' % self.instr_name)
            raise UnsupportInstructionError

        # Push the result back to the symbolic stack
        state.symbolic_stack.append(result)

        return [state]
