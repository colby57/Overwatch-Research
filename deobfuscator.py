import sys
import triton

class Deobfuscator:
    def __init__(self, bin_path):
        self.bin_path = bin_path
        self.ctx = triton.TritonContext()
        self.ctx.setArchitecture(triton.ARCH.X86_64)
        self.start_address = 0x1000

    def initialize(self):
        with open(self.bin_path, 'rb') as f:
            function_bytes = f.read()
        self.ctx.setConcreteMemoryAreaValue(self.start_address, function_bytes)
        self.ctx.setConcreteMemoryValue()
        self.ctx.setConcreteRegisterValue(self.ctx.registers.rip, self.start_address)

    def deobfuscate(self):
        pc = self.start_address
        final_state = {}

        while True:
            opcode = self.ctx.getConcreteMemoryAreaValue(pc, 16)
            instruction = triton.Instruction(pc, opcode)
            self.ctx.processing(instruction)

            if instruction.getType() == triton.OPCODE.X86.ADD and \
               instruction.getOperands()[0].getType() == triton.OPERAND.MEM and \
               instruction.getOperands()[0].getBaseRegister().getName() == 'rax' and \
               instruction.getOperands()[1].getName() == 'al':
                break

            self.process_instruction(instruction, final_state)
            pc = instruction.getNextAddress()

        return self.generate_optimized_code(final_state)

    def process_instruction(self, instruction, final_state):
        disasm = instruction.getDisassembly()
        if disasm.startswith(('mov', 'xor', 'add')):
            dest, src = instruction.getOperands()
            dest_name = self.get_operand_name(dest)
            src_value = self.get_value(src)
            
            if disasm.startswith('xor') and dest_name == self.get_operand_name(src):
                final_state[dest_name] = 0
            elif disasm.startswith('add'):
                dest_value = self.get_value(dest)
                final_state[dest_name] = (dest_value + src_value) & 0xFFFFFFFFFFFFFFFF
            else:
                final_state[dest_name] = src_value
        elif disasm.startswith('cmp'):
            left, right = instruction.getOperands()
            final_state['cmp'] = (self.get_value(left), self.get_value(right))

    def get_value(self, operand):
        if operand.getType() == triton.OPERAND.IMM:
            return operand.getValue()
        elif operand.getType() == triton.OPERAND.REG:
            return self.ctx.getConcreteRegisterValue(operand)
        elif operand.getType() == triton.OPERAND.MEM:
            return self.ctx.getConcreteMemoryValue(operand)

    def get_operand_name(self, operand):
        if operand.getType() == triton.OPERAND.REG:
            return operand.getName()
        elif operand.getType() == triton.OPERAND.MEM:
            return self.get_memory_alias(operand)
        return str(operand)

    def get_memory_alias(self, mem_operand):
        base = mem_operand.getBaseRegister().getName() if mem_operand.getBaseRegister() else ''
        index = mem_operand.getIndexRegister().getName() if mem_operand.getIndexRegister() else ''
        scale = mem_operand.getScale() if mem_operand.getScale() != 1 else ''
        disp = mem_operand.getDisplacement()

        parts = []
        if base:
            parts.append(base)
        if index:
            parts.append(f"{index}*{scale}" if scale else index)
        if disp:
            parts.append(hex(disp.getValue()))

        return f"[{' + '.join(parts)}]"

    def generate_optimized_code(self, final_state):
        optimized = []
        for reg, value in final_state.items():
            if reg != 'cmp':
                optimized.append(f"mov {reg}, {hex(value)}")
        if 'cmp' in final_state:
            left, right = final_state['cmp']
            optimized.append(f"cmp {hex(left)}, {hex(right)}")
        return optimized

    def run(self):
        self.initialize()
        optimized = self.deobfuscate()

        print("\nOptimized code:")
        for inst in optimized:
            print(inst)

def main():
    if len(sys.argv) != 2:
        print("Usage: python deobfuscator.py <path_to_bin_file>")
        sys.exit(1)

    bin_path = sys.argv[1]
    deobfuscator = Deobfuscator(bin_path)
    deobfuscator.run()

if __name__ == "__main__":
    main()