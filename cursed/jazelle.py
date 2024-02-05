# Enterprisify your 32-bit arm binaries
# @author Hypfer
# @category cursed
# @keybinding
# @menupath
# @toolbar

from ghidra.app.plugin.assembler import Assemblers

current_program = getCurrentProgram()
assembler = Assemblers.getAssembler(current_program)

listing = current_program.getListing()
instr_iter = listing.getInstructions(True)

bx_count = 0
bxj_count = 0
while instr_iter.hasNext():
    instr = instr_iter.next()
    mnemonic = instr.getMnemonicString()

    if mnemonic == "bx":
        bx_count += 1
        first_operand = instr.getOpObjects(0)[0]
        newInstruction = "bxj " + first_operand.toString()
        assembler.assemble(instr.getAddress(), newInstruction)
    elif mnemonic == "bxj":
        bxj_count += 1

print("Enterprisified " + str(bx_count) + " instructions and found " + str(bxj_count) + " existing ones.")
