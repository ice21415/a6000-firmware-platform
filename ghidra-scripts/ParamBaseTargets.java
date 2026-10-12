// SHA-pinned targeted offline study; raw output must stay private.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

/**
 * Export bounded ParamBase foundation targets for a private, hash-pinned
 * libObj.so program.  The export is evidence metadata for local research;
 * generated decompiler names are not semantic confirmations.
 */
public class ParamBaseTargets extends GhidraScript {
    private static final String SHA256 =
        "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a";

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2 ||
            !SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Requires private output and pinned 3.21 libObj.so");
        }
        long[][] targets = new long[][] {
            {0xe50b4, 0x14}, // ParamBase constructor body
            {0xe4734, 0x12}, // non-deleting base destructor body
            {0xe4854, 0x14}, // deleting base destructor body
            {0x7eda84, 0x08} // ParamList element-key setter
        };
        if (args.length == 2 && !"base".equals(args[1])) {
            throw new IllegalArgumentException("Unknown target profile");
        }
        try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
            out.println("PROGRAM_SHA256=" + currentProgram.getExecutableSHA256());
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println("LANGUAGE=" + currentProgram.getLanguageID());
            out.println("ADDRESS_SPACE=ram");
            out.println("ANALYSIS_SCOPE=PARAMBASE_VTABLE_CONSTRUCTOR_DESTRUCTOR_KEY_SETTER");
            for (long[] target : targets) {
                Address start = currentProgram.getImageBase().add(target[0]);
                Address end = start.add(target[1] - 1);
                clearListing(start, end);
                currentProgram.getProgramContext().setValue(
                    currentProgram.getRegister("TMode"), start, end, BigInteger.ONE);
                disassemble(start);
                Function function = getFunctionAt(start);
                if (function == null) function = createFunction(start, null);
                if (function == null) throw new IllegalStateException("No function at " + start);
                function.setBody(new ghidra.program.model.address.AddressSet(start, end));
            }
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                for (long[] target : targets) {
                    Address start = currentProgram.getImageBase().add(target[0]);
                    Function function = getFunctionAt(start);
                    out.println("TARGET_ELF_VMA=" + Long.toHexString(target[0]) +
                        " GHIDRA=" + start + " BODY=" + function.getBody());
                    InstructionIterator instructions =
                        currentProgram.getListing().getInstructions(function.getBody(), true);
                    while (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        out.println("INSTRUCTION=" + instruction.getAddress() +
                            " SIZE=" + instruction.getLength() + " " + instruction);
                    }
                    CodeBlockIterator blocks =
                        new BasicBlockModel(currentProgram).getCodeBlocksContaining(function.getBody(), monitor);
                    while (blocks.hasNext()) {
                        CodeBlock block = blocks.next();
                        out.println("BLOCK=" + block.getMinAddress() + ".." + block.getMaxAddress());
                        CodeBlockReferenceIterator references = block.getDestinations(monitor);
                        while (references.hasNext()) {
                            CodeBlockReference reference = references.next();
                            out.println("EDGE=" + reference.getReferent() + " -> " +
                                reference.getDestinationAddress() + " TYPE=" + reference.getFlowType());
                        }
                    }
                    DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                    if (!result.decompileCompleted()) {
                        throw new IllegalStateException(result.getErrorMessage());
                    }
                    out.println(result.getDecompiledFunction().getC());
                }
            } finally {
                decompiler.dispose();
            }
            out.println("COMPLETE_PARAMBASE_EXPORT");
        }
    }
}
