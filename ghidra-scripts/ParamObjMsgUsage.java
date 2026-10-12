// SHA-pinned private metadata export; never publish the source ELF or raw bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Export only address/function/reference metadata for the PrmObjMsg payload
 * family.  This is deliberately separate from the bounded body profile: an
 * xref is a lead about a caller, not proof of ownership or C++ semantics.
 */
public class ParamObjMsgUsage extends GhidraScript {
    private static final String SHA =
        "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a";

    private static final long[][] TARGETS = new long[][] {
        {0x12c754L, 0}, // local PrmObjMsg constructor
        {0x12c77cL, 1}, // local getter
        {0x12c784L, 2}, // local clone slot
        {0xe2080L, 3},  // constructor PLT
        {0xddee4L, 4},  // getter PLT
        {0xe0388L, 5},  // ObjMsg copy-constructor PLT
        {0xddd94L, 6}   // ObjMsg destructor PLT
    };

    private static String kind(long kind) {
        switch ((int) kind) {
            case 0: return "PRMOBJMSG_CONSTRUCTOR_LOCAL";
            case 1: return "PRMOBJMSG_GETTER_LOCAL";
            case 2: return "PRMOBJMSG_CLONE_LOCAL";
            case 3: return "PRMOBJMSG_CONSTRUCTOR_PLT";
            case 4: return "PRMOBJMSG_GETTER_PLT";
            case 5: return "OBJMSG_COPY_CONSTRUCTOR_PLT";
            case 6: return "OBJMSG_DESTRUCTOR_PLT";
            default: return "UNKNOWN";
        }
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Private output path required");
        if (!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Requires pinned official 3.21 libObj.so");
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println("LANGUAGE=" + currentProgram.getLanguageID());
            long count = 0;
            for (long[] target : TARGETS) {
                long vma = target[0];
                Address address = currentProgram.getImageBase().add(vma);
                out.println("TARGET=0x" + Long.toHexString(vma) + " KIND=" + kind(target[1])
                    + " GHIDRA=" + address);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function caller = functions.getFunctionContaining(from);
                    String callerName = caller == null ? "UNKNOWN" : caller.getName();
                    String callerEntry = caller == null ? "UNKNOWN" : caller.getEntryPoint().toString();
                    out.println("XREF TARGET=0x" + Long.toHexString(vma)
                        + " FROM=" + from + " CALLER=" + callerName
                        + " CALLER_ENTRY=" + callerEntry
                        + " TYPE=" + ref.getReferenceType());
                    count++;
                }
            }
            out.println("XREF_COUNT=" + count);
            out.println("COMPLETE_USAGE_EXPORT");
        }
    }
}
