// SHA-pinned private metadata export; no firmware bytes or decompiler text.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Export caller identity metadata for exact ELF VMA targets.
 *
 * A reference is retained as a locator only.  Generated function names do not
 * establish source semantics, and an absent containing function is preserved
 * as UNKNOWN rather than assigned by nearest-address heuristics.
 */
public class TargetCallers extends GhidraScript {
    private static final String SHA =
        "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a";
    private static final String ANALYZER_VERSION = "target-callers-1";

    private static long parseVma(String value) {
        if (!value.startsWith("0x")) {
            throw new IllegalArgumentException("target VMA must use 0x prefix");
        }
        return Long.parseLong(value.substring(2), 16);
    }

    private long elfVma(Address address) {
        return address.getOffset() - currentProgram.getImageBase().getOffset();
    }

    private String symbolAt(Address address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        return symbol == null ? "UNKNOWN" : symbol.getName();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output path and at least one 0x VMA are required");
        }
        if (!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Requires pinned official 3.21 libObj.so");
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
            out.println("PROGRAM_SHA256=" + currentProgram.getExecutableSHA256());
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println("LANGUAGE=" + currentProgram.getLanguageID());
            out.println("ADDRESS_SPACE=" + currentProgram.getImageBase().getAddressSpace().getName());
            out.println("ANALYSIS_SCOPE=TARGET_CALLER_METADATA");
            out.println("ANALYZER_VERSION=" + ANALYZER_VERSION);
            long referenceCount = 0;
            for (int i = 1; i < args.length; i++) {
                long vma = parseVma(args[i]);
                Address target = currentProgram.getImageBase().add(vma);
                out.println("TARGET=0x" + Long.toHexString(vma)
                    + " GHIDRA=" + target + " SYMBOL=" + symbolAt(target));
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function caller = functions.getFunctionContaining(from);
                    String callerName = caller == null ? "UNKNOWN" : caller.getName();
                    String callerEntry = caller == null ? "UNKNOWN" : caller.getEntryPoint().toString();
                    String callerVma = caller == null
                        ? "UNKNOWN" : "0x" + Long.toHexString(elfVma(caller.getEntryPoint()));
                    String body = caller == null ? "UNKNOWN" : caller.getBody().toString();
                    out.println("XREF TARGET=0x" + Long.toHexString(vma)
                        + " FROM_GHIDRA=" + from
                        + " FROM_ELF_VMA=0x" + Long.toHexString(elfVma(from))
                        + " CALLER=" + callerName
                        + " CALLER_ENTRY_GHIDRA=" + callerEntry
                        + " CALLER_ENTRY_ELF_VMA=" + callerVma
                        + " CALLER_BODY=" + body
                        + " ADDRESS_SPACE=" + from.getAddressSpace().getName()
                        + " TYPE=" + ref.getReferenceType());
                    referenceCount++;
                }
            }
            out.println("TARGET_COUNT=" + (args.length - 1));
            out.println("REFERENCE_COUNT=" + referenceCount);
            out.println("COMPLETE_TARGET_CALLER_EXPORT");
        }
    }
}
