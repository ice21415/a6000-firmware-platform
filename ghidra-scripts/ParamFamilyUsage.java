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
import java.util.List;

/**
 * Reusable constructor-usage index for the ParamBase family catalog.
 * Constructor names/addresses are evidence locators only; this script does
 * not assign source-level semantics to generated caller labels.
 */
public class ParamFamilyUsage extends GhidraScript {
    private static final String SHA =
        "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a";

    private static final String[][] PROFILES = new String[][] {
        {"PrmBool", "0xe50e8", ""},
        {"PrmNumber", "0xf0fb0", ""},
        {"PrmString", "0xff9c8", ""},
        {"PrmPoint", "0xffa3c", ""},
        {"PrmDimension", "0xe5128", ""},
        {"PrmStruct", "0xe7260", ""},
        {"PrmSet", "0x7efb00", ""},
        {"PrmNumberList", "", "_ZN13PrmNumberListC1Ev"},
        {"PrmCntInfoList", "", "_ZN14PrmCntInfoListC1Ev"},
        {"PrmObjMsg", "0x12c754", "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE"}
    };

    private static long parseVma(String value) {
        return Long.parseLong(value.substring(2), 16);
    }

    private long elfVma(Address address) {
        return address.getOffset() - currentProgram.getImageBase().getOffset();
    }

    private Address symbolAddress(String name) {
        if (name == null || name.length() == 0) return null;
        List<Symbol> symbols = currentProgram.getSymbolTable().getGlobalSymbols(name);
        for (Symbol symbol : symbols) {
            if (symbol.getAddress() != null) return symbol.getAddress();
        }
        return null;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Private output path required");
        if (!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Requires pinned official 3.21 libObj.so");
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        long familyCount = 0;
        long xrefCount = 0;
        try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
            out.println("PROGRAM_SHA256=" + currentProgram.getExecutableSHA256());
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println("LANGUAGE=" + currentProgram.getLanguageID());
            out.println("ADDRESS_SPACE=" + currentProgram.getImageBase().getAddressSpace().getName());
            out.println("ANALYSIS_SCOPE=PARAMBASE_CONSTRUCTOR_XREF_METADATA");
            for (String[] profile : PROFILES) {
                String family = profile[0];
                Address target = symbolAddress(profile[2]);
                String locator = "SYMBOL";
                if (target == null && profile[1].length() != 0) {
                    target = currentProgram.getImageBase().add(parseVma(profile[1]));
                    locator = "ELF_VMA";
                }
                familyCount++;
                if (target == null) {
                    out.println("FAMILY=" + family + " STATUS=UNRESOLVED SYMBOL=" + profile[2]);
                    continue;
                }
                long vma = elfVma(target);
                out.println("FAMILY=" + family + " TARGET=0x" + Long.toHexString(vma)
                    + " LOCATOR=" + locator + " SYMBOL=" + profile[2]);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function caller = functions.getFunctionContaining(from);
                    String callerName = caller == null ? "UNKNOWN" : caller.getName();
                    String callerEntry = caller == null ? "UNKNOWN" : caller.getEntryPoint().toString();
                    String callerEntryVma = caller == null
                        ? "UNKNOWN" : "0x" + Long.toHexString(elfVma(caller.getEntryPoint()));
                    out.println("XREF FAMILY=" + family + " TARGET=0x" + Long.toHexString(vma)
                        + " FROM_GHIDRA=" + from
                        + " FROM_ELF_VMA=0x" + Long.toHexString(elfVma(from))
                        + " CALLER=" + callerName
                        + " CALLER_ENTRY_GHIDRA=" + callerEntry
                        + " CALLER_ENTRY_ELF_VMA=" + callerEntryVma
                        + " ADDRESS_SPACE=" + from.getAddressSpace().getName()
                        + " TYPE=" + ref.getReferenceType());
                    xrefCount++;
                }
            }
            out.println("FAMILY_COUNT=" + familyCount);
            out.println("XREF_COUNT=" + xrefCount);
            out.println("COMPLETE_FAMILY_USAGE_EXPORT");
        }
    }
}
