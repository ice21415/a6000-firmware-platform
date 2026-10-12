// Metadata-only importer reference export.  No instruction bytes or
// decompiler text are written.  The script accepts a comma-separated list of
// exact symbol names and records every Ghidra reference to each matching
// symbol address, including the containing function when one is known.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

/**
 * Export references to exact imported/local symbols without assigning
 * semantic meaning to generated names.  This is intentionally independent of
 * any Sony class or symbol so it can be reused for other ELF dependencies.
 *
 * Arguments: output-path, comma-separated-symbol-names
 */
public class ImportedSymbolReferences extends GhidraScript {
    private PrintWriter out;
    private long records;

    private static String json(String value) {
        if (value == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String address(Address address) {
        return address == null ? null : String.format("0x%x", address.getOffset());
    }

    private long elfVma(Address address) {
        return address == null ? -1 : address.getOffset() - currentProgram.getImageBase().getOffset();
    }

    private static String elfAddress(long value) {
        return value < 0 ? null : String.format("0x%x", value);
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }

    private void emit(String kind, String fields) {
        out.printf("{\"kind\":%s,\"binary_sha256\":%s,%s}%n",
            json(kind), json(currentProgram.getExecutableSHA256()), fields);
        records++;
    }

    private Set<String> requested(String value) {
        Set<String> result = new HashSet<String>();
        for (String item : value.split(",")) {
            String name = item.trim();
            if (!name.isEmpty()) result.add(name);
        }
        return result;
    }

    private boolean matches(Set<String> requested, String raw, String qualified) {
        for (String item : requested) {
            if (item.equals(raw) || item.equals(qualified)) return true;
            if (item.startsWith("*") && item.endsWith("*") && item.length() > 2) {
                String needle = item.substring(1, item.length() - 1);
                if (raw.contains(needle) || qualified.contains(needle)) return true;
            } else if (item.endsWith("*") && raw.startsWith(item.substring(0, item.length() - 1))) {
                return true;
            } else if (item.startsWith("*") && raw.endsWith(item.substring(1))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Expected output path and one or more symbol names");
        }
        StringBuilder requestedNames = new StringBuilder();
        for (int i = 1; i < args.length; i++) {
            if (i > 1) requestedNames.append(',');
            requestedNames.append(args[i]);
        }
        Set<String> names = requested(requestedNames.toString());
        if (names.isEmpty()) throw new IllegalArgumentException("No symbol names requested");
        File file = new File(args[0]);
        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        out = new PrintWriter(new FileWriter(file, false));
        try {
            emit("metadata", String.format(
                "\"program\":%s,\"ghidra_version\":%s,\"language\":%s,\"compiler_spec\":%s,\"image_base\":%s,\"address_space\":%s,\"requested\":%s",
                json(currentProgram.getName()),
                json(getGhidraVersion()),
                json(currentProgram.getLanguage().getLanguageID().getIdAsString()),
                json(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
                json(address(currentProgram.getImageBase())),
                json(currentProgram.getAddressFactory().getDefaultAddressSpace().getName()),
                json(requestedNames.toString())));
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            Set<String> matched = new HashSet<String>();
            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();
                String name = symbol.getName();
                String qualified = symbol.getName(true);
                if (!matches(names, name, qualified)) continue;
                matched.add(name);
                Address target = symbol.getAddress();
                Function targetFunction = currentProgram.getFunctionManager().getFunctionAt(target);
                emit("symbol", String.format(
                    "\"name\":%s,\"qualified_name\":%s,\"ghidra_address\":%s,\"elf_vma\":%s,\"symbol_type\":%s,\"source\":%s,\"dynamic\":%s,\"namespace\":%s,\"target_function_entry_ghidra\":%s,\"target_function_entry_elf_vma\":%s",
                    json(name), json(qualified), json(address(target)), json(elfAddress(elfVma(target))),
                    json(symbol.getSymbolType().toString()),
                    json(symbol.getSource() == null ? null : symbol.getSource().toString()),
                    symbol.isDynamic() ? "true" : "false", json(safe(symbol.getParentNamespace().getName())),
                    json(targetFunction == null ? null : address(targetFunction.getEntryPoint())),
                    json(targetFunction == null ? null : elfAddress(elfVma(targetFunction.getEntryPoint())))));
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target);
                while (references.hasNext() && !monitor.isCancelled()) {
                    Reference reference = references.next();
                    Address from = reference.getFromAddress();
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(from);
                    emit("reference", String.format(
                        "\"symbol\":%s,\"target_address_ghidra\":%s,\"target_address_elf_vma\":%s,\"from_address_ghidra\":%s,\"from_address_elf_vma\":%s,\"reference_type\":%s,\"is_call\":%s,\"caller_entry_ghidra\":%s,\"caller_entry_elf_vma\":%s,\"caller_name\":%s,\"address_space\":%s,\"status\":%s",
                        json(name), json(address(target)), json(elfAddress(elfVma(target))),
                        json(address(from)), json(elfAddress(elfVma(from))),
                        json(reference.getReferenceType().toString()), reference.getReferenceType().isCall() ? "true" : "false",
                        json(caller == null ? null : address(caller.getEntryPoint())),
                        json(caller == null ? null : elfAddress(elfVma(caller.getEntryPoint()))),
                        json(caller == null ? null : safe(caller.getName())),
                        json(from.getAddressSpace().getName()),
                        json(caller == null ? "UNRESOLVED" : "PRIMARY_ELF_VERIFIED")));
                }
            }
            for (String name : names) {
                if (!matched.contains(name)) {
                    emit("unresolved_symbol", String.format("\"name\":%s,\"status\":\"UNRESOLVED\"", json(name)));
                }
            }
            out.printf("{\"kind\":\"complete\",\"binary_sha256\":%s,\"record_count\":%d,\"export_status\":\"complete\"}%n",
                json(currentProgram.getExecutableSHA256()), records);
        } finally {
            out.flush();
            out.close();
        }
    }
}
