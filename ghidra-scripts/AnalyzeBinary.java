/* Stable, evidence-oriented Ghidra export for one imported program. */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class AnalyzeBinary extends GhidraScript {
    private PrintWriter out;
    private String runId;
    private String sha256;
    private String ghidraVersion;
    private long recordsWritten;

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

    private static String bytes(Instruction instruction) {
        try {
            byte[] raw = instruction.getBytes();
            StringBuilder b = new StringBuilder();
            for (byte value : raw) b.append(String.format("%02x", value & 0xff));
            return b.toString();
        } catch (Exception ignored) {
            return "";
        }
    }

    private String instructionMode(Address address) {
        try {
            ghidra.program.model.lang.Register tmode = currentProgram.getLanguage().getRegister("TMode");
            if (tmode != null) {
                BigInteger value = currentProgram.getProgramContext().getValue(tmode, address, false);
                if (value != null) return value.testBit(0) ? "Thumb" : "ARM";
            }
        } catch (Exception ignored) {
            // Some processors do not expose a mode register; retain UNKNOWN.
        }
        return "UNKNOWN";
    }

    private void emit(String kind, String fields) {
        out.printf("{\"kind\":%s,\"run_id\":%s,\"binary_sha256\":%s,%s}%n",
            json(kind), json(runId), json(sha256), fields);
        recordsWritten++;
    }

    private void emitComplete() {
        out.printf("{\"kind\":\"complete\",\"run_id\":%s,\"binary_sha256\":%s,\"record_count\":%d,\"export_status\":\"complete\"}%n",
            json(runId), json(sha256), recordsWritten);
    }

    private String programIdentity() {
        Program p = currentProgram;
        String language = p.getLanguage().getLanguageID().getIdAsString();
        String compiler = p.getCompilerSpec().getCompilerSpecID().getIdAsString();
        return String.format("{\"program\":%s,\"language\":%s,\"compiler_spec\":%s,\"image_base\":%s,\"address_space\":%s}",
            json(p.getName()), json(language), json(compiler), json(address(p.getImageBase())),
            json(p.getAddressFactory().getDefaultAddressSpace().getName()));
    }

    private void exportFunction(Function f) {
        String prototype;
        try { prototype = f.getSignature().getPrototypeString(); }
        catch (Exception e) { prototype = ""; }
        emit("function", String.format("\"entry_vma\":%s,\"name\":%s,\"prototype\":%s,\"body_bytes\":%d,\"generated\":%s,\"confidence\":\"VERIFIED_STATIC\"",
            json(address(f.getEntryPoint())), json(f.getName()), json(prototype), f.getBody().getNumAddresses(),
            f.getSymbol().isDynamic() ? "true" : "false"));
        AddressRangeIterator ranges = f.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            emit("function_body_range", String.format("\"function_entry\":%s,\"start_vma\":%s,\"end_vma\":%s,\"address_space\":%s,\"status\":\"VERIFIED_STATIC\"",
                json(address(f.getEntryPoint())), json(address(range.getMinAddress())),
                json(address(range.getMaxAddress())),
                json(currentProgram.getAddressFactory().getDefaultAddressSpace().getName())));
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "ghidra-analysis.jsonl";
        runId = args.length > 1 ? args[1] : "ghidra-unknown-run";
        sha256 = args.length > 2 ? args[2] : "";
        ghidraVersion = args.length > 3 ? args[3] : "unknown";
        File file = new File(output);
        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        out = new PrintWriter(new FileWriter(file, false));
        try {
            emit("metadata", String.format("\"program_identity\":%s,\"analyzer\":\"ghidra_headless\",\"analyzer_version\":%s,\"confidence\":\"VERIFIED_STATIC\"", programIdentity(), json(ghidraVersion)));
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) exportFunction(functions.next());

            Listing listing = currentProgram.getListing();
            FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
            while (functionIterator.hasNext() && !monitor.isCancelled()) {
                Function function = functionIterator.next();
                InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructions.next();
                    String from = address(instruction.getAddress());
                    emit("instruction", String.format("\"function_entry\":%s,\"address\":%s,\"mnemonic\":%s,\"operands\":%s,\"bytes_hex\":%s,\"mode\":%s,\"confidence\":\"VERIFIED_STATIC\"",
                        json(address(function.getEntryPoint())), json(from), json(instruction.getMnemonicString()),
                        json(instruction.toString()), json(bytes(instruction)), json(instructionMode(instruction.getAddress()))));
                    for (Reference reference : instruction.getReferencesFrom()) {
                        Address target = reference.getToAddress();
                        Function callee = currentProgram.getFunctionManager().getFunctionContaining(target);
                        RefType type = reference.getReferenceType();
                        String kind = type.isCall() ? (callee == null ? "indirect_call_candidate" : "direct_call") :
                                      (type.isData() ? "data_reference" : "control_flow");
                        emit(type.isCall() ? "callsite" : "cross_reference", String.format(
                            "\"function_entry\":%s,\"from_address\":%s,\"to_address\":%s,\"target\":%s,\"callee_entry\":%s,\"address_space\":%s,\"relation_kind\":%s,\"status\":%s,\"confidence\":\"VERIFIED_STATIC\"",
                            json(address(function.getEntryPoint())),
                            json(from), json(address(target)), json(callee == null ? null : callee.getName()),
                            json(callee == null ? null : address(callee.getEntryPoint())),
                            json(currentProgram.getAddressFactory().getDefaultAddressSpace().getName()), json(kind),
                            json(callee == null && type.isCall() ? "CANDIDATE" : "VERIFIED_STATIC")));
                    }
                }
            }

            BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = blockModel.getCodeBlocks(monitor);
            while (blocks.hasNext() && !monitor.isCancelled()) {
                CodeBlock block = blocks.next();
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(block.getFirstStartAddress());
                emit("basic_block", String.format("\"function_entry\":%s,\"start_vma\":%s,\"end_vma\":%s,\"confidence\":\"VERIFIED_STATIC\"",
                    json(owner == null ? null : address(owner.getEntryPoint())), json(address(block.getFirstStartAddress())),
                    json(address(block.getMaxAddress()))));
                CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                while (destinations.hasNext() && !monitor.isCancelled()) {
                    CodeBlockReference destination = destinations.next();
                    CodeBlock targetBlock = destination.getDestinationBlock();
                    if (targetBlock == null) continue;
                    emit("cfg_edge", String.format("\"function_entry\":%s,\"from_address\":%s,\"to_address\":%s,\"source_instruction\":%s,\"edge_kind\":%s,\"address_space\":%s,\"confidence\":\"VERIFIED_STATIC\"",
                        json(owner == null ? null : address(owner.getEntryPoint())),
                        json(address(block.getFirstStartAddress())), json(address(targetBlock.getFirstStartAddress())),
                        json(address(destination.getSourceAddress())),
                        json(destination.getFlowType() == null ? "control_flow" : destination.getFlowType().toString()),
                        json(currentProgram.getAddressFactory().getDefaultAddressSpace().getName())));
                }
            }

            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();
                SourceType source = symbol.getSource();
                emit("symbol", String.format("\"name\":%s,\"address\":%s,\"symbol_type\":%s,\"source\":%s,\"dynamic\":%s,\"confidence\":\"VERIFIED_STATIC\"",
                    json(symbol.getName()), json(address(symbol.getAddress())), json(symbol.getSymbolType().toString()),
                    json(source == null ? null : source.toString()), symbol.isDynamic() ? "true" : "false"));
                if (symbol.getName().toLowerCase().contains("vtable")) {
                    emit("vtable_candidate", String.format("\"address\":%s,\"symbol\":%s,\"status\":\"CANDIDATE\",\"confidence\":\"CANDIDATE\"",
                        json(address(symbol.getAddress())), json(symbol.getName())));
                }
            }
            if (!monitor.isCancelled()) emitComplete();
        } finally {
            out.flush();
            out.close();
        }
    }
}
