// SHA-pinned, metadata-only reference export for private offline analysis.
// It writes function/xref identities and addresses, never instruction bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ParamFamilyReferences extends GhidraScript {
 private String hex(Address a) {
  // Use numeric offsets only after the caller has selected the program's
  // address space.  Ghidra may represent the imported ELF image base and
  // entry points with distinct named spaces even when their offsets map
  // one-to-one.
  return Long.toHexString(a.getOffset() - currentProgram.getImageBase().getOffset());
 }

 private String safe(String value) {
  if (value == null) return "";
  return value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
 }

 private String kind(String name) {
  if (name.contains("::~")) return "DESTRUCTOR";
  if (name.contains("::Prm")) return "CONSTRUCTOR_CANDIDATE";
  return "METHOD_CANDIDATE";
 }

 public void run() throws Exception {
  String[] args = getScriptArgs();
  if (args.length != 1 ||
      !"8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
          .equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
   throw new IllegalArgumentException("requires one private output path and the pinned 3.21 libObj.so");
  }
  // These are ELF VMAs of the family constructors and destructor bodies
  // profiled by param_family_probe.py.  They are metadata targets only.
  long[] targetVmas = new long[]{
   0xe50e8, 0xf0fb0, 0xff9c8, 0xffa3c, 0xe5128, 0xe7260,
   0x7efb00, 0xecdb8, 0x11d681, 0x12c754,
   0x42acd4,
   0xe4750, 0xe4840, 0xf0f2c, 0xf0f5c, 0xff904, 0xff940,
   0xe4774, 0xe4868, 0xe7150, 0xe717c, 0x7efb2c, 0x7efb58,
   0xece65, 0x11d54d
  };
  ReferenceManager refs = currentProgram.getReferenceManager();
  try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
   out.println("PROGRAM_SHA256=" + currentProgram.getExecutableSHA256());
   out.println("IMAGE_BASE=" + currentProgram.getImageBase());
   out.println("LANGUAGE=" + currentProgram.getLanguageID());
   int xrefCount = 0;
   int functionCount = 0;
   for (long targetVma : targetVmas) {
    Address entry = currentProgram.getImageBase().add(targetVma);
    Function target = currentProgram.getFunctionManager().getFunctionAt(entry);
    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(entry);
    String targetName = symbol == null ? (target == null ? "UNKNOWN" : target.getName()) : symbol.getName(true);
    out.println("FUNCTION ELF_VMA=" + hex(entry) +
                " GHIDRA=" + entry +
                " NAME=" + safe(targetName) +
                " KIND=" + kind(targetName) +
                " BODY=" + (target == null ? "UNKNOWN" : safe(target.getBody().toString())));
    functionCount++;
    ReferenceIterator references = refs.getReferencesTo(entry);
    while (references.hasNext()) {
     Reference reference = references.next();
     Address from = reference.getFromAddress();
     Function caller = currentProgram.getFunctionManager().getFunctionContaining(from);
     out.println("XREF FROM_ELF_VMA=" + hex(from) +
                 " FROM_GHIDRA=" + from +
                 " TARGET_ELF_VMA=" + hex(entry) +
                 " REF_TYPE=" + reference.getReferenceType() +
                 " CALLER_ENTRY=" + (caller == null ? "UNKNOWN" : hex(caller.getEntryPoint())) +
                 " CALLER_NAME=" + (caller == null ? "UNKNOWN" : safe(caller.getName())) +
                 " ADDRESS_SPACE=" + from.getAddressSpace().getName());
     xrefCount++;
    }
   }
   out.println("FUNCTION_COUNT=" + functionCount);
   out.println("XREF_COUNT=" + xrefCount);
   out.println("COMPLETE_PARAM_FAMILY_REFERENCE_EXPORT");
  }
 }
}
