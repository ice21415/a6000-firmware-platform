// SHA-pinned targeted offline study; output must stay in private storage.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import java.io.*;
import java.util.*;
public class ParamListTargets extends GhidraScript {
 private void clearOverlappingFunctions(Address start, Address end) {
  FunctionManager manager=currentProgram.getFunctionManager();
  ArrayList<Address> entries=new ArrayList<Address>();
  Iterator<Function> it=manager.getFunctionsOverlapping(new AddressSet(start,end));
  while(it.hasNext()) entries.add(it.next().getEntryPoint());
  for(Address entry:entries) manager.removeFunction(entry);
 }
 private Function prepareFunction(Address a, Address end) throws Exception {
  clearListing(a,end);
  clearOverlappingFunctions(a,end);
  currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),a,end,java.math.BigInteger.ONE);
  disassemble(a);
  Function f=getFunctionAt(a); if(f==null) f=createFunction(a,null);
  if(f==null) throw new IllegalStateException("No function at "+a);
  f.setBody(new AddressSet(a,end));
  return f;
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length<1 || args.length>2 || !"8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
   throw new IllegalArgumentException("Requires private output and pinned 3.21 libObj.so");
  long[][] targets={{0x7eda8c,8},{0x7eda94,8},{0x7edab0,14},{0x7edabe,12},{0x7edaca,76},{0x42abcc,12},{0x42abdc,36},{0x42ac00,36},{0x42acd4,0x82},{0x120968,8},{0x120970,14},{0xfe9ae,8},{0xfe9b6,8},{0xfe9be,14},{0x7edb40,0x36},{0x7edc3e,42},{0x7edcc6,0x42},{0x7edd08,46},{0x7ededa,0x8c},{0x7ee0b8,0x2e},{0x7ee0e6,0x30}};
  if(args.length==2) {
   if(args[1].equals("lifecycle")) {
    targets=new long[][]{{0x7eda84,8},{0xe50b4,20},{0xf0fb0,32},{0xe50e8,32},{0x10f9fc,8},{0x426acc,8},{0xe4840,20},{0xf0f5c,20},{0xf0f2c,26},{0xe4750,26},{0x7edcc6,66},{0x7ededa,144},{0xff9c8,62},{0xffa3c,38},{0xe5128,38},{0xe7260,54},{0x7efb00,36},{0xff954,36},{0xff904,28},{0xe4774,28},{0xe7150,36},{0x7efb2c,36}};
   } else if(args[1].equals("event-manager-init")) {
    targets=new long[][]{{0x7ef894,0x4e},{0x7f09be,0x14},{0x7f09d2,0x60},
      {0x111178,0x0a},{0x1111a2,0x0c},
      {0x1111ac,0x0c},{0x1111b8,0x14},{0x1111cc,0x0e},{0x111438,0x1a},
      {0x111460,0x0e},{0x1114b0,0x14},{0x111234,0x18},{0x111264,0x1a},
      {0x7ea7dc,0x10},{0x7ea7ec,0x0c}};
   } else if(args[1].equals("event-manager-count")) {
    targets=new long[][]{{0x7ef8f4,0x0e},{0x7ef902,0x0e},{0x7ef9fc,0x22},
      {0x7f0962,0x08},{0x7f096a,0x1a},{0x7f0984,0x18},
      {0x7f0a32,0x10},{0x7f0a42,0x0c},{0x7f0a4e,0x2c},
      {0x7f0a7a,0x0a},{0x7f0a84,0x1c},{0x7f0aa0,0x0c}};
   } else if(args[1].equals("event-manager-destroy")) {
    targets=new long[][]{{0x7ef3a8,0x2c},{0x7ef3d8,0x6e},{0x7efa1e,0x4c},
      {0x7ef8f4,0x0e},{0x7ef902,0x0e},{0x7f09d2,0x60}};
   } else if(args[1].equals("event-manager-owner-init")) {
    targets=new long[][]{{0x7ef254,0x88},{0x7ef894,0x4e},{0x7ef3d8,0x6e},{0x7efa1e,0x4c}};
   } else if(args[1].equals("event-manager-constructor")) {
    targets=new long[][]{{0x7ef1e4,0x5c},{0x7ef254,0x128},{0x7ef894,0x4e},
      {0x7ef960,0x9c},{0x7ef9fc,0x22}};
   } else if(args[1].equals("paramlist-lifetime")) {
    targets=new long[][]{{0x7edb32,0x08},{0x7edb40,0x36},{0x7edb76,0x0c},
      {0x7edc14,0x0e},{0x7edc22,0x0e},{0x7edc30,0x0e},{0x7edc3e,0x2a},
      {0x7edca2,0x16},{0x7edcb8,0x0e},{0x7edcc6,0x42},{0x7edd08,0x2e}};
   } else if(args[1].equals("paramlist-owner-use")) {
    targets=new long[][]{{0x114104,0x164},{0x7edcc6,0x42},{0x7edc3e,0x2a},
      {0x7ee0e6,0x30},{0xf0fb0,0x20},{0x7edd08,0x2e}};
   } else if(args[1].equals("request-event-factory")) {
    targets=new long[][]{{0x7f0b0c,0x6c}};
   } else if(args[1].equals("event-core")) {
    targets=new long[][]{{0x7f17f8,0x34},{0x7f182c,0x20},{0x7f184c,0x2a},{0x7f1876,0x22},{0xf0f84,0x0e},{0x10d098,0x0e}};
   } else if(args[1].equals("param-set")) {
     targets=new long[][]{{0x7efae8,0x08},{0x7efaf0,0x0e},{0x7efb00,0x24},{0x7efb2c,0x20},{0x7efb58,0x14},{0x7efb6c,0x40},{0x7efbb4,0x24},{0xffc40,0x08},{0xffc60,0x08},{0xffc68,0x08},{0xffc70,0x08},{0xffccc,0x08},{0xffcd4,0x08},{0xffcdc,0x08},{0xffce4,0x10},{0xffcf6,0x1e},{0xffd22,0x0e},{0xffd80,0x30},{0xffe1c,0x1a},{0xffe4c,0x24},{0xecd7a,0x0c},{0xefe6c,0x12},{0xffe70,0x60},{0xffed0,0xe6},{0x63e796,0x1a},{0x63e83a,0x6c},{0x63e8a6,0x0e},{0xffe0c,0x0e}};
    } else if(args[1].equals("param-set-exceptions")) {
     // Keep normal bodies and unreachable landing-pad regions separate so
     // Ghidra disassembles the cleanup instructions as independent bounded
     // functions.  This profile is for private cross-checks; it emits
     // metadata, never firmware bytes.
     targets=new long[][]{{0x7efb6c,0x30},{0x7efb9c,0x10},{0x7efbb4,0x1c},{0x7efbce,0x0c}};
   } else if(args[1].equals("param-set-callers")) {
    targets=new long[][]{{0x7f4390,0x13e},{0x7f44ce,0x4c},{0xfffb6,0x30},{0xffe70,0x60},{0xffed0,0xe6}};
   } else if(args[1].equals("param-pair")) {
    targets=new long[][]{{0xffa3c,0x2a},{0xff904,0x1a},{0xff940,0x14},{0xffa70,0x1c},{0xe5128,0x2a},{0xe4774,0x1a},{0xe4868,0x14},{0xe515c,0x1a}};
   } else if(args[1].equals("param-string")) {
    targets=new long[][]{{0xff9c8,0x3e},{0xff954,0x2c},{0xff980,0x14},{0xffa18,0x18}};
   } else if(args[1].equals("param-objmsg")) {
    targets=new long[][]{{0x12c700,0x34},{0x12c740,0x14},{0x12c754,0x28},{0x12c77c,0x08},{0x12c784,0x34}};
   } else if(args[1].equals("param-struct")) {
    targets=new long[][]{{0xe7260,0x34},{0xe7150,0x20},{0xe717c,0x14},{0xe72a0,0x18}};
   } else if(args[1].equals("param-cntinfolist")) {
    targets=new long[][]{{0x11d42c,0x16},{0x11d44c,0x0e},{0x11d45a,0x0e},{0x11d4ac,0x10},{0x11d4bc,0x10},{0x11d4cc,0x0e},{0x11d4da,0x0e},{0x11d47e,0x20},{0xe77a2,0x14},{0x11d468,0x16},{0xe7e86,0x20},{0x11d8e6,0x28},{0x11d8b0,0x36},{0xecd7a,0x0c},{0x11d90e,0x28},{0x11d82e,0x82},{0x11d72a,0x104},{0x11d680,0x54},{0x11d938,0x78},{0x11da18,0x64},{0x11d54c,0x44},{0x11d590,0x14}};
   } else {
    throw new IllegalArgumentException("Unknown target profile");
   }
  }
  DecompInterface dec=new DecompInterface();
  try(PrintWriter out=new PrintWriter(new FileWriter(args[0]))) {
   String profile=args.length>=2 ? args[1] : "default";
   out.println("PROFILE="+profile);
   out.println("PROGRAM_SHA256="+currentProgram.getExecutableSHA256());
   out.println("IMAGE_BASE="+currentProgram.getImageBase()+" LANGUAGE="+currentProgram.getLanguageID());
   out.println("COMPILER_SPEC="+currentProgram.getCompilerSpec().getCompilerSpecID());
   out.println("ADDRESS_SPACE="+currentProgram.getAddressFactory().getDefaultAddressSpace().getName());
   for(long[] target:targets){
    Address a=currentProgram.getImageBase().add(target[0]);
    Address end=a.add(target[1]-1);
    prepareFunction(a,end);
   }
   dec.openProgram(currentProgram);
   for(long[] target:targets){
    Address a=currentProgram.getImageBase().add(target[0]); Function f=getFunctionAt(a);
    if(f==null) f=prepareFunction(a,a.add(target[1]-1));
    out.println("ELF_VMA="+Long.toHexString(target[0])+" GHIDRA="+a+" BODY="+f.getBody());
    InstructionIterator instructions=currentProgram.getListing().getInstructions(f.getBody(),true);
    while(instructions.hasNext()){Instruction ins=instructions.next();out.println(ins.getAddress()+" SIZE="+ins.getLength()+" "+ins);}
    CodeBlockIterator blocks=new BasicBlockModel(currentProgram).getCodeBlocksContaining(f.getBody(),monitor);
    while(blocks.hasNext()) {
     CodeBlock block=blocks.next();out.println("BLOCK="+block.getMinAddress()+".."+block.getMaxAddress());
     CodeBlockReferenceIterator refs=block.getDestinations(monitor);
     while(refs.hasNext()){CodeBlockReference ref=refs.next();out.println("EDGE="+ref.getReferent()+" -> "+ref.getDestinationAddress()+" TYPE="+ref.getFlowType());}
    }
    DecompileResults result=dec.decompileFunction(f,30,monitor);
    if(!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
    out.println(result.getDecompiledFunction().getC());
   }
   out.println("COMPLETE_TARGET_EXPORT");
  } finally {dec.dispose();}
 }
}
