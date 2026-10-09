// SHA-pinned targeted offline study; output must stay in private storage.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import java.io.*;
public class ParamListTargets extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length<1 || args.length>2 || !"8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
   throw new IllegalArgumentException("Requires private output and pinned 3.21 libObj.so");
  long[][] targets={{0x7eda8c,8},{0x7eda94,8},{0x7edab0,14},{0x7edabe,12},{0x7edaca,76},{0x42abcc,12},{0x42abdc,36},{0x42ac00,36},{0x42acd4,0x82},{0x120968,8},{0x120970,14},{0xfe9ae,8},{0xfe9b6,8},{0xfe9be,14},{0x7edb40,0x36},{0x7edc3e,42},{0x7edcc6,0x42},{0x7edd08,46},{0x7ededa,0x8c},{0x7ee0b8,0x2e},{0x7ee0e6,0x30}};
  if(args.length==2) {
   if(args[1].equals("lifecycle")) {
    targets=new long[][]{{0x7eda84,8},{0xe50b4,20},{0xf0fb0,32},{0xe50e8,32},{0x10f9fc,8},{0x426acc,8},{0xe4840,20},{0xf0f5c,20},{0xf0f2c,26},{0xe4750,26},{0x7edcc6,66},{0x7ededa,144},{0xff9c8,62},{0xffa3c,38},{0xe5128,38},{0xe7260,54},{0x7efb00,36},{0xff954,36},{0xff904,28},{0xe4774,28},{0xe7150,36},{0x7efb2c,36}};
   } else if(args[1].equals("event-manager-init")) {
    targets=new long[][]{{0x7ef894,0x4e}};
   } else if(args[1].equals("request-event-factory")) {
    targets=new long[][]{{0x7f0b0c,0x6c}};
   } else if(args[1].equals("event-core")) {
    targets=new long[][]{{0x7f17f8,0x34},{0x7f182c,0x20},{0x7f184c,0x2a},{0x7f1876,0x22},{0xf0f84,0x0e},{0x10d098,0x0e}};
   } else {
    throw new IllegalArgumentException("Unknown target profile");
   }
  }
  DecompInterface dec=new DecompInterface();
  try(PrintWriter out=new PrintWriter(new FileWriter(args[0]))) {
   out.println("IMAGE_BASE="+currentProgram.getImageBase()+" LANGUAGE="+currentProgram.getLanguageID());
   for(long[] target:targets){
    Address a=currentProgram.getImageBase().add(target[0]);
    Address end=a.add(target[1]-1);
    clearListing(a,end);
    currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),a,end,java.math.BigInteger.ONE);
    disassemble(a);
    Function f=getFunctionAt(a); if(f==null) f=createFunction(a,null);
    if(f==null) throw new IllegalStateException("No function at "+a);
    f.setBody(new AddressSet(a,end));
   }
   dec.openProgram(currentProgram);
   for(long[] target:targets){
    Address a=currentProgram.getImageBase().add(target[0]); Function f=getFunctionAt(a);
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
