// Targeted offline disassembly and decompilation; output belongs in private storage.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
public class CoreAbiTargets extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=1) throw new IllegalArgumentException("Private output path required");
  if(!"8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
   throw new IllegalArgumentException("Requires pinned official 3.21 libObj.so");
  try(PrintWriter out=new PrintWriter(new FileWriter(args[0]))) {
   out.println("image_base="+currentProgram.getImageBase());
   out.println("language="+currentProgram.getLanguageID());
   DecompInterface decompiler=new DecompInterface();
   try {
    // Relocation-confirmed PLT entries must not be decoded as Thumb function bodies.
    long[] stubs={0xdbd1cL,0xe2890L};
    String[] names={"_ZNK5Event12getParamListEv","_ZNK9ParamList3getEmm"};
    for(int i=0;i<stubs.length;i++) {
     Address stub=currentProgram.getImageBase().add(stubs[i]);
     clearListing(stub,stub.add(15));
     Function thunk=currentProgram.getFunctionManager().createFunction("relocation_thunk_"+i,stub,new AddressSet(stub,stub.add(15)),SourceType.USER_DEFINED);
     Function ext=currentProgram.getExternalManager().addExtFunction("relocation_verified_local_definition",names[i],null,SourceType.USER_DEFINED).getFunction();
     thunk.setThunkedFunction(ext);
    }
    decompiler.openProgram(currentProgram);
    for(long vma:new long[]{0x13200aL,0x42ac00L,0xfe9d4L,0xe5b20L,0xe5b18L}) {
     Address a=currentProgram.getImageBase().add(vma); out.println("ELF_VMA="+Long.toHexString(vma)+" GHIDRA_ADDRESS="+a);
     int length=vma==0x13200aL?14:vma==0x42ac00L?36:vma==0xe5b20L?14:8;
     clearListing(a,a.add(length-1));
     currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),a,a.add(length-1),java.math.BigInteger.ONE);
     disassemble(a); Function f=getFunctionAt(a);
     if(f==null) f=createFunction(a,null);
     if(f==null){out.println("UNRESOLVED_FUNCTION"); continue;}
     // These are manually reviewed target extents, not general function discovery.
     f.setBody(new AddressSet(a,a.add(length-1)));
     out.println("body="+f.getBody());
     InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
     int n=0; while(it.hasNext()&&n++<160) {Instruction ins=it.next();out.println(ins.getAddress()+" "+ins);}
     DecompileResults result=decompiler.decompileFunction(f,30,monitor);
     if(vma==0x13200aL || vma==0xe5b20L)
      out.println("DECOMPILATION_REJECTED: unanalysed interworking PLT tail-call; use relocation evidence");
     else if(result.decompileCompleted()) out.println(result.getDecompiledFunction().getC());
     else out.println("DECOMPILER_ERROR="+result.getErrorMessage());
    }
    out.println("COMPLETE_TARGET_EXPORT; decompiler types remain hypotheses");
   } finally {decompiler.dispose();}
  }
 }
}
