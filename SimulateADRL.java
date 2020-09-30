//Script simulate ADRL instruction combining ADRP and ADD and fix string reference issues
//@author Grzegorz Wypych (h0rac)
//@category Processor AARCH (ARM64 v8)
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;

public class SimulateADRL extends GhidraScript {

    public void run() throws Exception {
    
    adrlSimulate();

   }
    

    private void adrlSimulate() {
        Listing listing = currentProgram.getListing();
        Address adrpAddr = null;
        Address nextAddr = null;
        Instruction instr = null;
        CodeUnit codeUnit = null;
        
        for (CodeUnitIterator i = listing.getCodeUnits(true); i.hasNext();) {
        	CodeUnit temp = i.next();
           	long adrpValue = 0;
        	long nextAddrValue = 0;
            if(temp.getMnemonicString().equals("adrp")) {
            	adrpAddr = temp.getAddress();
            	nextAddr = temp.getMaxAddress().add(1);
            	
        		codeUnit = currentProgram.getListing().getCodeUnitAt(nextAddr);
        		if(codeUnit == null) {
        			return;
        		}
        		String addOperand = codeUnit.getMnemonicString();
        		if (addOperand.equals("add")) {
        			int numOperands = codeUnit.getNumOperands();
        			int adrpOperands = temp.getNumOperands();
                	println("Address: "+ adrpAddr);
                	println("ARM64 mnemonic 1: "+ temp.getMnemonicString());
            		println("ARM64 mnemonic 1 operands number: "+adrpOperands);
                	println("Next Addr: "+nextAddr);
        			println("ARM64 mnemonic 2: "+addOperand);
        			println("ARM64 mnemonic 2 operands number: "+numOperands);
                	instr = listing.getInstructionAt(adrpAddr);
                	if(instr == null) {
                		return;
                	}
                    adrpValue = Long.decode(instr.getOpObjects(1)[0].toString());
                    println("adrp value: "+Long.toHexString(adrpValue));
                	instr = listing.getInstructionAt(nextAddr);
                	if(instr == null) {
                		return;
                	}
                	nextAddrValue = Long.decode(instr.getOpObjects(2)[0].toString());
                	println("add value: "+Long.toHexString(nextAddrValue));
              
        		}else {
        			continue;
        		}
            	long refValue = adrpValue + nextAddrValue;
            	Address addr = parseAddress(Long.toHexString(refValue));
            	if(addr == null) {
            		return;
            	}
            	println("refValue : "+Long.toHexString(refValue));
            	println("Reference addr : "+ addr.toString());
        		temp.addOperandReference(1, addr , RefType.DATA, SourceType.DEFAULT);
        		
            }
         }
    }
}