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
        monitor.initialize(listing.getNumCodeUnits());
        CodeUnitIterator i = listing.getCodeUnits(true);
        while (i.hasNext() && !monitor.isCancelled()) {
        	CodeUnit temp = i.next();
        	monitor.incrementProgress(1);
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
        		instr = listing.getInstructionAt(adrpAddr);
        		if(instr == null) {
        			return;
        		}
        		adrpValue = Long.decode(instr.getOpObjects(1)[0].toString());
        		if (addOperand.equals("add")) {
        			println("ADRP mnemonic address: "+ adrpAddr);
        			instr = listing.getInstructionAt(nextAddr);
        			if(instr == null) {
        				return;
        			}
        			nextAddrValue = Long.decode(instr.getOpObjects(2)[0].toString());
        		}else {
        			continue;
        		}
        		long refValue = adrpValue + nextAddrValue;
        		Address addr = parseAddress(Long.toHexString(refValue));
        		if(addr == null) {
        			return;
        		} 
        		temp.addOperandReference(1, addr , RefType.DATA, SourceType.DEFAULT);

        	}
        }
    }
}