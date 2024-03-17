//Find and deobfuscate strings obfuscated with per-character XOR keys contiguously stored in memory
//@author Ankur Bohra
//@category Analysis
//@keybinding 
//@menupath Search.For XOR-obfuscated Strings
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindDeobfuscateXORdStrings extends GhidraScript {
	record AddressCharacterPair(GenericAddress address, char character) {
	}

	public void run() throws Exception {
		InstructionIterator iIter = currentProgram.getListing().getInstructions(true);
		AddressSet set = new AddressSet();
		Register currentArrayBaseRegister = null;
		int currentArrayOffset = -1;
		LinkedList<AddressCharacterPair> currentStringInfo = new LinkedList<>();
		while (iIter.hasNext()) {
			// 1. The current instruction is an XOR instruction
			Instruction instruction = iIter.next();
			boolean isXorInstruction = instruction.getMnemonicString().equals("XOR");
			boolean isScalarInstruction = OperandType.isScalar(instruction.getOperandType(1));
			boolean isRegisterInstruction = OperandType.isRegister(instruction.getOperandType(0));
			if (!(isXorInstruction && isScalarInstruction && isRegisterInstruction))
				continue;
			Scalar scalar = (Scalar) instruction.getOpObjects(1)[0];
			int xorKey = (int) scalar.getUnsignedValue();

			// 2. The previous instruction was a MOV-family instruction
			Instruction prevInstruction = instruction.getPrevious();
			boolean prevIsMovInstruction = prevInstruction.getMnemonicString().toUpperCase().startsWith("MOV");
			boolean prevIsRegisterInstruction = OperandType.isRegister(prevInstruction.getOperandType(0));
			if (!(prevIsMovInstruction && prevIsRegisterInstruction))
				continue;

			// 3. The previous instruction loaded the register used in the XOR instruction
			boolean prevMovToXorRegister = prevInstruction.getRegister(0).contains(instruction.getRegister(0));
			boolean prevMovFromDataAddress = OperandType.isDataReference(prevInstruction.getOperandType(1));
			if (!(prevMovToXorRegister && prevMovFromDataAddress))
				continue;
			GenericAddress dataAddress = (GenericAddress) prevInstruction.getOpObjects(1)[0];
			// dataAddress should exist since prevMovFromDataAddress passed
			Data data = getDataAt(dataAddress);
			scalar = (Scalar) data.getValue();
			int dataValue = (int) scalar.getUnsignedValue();

			// 4. The next address is a MOV-family instruction to an array like address
			Instruction nextInstruction = instruction.getNext();
			boolean nextIsMovInstruction = nextInstruction.getMnemonicString().toUpperCase().startsWith("MOV");
			Object[] nextMovOpObjects = nextInstruction.getOpObjects(0);

			boolean nextMovsToArrayLike = true
					// Array base register
					&& (nextMovOpObjects.length >= 1 && nextMovOpObjects[0].getClass().equals(Register.class))
					// Array offset
					&& (nextMovOpObjects.length != 2 || nextMovOpObjects[1].getClass().equals(Scalar.class))
					&& (nextMovOpObjects.length <= 2);
			if (!(nextIsMovInstruction && nextMovsToArrayLike))
				continue;
			Register arrayBaseRegister = (Register) nextInstruction.getOpObjects(1)[0];
			int arrayOffset = 0;
			if (nextMovOpObjects.length == 2) {
				scalar = (Scalar) nextInstruction.getOpObjects(0)[1];
				arrayOffset = (int) scalar.getUnsignedValue();
			}

			int decryptedValue = dataValue ^ xorKey;
			char c = (char) decryptedValue;
//			printf("%x ^ %x = %c\n", dataValue, xorKey, c);
			if (arrayBaseRegister != currentArrayBaseRegister || arrayOffset <= currentArrayOffset) {
				if (currentStringInfo.size() > 1) {
					printf("[%s]: ", currentStringInfo.getFirst().address());
					for (AddressCharacterPair pair : currentStringInfo) {
						printf("%c", pair.character());
					}
					printf("\n");					
				}
				currentStringInfo.clear();
				currentArrayBaseRegister = arrayBaseRegister;
				currentArrayOffset = arrayOffset;
			}
			currentStringInfo.add(new AddressCharacterPair(dataAddress, c));
			set.add(instruction.getMinAddress());
		}
		Address[] addresses = new Address[set.getNumAddressRanges()];
		int i = 0;
		for (AddressRange range : set) {
			addresses[i++] = range.getMinAddress();
		}
		this.show(addresses);
		return;
	}

}
