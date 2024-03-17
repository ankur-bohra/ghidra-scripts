//Find and deobfuscate strings obfuscated with character XOR keys stored in memory
//@author Ankur Bohra
//@category Analysis
//@keybinding 
//@menupath Analysis.Deobfuscate &XOR-obfuscated Strings
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.tablechooser.*;
import java.util.*;

public class FindDeobfuscateXORdStrings extends GhidraScript {
	record CharacterInfo(GenericAddress dataAddress, Address instructionAddress, char character) {
	}

	public void run() throws Exception {
		InstructionIterator iIter = currentProgram.getListing().getInstructions(true);
		AddressSet set = new AddressSet();
		Register currentArrayBaseRegister = null;
		int currentArrayOffset = -1;
		LinkedList<CharacterInfo> currentStringInfo = new LinkedList<>();
		ArrayList<List<CharacterInfo>> stringsInfo = new ArrayList<>();
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
					List<CharacterInfo> finalStringInfo = Collections
							.unmodifiableList(new LinkedList<>(currentStringInfo));
					stringsInfo.add(finalStringInfo);
					printf("[%s]: ", currentStringInfo.getFirst().dataAddress());
					for (CharacterInfo pair : currentStringInfo) {
						printf("%c", pair.character());
					}
					printf("\n");
				}
				currentStringInfo.clear();
			}
			currentArrayBaseRegister = arrayBaseRegister;
			currentArrayOffset = arrayOffset;
			currentStringInfo.add(new CharacterInfo(dataAddress, instruction.getAddress(), c));
			set.add(instruction.getMinAddress());
		}

		TableChooserDialog tableChooserDialog = createTableChooserDialog("Search results", new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Add hints";
			}

			private String fstringChar = "xs_\"%s\"_%c";
			private String fstringString = "xs_\"%s\"";
			// xs_"..."
			// xxs_"..." if the restricted character set had to be used
			@Override
			public boolean execute(AddressableRowObject rowObject) {
				CustomAddressableRowObject customRowObject = (CustomAddressableRowObject) rowObject;
				String s = customRowObject.getString().replaceAll("\\s", "_");
				for (CharacterInfo characterInfo : customRowObject.getStringInfo()) {
					GenericAddress dataAddress = characterInfo.dataAddress();
					char c = characterInfo.character();
					try {
						createLabel(dataAddress, fstringChar.formatted(s, c), false);
					} catch (Exception e) {
						String safe = fstringChar.formatted(s, c).replaceAll("[^\\w\\d!@#\\$%^\\&\\*\\(\\)_\\+\\-\\\\\\|\\[\\]{};',\\.\\/:\"<>\\?]", "_");
						safe = "x" + safe;
						try {
							createLabel(dataAddress, safe, false);
						} catch (Exception e1) {
							// This shouldn't happen
							e1.printStackTrace();
						}
					}
				}
				setPreComment(customRowObject.getMinInstructionAddress().subtract(1), "Loads " + fstringString.formatted(s));
				setPreComment(customRowObject.getMinDataAddress(), fstringString.formatted(s));
				setPostComment(customRowObject.getMaxDataAddress(), "(" + fstringString.formatted(s) + " ends)");
				return false;
			}

		});

		tableChooserDialog.addCustomColumn(new StringDisplay());
		tableChooserDialog.addCustomColumn(new MinDataAddressDisplay());
		tableChooserDialog.addCustomColumn(new MaxDataAddressDisplay());
		tableChooserDialog.addCustomColumn(new MinInstructionAddressDisplay());
		tableChooserDialog.addCustomColumn(new MaxInstructionAddressDisplay());
		
		for (List<CharacterInfo> stringInfo: stringsInfo) {
			tableChooserDialog.add(new CustomAddressableRowObject(stringInfo));
		}
		
		tableChooserDialog.show();
		return;
	}

	class CustomAddressableRowObject implements AddressableRowObject {
		private List<Address> dataAddresses = new ArrayList<>();
		private List<Address> instructionAddresses = new ArrayList<>();
		private List<CharacterInfo> characterInfo;
		private String string;

		public CustomAddressableRowObject(List<CharacterInfo> characterInfo) {
			this.characterInfo = new ArrayList<>(characterInfo);
			char[] charArray = new char[characterInfo.size()];
			int i = 0;
			for (CharacterInfo info : this.characterInfo) {
				dataAddresses.add(info.dataAddress());
				instructionAddresses.add(info.instructionAddress());
				charArray[i++] = info.character();
			}
			string = String.valueOf(charArray);
			Collections.sort(dataAddresses);
			Collections.sort(instructionAddresses);
		}

		@Override
		public Address getAddress() {
			//  Auto-generated method stub
			return getMinDataAddress();
		}

		public List<Address> getDataAddresses() {
			return Collections.unmodifiableList(dataAddresses);
		}

		public Address getMinDataAddress() {
			return dataAddresses.get(0);
		}

		public Address getMaxDataAddress() {
			return dataAddresses.get(dataAddresses.size() - 1);
		}

		public List<Address> getInstructionAddresses() {
			return Collections.unmodifiableList(instructionAddresses);
		}

		public Address getMinInstructionAddress() {
			return instructionAddresses.get(0);
		}

		public Address getMaxInstructionAddress() {
			return instructionAddresses.get(instructionAddresses.size() - 1);
		}

		public String getString() {
			return string;
		}

		public List<CharacterInfo> getStringInfo() {
			return Collections.unmodifiableList(characterInfo);
		}

	}

	class StringDisplay implements ColumnDisplay<String> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			CustomAddressableRowObject co1 = (CustomAddressableRowObject) o1;
			CustomAddressableRowObject co2 = (CustomAddressableRowObject) o2;
			return co1.getString().compareTo(co2.getString());
		}

		@Override
		public String getColumnValue(AddressableRowObject rowObject) {
			return ((CustomAddressableRowObject) rowObject).getString();
		}

		@Override
		public String getColumnName() {
			return "Deobfuscated string";
		}

		@Override
		public Class<String> getColumnClass() {
			return String.class;
		}

	}

	class MinDataAddressDisplay implements ColumnDisplay<Address> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return (((CustomAddressableRowObject) o1).getMinDataAddress())
					.compareTo(((CustomAddressableRowObject) o2).getMinDataAddress());
		}

		@Override
		public Address getColumnValue(AddressableRowObject rowObject) {
			return ((CustomAddressableRowObject) rowObject).getMinDataAddress();
		}

		@Override
		public String getColumnName() {
			return "Minimum data address";
		}

		@Override
		public Class<Address> getColumnClass() {
			return Address.class;
		}

	}

	class MaxDataAddressDisplay implements ColumnDisplay<Address> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return (((CustomAddressableRowObject) o1).getMaxDataAddress())
					.compareTo(((CustomAddressableRowObject) o2).getMaxDataAddress());
		}

		@Override
		public Address getColumnValue(AddressableRowObject rowObject) {
			return ((CustomAddressableRowObject) rowObject).getMaxDataAddress();
		}

		@Override
		public String getColumnName() {
			return "Maximum data address";
		}

		@Override
		public Class<Address> getColumnClass() {
			return Address.class;
		}

	}

	class MinInstructionAddressDisplay implements ColumnDisplay<Address> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return (((CustomAddressableRowObject) o1).getMinInstructionAddress())
					.compareTo(((CustomAddressableRowObject) o2).getMinInstructionAddress());
		}

		@Override
		public Address getColumnValue(AddressableRowObject rowObject) {
			return ((CustomAddressableRowObject) rowObject).getMinInstructionAddress();
		}

		@Override
		public String getColumnName() {
			return "Minimum instruction address";
		}

		@Override
		public Class<Address> getColumnClass() {
			return Address.class;
		}

	}

	class MaxInstructionAddressDisplay implements ColumnDisplay<Address> {

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return (((CustomAddressableRowObject) o1).getMaxInstructionAddress())
					.compareTo(((CustomAddressableRowObject) o2).getMaxInstructionAddress());
		}

		@Override
		public Address getColumnValue(AddressableRowObject rowObject) {
			return ((CustomAddressableRowObject) rowObject).getMaxInstructionAddress();
		}

		@Override
		public String getColumnName() {
			return "Maximum instruction address";
		}

		@Override
		public Class<Address> getColumnClass() {
			return Address.class;
		}

	}
}
