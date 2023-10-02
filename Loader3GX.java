//@author Hidegon
//@category 3ds 3gx
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.util.demangler.*;

public class Loader3GX extends GhidraScript {

    private int byte_array_to_int(byte[] bytes) {
        int value = 0;
        for (int i = 0; i < bytes.length; i++) {
            value |= (bytes[i] & 0xFF) << (8*i);
        }
        return value;
    }

    private int read32(int offset) throws Exception {
        Memory memory = getState().getCurrentProgram().getMemory();
        Address target_offset = toAddr(offset);
        byte[] value_bytes = new byte[4];
        int read_bytes = memory.getBytes(target_offset, value_bytes);
        if (read_bytes == value_bytes.length) {
            return byte_array_to_int(value_bytes);
        }
        else {
            return -1;
        }
    }

    private int read8(int offset) throws Exception {
        Memory memory = getState().getCurrentProgram().getMemory();
        Address target_offset = toAddr(offset);
        byte[] value_bytes = new byte[1];
        int read_bytes = memory.getBytes(target_offset, value_bytes);
        if (read_bytes == value_bytes.length) {
            return byte_array_to_int(value_bytes);
        }
        else {
            return -1;
        }
    }

    private Function get_function_by_address(Address address) {
        FunctionManager functionManager = getState().getCurrentProgram().getFunctionManager();
        return functionManager.getFunctionAt(address);
    }

    private int address_to_file_offset(int address) throws Exception {
        return address - 0x7000100 + read32(88);
    }

    public void run() throws Exception {
        Program current_program = getState().getCurrentProgram();
        int symbol_offset = read32(140);
        int name_table_offset = read32(144);
        int symbol_count = read32(136);
        int name_offset = 0;
        int function_address = 0;
        String symbol_name = "";
        for (int i = 0; i < symbol_count*12; i += 12) {
            function_address = read32(symbol_offset + i);
            name_offset = read32(symbol_offset + i + 8);
            symbol_name = "";
            for (int j = name_table_offset + name_offset; j < name_table_offset + name_offset + 0xFF; j++) {
                symbol_name += Character.toString((char)read8(j));
                if (read8(j) == 0) {
                    DemangledObject demangled_object = DemanglerUtil.demangle(symbol_name);
                    if (demangled_object != null) {
                        String demangled_name = demangled_object.getNamespaceString();
                        Function function = get_function_by_address(toAddr(address_to_file_offset(function_address)));
                        if (function != null ) {
                            try {
                                function.setName(demangled_name, SourceType.ANALYSIS);
                            } catch (Exception e) { }
                        }
                    }
                    break;
                }
            }
        }
    }
}
