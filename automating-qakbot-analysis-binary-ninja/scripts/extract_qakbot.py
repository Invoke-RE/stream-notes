"""
Fingerprints, identifies resource decryption function
and extracts XOR key used to decrypt Qakbot DLL.

691bc000  uint64_t sub_691bc000()
691bc013      var_28_19
691bc013      __builtin_memset(s: &var_28_19, c: 0, n: 0x14)
691bc02b      char copied_alphabet
691bc02b      __builtin_strncpy(dest: &copied_alphabet, src: "@AlzsQ1DSS>I9XX7kB7M1MT3?CH8B1ggtV_!RTX0zJSbzmUYpW5H2n@o$", n: 0x3a)
691bc1cb      int16_t lpName = 0x3b4
691bc1d6      var_70_470
691bc1d6      __builtin_memset(s: &var_70_470, c: 0, n: 0x20)
"""
from binaryninja import HighLevelILOperation
from binaryninja import BinaryViewType
from binaryninja import commonil
import pefile, binascii
from sys import argv

def extract_resource(bin_path, identifier):
    pe = pefile.PE(bin_path)
    pe.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].struct.Name
    res_data = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for inner_entry in entry.directory.entries:
            if inner_entry.struct.Name == identifier:
                offset = inner_entry.struct.OffsetToData
                entire_mapped_image = pe.get_memory_mapped_image()
                print("Size of entire mapped image: {} and offset: {}".format(len(entire_mapped_image), offset))
                #res_data = pe.get_memory_mapped_image()[offset:offset+size-offset]
                break
    #print(binascii.hexlify(res_data[:256]))
    return res_data

def get_key(bv):
    print("Looking for decryption key...")
    key = None
    for f in bv.functions:
        key = get_key_from_func(f)
        if key:
            break
    return key

def get_key_from_func(f):
    needed_len = 5
    insts = []
    ci = 0
    #For some reason not all functions have instructions?
    try:
        f.hlil.instructions
    except:
        return None

    #TODO Do this with the generator index
    for e in f.hlil.instructions:
        insts.append(e)
        ci += 1
        if ci == needed_len:
            break
	#TODO do this at the highest bv level and use our length
	#heuristic to avoid all fingerprinting code.
    if len(insts) >= needed_len:
        if(check_ops(insts)):
            for inst in insts:
                inst.visit(visitor)

def visitor(_a, inst, _c, _d) -> bool:
    if isinstance(inst, commonil.Localcall):
        if len(inst.params) > 1:
            if inst.params[1].size > 25:
                key = inst.params[1].tokens[1]
                inst_index = 4
                rsrcid = None
                for index, inst in enumerate(inst.function.instructions):
                    if index == inst_index:
                        rsrcid = inst.operands[1].value.value
                        break
                print("Key: {} and Resource ID: {}".format(key, rsrcid))
        return False

# Check if these instructions are calls to memset and strncpy
# might be a brittle heuristic but need more than one sample
def check_ops(ops):
    return ops[1].operation == HighLevelILOperation.HLIL_CALL and \
    ops[3].operation == HighLevelILOperation.HLIL_CALL and \
    ops[1].operands[0].tokens[0].text == '__builtin_memset' and \
    ops[3].operands[0].tokens[0].text == '__builtin_strncpy'

if __name__ == '__main__':
    bin_path = argv[1]
    bv = BinaryViewType['PE'].open(argv[1])
    bv.update_analysis_and_wait()
    key = get_key(bv)
    #extract_resource(bin_path, 0x3b4) TODO: Fix this
