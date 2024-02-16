import struct
import zlib
import json
import sys
import re
from binaryninja.types import SymbolType
from binaryninja.enums import SymbolBinding 
from binaryninja import BinaryViewType

def decrypt_mod_name(module_ct_bytes, offset, xor_key):
    offset_mod = offset * 0x21
    module_name_length = module_ct_bytes[offset_mod]
    module_name_ct = module_ct_bytes[offset_mod+1:offset_mod+1+module_name_length]
    rbytes = bytes()
    xoff = 0
    for i, b in enumerate(module_name_ct):
        rbytes += (b ^ xor_key[i & 3]).to_bytes(1, byteorder='little')

    return rbytes.decode('ascii')

def gen_dll_hash_table(dllname, hash_xor):
    dbv = BinaryViewType['PE'].open("dependencies/{}".format(dllname))
    dbv.update_analysis_and_wait()
    table = {}
    for symbol in dbv.get_symbols_of_type(SymbolType.FunctionSymbol):
        if symbol.binding is SymbolBinding.GlobalBinding or symbol.binding is SymbolBinding.WeakBinding:
            tmp_symbol = re.sub("Stub", "", symbol.full_name)
            rhash = zlib.crc32(bytes(tmp_symbol, 'ascii')) ^ hash_xor
            table[rhash] = tmp_symbol
    return table

def generate_header(resolved_hashes, hash_table_addr):
    rstr = bytes()
    rstr += b"struct hashes_%x {" % hash_table_addr
    for k, v in resolved_hashes.items():
        rstr += bytes("int32_t {}; ".format(k, v), 'ascii')
    rstr += b"};"
    return rstr.decode('ascii')

def resolve_hash_tables(bv, module_ct_bytes, xor_key_bytes, hash_xor, import_res_addr):
    resolved_hashes = {}
    import_resolution_func = bv.get_function_at(import_res_addr)
    for call_site in import_resolution_func.caller_sites:
        tokens = call_site.hlil.tokens
        hash_table_addr = tokens[3].value
        offset = tokens[7].value
        #This shift is done in the code
        hash_table_size = (tokens[5].value >> 3) * 4
        
        dllname = decrypt_mod_name(module_ct_bytes, offset, xor_key_bytes)
        print("Resolving hashes for: %s from hash table at: 0x%x with size: 0x%x" % (dllname, call_site.address, hash_table_size))
        hash_table = bv.read(hash_table_addr, hash_table_size)
        hash_table_hashes = struct.unpack("I"*(hash_table_size//4), hash_table)
        dll_hash_table = gen_dll_hash_table(dllname, hash_xor)

        for chash in hash_table_hashes:
            if chash in dll_hash_table:
                found_func_name = dll_hash_table[chash]
            else:
                print("Was not able to find hash: 0x%x in DLL: %s" % (chash, dllname))
                found_func_name = "unk_%x" % chash

            if found_func_name:
                print("Found hash: 0x%x in DLL: %s" % (chash, dllname))
                resolved_hashes[found_func_name] = chash

        print(generate_header(resolved_hashes, call_site.address))
        resolved_hashes = {}

if __name__ == '__main__':
    bin_path = sys.argv[1]
    bv = BinaryViewType['PE'].open(bin_path)
    bv.update_analysis_and_wait()
    #TODO make discovery of these parameters generic
    module_ct_bytes = bv.read(0x180028470, 0x2c0)
    xor_key_bytes = struct.pack("I", 0xa235cb91)
    hash_xor = 0xa235cb91
    import_res_func = 0x18000cc58
    resolve_hash_tables(bv, module_ct_bytes, xor_key_bytes, hash_xor, import_res_func)
