#!/usr/bin/env python3

"""
Fingerprints, identifies resource decryption function
and unpacks Qakbot DLL.

691bc000  uint64_t sub_691bc000()
691bc013      var_28_19
691bc013      __builtin_memset(s: &var_28_19, c: 0, n: 0x14)
691bc02b      char copied_alphabet
691bc02b      __builtin_strncpy(dest: &copied_alphabet, src: "@AlzsQ1DSS>I9XX7kB7M1MT3?CH8B1ggtV_!RTX0zJSbzmUYpW5H2n@o$", n: 0x3a)
691bc1cb      int16_t lpName = 0x3b4
691bc1d6      var_70_470
691bc1d6      __builtin_memset(s: &var_70_470, c: 0, n: 0x20)
"""
from binaryninja import BinaryViewType
from binaryninja import commonil
from struct import unpack
from refinery.units.formats.pe import get_pe_size
import pefile
from pefile import PEFormatError, PE
from sys import argv
import re

found_pe = False

# Based on https://binref.github.io/units/pattern/carve_pe.html
# Thanks Rattle <3
def carve_pe(data):
    cursor = 0
    mv = memoryview(data)
    carved = []
    while True:
        offset = data.find(B'MZ', cursor)
        if offset < cursor: break
        cursor = offset + 2
        ntoffset = mv[offset + 0x3C:offset + 0x3E]
        if len(ntoffset) < 2:
            return None
        ntoffset, = unpack('H', ntoffset)
        if mv[offset + ntoffset:offset + ntoffset + 2] != B'PE':
            print(F'invalid NT header signature for candidate at 0x{offset:08X}')
            continue
        try:
            pe = PE(data=data[offset:], fast_load=True)
            print("Found a valid PE: {}".format(bytes(data[offset:offset+256]).hex()))
        except PEFormatError as err:
            print(F'parsing of PE header at 0x{offset:08X} failed:', err)
            continue
        pesize = get_pe_size(pe, memdump=False)
        pedata = mv[offset:offset + pesize]
        carved.append(bytes(pedata))
    return carved

def extract_resource(fpath, min_resource_size, rsrcid):
    rsrc_data = None
    pe = pefile.PE(fpath)
    pe_mapped = pe.get_memory_mapped_image()
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.directory.entries[0].data.struct.Size >= min_resource_size and entry.struct.Name == rsrcid:
                rsrc_offset = entry.directory.entries[0].data.struct.OffsetToData
                rsrc_size = entry.directory.entries[0].data.struct.Size
                rsrc_data = pe_mapped[rsrc_offset:rsrc_offset + rsrc_size]
    return rsrc_data

def get_key(bv):
    print("Looking for decryption key...")
    key = None
    for inst in bv.hlil_instructions:
        inst.visit(visitor)
    return key

def visitor(_a, inst, _c, _d) -> bool:
    global found_pe
    if found_pe:
        return False
    if isinstance(inst, commonil.Localcall):
        if len(inst.params) > 1:
            if inst.tokens[0].text == '__builtin_strncpy':
                try:
                    print("Found target strncpy: {}".format(inst))
                    key = bytes(inst.params[1].tokens[1].text + "\x00", 'ascii') 
                    rsrc_inst_index = 4
                    rsrcid = None
                    rsrc_inst = list(inst.function.instructions)[rsrc_inst_index]
                    rsrcid = rsrc_inst.operands[1].value.value
                    path = re.sub(r"\.bndb", "", inst.function.view.file.filename)
                    rsrc_data = extract_resource(path, 1024, rsrcid)
                    print("Identified key: {} // Identified Resource ID: {}".format(key, rsrcid))
                    r = xor(key, rsrc_data)
                    carved = carve_pe(r)
                    if len(carved) >= 2:
                        qakbot_dll = carved[1]
                    elif len(carved) == 1:
                        qakbot_dll = carved[0]
                    fw = open("qakbot.dll", "wb")
                    fw.write(qakbot_dll)
                    fw.close()
                    found_pe = True
                    return False # Stop recursion (once we find a constant, don't recurse in to any sub-instructions (which there won't actually be any...))
                except:
                    pass

def xor(key, ct):
    r = bytes()
    for i, b in enumerate(ct):
        r += (b ^ key[i % len(key)]).to_bytes(1, 'little')
    return r

if __name__ == '__main__':
    bin_path = argv[1]
    bv = BinaryViewType['PE'].open(argv[1])
    bv.update_analysis_and_wait()
    key = get_key(bv)