# IDA 9.0

* IDA 9.0 Improvements [https://docs.hex-rays.com/release-notes/9_0#idapython-improvements](https://docs.hex-rays.com/release-notes/9_0#idapython-improvements)
* [EverythingIDA's video on IDA 9.0](https://www.youtube.com/watch?v=c9ehQfLY-d4)

## Direct Syscall Sample

* PHNT TIL type files [https://github.com/Dump-GUY/IDA_PHNT_TYPES](https://github.com/Dump-GUY/IDA_PHNT_TYPES)
* [Fixing _LDR_DATA_TABLE_ENTRY struct references with shifted pointers](https://research.openanalysis.net/rhadamanthys/config/ida/shifted%20pointers/peb/_list_entry/_ldr_data_table_entry/2023/01/19/rhadamanthys.html#PEB-Walk-_LDR_DATA_TABLE_ENTRY-and-Shifted-Pointers-in-IDA) - this was painful
* [test.py](test.py) testing IDA 9.0 headless mode to recover hashes for Syscall sample
* Terminus project for visualizing structures [http://terminus.rewolf.pl/terminus/](http://terminus.rewolf.pl/terminus/)

## BRC4 Analysis

* BRC4 blog [https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)

### RC4 string decryption:

Note: this was difficult using the IDAPython API, so we moved to using Binary Ninja to automate this decryption.

```
import binascii
import struct

def get_instr_index(instr):
    instruction_index = None
    all_instr = []
    rinstr1 = None
    rinstr2 = None
    hlil_func = instr.function
    for index, insn in enumerate(hlil_func.instructions):
        all_instr.append(insn)
        if insn.address == instr.address:
            rinstr1 = all_instr[index-1]
            rinstr2 = all_instr[index-2]
    return rinstr1, rinstr2

func = bv.get_function_at(0x0000000010004B10)
callsites = list(func.caller_sites)

rc4 = Transform['RC4']
key = binascii.unhexlify("7b2d6c2c22202b72332f237e263b765f")
for callsite in callsites:
    hlcall = callsite.hlil
    ct_len = None
    ct_loc = hlcall.params[0]
    if isinstance(ct_loc, binaryninja.highlevelil.HighLevelILCall):
        if '__builtin_memcpy' in ct_loc.tokens[0].text:
            addr = ct_loc.params[1]
            addr_val = addr.constant
            ct_len = ct_loc.params[2].constant - 1
            ct = bv.read(addr_val, ct_len)
            pt = rc4.decode(ct, {'key': key})
            bv.set_comment_at(callsite.address, pt.decode('ascii'))
    elif isinstance(ct_loc, binaryninja.highlevelil.HighLevelILConstPtr):
        rinstr1, rinstr2 = get_instr_index(hlcall)
        ct = bytes()
        #<HighLevelILVarInit: int64_t var_24 = 0x72b29a76b557027>
        ct += struct.pack("Q", rinstr1.operands[1].constant)
        ct += struct.pack("Q", rinstr2.operands[1].constant)
        pt = rc4.decode(ct, {'key': key})
        pt = rc4.decode(ct, {'key': key})[:hlcall.operands[1][4].constant]
        strpt = None
        try:
            strpt = pt.decode('ascii')
        except:
            ct = bytes()
            ct += struct.pack("Q", rinstr2.operands[1].constant)
            ct += struct.pack("Q", rinstr1.operands[1].constant)
            pt = rc4.decode(ct, {'key': key})
            pt = rc4.decode(ct, {'key': key})[:hlcall.operands[1][4].constant]
            strpt = pt.decode('ascii')
        print(strpt)
            
        #print(ct.hex())
        #print(f"Callsite: 0x{hlcall.address:2x}")
        #print(pt)
    else:
        print(f"Callsite different format: 0x{callsite.address:2x}")
```

