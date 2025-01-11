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

```python
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

## Dec 22 BRC4 Deobfuscation Hex-Rays API

* Global variable renaming based on resolved API funtion hash in function call

Example:
```
CryptSetProperty_0 = mw_walk_hash_brc4_algo(BCryptSetProperty_0, qword_10040468);
```

Code to rename global variables:
```python
import idaapi
import ida_hexrays
import idc
import ida_lines
import random
import string

HASH_ENUM_INDEX = 0

class ctree_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_name = "mw_walk_hash_brc4_algo"# API resolution function name
    
    def get_expr_name(self, expr):
        name = expr.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call:
            if idc.get_name(expr.x.obj_ea) == self.func_name:
                carg_1 = expr.a[HASH_ENUM_INDEX]
                api_name = ida_lines.tag_remove(
                    carg_1.cexpr.print1(None)
                )  # Get API name
                expr_parent = self.cfunc.body.find_parent_of(expr)  # Get node parent

                # find asg node
                while expr_parent.op != idaapi.cot_asg:
                    expr_parent = self.cfunc.body.find_parent_of(expr_parent)

                # The global variable assignment is of type cot_obj
                # getting the name of this object was a giant pain but found
                # an example that's done in get_expr_name
                if expr_parent.cexpr.x.op == idaapi.cot_obj:
                    lvariable_old_name = (
                        self.get_expr_name(expr_parent.cexpr.x)
                    )  # get name of variable
                    print(f"Changing 0x{expr_parent.cexpr.x.obj_ea:2x} to {api_name}")
                    idc.set_name(
                        expr_parent.cexpr.x.obj_ea, api_name
                    ) # rename variable
        return 0


def main():
    cfunc = idaapi.decompile(idc.here())
    v = ctree_visitor(cfunc)
    v.apply_to(cfunc.body, None)


main()
```
* Useful plugin for visualizing C-Tree API in IDA https://github.com/patois/HRDevHelper
* Sleep obfuscation is used to refer to code that encrypts itself in memory when it's not being used

## Inline String Handler

```python
import idaapi
import ida_hexrays
import idc
import ida_lines
import random
import string
import struct
import re

LEN_INDEX = 1

class ctree_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_name = "mw_gen_obf_str"# Obfuscated str func name

    def set_hexrays_comment(self, address, text):
        '''
        set comment in decompiled code
        '''
        cfunc = idaapi.decompile(address)
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, text)
        cfunc.save_user_cmts() 

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call:
            if idc.get_name(expr.x.obj_ea) == self.func_name:
                call_addr = expr.ea
                larg = expr.a[LEN_INDEX]
                size = int(ida_lines.tag_remove(larg.print1(None)))
                #print(f"Size for {ida_lines.tag_remove(expr.print1(None))} is {size}") 
                args = list(expr.a)[LEN_INDEX+1:]
                rstr = bytes()
                # Each argument is of type carg_t which contains
                # a pointer to a UTF-16 string, so we need to collect
                # all addresses and read bytes from each address offset
                # to reassemble each string
                print(f"Enumerating args at address: 0x{call_addr:2x} with length: {size} at start index ")
                for arg in args:
                    try:
                        if arg.obj_ea == 0xffffffffffffffff:
                            if arg.x == None:
                                continue
                            tmp_str = idc.get_bytes(arg.x.obj_ea, 8)
                            rstr += tmp_str.split(b"\x00\x00\x00")[0]
                            print("0x%x" % arg.ea)
                            #rstr += tmp_str
                        else:
                            tmp_str = idc.get_bytes(arg.obj_ea, 8)
                            rstr += tmp_str.split(b"\x00\x00\x00")[0]
                            print("0x%x" % arg.obj_ea)
                            #rstr += tmp_str
                    except:
                        print(f"An exception occurred when processing: 0x{call_addr:2x}")
                print(re.sub(b"\x00", b"", rstr))
                final_str = re.sub(b"\x00", b"", rstr).decode('ascii')
                self.set_hexrays_comment(call_addr, final_str)
                #print((rstr+b"\x00\x00").decode('UTF-16'))
                    
        return 0


def main():
    cfunc = idaapi.decompile(idc.here())
    v = ctree_visitor(cfunc)
    v.apply_to(cfunc.body, None)


main()
```
