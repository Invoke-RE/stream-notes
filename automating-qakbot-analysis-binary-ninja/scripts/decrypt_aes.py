#!/usr/bin/env python3

import sys
from binaryninja import BinaryViewType
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from binaryninja import commonil
from binaryninja import HighLevelILOperation
from binaryninja import HighLevelILInstruction
from binaryninja import HighLevelILVarInit
from binaryninja import HighLevelILCall
from binaryninja import HighLevelILIf
import struct
import socket
"""
This function decrypts data using AES-256 in CBC mode where the key is derived using SHA256 and a hard-coded string
"""
def decrypt_aes(aes_key_data, iv_xor_ct_data):
    h = SHA256.new()
    h.update(aes_key_data)
    aes256key = h.digest()
    cipher = AES.new(aes256key, AES.MODE_CBC, iv_xor_ct_data[:16])
    xor_key_ct = iv_xor_ct_data[16:]
    xor_key = unpad(cipher.decrypt(xor_key_ct), AES.block_size)
    return xor_key

def xor_byte_data(data, key):
    rbytes = bytes()
    for i, b in enumerate(data):
        rbytes += (b ^ key[i % len(key)]).to_bytes(1, byteorder='little')
    return rbytes

def get_xor_key_and_ct(inst):
    #mw_decrypt_data(&data_180027240, 0x5ab, &data_1800271a0, 0x90,\
    # &data_180027150, 0x47, arg1)
    tokens = inst.tokens
    ct_addr = tokens[3].value
    ct_len = tokens[5].value
    ct = bv.read(ct_addr, ct_len)
    
    iv_xor_ct_data_addr = tokens[8].value
    iv_xor_ct_data_len = tokens[10].value
    iv_xor_ct_data = bv.read(iv_xor_ct_data_addr, iv_xor_ct_data_len)
    
    aes_key_data_addr = tokens[13].value
    aes_key_data_len = tokens[15].value
    aes_key_data = bv.read(aes_key_data_addr, aes_key_data_len)
    xor_key = decrypt_aes(aes_key_data, iv_xor_ct_data)
    return xor_key, ct

def recurse_get_call(instr):
    # Base case: If the instruction is a call, return it
    if instr.operation == HighLevelILOperation.HLIL_CALL:
        return instr
    # If the instruction has operands, recursively search within them
    if hasattr(instr, 'operands'):
        for operand in instr.operands:
            if isinstance(operand, HighLevelILInstruction):
                result = recurse_get_call(operand)
                if result is not None:
                    return result
    # If no call is found in this instruction or its operands
    return None

def recurse_get_const(instr):
    # Base case: If the instruction is a constant, return it
    if instr.operation == HighLevelILOperation.HLIL_CONST:
        return instr
    # If the instruction has operands, recursively search within them
    if hasattr(instr, 'operands'):
        for operand in instr.operands:
            if isinstance(operand, HighLevelILInstruction):
                result = recurse_get_const(operand)
                if result is not None:
                    return result
            elif isinstance(operand, list):
                for op in operand:
                    result = recurse_get_const(op)
                    if result is not None:
                        return result
    return None

def get_str_offsets(call_site):
    #Get first call within nested operands, does not account for nested 
    #calls, but we haven't seen those.
    rcall = recurse_get_call(call_site.hlil)
    #Get first constant within operands of call
    rconst = recurse_get_const(rcall)
    if rconst:
        return rconst.value.value
    else:
        return None

def decrypt_config_aes(aes_key_data, iv_ct_data):
    h = SHA256.new()
    h.update(aes_key_data)
    aes256key = h.digest()
    iv_ct_data_no_blobid = iv_ct_data[1:]
    iv = iv_ct_data_no_blobid[:16]
    ct = iv_ct_data_no_blobid[16:len(iv_ct_data_no_blobid)]
    cipher = AES.new(aes256key, AES.MODE_CBC, iv)
    result = unpad(cipher.decrypt(ct), AES.block_size)
    return result

def parse_campaign_info(info_blob):
    #Skip over SHA256 of config
    info = info_blob[32:]
    s_info = info.split(b"\r\n")
    campaign_info = {}
    for cinfo in info.split(b"\r\n"):
        if b"10=" in cinfo:
            campaign_info['campaign_id'] = cinfo.split(b"=")[1].decode('ascii')
        elif b"3=" in cinfo:
            campaign_info['timestamp'] = cinfo.split(b"=")[1].decode('ascii')
    return campaign_info

def enum_callsite_for_campaign_func(inst, dec_str):
    insts = list(inst.function.hlil.instructions)
    campaign_info = None
    if len(insts) > 5:
        #Fingerprint with surrounding instruction types and number of basic blocks.
        #We can probably improve on this.
        if(type(insts[4]) == HighLevelILVarInit 
           and type(insts[4].operands[1]) == HighLevelILCall
           and type(insts[5]) == HighLevelILVarInit
           and type(insts[6]) == HighLevelILIf and
           len(inst.function.basic_blocks) == 5):
            print(F"Found call to campaign info decryption function: {inst.address:08X}")
            #uint32_t ct_len = zx.d(ct_len)
            iv_ct_len_addr = insts[1].tokens[7].value
            #WORD from aquired address for ciphertext length
            iv_ct_len = (struct.unpack("H", bv.read(iv_ct_len_addr, 2))[0])
            iv_ct_addr = insts[4].tokens[8].value
            #Read ciphertext and IV from this address
            iv_ct = bv.read(iv_ct_addr, iv_ct_len)
            aes_key_data = dec_str
            campaign_info = parse_campaign_info(decrypt_config_aes(aes_key_data, iv_ct))
            #Need to get this as the decrypted string from the call site
    return campaign_info

def parse_c2_info(c2_info_blob):
    c2_info = []
    #Skip over C2 config SHA256 and boolean
    info = c2_info_blob[32:]
    #Each C2 entry is 8 bytes
    num_entries = len(info) // 8
    for i in range(0, num_entries):
        ip_port = info[i*8:i*8+8]
        ip = socket.inet_ntoa(ip_port[1:5])
        port = struct.unpack(">H", ip_port[5:5+2])[0]
        c2_info.append({"IP": ip, "Port": port})
    return c2_info

def enum_callsite_for_c2_func(inst, dec_str):
    insts = list(inst.function.hlil.instructions)
    c2_info = None
    #Fingerprint with surrounding instructions, we can probably improve
    #on this.
    if(len(insts) > 20 and type(insts[17]) == HighLevelILVarInit and
       len(inst.function.basic_blocks) == 46):
        print(F"Found call to C2 decryption function: {inst.address:08X}")
        #uint32_t ct_len = zx.d(ct_len)
        iv_ct_len_addr = insts[14].tokens[7].value
        #WORD from aquired address for ciphertext length
        iv_ct_len = (struct.unpack("H", bv.read(iv_ct_len_addr, 2))[0])
        iv_ct_addr = insts[17].tokens[8].value
        #Read ciphertext and IV from this address
        iv_ct = bv.read(iv_ct_addr, iv_ct_len)
        aes_key_data = dec_str
        return parse_c2_info(decrypt_config_aes(aes_key_data, iv_ct))

def markup_str_as_comments(decrypted_str_table, inst):
    rstr = {}
    for callsite in inst.function.source_function.caller_sites:
        #print(F"Found call site: {callsite.address:08X}")
        str_offset = get_str_offsets(callsite)
        dec_str = decrypted_str_table[str_offset:].split(b"\x00")[0]

        #While we're enumerating all callsites, we should check them for the
        #strings that are being used to decrypt the campaign info and C2
        campaign_info = enum_callsite_for_campaign_func(callsite, dec_str)
        if campaign_info:
            print(campaign_info)

        c2_info = enum_callsite_for_c2_func(callsite, dec_str)
        if c2_info:
            print(c2_info)

        if not dec_str or not str_offset:
            #print("Failed to get string from offset: {}".format(str_offset))
            pass
        else:
            #print(F"String offset: {str_offset:08X} // Decrypted string: {dec_str}")
            rstr["0x%x" % callsite.address] = dec_str.decode('ascii')
            bv.set_comment_at(callsite.address, dec_str)
    #print(json.dumps(rstr, indent=4))

def visitor(_a, inst, _c, _d):
    if isinstance(inst, commonil.Localcall):
        if len(inst.params) == 7:
            if len(list(inst.function.instructions)) == 1:
                xor_key, ct = get_xor_key_and_ct(inst)
                decrypted_str_table = xor_byte_data(ct, xor_key)
                markup_str_as_comments(decrypted_str_table, inst)
                return False

def markup_string_tables(bv):
    #print("Looking for decryption key...")
    key = None
    for inst in bv.hlil_instructions:
        inst.visit(visitor)
    return key

if __name__ == '__main__':
    bin_path = sys.argv[1]
    bv = BinaryViewType['PE'].open(bin_path)
    bv.update_analysis_and_wait()
    markup_string_tables(bv)