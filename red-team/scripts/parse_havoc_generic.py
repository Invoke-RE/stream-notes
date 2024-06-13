def find_parse_func():
    for f in bv.functions:
        finstr = list(f.hlil.instructions)
        if len(finstr) > 10:
            if isinstance(finstr[0], HighLevelILVarInit):
                if isinstance(finstr[2], HighLevelILCall):
                    if isinstance(finstr[3], HighLevelILCall):
                        if isinstance(finstr[4], HighLevelILCall):
                            config_ref_call = finstr[3]
                            return config_ref_call.params[1].value.value

def extract_str(offset, data, data_len):
    targ_bytes = struct.unpack("s"*data_len, \
        data[offset:offset+data_len])
    
    tmp = b''
    for b in targ_bytes:
        tmp += b
    
    return tmp.decode('UTF-16-LE')

def parse_config_struct(struct_b):
    config_r = {}
    conf = struct.unpack("I"*5, struct_b[:4*5])
    config_r['sleep'] = conf[0]
    config_r['jitter'] = conf[1]
    config_r['alloc'] = conf[2]
    config_r['execute'] = conf[3]
    config_r['inj_target_len32'] = conf[4]
    
    config_r['inj_target32'] = extract_str(4*5, struct_b, config_r['inj_target_len32'])
    current_offset = 4*5+config_r['inj_target_len32']
    
    config_r['inj_target_len64'] = struct.unpack("I", struct_b[current_offset:current_offset+4])[0]
    current_offset += 4
    config_r['inj_target64'] = extract_str(current_offset, struct_b, config_r['inj_target_len64'])
    current_offset = current_offset+config_r['inj_target_len64']
    
    conf = struct.unpack("I"*10, struct_b[current_offset:current_offset+4*10])
    config_r['sleep_mask_technique'] = conf[0]
    config_r['sleep_jmp_bypass'] = conf[1]
    config_r['stack_spoof'] = conf[2]
    config_r['proxy_landing'] = conf[3]
    config_r['sys_indirect'] = conf[4]
    config_r['amsi_etw_patch'] = conf[5]
    config_r['download_chunk_size'] = conf[6]
    config_r['kill_date'] = conf[7]
    config_r['working_hours'] = conf[8]
    config_r['http_method_len'] = conf[9]
    
    current_offset = current_offset + 4*10
    config_r['http_method'] = extract_str(current_offset, struct_b, config_r['http_method_len'])
    current_offset = current_offset + config_r['http_method_len']
    
    conf = struct.unpack("III", struct_b[current_offset:current_offset+(4*3)])
    config_r['host_rotations'] = conf[0]
    config_r['num_hosts'] = conf[1]
    config_r['host_len'] = conf[2]
    current_offset += 4*3
    
    config_r['host'] = extract_str(current_offset, struct_b, config_r['host_len'])
    #current_offset += config_r['host_len']

    return config_r

STRUCT_SIZE = 1024
start_addr = find_parse_func()
conf_bytes = bv.read(start_addr, STRUCT_SIZE)
print(parse_config_struct(conf_bytes))
