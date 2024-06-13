def get_enum(phash):
    enum = bv.types['hashdb_strings_djb2_nokoyawa']
    for renum in enum.members:
        if renum.value == phash:
            return renum.name

def is_call_hash_func(instr):
    if isinstance(instr, HighLevelILCall):
        if instr.operands[0].value.value == 5368766480:
            #Accessing second parameter hash value
            return instr.operands[1][1].value.value

def enum_for_calls(instr):
    r = list(instr.traverse(is_call_hash_func))
    #Interestingly we'll get all hashes from an if statement
    #so there are instances that we'll get all of them
    #but we just want to use the sub-instructions
    if len(r) == 1:
        #Hash value
        name = get_enum(r[0])
        print(F"Assigning {name} to {instr}")
        instr.operands[0].name = name

for instr in list(bv.get_function_at(0x140011020).hlil.instructions):
    enum_for_calls(instr)
