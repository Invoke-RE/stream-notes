import ida_hexrays
import ida_funcs
import ida_idaapi
import struct

class ForLoopVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super(ForLoopVisitor, self).__init__(ida_hexrays.CV_FAST)
        self.total_expr = 0
        self.start_addr = None
        self.instructions = []
        self.for_loop_vars = []
        self.method = None

    def visit_insn(self, insn):
        # Check if the instruction is a for-loop
        if insn.op == ida_hexrays.cit_for and self.total_expr >= 3:
            # insn details a for-loop, represented by cfor_t
            for_loop = insn.cfor
            # Access the components of the for-loop
            #init = for_loop.init
            #cond = for_loop.expr
            body = for_loop.body
            body_visitor = InstructionCollector()
            body_visitor.apply_to(insn.cfor.body, None)
            self.instructions.extend(body_visitor.collected_instructions)
            for instr in self.instructions:
                collector = ExprCollector(instr)
                collector.apply_to(body, None)
                self.method = collector.method
                # Look up the variable in the function's local variable list
                self.for_loop_vars.extend(collector.vxids)
        
        if insn.op == ida_hexrays.cit_expr:
            self.total_expr += 1 
            # Example: Print the condition expression
            #print("Condition:", ida_hexrays.print_citem(cond))
            # Add your analysis or modification code here
        #print(F"Instruction: {insn.opname}")
        return 0  # Continue visiting other instructions

class InstructionCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super(InstructionCollector, self).__init__(ida_hexrays.CV_FAST)
        self.collected_instructions = []

    def visit_insn(self, insn):
        # Collect all instructions within the for-loop body
        self.collected_instructions.append(insn)
        return 0  # Continue visiting other instructions
    
class ExprCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        super(ExprCollector, self).__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.expressions = []
        self.vxids = []
        self.method = None

    def visit_expr(self, expr):
        # Convert the expression to a Python-evaluable string
        py_expr = self.convert_expr_to_python(expr)
        if py_expr:
            self.expressions.append(py_expr)
        return 0  # Continue traversal

    def convert_expr_to_python(self, expr):
        # Example conversion (very simplified)
        if expr.op == ida_hexrays.cot_var:
            var_idx = expr.v.idx
            # Look up the variable in the function's local variable list
            self.vxids.append(var_idx)
            #print(f"Variable name: {var_name}")
        #for ( i = 0LL; i < 40; ++i )
        #*((_BYTE *)v22 + i) -= *((_BYTE *)v23 + i);
        #"OALabsLive: I don't think this is gonna work at all though"
        elif (expr.op is ida_hexrays.cot_asgsub and
        expr.x.op is ida_hexrays.cot_ptr and
        expr.x.x.op is ida_hexrays.cot_add and
        expr.x.x.x.op is ida_hexrays.cot_cast and
        expr.x.x.x.x.op is ida_hexrays.cot_var and
        expr.x.x.y.op is ida_hexrays.cot_var and
        expr.y.op is ida_hexrays.cot_ptr and
        expr.y.x.op is ida_hexrays.cot_add and
        expr.y.x.x.op is ida_hexrays.cot_cast and
        expr.y.x.x.x.op is ida_hexrays.cot_var and
        expr.y.x.y.op is ida_hexrays.cot_var):
            self.method = 'subtractequals'
        return None
    
class VarInitFinder(ida_hexrays.ctree_visitor_t):
    def __init__(self, target_vars):
        super(VarInitFinder, self).__init__(ida_hexrays.CV_FAST)
        self.target_vxid = target_vars
        self.array_assigns = []

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_asg:
            # Check if the left-hand side of the assignment is an array element
            if expr.x.op == ida_hexrays.cot_idx:
                # Check if the array is 'v22' or 'v23' by looking at the variable name
                array_var = expr.x.x
                if array_var.op == ida_hexrays.cot_var:
                    if array_var.v.idx in self.target_vxid:
                        # The right-hand side contains the value being assigned
                        value = expr.y
                        # Assuming the value is a constant integer
                        if value.op == ida_hexrays.cot_num:
                            self.array_assigns.append(value.n._value)
        return 0  # Continue traversal

def parse_for_loops(func_ea):
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays Decompiler is not available.")
        return

    f = ida_funcs.get_func(func_ea)
    if f is None:
        print("Function not found.")
        return

    cfunc = ida_hexrays.decompile(f)
    if cfunc is None:
        print("Failed to decompile function.")
        return

    visitor = ForLoopVisitor()
    visitor.apply_to(cfunc.body, None)
    for vxid in visitor.for_loop_vars:
        lvars = cfunc.get_lvars()
        var_name = lvars[vxid].name
        print(f"Variable name: {var_name}")
    
    expr_visitor = VarInitFinder(visitor.for_loop_vars)
    expr_visitor.apply_to(cfunc.body, None)
    for assign in expr_visitor.array_assigns:
        print(hex(assign))

    if visitor.method:
        if visitor.method == 'subtractequals':
            print("Subtraction method found!")
            v23 = expr_visitor.array_assigns[:5]
            v22 = expr_visitor.array_assigns[5:]
            for a in v22:
                print("0x%x" % a)
            r = []
            for i,q in enumerate(v22):
                v22_bytes = v22[i].to_bytes(8, 'little')
                v23_bytes = v23[i].to_bytes(8, 'little')
                for j,b in enumerate(v22_bytes):
                    print(F"{v22_bytes[j]:2x} - {v23_bytes[j]:2x}")
                    r.append((v22_bytes[j] - v23_bytes[j]) & 0xFF)
            print(struct.pack("B"*len(r), *r))

# Example usage: parse for-loops in the function at the given address
parse_for_loops(0xDDE6E0)  # Replace 0x401000 with the actual address of your function