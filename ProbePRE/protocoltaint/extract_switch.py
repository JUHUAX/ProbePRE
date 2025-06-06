import functools
import idautils
import idc
import re
import json


# ================== 从反汇编注释中提取case值 ==================
def extract_cases_from_disasm_comments(func_ea):
    """从函数反汇编注释中提取case值（支持范围如case 4-6）"""
    cases = set()
    comment_pattern = re.compile(r'cases?\s+((0x[0-9a-fA-F]+|\d+)(\s*-\s*(0x[0-9a-fA-F]+|\d+))?)', re.IGNORECASE)
    
    for ea in idautils.FuncItems(func_ea):
        # 获取常规注释和可重复注释
        for comment_type in [0, 1]:
            comment = idc.get_cmt(ea, comment_type)
            if not comment:
                continue
            # 匹配注释中的case描述
            matches = comment_pattern.findall(comment)
            for m in matches:
                if '-' in m[0]:  # 处理范围（如case 4-6）
                    start, end = m[0].split('-')
                    start_val = int(start.strip(), 0)
                    end_val = int(end.strip(), 0)
                    cases.add((start_val, end_val))
                else:           
                    # 单个值
                    value = int(m[0].strip(), 0)
                    cases.add((value, value))

    def cmp(a, b):
        if isinstance(a, tuple):
            aa = a[0]
        else:
            aa = a
        if isinstance(b, tuple):
            bb = b[0]
        else:
            bb = b
        return aa - bb

    return sorted(cases, key=functools.cmp_to_key(cmp))

def get_jump_addr(func_ea): ## 获得switch跳转的地址
    jump_addr = None
    for ea in idautils.FuncItems(func_ea):
        for comment_type in [0, 1]:
            comment = idc.get_cmt(ea, comment_type)
            if not comment:
                continue
            # print(comment)
            if "switch jump" in comment:
                jump_addr = ea
                break
    return jump_addr

# ================== 从伪代码文本中提取所有case值 ==================
def extract_cases_from_pseudocode(func_ea):
    pseudo_code = str(idaapi.decompile(func_ea))
    cases = set() 
    lines = pseudo_code.split('\n')
    var = None
    
    for line in lines:
        if "switch" in line and var is None and "+" not in line and "-" not in line and "_BYTE" not in line: #
            #   switch ( v3 )
            # switch ( (__int16)v12 )
            # switch ( *(_DWORD *)a2 )
            pattern = r"(?i)\bswitch\s*\(\s*(?:\(\s*[\w:]+(?:\s*\*+\s*)*\)\s*)*(?:&?\s*\**\s*|\s*\**\s*&?\s*)*([A-Za-z_]\w*)(?!\s*\()\b"
            match = re.search(pattern, line)
            if match:
                var = match.group(1) ## 情况多变
            else:
                print(line)
                pattern = r"switch\s*\(\s*\*\(_DWORD\s*\*\)(\w+)\s*\)"
                match = re.search(pattern, line)
                if match:
                    var = match.group(1)
                # else:
                #     var = None
        if "case" in line and var:
            value = line.strip().strip(":").strip("u")
            value = value.split()[1]
            if "0x" in value:
                value = int(value, 16)
            elif "'" in value:
                value = value.strip("'")
                if value == '': ## 有种情况case值是32，反汇编为空格 case ' ':
                    value = ' '
                print(line)
                print(value)
                value = ord(value.strip("'"))
            else:
                try:
                    value = int(value)
                except ValueError as e:
                    value = None
            if value is not None:     
                cases.add((value, value))

    if var:
        # if ( v3 == 0xF0 )
        pattern = "(?:$$\s*\(*[^)]+$$\s*\)\s*)*([a-zA-Z0-9_]+)\s*(?:==|!=)\s*(0x[0-9A-Fa-f]+|'[^']*'|\d+)"
        for line in lines:
            value = None
            if var in line and "if" in line and "-" not in line and "+" not in line and ":" not in line:
                if "==" in line or "!=" in line:
                
                    equel = re.findall(pattern, line)
                    for e in equel:
                        if e[0] == var:
                            value = e[1]
                            break
                    if value:
                        if "0x" in value:
                            value = int(value, 16)
                        elif "'" in value:
                            value = ord(value.strip("'"))
                        else:
                            value = int(value)
                        cases.add((value, value))

                
    return sorted(cases)

loops = []

# def explore_paths(graph, node, path, all_paths, visited):
#     if node in visited:
#         #识别循环
#         loop = []
#         flag = False
#         for id in path:
#             if id == node:
#                 loop.append(node)
#                 flag = True
#             elif flag:
#                 loop.append(id)
#         loops.append(loop)
#         all_paths.append(list(path))
#         return

#     path.append(node)
#     visited.add(node)
#     if not graph[node]:
#         all_paths.append(list(path))
#     else:
#         for succ in graph[node]:
#             explore_paths(graph, succ, path, all_paths, visited)
    
#     path.pop()
#     visited.remove(node)

def explore_paths(graph, node, path, all_paths, visited, loops):
    stack = [(node, False)]  # 栈元素格式：(当前节点, 是否已处理)

    while stack:
        current_node, is_processed = stack.pop()

        if not is_processed:
            if current_node in visited:
                # 检测到循环，记录循环路径
                loop = []
                flag = False
                for id in path:
                    if id == current_node:
                        loop.append(current_node)
                        flag = True
                    elif flag:
                        loop.append(id)
                loops.append(loop)
                all_paths.append(list(path))
                continue

            # 访问当前节点：加入路径和已访问集合
            path.append(current_node)
            visited.add(current_node)

            # 若当前节点无后继，保存路径
            if not graph.get(current_node, []):
                all_paths.append(list(path))

            # 将当前节点重新压栈（标记为已处理），以便后续回溯
            stack.append((current_node, True))

            # 将子节点逆序压栈，保持处理顺序与递归一致
            for succ in reversed(graph.get(current_node, [])):
                stack.append((succ, False))
        else:
            # 回溯：从路径和已访问集合中移除当前节点
            path.pop()
            visited.remove(current_node)

def get_function_paths(func_ea):
    """
    获取函数的所有控制流路径。
    """
    func = idaapi.get_func(func_ea)
    if not func:
        return []
    flowchart = idaapi.FlowChart(func)
    graph = {block.id: [succ.id for succ in block.succs()] for block in flowchart}
    all_paths = []
    start_node = next(flowchart.__iter__()).id
    explore_paths(graph, start_node, [], all_paths, set(), [])

    return all_paths, flowchart

def get_basic_block_id(ea):
    # 确保地址有效
    if not idc.is_loaded(ea):
        print(f"地址 0x{ea:X} 无效（未在二进制范围内）")
        return None

    # 获取所在函数的起始地址
    func = idaapi.get_func(ea)
    if not func:
        print(f"地址 0x{ea:X} 不属于任何函数")
        return None

    # 生成函数的控制流图
    flowchart = idaapi.FlowChart(func)

    # 遍历所有基本块，找到包含目标地址的块
    for block in flowchart:
        if block.start_ea <= ea < block.end_ea:
            return block.id

    print(f"地址 0x{ea:X} 未找到所属基本块（可能在函数间隙）")
    return None

def get_basic_block_instructions(block):
    """
    获取基本块中的所有指令。
    """
    instructions = [idc.get_name(block.start_ea, idaapi.GN_VISIBLE)]
    ea = block.start_ea
    while ea < block.end_ea:
        if idc.is_code(idc.get_full_flags(ea)):
            instructions.append(hex(ea) + " " + idc.generate_disasm_line(ea, 0))
        ea = idc.next_head(ea, block.end_ea)
    return instructions


def get_target_path_instructions(jump_addr, func_ea): ## 获取target path的指令
    all_paths, flowchart = get_function_paths(func_ea)
    basic_id = get_basic_block_id(jump_addr)
    ##寻找目标路径
    target_path = []
    for path in all_paths:
        if basic_id in path:
            target_path = path.copy()
    
    ## 获得target路径中的所有指令，但是在switch jump处截断
    index = None
    instructions = []
    for block_id in target_path:
        block = next(block for block in flowchart if block.id == block_id)
        instruction = get_basic_block_instructions(block)
        for i in instruction:
            if hex(jump_addr) in i:
                index = instruction.index(i)
                break
        if index: 
            instructions  = instructions + instruction[0:index+1] ##在switch jump处截断
            break
        else:
            instructions  = instructions + instruction
            
    return instructions

def get_indexreg(instructions): # instructions要求已经是逆向序列
    pattern = r"\[(?:.*?[+\-])?([a-z\d_]+)(?:\*\d+)?\]"
    index = None
    indexreg = None
    for i in instructions:
        if "ds:(jpt_" in i or "ds:jpt" in i:
            indexreg = re.search(pattern, i.split(",")[-1]).group(1)
            index = instructions.index(i)
            break
    return indexreg, index

regs_map = {
    "rax": ["eax", "ax", "al", "ah"],
    "eax": ["rax", "ax", "al", "ah"],
    "ax": ["eax", "rax", "al", "ah"],
    "al": ["eax", "ax", "rax", "ah"],
    "ah": ["eax", "ax", "al", "rax"],
    
    "rbx": ["ebx", "bx", "bl", "bh"],
    "ebx": ["rbx", "bx", "bl", "bh"],
    "bx": ["ebx", "rbx", "bl", "bh"],
    "bl": ["ebx", "bx", "rbx", "bh"],
    "bh": ["ebx", "bx", "bl", "rbx"],
    
    "rcx": ["ecx", "cx", "cl", "ch"],
    "ecx": ["rcx", "cx", "cl", "ch"],
    "cx": ["ecx", "rcx", "cl", "ch"],
    "cl": ["ecx", "cx", "rcx", "ch"],
    "ch": ["ecx", "cx", "cl", "rcx"],
    
    "rdx": ["edx", "dx", "dl", "dh"],
    "edx": ["rdx", "dx", "dl", "dh"],
    "dx": ["edx", "rdx", "dl", "dh"],
    "dl": ["edx", "dx", "rdx", "dh"],
    "dh": ["edx", "dx", "dl", "rdx"],
    
    "identifier": ["rsi", "esi", "si", "sil"],
    "rsi": ["esi", "si", "sil"],
    "esi": ["rsi", "si", "sil"],
    "si": ["esi", "rsi", "sil"],
    "sil": ["esi", "si", "rsi"],

    "connack_code": ["rdi", "edi", "di", "dil"],
    "reason_code": ["rdi", "edi", "di", "dil"],
    "rdi": ["edi", "di", "dil"],
    "edi": ["rdi", "di", "dil"],
    "di": ["edi", "rdi", "dil"],
    "dil": ["edi", "di", "rdi"],
    
    "rbp": ["ebp", "bp", "bpl"],
    "ebp": ["rbp", "bp", "bpl"],
    "bp": ["ebp", "rbp", "bpl"],
    "bpl": ["ebp", "bp", "rbp"],
    
    "rsp": ["esp", "sp", "spl"],
    "esp": ["rsp", "sp", "spl"],
    "sp": ["esp", "rsp", "spl"],
    "spl": ["esp", "sp", "rsp"],
    
    "r8": ["r8d", "r8w", "r8b"],
    "r8d": ["r8", "r8w", "r8b"],
    "r8w": ["r8d", "r8", "r8b"],
    "r8b": ["r8d", "r8w", "r8"],
    
    "r9": ["r9d", "r9w", "r9b"],
    "r9d": ["r9", "r9w", "r9b"],
    "r9w": ["r9d", "r9", "r9b"],
    "r9b": ["r9d", "r9w", "r9"],
    
    "r10": ["r10d", "r10w", "r10b"],
    "r10d": ["r10", "r10w", "r10b"],
    "r10w": ["r10d", "r10", "r10b"],
    "r10b": ["r10d", "r10w", "r10"],
    
    "r11": ["r11d", "r11w", "r11b"],
    "r11d": ["r11", "r11w", "r11b"],
    "r11w": ["r11d", "r11", "r11b"],
    "r11b": ["r11d", "r11w", "r11"],
    
    "r12": ["r12d", "r12w", "r12b"],
    "r12d": ["r12", "r12w", "r12b"],
    "r12w": ["r12d", "r12", "r12b"],
    "r12b": ["r12d", "r12w", "r12"],
    
    "r13": ["r13d", "r13w", "r13b"],
    "r13d": ["r13", "r13w", "r13b"],
    "r13w": ["r13d", "r13", "r13b"],
    "r13b": ["r13d", "r13w", "r13"],
    
    "r14": ["r14d", "r14w", "r14b"],
    "r14d": ["r14", "r14w", "r14b"],
    "r14w": ["r14d", "r14", "r14b"],
    "r14b": ["r14d", "r14w", "r14"],
    
    "r15": ["r15d", "r15w", "r15b"],
    "r15d": ["r15", "r15w", "r15b"],
    "r15w": ["r15d", "r15", "r15b"],
    "r15b": ["r15d", "r15w", "r15"],
}


def reverse_dataflow(instructions, target_reg): ## 对目标寄存器进行反向数据流分析， 注意instructions需要是逆向排列的
    trace_reg = target_reg
    log_instructions = {}
    op, s, d = None, None, None
    for instruction in instructions:
        if "0x" not in instruction or "push" in instruction or "pop" in instruction or "call" in instruction or "cmp" in instruction or "j" in instruction or "end" in instruction:
            continue

        go = False
        for reg in regs_map[trace_reg]:
            if reg in instruction:
                go = True
        if not go:
            continue
        instruction = instruction.split(";")[0] ## 去除注释
        if "fptr" in instruction:
            parts = instruction.split()
            ## 不需要考虑push pop等指令
            if len(parts) > 3:
                addr = parts[0]
                op = parts[1]
                s = parts[3]
                d = parts[2][0:-1]
        elif "ptr" in instruction:
            parts = instruction.split(",")
            parts1 = parts[0].split()
            addr = parts1[0]
            op = parts1[1]
            d = parts1[2]
            parts2 = parts[1].split()
            if len(parts2) > 2:
                s = parts2[2]
            else:
                s = parts2[0]
        elif "ptr" not in instruction: 
            parts = instruction.split()
            ## 不需要考虑push pop等指令
            if len(parts) > 3:
                addr = parts[0]
                op = parts[1]
                s = parts[3]
                d = parts[2][0:-1]
        if op in ["mov", "movzx", "movups", "movsx"]:
            if d in regs_map[trace_reg]:
                ## 如果目标操作数是需要追踪的寄存器，则记录指令
                log_instructions[addr] = instruction
                if s in regs_map.keys():
                    ## 如果源操作数是寄存器，那么追踪该寄存器
                    trace_reg = s
                elif "[" in s and "]" in s:
                    ## 如果源操作数是内存地址，则可以停止数据流分析
                    return log_instructions

        if op in ["lea"] and "[" in s and "]" in s:
            ## lea指令经常用来计算赋值
            if d in regs_map[trace_reg]:
                log_instructions[addr] = instruction
                match = re.search("\[([a-z\d_]+)(?:[+\-].*)?\]", s)
                if match.group(1) in regs_map.keys():
                    trace_reg = match.group(1)
    return log_instructions


def find_switch_functions():
    """
    查找包含switch结构的函数并返回它们的地址。
    """
    switch_functions = set()
    for seg in idautils.Segments():
        for fn in idautils.Functions(seg, idc.get_segm_end(seg)):
            for head in idautils.Heads(fn, idc.get_func_attr(fn, idc.FUNCATTR_END)):
                if idaapi.get_switch_info(head):
                    switch_functions.add(fn)
                    break
    return list(switch_functions)



# ================== 主逻辑 ==================
def analyze_switches():
    with open("switch_cases.txt", "w") as f:
        """遍历所有函数并输出case信息"""
        ans = {}
        switch_functions = find_switch_functions()
        for func_ea in switch_functions:
            # func_name = idaapi.demangle_name(idc.get_func_name(func_ea), 0) ## c++函数名解析
            func_name = idc.get_func_name(func_ea) ## 如果解析输出None，则不需要解析
            if func_name in ["cj5_get_str", "process_string"]:
                ## 分析程序时ida将case值92反汇编为'\\'，使用ord处理的时候不知道为什么没有转义，这个函数不重要，干脆直接跳过
                continue
            # 通过反汇编注释提取
            print("funcname", func_name)
            jump_addr = get_jump_addr(func_ea)
            disasm_cases = extract_cases_from_disasm_comments(func_ea)
            disasm_cases = extract_cases_from_pseudocode(func_ea) + disasm_cases
            disasm_cases = list(set(disasm_cases))

            if disasm_cases and jump_addr:
                if func_name:
                    func_name = func_name.split("(")[0]
                else:
                    func_name = "None"
                f.write(f"\nFunction: {func_name} ({hex(func_ea)})\n")
                f.write(f"  Cases: {disasm_cases}\n")
                instructions = get_target_path_instructions(jump_addr, func_ea)
                instructions.reverse()
                target_reg, index = get_indexreg(instructions)
                instructions = instructions[index + 1:]
                # for i in instructions:
                #     f.write(i + "\n")
                f.write(f"{target_reg} reverse data flow: \n")
                result = reverse_dataflow(instructions, target_reg)
                for addr in result:
                    f.write(result[addr] + "\n")
                ans[func_name] = []
                ans[func_name].append(disasm_cases)
                ans[func_name].append(list(result.keys()))
    
    return ans

                

if __name__ == "__main__":
    print("start")
    ans = analyze_switches()
    with open("preprocess.json", "w", encoding="utf-8") as f:
        json.dump(ans, f, ensure_ascii=False, indent=2)
    print(ans)
    print("end")