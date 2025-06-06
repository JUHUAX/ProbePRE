from ast import Import
from collections import defaultdict
import angr
import claripy
from openai import OpenAI
import re


def get_offset_value(line, checked_offset):
    if "j" in line or "push" in line or "pop" in line or "call" in line or "ret" in line:
        return None
    offset = line.split("\t")[2].strip("w").strip("r")
    if ";" in offset:
        offset = offset.split(";")
        offset1 = [int(offset[0].split(",")[0]), int(offset[0].split(",")[-1])] if offset[0] else None
        offset2 = [int(offset[1].split(",")[0]), int(offset[1].split(",")[-1])] if offset[1] else None
        value = line.split("\t")[-1].split(";")
        if offset1 and (offset1[0] >= checked_offset[0] and offset1[1] <= checked_offset[1]):
            value = int(value[0], 16)
            return value
        elif offset2 and (offset2[0] >= checked_offset[0] and offset2[1] <= checked_offset[1]):
            value = int(value[-1], 16)
            return value
    else:
        offset = [int(offset.split(",")[0]), int(offset.split(",")[-1])]
        if offset[0] >= checked_offset[0] and offset[1] <= checked_offset[1]:
            value = line.split("\t")[-1]
            value = int(value.split(";")[0], 16)
            return value
    return None
    



def program_slice(changed_offset, info_path, need_to_compute_offset):
    """
    changed_offset: dict, key:addr, value: (offset(str), offset对应的payload的原值(int))   待切片的地址和字段范围
    changed_offset {'0x7f706b04d869': ([2, 3], 25), '0x7f706b04df03': ([2, 3], 25), '0x7f706b04dff8': ([6, 6], 128), '0x7f706b050b6a': ([13, 14], 8)}
    need_to_compute_offset: list, 需要计算的offset
    need_to_compute_offset [[2, 3], [6, 6], [13, 14]]
    """
    ## 从info文件中获得指令
    with open(info_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    ## 遍历指令，进行程序切片
    program_slice = defaultdict(list) ##key:addr, value: [instructions]
    for idx, line in enumerate(lines):
        addr = line.split(":")[0].split()[1] 
        if addr in changed_offset: ## 如果当前指令的地址是待切片地址，则开始切片
            target_offset = changed_offset[addr][0]
            ## 获得payload中的值
            value_payload = changed_offset[addr][1]
            ##前向切片
            tf = f"{str(target_offset[0])},{str(target_offset[-1])}"
            if tf not in program_slice and target_offset in need_to_compute_offset:
                program_slice[tf].append(line[:-1])
                for i in range(idx-1, -1, -1):
                    if lines[i].startswith("Instruction"):
                        value = get_offset_value(lines[i], target_offset)
                        if value:
                            program_slice[tf].append(lines[i][:-1])
                        ## 当值正常停止切片
                        if value == value_payload:
                            break

    for offset in program_slice:
        program_slice[offset].reverse()
        print("offset:", offset)
        for ins in program_slice[offset]:
            print("ins", ins)

    return program_slice

# def get_constraints()




    
def analyze_ax_to_edx():
    # 1. 加载二进制文件（替换为你的目标文件）
    binary_path = "/home/juhua/experiment/MY/binary/libsnap7.so"
    project = angr.Project(binary_path, auto_load_libs=False)

    # 2. 定义起始地址和目标地址
    start_addr = 0x19ED0  # 初始指令地址
    target_addr = 0x19EDA  # 目标指令地址

    # 3. 符号化 AX 寄存器（16位）
    eax_initial = claripy.BVS("eax_initial", 32)  # 符号化 AX 的初始值

    # 4. 初始化状态（从 start_addr 开始）
    state = project.factory.call_state(
        start_addr,
        # 设置 AX 的符号值（假设此时 AX 未被其他代码修改）
        regs={'eax': eax_initial}
    )

    # 5. 设置模拟管理器
    simgr = project.factory.simulation_manager(state)

    # 6. 执行到目标地址（过滤无关路径）
    simgr.explore(
        find=target_addr,
        avoid=[...]  # 可选：排除无关地址（如错误处理分支）
    )

    # 7. 提取结果
    if simgr.found:
        found_state = simgr.found
        # 获取最终 EDX 的符号表达式
        edx_final = found_state.regs.edx
        # 反向求解 EDX 与 AX 的关系
        print("EDX 的表达式:", edx_final)
        print("约束条件:", found_state.solver.constraints)
    else:
        print("未找到路径")




def analysis_constraint(program_slice):
    need_to_update_offset = []
    need_to_update_value = {}
    for offset in program_slice:
        request_lines = ""
        target_reg = None
        for ins in program_slice[offset]:
            i = ins.split(":")[1][1:].split("\t")[0]
            if target_reg is None:
                target_reg = i.split(" ")[1][:-1]
            request_lines += i + "\n"
        request_lines = request_lines[:-1]
        print(offset)
        print(request_lines)
        print(target_reg)
    
        client = OpenAI(api_key="sk-e9cb39d17d784b6f855ec6d3c6c569a8", base_url="https://api.deepseek.com")

        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "你是一个专业的二进制分析师，擅长对汇编代码进行数据流分析。"},
                {"role": "user", "content": f"""需求：
给定一段汇编代码，请分析指定寄存器或值在该代码片段中的完整数据流动，并输出一个关于初始值 x 的最终表达式。
要求：
1.不解释分析过程，只输出精简的数学表达式。
2.表达式规则：
    直接传递（如 mov）：x
    运算操作（如 add、lea）：体现运算逻辑（如 x + 1）
    若该值在片段中未被使用或影响，输出 [unchanged]。
    数值全用十进制表示
示例：
    代码片段：
    mov eax, ebx  
    add eax, ecx  
    分析目标：ebx 的流动
    输出：x + ecx
待分析：
    代码片段：
    {request_lines} 
    分析目标：{target_reg} 的流动"""},
            ],
            stream=False
        )

        print(response.choices[0].message.content)
        need_to_update_offset.append([int(offset[0]), int(offset[-1])])
        need_to_update_value[offset] = response.choices[0].message.content

    return need_to_update_offset, need_to_update_value


def reverse_operation(range_tuple, expr):
    min_val, max_val = range_tuple
    expr = expr.replace(' ', '')  # 移除空格方便解析
    if expr == "x":
        return range_tuple
    # 匹配位移操作 (>> 或 <<)
    shift_match = re.match(r'x(>>|<<)(\d+)', expr)
    if shift_match:
        direction, amount = shift_match.groups()
        shift = int(amount)
        if direction == '>>':
            return (min_val << shift, max_val << shift)
        else:
            return (min_val >> shift, max_val >> shift)
    
    # 匹配算术运算 (+/-/*/)
    arith_match = re.match(r'x([+\-*/])(\d+)', expr)
    if arith_match:
        op, num = arith_match.groups()
        num = int(num)
        if op == '+':
            return (min_val - num, max_val - num)
        elif op == '-':
            return (min_val + num, max_val + num)
        elif op == '*':
            return (min_val // num, max_val // num)
        elif op == '/':
            return (min_val * num, max_val * num)
    
    # 匹配括号表达式（简单处理两步操作）
    bracket_match = re.match(r'\(x([+\-*/])(\d+)\)([>>|<<]+)(\d+)', expr)
    if bracket_match:
        op1, num, direction, shift = bracket_match.groups()
        num, shift = int(num), int(shift)
        # 先处理外层位移
        if direction == '>>':
            temp_min, temp_max = min_val << shift, max_val << shift
        else:
            temp_min, temp_max = min_val >> shift, max_val >> shift
        # 再处理内部算术
        if op1 == '+':
            return (temp_min - num, temp_max - num)
        elif op1 == '-':
            return (temp_min + num, temp_max + num)
        elif op1 == '*':
            return (temp_min // num, temp_max // num)
        elif op1 == '/':
            return (temp_min * num, temp_max * num)
    
    return False
    raise ValueError(f"Unsupported expression: {expr}")


