import re
import functools
import os
import traceback
import sys
import preprocess

base_addrs = []

def str_filed2list_file(a):
    if "," in a:
        return [int(a.split(",")[0]) ,int(a.split(",")[-1])]
    else:
        return [int(a)]

def analysis_jmp(line):
    # jump_instructions = {
    #     # 无条件跳转指令
    #     "JMP": "无条件跳转到指定的地址或标签。",

    #     # 基于零标志（ZF）的跳转
    #     "JE": "如果 ZF = 1（即两个操作数相等或结果为 0），则跳转。",
    #     "JZ": "同 JE，如果 ZF = 1（即两个操作数相等或结果为 0），则跳转。",
    #     "JNE": "如果 ZF = 0（即两个操作数不相等或结果不为 0），则跳转。",
    #     "JNZ": "同 JNE，如果 ZF = 0（即两个操作数不相等或结果不为 0），则跳转。",

    #     # 基于进位标志（CF）的跳转
    #     "JB": "如果 CF = 1（即无符号数比较中，操作数1 < 操作数2），则跳转。",
    #     "JNAE": "同 JB，如果 CF = 1（即无符号数比较中，操作数1 < 操作数2），则跳转。",
    #     "JAE": "如果 CF = 0（即无符号数比较中，操作数1 >= 操作数2），则跳转。",
    #     "JNB": "同 JAE，如果 CF = 0（即无符号数比较中，操作数1 >= 操作数2），则跳转。",

    #     # 基于符号标志（SF）的跳转
    #     "JL": "如果有符号数比较中，操作数1 < 操作数2，则跳转。",
    #     "JNGE": "同 JL，如果有符号数比较中，操作数1 < 操作数2，则跳转。",
    #     "JGE": "如果有符号数比较中，操作数1 >= 操作数2，则跳转。",
    #     "JNL": "同 JGE，如果有符号数比较中，操作数1 >= 操作数2，则跳转。",

    #     # 基于溢出标志（OF）的跳转
    #     "JO": "如果 OF = 1（即结果溢出），则跳转。",
    #     "JNO": "如果 OF = 0（即结果未溢出），则跳转。",

    #     # 基于奇偶标志（PF）的跳转
    #     "JP": "如果 PF = 1（即结果的低 8 位中有偶数个 1），则跳转。",
    #     "JPE": "同 JP，如果 PF = 1（即结果的低 8 位中有偶数个 1），则跳转。",
    #     "JNP": "如果 PF = 0（即结果的低 8 位中有奇数个 1），则跳转。",
    #     "JPO": "同 JNP，如果 PF = 0（即结果的低 8 位中有奇数个 1），则跳转。",

    #     # 基于符号标志和溢出标志的组合跳转
    #     "JG": "如果有符号数比较中，操作数1 > 操作数2，则跳转。",
    #     "JNLE": "同 JG，如果有符号数比较中，操作数1 > 操作数2，则跳转。",
    #     "JLE": "如果有符号数比较中，操作数1 <= 操作数2，则跳转。",
    #     "JNG": "同 JLE，如果有符号数比较中，操作数1 <= 操作数2，则跳转。",

    #     # 基于进位标志和零标志的组合跳转
    #     "JA": "如果无符号数比较中，操作数1 > 操作数2，则跳转。",
    #     "JNBE": "同 JA，如果无符号数比较中，操作数1 > 操作数2，则跳转。",
    #     "JBE": "如果无符号数比较中，操作数1 <= 操作数2，则跳转。",
    #     "JNA": "同 JBE，如果无符号数比较中，操作数1 <= 操作数2，则跳转。",

    #     # 其他跳转指令
    #     "JCXZ": "如果 CX 寄存器的值为 0，则跳转。",
    #     "LOOP": "将 ECX 寄存器的值减 1，如果 ECX != 0，则跳转。"
    # }
    jump_instructions = {
        # 无条件跳转指令
        "jmp": "unconditional jump",

        # 基于零标志（ZF）的跳转
        "je": "op1 == op2",
        "jz": "result == 0",
        "jne": "op1 != op2",
        "jnz": "result != 0",

        # 基于进位标志（CF）的跳转
        "jb": "op1 < op2 (unsigned)",
        "jnae": "op1 < op2 (unsigned)",
        "jae": "op1 >= op2 (unsigned)",
        "jnb": "op1 >= op2 (unsigned)",

        # 基于符号标志（SF）的跳转
        "jl": "op1 < op2 (signed)",
        "jnge": "op1 < op2 (signed)",
        "jge": "op1 >= op2 (signed)",
        "jnl": "op1 >= op2 (signed)",

        # 基于溢出标志（OF）的跳转
        "jo": "overflow",
        "jno": "no overflow",

        # 基于奇偶标志（PF）的跳转
        "jp": "parity even",
        "jpe": "parity even",
        "jnp": "parity odd",
        "jpo": "parity odd",

        # 基于符号标志和溢出标志的组合跳转
        "jg": "op1 > op2 (signed)",
        "jnle": "op1 > op2 (signed)",
        "jle": "op1 <= op2 (signed)",
        "jng": "op1 <= op2 (signed)",

        # 基于进位标志和零标志的组合跳转
        "ja": "op1 > op2 (unsigned)",
        "jnbe": "op1 > op2 (unsigned)",
        "jbe": "op1 <= op2 (unsigned)",
        "jna": "op1 <= op2 (unsigned)",

        # 其他跳转指令
        "jcxz": "CX == 0",
        "loop": "ECX--; if ECX != 0, jump",
        "setnz":"op1 == op2",
        "js": "op1 < op2",
    }
    op = line.split("\t")[0].split(" ")[2]
    if op in jump_instructions:
        return jump_instructions[op]
    else:
        return None


def analysis_cmp(line, jmp, cmp_offset, switch_field):
    ## 先分操作数，然后看哪个是被污染的，然后根据jmp推导约束
    parts = line.split("\t")
    offset = parts[2]
    value = parts[-1]
    if ";" in offset:
        ## offset中有";"，说明两个操作数都被污染，形式可能是regreg regmem memreg
        offset1 = offset.split(";")[0]
        offset2 = offset.split(";")[1]
        if offset1 in switch_field or offset2 in switch_field:
            print("offset:", offset1, offset2)
            return
        constraint = (offset1, jmp, offset2)
        if offset1 and offset1 != "65535":
            if offset1 in cmp_offset:
                cmp_offset[offset1].add(constraint)
            else:
                cmp_offset[offset1] = set()
                cmp_offset[offset1].add(constraint)
        if offset2 and offset2 != "65535":
            if offset2 in cmp_offset:
                cmp_offset[offset2].add(constraint)
            else:
                cmp_offset[offset2] = set()
                cmp_offset[offset2].add(constraint)
    else:
        ## 只有一个操作数被污染
        if ";" in value:
            ## regreg regmem memreg
            ## 不是立即数的暂时不记录，不记录的原因是 不是立即数的值会变动频繁，记录下来会生成多个约束多个分支
            # value = value.split(";")[1]
            # if offset:
            #     position = offset[0]
            #     offset = offset[1:]
            #     if position == "w":
            #         constraint = (offset, jmp, int(value, 16))
            #     elif position == "r":
            #         constraint = (int(value, 16), jmp, offset)
            #     if offset in cmp_offset:
            #         cmp_offset[offset].add(constraint)
            #     else:
            #         cmp_offset[offset] = set()
            #         cmp_offset[offset].add(constraint)
            pass
        else:
            ## regimm memimm
            value = re.search(r"(?<!\[)(?<!\w)(0x[0-9a-fA-F]+|\d+)\b(?!\])", parts[0].split(":")[1]).group(0)
            # print("offset在这里:", offset, offset2)
            # print("switch_field:", switch_field)
            if offset and offset not in switch_field:
                constraint = (offset, jmp, int(value, 16))
                if offset != "65535":
                    if offset in cmp_offset:
                        cmp_offset[offset].add(constraint)
                    else:
                        cmp_offset[offset] = set()
                        cmp_offset[offset].add(constraint)
    

def process_cmp_offset(cmp_offset): ## 规范化约束，统一形式(1，2，3)1是字段，2是关系，3是值
    reverse_table = {
        "==": "==",
        "!=": "!=",
        "<": ">",
        ">": "<",
        "<=": ">=",
        ">=": "<=",
    }
    for offset in cmp_offset:
        if len(list(cmp_offset[offset])[0]) == 2:
            continue
        constraints = set()
        for constraint in cmp_offset[offset]:
            constraint = list(constraint)
            if constraint[0] == offset:
                constraint[1] = reverse_table[constraint[1].split(" ")[1]]
            else:
                tmp = constraint[0]
                constraint[0] = offset
                constraint[2] = tmp
                constraint[1] = reverse_table[constraint[1].split(" ")[1]]
            constraints.add(tuple(constraint))
        cmp_offset[offset] = constraints
            

def cmp_value_changed(line, payload):
    value = line.split("\t")[-1]
    value = int(value.split(";")[0], 16)
    offset = line.split("\t")[2]
    if offset != '6':
        return None
    if ";" in offset or "w" in offset or "r" in offset: ##说明当前cmp比较的是两个寄存器，或者是内存和寄存器，暂不考虑
        print("cmp_value_changed error", line)
        return None
    offset = offset.strip("w").strip("r")
    offset = [int(offset.split(",")[0]), int(offset.split(",")[-1])]
    value_payload = ""
    for i in range(offset[0], offset[1] + 1):
        value_payload += hex(payload[i])[2:]
    value_payload = int(value_payload, 16)
    if value != value_payload:
        addr = line.split(":")[0].split()[1]
        return (addr, offset, value_payload)
    return None
    ##如果当前line的值和payload原值不一样，则会返回一个元组，第一个是当前line的addr，第二个是line中涉及的字段偏移

def analysis_info(path, packet_size, payload, preprocess_path=None):
    field_value = {} ##存储字段和值
    cmp_offset = {} ##存储字段和对应的比较值
    loops_address = [] ##存储循环基本块的边界
    loop_relative_offset = {} ##存储和循环相关的字节偏移
    candidate_length_field = []
    fields = []
    functions = []
    changed_offset = {} ## key是addr, value是offset
    
    if path:
        # 提取数据流结果
        with open(path, "r") as f:
            lines = f.readlines()


        for line in lines:
            line = line.strip().strip("\n")
            # 提取疑似长度字段
            if line.startswith("LENGTH"):
                offset = line.split("\t")[1]
                candidate_length_field.append(offset)

            # 提取循环基本块
            if line.startswith("LOOP"):
                address = line.split("\t")[1]
                size = line.split("\t")[2]
                loops_address.append([int(address, 16), int(address, 16) + int(size, 16)])
        loops_address = sorted(loops_address)
        # for i in loops_address:  # for debug
        #     print(hex(i[0]), hex(i[1]))
        # print()

        ## 将重叠的基本块合并 
        if loops_address:
            l = loops_address[0][0]
            r = loops_address[0][1]
            tmp = []
            for i in range(1, len(loops_address) + 1):
                if i == len(loops_address):
                    tmp.append([l, r])
                elif r < loops_address[i][0]:
                    tmp.append([l, r])
                    l = loops_address[i][0]
                    r = loops_address[i][1]
                elif loops_address[i][0] <= r:
                    if r <= loops_address[i][1]:
                        r = loops_address[i][1]
            loops_address = tmp
            # for i in loops_address: # for debug
            #     print(hex(i[0]), hex(i[1]))
        else:
            print("所分析文件中没有loop tag")
        

        switch_data = preprocess.preprocess(preprocess_path)
        switch_relate_instructions_addr = None
        switch_field = []
        case_values = None
        ## 逐行分析info文件
        cmp_line = ""
        for idx, line in enumerate(lines):
            if line.startswith("Function") and "enter" in line:
                func_name = line.split("\t")[3].split("(")[0]
                if func_name not in functions:
                    if idx < len(lines) - 1 and (lines[idx + 1].startswith("Instruction") and "setnz" not in lines[idx + 1]):
                        functions.append(func_name)
                    elif idx > 0 and (lines[idx - 1].startswith("Instruction")):
                        functions.append(func_name)
                if func_name in switch_data.keys():
                    # print("函数名：" + func_name)
                    switch_relate_instructions_addr = switch_data[func_name][1]
                    case_values = switch_data[func_name][0]
            if line.startswith("Instruction"):
                # print(line)
                ## 首先匹配switch相关字段
                if switch_relate_instructions_addr:
                    seg = line.split()[1][:-1][:2]  ##又是在打补丁，因为主程序基址和动态库基址还不一样
                    base_addr = None
                    for a in base_addrs:
                        if a.startswith(seg):
                            base_addr = int(a, 16)
                            break
                    instr_addr = hex(int(line.split()[1][:-1], 16) - base_addr)
                    # print("基地址：", hex(base_addr))
                    # print(line[:-1])
                    # print("地址：", instr_addr)
                    # print("")
                    if instr_addr in switch_relate_instructions_addr:
                        offset = line.split("\t")[2] ##大概率只有一个字节，暂不考虑多字节
                        # print("switch字段 ", offset)
                        # print("约束值 ", case_values)
                        
                        cmp_offset[offset] = set(case_values)
                        switch_field.append(offset)
                        # print("约束值 ", case_values)
                        continue
                
                ## 判断涉及cmp的字段值是否发生了变化
                if "cmp" in line:
                    tmp = cmp_value_changed(line, payload)
                    # if tmp and str(tmp[1][0]) not in switch_field:
                    if tmp and tmp[1][0] != 17 and tmp[1][0] != 18:
                        changed_offset[tmp[0]] = (tmp[1], tmp[2])

                ## 提取涉及cmp的字节和值
                if "cmp" in line:
                    cmp_line = line
                    continue
                if ("j" in line or "setnz" in line) and cmp_line:
                    jmp = analysis_jmp(line)
                    if jmp:
                        analysis_cmp(cmp_line, jmp, cmp_offset, switch_field)
                    else:
                        print(line)
                        print("jmp error")
                    cmp_line = ""
                    continue

                if "setnz" in line:
                    continue
                
                ## 提取涉及循环的字节偏移
                if loops_address:
                    address = int(line.split(":")[0].split(" ")[1], 16)
                    for loop_address_l, loop_address_r in loops_address:
                        if loop_address_l <= address and address < loop_address_r:
                            try:
                                offset = line.split(":", 1)[1].split("\t")[2]
                                opcode = line.split(":", 1)[1].split(" ")[1]
                            except:
                                print(traceback.format_exc())
                                print(line)
                                sys.exit(0)
                            if ";" in offset:
                                offset_1 = offset.split(";")[0]
                                offset_2 = offset.split(";")[1]
                                if offset_1:
                                    if offset_1 in loop_relative_offset:
                                        loop_relative_offset[offset_1].append(opcode)
                                    else:
                                        loop_relative_offset[offset_1] = []
                                        loop_relative_offset[offset_1].append(opcode)
                                if offset_2:
                                    if offset_2 in loop_relative_offset:
                                        loop_relative_offset[offset_2].append(opcode)
                                    else:
                                        loop_relative_offset[offset_2] = []
                                        loop_relative_offset[offset_2].append(opcode)
                            else:
                                if offset in loop_relative_offset:
                                    loop_relative_offset[offset].append(opcode)
                                else:
                                    loop_relative_offset[offset] = []
                                    loop_relative_offset[offset].append(opcode)

                ## 提取field和value
                part = line.split("\t")
                if len(part) >= 3:
                    field = part[2][1:] if ("w" in part[2] or "r" in part[2]) else part[2]
                    value = part[-1]
                    if not (field in field_value) and not(";" in field) and field != "65535":
                        field_value[field] = value
        
        process_cmp_offset(cmp_offset)
        # print(cmp_offset)
        
        def cmp(a, b):
            a_1 = int(a.split(",")[-1])
            b_1 = int(b.split(",")[-1])
            if a_1 == b_1:
                return len(a) - len(b)
            return a_1 - b_1
        # field_value = dict(sorted(field_value.items(), key=lambda x: (int(x[0].split(",")[-1]))))
        fields_access_order = list(field_value.keys())
        fields = sorted(list(field_value.keys()), key=functools.cmp_to_key(cmp))
        # print(fields)

        loop_relative_offset = dict(sorted(loop_relative_offset.items(), key=lambda x: len(x[1]), reverse=True))

        ## 去除异常值
        try:
            i = None
            j = None
            for i in reversed(range(len(fields))):
                for j in fields[i].split(","):
                    if j and int(j) > packet_size:
                        del fields[i]
                        break
        except:
            print("异常i&j", i, j)
            print("fields", fields)
            print("fields 长度", len(fields))
            print(traceback.format_exc())
            sys.exit(0)

        if not fields:
            return True
        # 提取数据流结果用于字段划分
        ## 去重
        i = 0
        ranges = []
        while i < len(fields):
            for j in range(i+1, len(fields)):
                # print(i,j)
                if int(fields[i].split(",")[-1]) <= int(fields[j].split(",")[-1]) and int(fields[i].split(",")[-1]) >= int(fields[j].split(",")[0]):
                    i = j
            ranges.append(fields[i])
            i += 1
        fields = ranges

        ## 补充缺失的值
        result = []
        merge = []

        i = 0
        j = 0
        j_l = int(fields[j].split(",")[0])
        j_r = int(fields[j].split(",")[-1])

        while j < len(fields):
            # print(result, i, fields[j], j_l, j_r)
            if i < j_l:
                merge.append(i)
                i += 1
                continue

            if i >= j_l and i <= j_r:
                if merge:
                    result.append(merge)
                # if merge:
                #     for m in merge:
                #         result.append([m])
                    merge = []
                result.append(list(map(lambda x: int(x),fields[j].split(","))))
                j += 1
                if j >= len(fields):
                    break
                i = j_r + 1
                j_l = int(fields[j].split(",")[0])
                j_r = int(fields[j].split(",")[-1])
        
        #注释的原因是在每次变异的时候尾部有一大串没有使用的字节分在一起，这其实是没必要的，fields只输出使用过的字段就行
        #使用groundtruth.py的时候取消注释
        # if j_r < packet_size:
        #     i = j_r + 1
        #     if merge:
        #         merge = []
        #     for i in range(i, packet_size + 1):
        #         merge.append(i)
        #     result.append(merge)
        fields = result

        # cmp_offset = dict(sorted(cmp_offset.items(), key=lambda x: len(x[1]), reverse=True)) ##按照约束值的多少进行排序
        ## 对每个值set排序
        # for i in cmp_offset:
        #     cmp_offset[i][0] = set(sorted(list(cmp_offset[i][0])))
        #     cmp_offset[i][1] = set(sorted(list(cmp_offset[i][1])))
    
    if not fields:
        return True

    return fields, functions, fields_access_order, cmp_offset, loop_relative_offset, candidate_length_field, changed_offset


def count_bbl(path, bbls, last_file_size):
    current_file_size = os.path.getsize(path)
    if current_file_size <= last_file_size:
        return 0, len(bbls), last_file_size, bbls
    
    last_count = len(bbls)
    global base_addrs
    base_addrs = []
    base_addr = None
    with open(path, "r") as f:
        lines = f.readlines()
        for line in lines:
            if "BASE" in line:
                base_addr = line.split(": ")[1]
                if base_addr not in base_addrs:
                    base_addrs.append(base_addr)
                base_addr = int(base_addr, 16)
            elif "BBL" in line:
                address = int(line.split("\t")[1], 16) - base_addr
                bbls.add(address)
    current_count = len(bbls)
    return (current_count - last_count) / last_count * 100 if last_count else 0, current_count, current_file_size, bbls
    
def analysis_bbltrace(path):
    bbltrace = []
    with open(path, "r") as f:
        lines = f.readlines()
        for line in lines:
            if "orgBBL" in line:
                address = line.split("\t")[1]
                if address not in bbltrace:
                    bbltrace.append(address)
    return bbltrace