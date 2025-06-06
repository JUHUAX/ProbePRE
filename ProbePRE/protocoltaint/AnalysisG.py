import re
import functools
import os
import traceback
import sys
import preprocess

base_addrs = []

def analysis(path, packet_size):
    field_value = {} ##存储字段和值
    loops_address = [] ##存储循环基本块的边界
    loop_relative_offset = {} ##存储和循环相关的字节偏移
    candidate_length_field = []
    fields = []
    
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
        

        
        for idx, line in enumerate(lines):
            if line.startswith("Instruction"):
                # print(line)

                if "setnz" in line or "j" in line:
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
                    for m in merge:
                        result.append([m])
                    # result.append(merge)
                    # print("merge", merge)
                    merge = []
                result.append(list(map(lambda x: int(x),fields[j].split(","))))
                j += 1
                if j >= len(fields):
                    break
                i = j_r + 1
                j_l = int(fields[j].split(",")[0])
                j_r = int(fields[j].split(",")[-1])
        
        #注释的原因是在每次变异的时候尾部有一大串没有使用的字节分在一起，这其实是没必要的，fields只输出使用过的字段就行
        # 使用groundtruth.py的时候取消注释
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

    return fields, loop_relative_offset, candidate_length_field


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