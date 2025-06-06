import argparse
import Packet_send
import Analysis
import File_operate
import Mutate
import Instrument
import time
import os
import Format
import Extract_constraint

parser = argparse.ArgumentParser(description="protocol taint analysis")
parser.add_argument("-p", "--protocol", type=str, help="protocol name")
args = parser.parse_args()
if args.protocol:
    protocol = args.protocol
else:
    protocol = "Libmodbus"


# 全局变量
## pcap_file = "/home/juhua/experiment/BinPRE/pcap/modbus.pcap"
ip = "127.0.0.1"
binary_map = {
    "S7comm": ["/home/juhua/experiment/MY/binary/s7_server", False],
    "Libmodbus": ["/home/juhua/experiment/MY/binary/modbus_libmodbus", False],
    "Freemodbus": ["/home/juhua/experiment/MY/binary/modbus_freemodbus", False],
    "Iec104": ["/home/juhua/experiment/MY/binary/iec104server /home/juhua/experiment/MY/binary/iec104server.json", False],
    "Enip": ["/home/juhua/experiment/MY/binary/enip_server 127.0.0.1 255.255.255.0 127.0.0.1 test.com testdevice 00:15:C5:BF:D0:87", False],
    # "Enip": ["/home/juhua/experiment/MY/binary/OpENer lo", False],
    # "Enip": ["/home/juhua/experiment/MY/binary/CIP 127.0.0.1 255.255.255.0 127.0.0.1 test.com testdevice 00:15:C5:BF:D0:87", False],
    "Bacnet": ["/home/juhua/experiment/MY/binary/bacserv", True],
    "Ftp": ["/home/juhua/experiment/MY/binary/ftp", False],
    "Dnp3": ["/home/juhua/experiment/MY/binary/dnp3-server", False],
    "Mqtt": ["/home/juhua/experiment/MY/binary/mqtt", False],

}
binary_path = binary_map[protocol][0]
result_path = "/home/juhua/experiment/MY/protocoltaint/result"
info_path = f"{result_path}/process_data/info.txt"
capture_info_path = f"{result_path}/process_data"
bbl_path = f"{result_path}/process_data/BBLs.txt"
bbltrace_path = f"{result_path}/process_data/BBLtrace.txt"
output_path = f"{result_path}/{protocol}/output.txt"
preprocess_path = f"/home/juhua/experiment/MY/protocoltaint/prepocess/{protocol}_preprocess.json"
format_path = f"{result_path}/{protocol}/format.txt"
isUDP = binary_map[protocol][1]
info_last_file_size = 0
bbl_last_file_size = 0
bbltrace_last_file_size = 0
bbl_all = 0
bbls = set()
packets = []
mutate = Mutate.Mutate()
change = False
terminate = False
index = 0
limit = 100000000

with open(output_path, "w+") as f:
    start_time = time.time()
    # 启动插桩
    packet = mutate.get_start_packet(protocol, 10)
    process = Instrument.start_instrument(binary_path)
    if protocol == 'Enip':
        time.sleep(20)

    last_time = start_time
    # 开始字段划分和协议探索
    while index < limit and not terminate:
    # while not terminate:
        print("")
        print(f"{index} round:")
        ## 发送msg
        payload = packet.get_payload()
        payload_size = len(payload)
        print(payload)
        reboot = Packet_send.send_msg(ip, payload, protocol, isUDP)
        time.sleep(3)
        if reboot == True:
            print("send_msg reboot")
            Instrument.stop_instrument(process)
            process = Instrument.reboot_instrument(binary_path)
            if protocol == 'Enip':
                time.sleep(20)
            info_last_file_size = 0
            bbl_last_file_size = 0
            bbltrace_last_file_size = 0
            continue

        msg = reboot.copy()
        ## 字段划分&提取信息
        info_last_file_size, capture_info_file = File_operate.capture_execution_info(info_path, capture_info_path, info_last_file_size, index) ## info.txt
        bbltrace_last_file_size, capture_bbltrace_file = File_operate.capture_execution_bbltrace(bbltrace_path, capture_info_path, bbltrace_last_file_size, index) ## BBLtrace.txt
        
        if capture_info_file == "":
            print("capture_info_file reboot")
            Instrument.stop_instrument(process)
            process = Instrument.reboot_instrument(binary_path)
            if protocol == 'Enip':
                time.sleep(20)
            info_last_file_size = 0
            bbl_last_file_size = 0
            bbltrace_last_file_size = 0
            continue


        count = 0
        with open(capture_info_file, 'r', encoding='utf-8') as file:
            for _ in file:
                count += 1
                if count > 200:
                    break
        if count <= 200 and protocol != "Ftp":
            print("count reboot")
            Instrument.stop_instrument(process)
            process = Instrument.reboot_instrument(binary_path)
            if protocol == 'Enip':
                time.sleep(20)
            info_last_file_size = 0
            bbl_last_file_size = 0
            bbltrace_last_file_size = 0

            continue
        
        ## 基本块计数
        bbl_increase, bbl_all, bbl_last_file_size, bbls = Analysis.count_bbl(bbl_path, bbls, bbl_last_file_size)
        bbltrace = Analysis.analysis_bbltrace(capture_bbltrace_file)

        reboot = Analysis.analysis_info(capture_info_file, payload_size - 1, payload, preprocess_path)
        if reboot == True:
            print("analysis reboot")
            Instrument.stop_instrument(process)
            process = Instrument.reboot_instrument(binary_path)
            if protocol == 'Enip':
                time.sleep(20)
            info_last_file_size = 0
            bbl_last_file_size = 0
            bbltrace_last_file_size = 0
            continue
        fields_, functions, fields_access_order, cmp_offset, loop_relative_offset, candidate_length_field, changed_offset = reboot
        print("changed_offset", changed_offset)
        print("cmp_offset:", cmp_offset)

        if index == 0:
            # 如果是第一轮，则实例化Fields类
            fields = Mutate.Fields(fields_, cmp_offset)## 包含当前字段信息的class，包括字段划分和字段约束
        else:
            if fields.fields != fields_:
                change = True
                tmp = fields.fields
                fields.fields = fields_
            fields.update_fields_info(cmp_offset)

        ## 处理经过计算的约束
        if changed_offset:
            need_to_compute_offset = fields.checked_changed_offset(changed_offset)
            program_slice = Extract_constraint.program_slice(changed_offset, capture_info_file, need_to_compute_offset)
            need_to_update_offset, need_to_update_value = Extract_constraint.analysis_constraint(program_slice)
            fields.update_changed_offset(need_to_update_offset, need_to_update_value)

        if candidate_length_field != []:
            if candidate_length_field[0] in fields.fields_with_info:
                fields.fields_with_info[candidate_length_field[0]].isLength = True
            else:
                print("candidate_length_field", candidate_length_field)
                fields.fields_with_info[candidate_length_field[0]] = Mutate.Field(candidate_length_field[0], [candidate_length_field[0].split(",")[0], candidate_length_field[0].split(",")[1]], 0, set(), None)
            fields.fields_with_info[candidate_length_field[0]].constrinat_use = False
            mutate.length_field_recognize = True

        packet.set_fields(fields) ## 将分析结果存入对应packet
        
        if bbl_increase:## 如果增加了覆盖率，则存档
            packets.append(packet)
        # mutate.set_last_bbl_increase(bbl_increase)
        curr_constraint_combination = mutate.constraint_combination
        if index == 0:
            mutate.init(fields)
        mutated_payload = mutate.get_next_payload(payload, fields)
        if mutated_payload:
            packet = Mutate.Packet(index + 1, mutated_payload, None)
        else:
            terminate = True
        next_constraint_combination = mutate.constraint_combination
        ## 计时
        now_time = time.time()
        execution_time = now_time - start_time
        round_time = now_time - last_time
        last_time = now_time
        execution_hours = execution_time // 3600  # 计算小时
        execution_minutes = (execution_time % 3600) // 60  # 计算分钟
        execution_seconds = execution_time % 60  # 计算秒
        round_hours = round_time // 3600  # 计算小时
        round_minutes = (round_time % 3600) // 60  # 计算分钟
        round_seconds = round_time % 60  # 计算秒

        ## 打印
        f.write("\n\n==========================================================================================================\n")
        f.write(f"{index} round:\n")
        f.write("\n")
        f.write(f"message send: {msg}\n")
        f.write("\n")

        f.write("字段划分-------------------------------------------------------------------------------------------------------\n")
        f.write(f"fields: {str(fields.fields)}\n")
        if change:
            f.write(f"fields change: {str(tmp)} -> {str(fields.fields)}\n")
            change = False
        f.write("\n")

        f.write("约束字段访问顺序------------------------------------------------------------------------------------------------\n")
        f.write(f"order: {str(fields.fields_position)}\n")
        f.write("\n")

        f.write("函数执行链------------------------------------------------------------------------------------------------------\n")
        f.write(f"chain: {str(functions)}\n")
        f.write("\n")

        f.write("基本块记录------------------------------------------------------------------------------------------------------\n")
        f.write(f"BBLtrace: {str(bbltrace)}\n")
        f.write("\n")


        # f.write("字段&约束详情---------------------------------------------------------------------------------------------------\n")
        # print(cmp_offset)
        # for i in fields.fields_with_info:
        #     f.write(f"{fields.fields_with_info[i].get_info()}\n")

        # f.write("\n")

        # f.write("处于循环基本块中的指令涉及的字段以及对应的助记符序列-----------------------------------------------------------\n")
        # for i in loop_relative_offset:
        #     f.write(f"{i}:\t{loop_relative_offset[i]}\n")
        # f.write("\n")

        f.write("长度字段候选-----------------------------------------------------------------------------------------------\n")
        f.write(str(candidate_length_field))
        f.write("\n")

        f.write("\n新增基本块所占百分比&当前覆盖基本块总数----------------------------------------------------------------------\n")
        f.write(f"{round(bbl_increase, 2)}% & {bbl_all}\n")
        f.write("\n")

        f.write("变异------------------------------------------------------------------------------------------------------\n")
        f.write(f"下一轮所选策略: {mutate.status}\n")
        if mutate.status == "mutate value":
            f.write(f"当前约束组合: {str(curr_constraint_combination)}\n")
            f.write(f"所选约束组合: {str(next_constraint_combination)}\n")
            f.write(f"payload: {msg}\n")
            f.write("当前payload长度：{}\n".format(len(packet.get_payload())))
        elif mutate.status == "mutate length":
            f.write(f"变异后的payload: {packet.get_payload()}\n")
            f.write("变异后长度：{}\n".format(len(packet.get_payload())))
            f.write(f"当前约束组合: {str(curr_constraint_combination)}\n")
        f.write("\n")

        f.write(f"本轮时间：{round_hours} hours {round_minutes} minutes {round_seconds} seconds\n")
        f.write(f"当前花费时间：{execution_hours} hours {execution_minutes} minutes {execution_seconds} seconds\n")

        index += 1

    Instrument.stop_instrument(process)
    execution_time = time.time() - start_time
    round_time = execution_time / limit
    execution_hours = execution_time // 3600  # 计算小时
    execution_minutes = (execution_time % 3600) // 60  # 计算分钟
    execution_seconds = execution_time % 60  # 计算秒
    round_hours = round_time // 3600  # 计算小时
    round_minutes = (round_time % 3600) // 60  # 计算分钟
    round_seconds = round_time % 60  # 计算秒
    f.write(f"最终花费时间：{execution_hours} hours {execution_minutes} minutes {execution_seconds} seconds\n")
    f.write(f"平均每轮花费时间：{round_hours} hours {round_minutes} minutes {round_seconds} seconds\n")

os.remove(info_path) #删除它是因为它太大了，没办法上传github
Format.get_format(output_path, format_path)

