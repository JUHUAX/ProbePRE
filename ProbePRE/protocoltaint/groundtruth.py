import scapy
import pyshark
import Packet_send
import File_operate
import AnalysisG
import time
import subprocess
import time
import psutil
import json

def get_payload(path, protocol):
    if protocol == "Iec104":
        port = 2404
    elif protocol == "Cip":
        port = 44818
    elif protocol == "Libmodbus":
        port = 502  
    elif protocol == "Freemodbus":  
        port = 502
    elif protocol == "S7comm":
        port = 102
    elif protocol =="ftp":
        port = 21
    elif protocol == "Iec104":
        port = 2404
    elif protocol == "Enip":
        port = 44818
    elif protocol == "Bacnet":
        port = 47808
    elif protocol == "Dnp3":
        port = 20000
    payloads = []
    packets = scapy.all.rdpcap(path)
    for packet in packets:
        if packet.haslayer(scapy.all.Raw) and packet.dport == port:
            payloads.append(packet[scapy.all.Raw].load)
    return payloads


def parse_above_transport_layer(pcap_file="", protocol=""):
    if protocol == "modbus_8":
        all_fields = [
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10],
            [0, 2, 4, 6, 7, 8, 10, 12, 13],
            [0, 2, 4, 6, 7, 8, 10, 12, 13],
        ]
        return all_fields

    # 打开PCAP文件进行解析
    cap = pyshark.FileCapture(pcap_file)
    all_fields = []
    for packet in cap:
        fields = []
        index = 0
        # print(f"Packet Number: {packet.number}")
        # 遍历每个协议层，跳过运输层以下的协议
        for layer in packet.layers:
            if layer.layer_name in ["ip", "tcp", "udp", "eth"]:
                continue  # 跳过 IP 层、TCP 层和 UDP 层

            # print(f"Protocol: {layer.layer_name.upper()}")

            # 遍历协议层的所有字段
            # print(layer.field_names)
            for field_name in layer.field_names:
                field = layer.get_field(field_name)
                if field and hasattr(field, 'raw_value') and field.raw_value:  # 检查字段是否有原始值
                    raw_value = field.raw_value
                    if len(raw_value) == 1:
                        field_length = 1
                    else:
                        field_length = len(raw_value) // 2  # 原始值是十六进制字符串，每两字符表示一个字节

                else:
                    field_length = 0  # 无法获取字段长度时默认0
                ## 有时候pyshark分析结果和实际有出入，需要手动调整一下
                if field_name in ["param_userdata_funcgroup", "eot", "segment_data", "data_userdata_szl_id_diag_type", "data_userdata_szl_id_partlist_ex",
                                  "data_userdata_szl_id_partlist_num", "param_blockcontrol_filename", "param_blockcontrol_functionstatus_error", "param_blockcontrol_functionstatus_more",
                                  "cpu_msg_events_modetrans", "cpu_msg_events_system", "cpu_msg_events_userdefined","cpu_msg_events_alarms",'control_net', 'control_res1', 'control_dest', 
                                  'control_res2', 'control_src', 'control_expect', 'control_prio_high', 'control_prio_low','pduflags', 'segmented_request','sa', 'response_segments', 'max_adpu_size', 
                                  '', 'tag_class', 'application_tag_number', 'instance_number']:
                    field_length = 0 
                
                if field_name == "param_blockcontrol_filename_len":
                    fields.append(index)
                    index += 4
                    # print(f"  Field Name: data_blockcontrol_unknown2, Field Length: 4 bytes")
                if layer.layer_name.upper() == "CIP" and protocol == "Enip":
                    field_length = 0
                
                if field_length:
                    fields.append(index)
                    index += field_length
                    # print(f"  Field Name: {field_name}, Field Length: {field_length} bytes")
        if layer.layer_name.upper() == "DNP3":
            fields.append(index)
            index += 2
        #     print(f"  Field Name: dnp_data_chunk_crc, Field Length: 2 bytes")
        # print(fields)
        # print("-" * 50)
        all_fields.append(fields)
    # print(all_fields)
    return all_fields

def get_exp_result(path):
    with open(path, "r") as f:
        lines = f.readlines
    results = []
    for line in lines:
        if "fields:" in line:
            results.append(eval(line.split("  ")[1]))
    return results

def cal_f1_score_for_single(groundtruth_positive, exp_result_positive, packet_size):
    predicted_positives = [field[0] for field in exp_result_positive]
    groundtruth_set = set(groundtruth_positive)
    predicted_set = set(predicted_positives)

    true_positives = len(groundtruth_set.intersection(predicted_set))
    false_positives = len(predicted_set.difference(groundtruth_set))
    false_negatives = len(groundtruth_set.difference(predicted_set))

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return (precision, 0, recall, f1_score)

# def cal_f1_score_for_single(groundtruth_positive, exp_result_positive, packet_size):
#     exp_result_positive = [index[0] for index in exp_result_positive]
#     i = 0
#     groundtruth_negtive = []
#     for i in range(packet_size):
#         if i not in groundtruth_positive:
#             groundtruth_negtive.append(i)
#     i = 0
#     exp_result_negtive = []
#     for i in range(packet_size):
#         if i not in exp_result_positive:
#             exp_result_negtive.append(i)

#     TP = 0
#     for index in exp_result_positive:
#         if index in groundtruth_positive:
#             TP += 1
#     TN = 0
#     for index in exp_result_negtive:
#         if index in groundtruth_negtive:
#             TN += 1
    
#     FN = len(exp_result_negtive) - TN

#     FP = len(exp_result_positive) - TP
#     # print(exp_result_positive, exp_result_negtive, groundtruth_positive ,groundtruth_negtive)
#     # print(TP, TN)

#     ## 准确率
#     accuracy = (TP + TN) / (TP + TN + FP + FN)
#     ##精确率
#     precision = TP / (TP + FP)
#     ## 召回率
#     recall = TP / (TP + TN)
#     ##f1
#     F1 = (TP + TP) / (TP + TP + FP + FN)
#     return (accuracy, precision, recall, F1)

def cal_all_f1(path):
    with open(path, 'r') as f:
        lines = f.readlines()
    accuracy = 0
    f1 = 0
    for line in lines:
        if "accuracy" in line:
            accuracy += float(line.split(":")[1])
            continue
        if "F1 score" in line:
            f1 += float(line.split(":")[1])
            continue
    return accuracy, f1

def start_instrument(binary_path):
    print("插桩开启")
    process = subprocess.Popen(["./run", "run", "taint", binary_path])
    time.sleep(3)
    return process

def reboot_instrument(binary_path):
    time.sleep(3)
    print("插桩重启")
    process = subprocess.Popen(["./run", "run", "taint", binary_path])
    time.sleep(3)
    return process

def stop_instrument(process):
    psutil_process = psutil.Process(process.pid)
    for child in psutil_process.children(recursive=True):
        child.kill()
    psutil_process.kill()
    time.sleep(3)


if __name__ == "__main__":
    start_time = time.time()
    pcap_file = "/home/juhua/experiment/MY/pcaps/modbus.pcap"
    info_path = "/home/juhua/experiment/MY/protocoltaint/result/process_data/info.txt"
    capture_info_path = f"/home/juhua/experiment/MY/protocoltaint/result/process_data"
    result_path = "/home/juhua/experiment/MY/groundtruth/LibmodbusGM.txt"
    protocol = "Libmodbus"
    binary_map = {
        "S7comm": ["/home/juhua/experiment/MY/binary/s7_server", False],
        "Libmodbus": ["/home/juhua/experiment/MY/binary/modbus_libmodbus", False],
        "Freemodbus": ["/home/juhua/experiment/MY/binary/modbus_freemodbus", False],
        "Iec104": ["/home/juhua/experiment/MY/binary/iec104server /home/juhua/experiment/MY/binary/iec104server.json", False],
        "Enip": ["/home/juhua/experiment/MY/binary/enip_server 127.0.0.1 255.255.255.0 127.0.0.1 test.com testdevice 00:15:C5:BF:D0:87", False], # 读取cip的值，但是不解析
        # "Enip": ["/home/juhua/experiment/MY/binary/OpENer lo", False], ## 不读取cip的值，甚至部分enip都不读取
        # "Enip": ["/home/juhua/experiment/MY/binary/CIP 127.0.0.1 255.255.255.0 127.0.0.1 test.com testdevice 00:15:C5:BF:D0:87", False],
        "Bacnet": ["/home/juhua/experiment/MY/binary/bacserv", True],
        "Ftp": ["/home/juhua/experiment/MY/binary/ftp", False],
        "Mqtt": ["/home/juhua/experiment/MY/binary/mqtt", False],
        "Dnp3": ["/home/juhua/experiment/MY/binary/dnp3-server", False],
    }
    binary_path = binary_map[protocol][0]
    isUDP = binary_map[protocol][1]
    field_result = {}

    with open(result_path, "w+") as f:
        acc = 0
        rec = 0
        F1_score = 0
        groundtruth_positives = parse_above_transport_layer(pcap_file, protocol)
        payloads = get_payload(pcap_file, protocol)
        # print(len(groundtruth_positives))
        # print(len(payloads))
        
        print("插桩开启")
        if protocol != "Dnp3":
            process = subprocess.Popen(["./run", "run", "taint", binary_path])
            time.sleep(10)

        info_last_file_size = 0
        limit = len(payloads)
        # limit = 1
        i = 0
            
        while i < limit:
            payload_size = len(payloads[i])
            reboot = Packet_send.send_msg("127.0.0.1", payloads[i], protocol, isUDP)
            time.sleep(5)
            if protocol == "Dnp3":
                time.sleep(30)
            if reboot == True and protocol != "Dnp3":
                print("send_msg reboot")
                stop_instrument(process)
                process = reboot_instrument(binary_path)
                info_last_file_size = 0
                if protocol == "Dnp3":
                    time.sleep(50)
                continue
            elif reboot == True:
                print("send_msg reboot")
                break
            msg = reboot

            info_last_file_size, capture_info_file = File_operate.capture_execution_info(info_path, capture_info_path, info_last_file_size, i)
            
            reboot = AnalysisG.analysis(capture_info_file, payload_size - 1)
            #记得把analysis中补全字段的功能解除注释
            if reboot == True and protocol != "Dnp3":
                print("analysis reboot")
                stop_instrument(process)
                process = reboot_instrument(binary_path)
                info_last_file_size = 0
                if protocol == "Dnp3":
                    time.sleep(50)
                continue
            elif reboot == True:
                print("analysis reboot")
                break
            fields, loop_relative_offset, candidate_length_field = reboot

            # del
            # if protocol == "Cip":
            #     fields = [item for item in fields if item not in [[13], [14], [15], [16], [17], [18], [19]]]

            if protocol == "Enip":
                fields = [item for item in fields if item not in [[13], [14], [15], [16], [17], [18], [19]]]
                for j in range(len(fields)):
                    if fields[j] == [40]:
                        fields = fields[:j + 1]
                        break

            field_result[i] = fields
            accuracy, precision, recall, F1 = cal_f1_score_for_single(groundtruth_positives[i], fields, payload_size)
            acc += accuracy
            rec += recall
            F1_score += F1
            execution_time = time.time() - start_time
            hours = execution_time // 3600  # 计算小时
            minutes = (execution_time % 3600) // 60  # 计算分钟
            seconds = execution_time % 60  # 计算秒
            f.write("packet" + str(i) + "\n")
            f.write("send " + str(msg) + "\n")
            f.write(str(groundtruth_positives[i]) + "\n")
            f.write(str(fields) + "\n")
            f.write("accuracy:" + str(accuracy) + "\n")
            f.write("recall:" + str(recall) + "\n")
            f.write("F1 score:" + str(F1) + "\n")
            f.write(f"当前平均准确率为：{acc / (i + 1)}, 平均召回率为：{rec / (i + 1)}, F1 score为：{F1_score / (i + 1)}\n")
            f.write(f"当前花费时间：{hours} hours {minutes} minutes {seconds} seconds\n")
            f.write("-"*50 + "\n")
            i += 1
        if protocol != "Dnp3":
            stop_instrument(process)
        f.write(f"平均准确率为：{acc / limit}, 平均召回率为：{rec / limit}, F1 score为：{F1_score / limit}\n")
        execution_time = time.time() - start_time
        hours = execution_time // 3600  # 计算小时
        minutes = (execution_time % 3600) // 60  # 计算分钟
        seconds = execution_time % 60  # 计算秒
        f.write(f"最终花费时间：{hours} hours {minutes} minutes {seconds} seconds\n")
    
    filename = 'MYresult.json'
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(field_result, f, indent=4, ensure_ascii=False) # ensure_ascii=False 让中文正常显示

        print(f"成功保存到文件: {filename}")

    except IOError as e:
        print(f"写入文件时发生错误: {e}")





