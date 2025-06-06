import scapy
import pyshark
import time
import subprocess
import time
import psutil
import json

def get_payload(path, protocol):
    if protocol == "Iec104":
        port = 20000
    elif protocol == "eip":
        port = 44818
    elif protocol == "Libmodbus":
        port = 502  
    elif protocol == "Freemodbus":  
        port = 1502
    elif protocol == "S7comm":
        port = 102
    elif protocol =="ftp":
        port = 21
    elif protocol == "Iec104":
        port = 2404
    elif protocol == "Enip":
        port = 44818
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
                                  "cpu_msg_events_modetrans", "cpu_msg_events_system", "cpu_msg_events_userdefined","cpu_msg_events_alarms"]:
                    field_length = 0 
                if layer.layer_name.upper() == "DNP3" and field_name in ["", "ctl_prifunc", "ctl_fcv", "ctl_fcb", "ctl_prm", "ctl_dir", "addr","al_obj",
                                                                         "tr_fin", "tr_fir", "tr_seq", "al_fragment", "al_seq","al_uns","al_con","al_fin","al_fir", "dnp_data_chunk","dnp_data_chunk_crc"]:
                    field_length = 0
                if layer.layer_name.upper() == "DNP3" and field_name == "al_obj":
                    field_length = 1
                if field_name == "param_blockcontrol_filename_len":
                    fields.append(index)
                    index += 4
                    # print(f"  Field Name: data_blockcontrol_unknown2, Field Length: 4 bytes")
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
    exp_result_positive = [index[0] for index in exp_result_positive]
    i = 0
    groundtruth_negtive = []
    for i in range(packet_size):
        if i not in groundtruth_positive:
            groundtruth_negtive.append(i)
    i = 0
    exp_result_negtive = []
    for i in range(packet_size):
        if i not in exp_result_positive:
            exp_result_negtive.append(i)

    TP = 0
    for index in exp_result_positive:
        if index in groundtruth_positive:
            TP += 1
    TN = 0
    for index in exp_result_negtive:
        if index in groundtruth_negtive:
            TN += 1
    
    FN = len(exp_result_negtive) - TN

    FP = len(exp_result_positive) - TP
    # print(exp_result_positive, exp_result_negtive, groundtruth_positive ,groundtruth_negtive)
    # print(TP, TN)

    ## 准确率
    accuracy = (TP + TN) / (TP + TN + FP + FN)
    ##精确率
    precision = TP / (TP + FP)
    ## 召回率
    recall = TP / (TP + TN)
    ##f1
    F1 = (TP + TP) / (TP + TP + FP + FN)
    return (accuracy, precision, recall, F1)

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
    protocol = "S7comm"
    pcap_file = "/home/juhua/experiment/MY/pcaps/S7comm.pcap"
    result_path = "/home/juhua/experiment/MY/groundtruth/S7commB.txt"
    filename = ''

    with open(result_path, "w+") as f:
        BinPRE_acc = 0
        BinPRE_rec = 0
        BinPRE_F1_score = 0
        Polyglot_acc = 0
        Polyglot_rec = 0
        Polyglot_F1_score = 0
        Autoformat_acc = 0
        Autoformat_rec = 0
        Autoformat_F1_score = 0
        Tupni_acc = 0
        Tupni_rec = 0
        Tupni_F1_score = 0
        groundtruth_positives = parse_above_transport_layer(pcap_file, protocol)
        payloads = get_payload(pcap_file, protocol)
        # print(len(groundtruth_positives))
        # print(len(payloads))
        with open(filename, 'r', encoding='utf-8') as f:
            loaded_data = json.load(f)

        BinPRE_result = loaded_data[0]
        Polyglot_Syntax =  loaded_data[1]
        Autoformat_syntaxRes =  loaded_data[2]
        Tupni_Syntax = loaded_data[3]

        limit = len(payloads)
        i = 0
            
        while i < limit:
            f.write("packet" + str(i) + "\n")
            f.write(str(groundtruth_positives[i]) + "\n")
            payload_size = len(payloads[i])

            ##BinPRE
            f.write("#################BinPRE###############\n")
            accuracy, precision, recall, F1 = cal_f1_score_for_single(groundtruth_positives[i], BinPRE_result[i], payload_size)
            BinPRE_acc += accuracy
            BinPRE_rec += recall
            BinPRE_F1_score += F1
            f.write(str(BinPRE_result[i]) + "\n")
            f.write("accuracy:" + str(BinPRE_acc) + "\n")
            f.write("recall:" + str(BinPRE_rec) + "\n")
            f.write("F1 score:" + str(BinPRE_F1_score) + "\n")
            f.write(f"当前平均准确率为：{BinPRE_acc / (i + 1)}, 平均召回率为：{BinPRE_rec / (i + 1)}, F1 score为：{BinPRE_F1_score / (i + 1)}\n")


            ##Polyglot
            f.write("#################Polyglot###############\n")
            accuracy, precision, recall, F1 = cal_f1_score_for_single(groundtruth_positives[i], Polyglot_Syntax[i], payload_size)
            Polyglot_acc += accuracy
            Polyglot_rec += recall
            Polyglot_F1_score += F1
            f.write(str(Polyglot_Syntax[i]) + "\n")
            f.write("accuracy:" + str(Polyglot_acc) + "\n")
            f.write("recall:" + str(Polyglot_rec) + "\n")
            f.write("F1 score:" + str(Polyglot_F1_score) + "\n")
            f.write(f"当前平均准确率为：{Polyglot_acc / (i + 1)}, 平均召回率为：{Polyglot_rec / (i + 1)}, F1 score为：{Polyglot_F1_score / (i + 1)}\n")

            ##Autoformat
            f.write("#################Autoformat###############\n")
            accuracy, precision, recall, F1 = cal_f1_score_for_single(groundtruth_positives[i], Autoformat_syntaxRes[i], payload_size)
            Autoformat_acc += accuracy
            Autoformat_rec += recall
            Autoformat_F1_score += F1
            f.write(str(Autoformat_syntaxRes[i]) + "\n")
            f.write("accuracy:" + str(Autoformat_acc) + "\n")
            f.write("recall:" + str(Autoformat_rec) + "\n")
            f.write("F1 score:" + str(Autoformat_F1_score) + "\n")
            f.write(f"当前平均准确率为：{Autoformat_acc / (i + 1)}, 平均召回率为：{Autoformat_rec / (i + 1)}, F1 score为：{Autoformat_F1_score / (i + 1)}\n")

            ##Tupni
            f.write("#################Tupni###############\n")
            accuracy, precision, recall, F1 = cal_f1_score_for_single(groundtruth_positives[i], Tupni_Syntax[i], payload_size)
            Tupni_acc += accuracy
            Tupni_rec += recall
            Tupni_F1_score += F1
            f.write(str(Tupni_Syntax[i]) + "\n")
            f.write("accuracy:" + str(Tupni_acc) + "\n")
            f.write("recall:" + str(Tupni_rec) + "\n")
            f.write("F1 score:" + str(Tupni_F1_score) + "\n")
            f.write(f"当前平均准确率为：{Tupni_acc / (i + 1)}, 平均召回率为：{Tupni_rec / (i + 1)}, F1 score为：{Tupni_F1_score / (i + 1)}\n")

            f.write("-"*50 + "\n")
            i += 1
        





