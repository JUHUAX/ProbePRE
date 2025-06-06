import ast
from collections import defaultdict
from pprint import pprint

def parse_list_string(list_str):
    """
    将字符串形式的列表转换为真正的列表结构
    :param list_str: 字符串形式的列表，例如 "[[0, 1], [2, 3], , ]"
    :return: 解析后的列表结构，若失败返回 None
    """
    if not isinstance(list_str, str):
        print("错误：输入必须是字符串类型")
        return None

    try:
        parsed_list = ast.literal_eval(list_str)
        if not isinstance(parsed_list, list):
            print("错误：输入字符串不表示列表结构")
            return None
        return parsed_list
    except (SyntaxError, ValueError) as e:
        print(f"解析失败: {str(e)}")
        return None
    
    
def parse_dict_string(dict_str):
    """
    将字符串形式的字典转换为真正的字典结构
    :param dict_str: 符合Python语法的字典字符串，例如 "{'5': (0, 127), '2,3': (0, 5)}"
    :return: 解析后的字典对象 (失败返回None)
    """
    if not isinstance(dict_str, str):
        print("错误：输入必须是字符串类型")
        return None

    try:
        parsed_dict = ast.literal_eval(dict_str)
        if not isinstance(parsed_dict, dict):
            print("错误：输入字符串不表示字典结构")
            return None
        return parsed_dict
    except (SyntaxError, ValueError) as e:
        print(f"解析失败: {str(e)}")
        return None


def extract_format(output_path):
    outputs = []
    with open(output_path, "r") as f:
        lines = f.readlines()
        fields = None
        constraints = None
        func_name = None
        for line in lines:
            if line.startswith("fields:"):
                fields = line.split(":")[1][1:-1]
                # print(fields)
            if line.startswith("当前约束组合:"):
                constraints = "{" + line.split("{")[1][:-1]
                # print(constraints)
            if line.startswith("chain:"):
                func_name = line.split(":", 1)[1][1:-1]
                # print(func_name)
            if fields and constraints:
                outputs.append((parse_list_string(fields), parse_list_string(func_name), parse_dict_string(constraints)))
                fields = None
                constraints = None
                func_name = None
                # print("")
    return outputs

def cluster_fields(data):
    """字段 → 函数链 → 约束 三级聚类"""
    # 第一层：字段结构聚类
    field_clusters = defaultdict(list)
    for fields, func_chain, constraints in data:
        fields_key = tuple(tuple(f) for f in fields)  # 可哈希化
        field_clusters[fields_key].append((func_chain, constraints))

    final_clusters = []
    
    # 处理每个字段分组
    for fields_key, entries in field_clusters.items():
        # 第二层：函数调用链聚类
        func_clusters = defaultdict(list)
        for func_chain, constraints in entries:
            # 保持函数链顺序的精确匹配
            func_key = tuple(func_chain)
            func_clusters[func_key].append(constraints)
        
        # 处理每个函数链分组
        sub_clusters = []
        for func_key, constraints_list in func_clusters.items():
            # 第三层：约束条件聚类
            constraint_groups = defaultdict(list)
            for constraints in constraints_list:
                # 生成规范化约束签名
                sorted_keys = tuple(sorted(constraints.keys()))
                sorted_values = tuple(sorted((k, tuple(v)) for k, v in constraints.items()))
                constraint_groups[(sorted_keys, sorted_values)].append(constraints)
            
            # 构建约束子类
            constraint_clusters = []
            for (c_keys, c_values), samples in constraint_groups.items():
                constraint_clusters.append({
                    "constraint_keys": c_keys,
                    "constraint_values": dict(c_values),
                    "count": len(samples)
                })
            
            sub_clusters.append({
                "func_chain": list(func_key),
                "constraints": sorted(constraint_clusters, key=lambda x: -x["count"]),
                "total": len(constraints_list)
            })
        
        final_clusters.append({
            "fields": [list(f) for f in fields_key],
            "sub_clusters": sorted(sub_clusters, key=lambda x: -x["total"]),
            "total": len(entries)
        })
    
    return sorted(final_clusters, key=lambda x: -x["total"])

def print_clusters(clusters):
    """分级可视化输出"""
    for i, cluster in enumerate(clusters):
        print(f"\n=== 主协议格式 {i+1} ===")
        print(f"字段划分：{cluster['fields']}")
        print(f"总出现次数：{cluster['total']}")
        
        for j, sub in enumerate(cluster['sub_clusters']):
            print(f"\n  ■ 函数链子类 {j+1}：")
            print(f"  调用链：{sub['func_chain']}")
            print(f"  数据包数量：{sub['total']}")
            
            # for k, con in enumerate(sub['constraints']):
            #     print(f"\n    约束组 {k+1}（出现{con['count']}次）:")
                
            #     # 自然排序约束键
            #     sorted_keys = sorted(con['constraint_keys'],
            #                        key=lambda x: [int(n) if n.isdigit() else n 
            #                                     for n in x.split(',')])
            #     print(f"    约束键：{sorted_keys}")
                
                # 自然排序约束值
                # print("    约束值范围：")
                # sorted_cons = sorted(con['constraint_values'].items(),
                #                    key=lambda x: [int(n) if n.isdigit() else n 
                #                                 for n in x[0].split(',')])
                # for key, val in sorted_cons:
                #     print(f"      {key}: {val}")

def print_clusters_2_file(clusters, path):
    """分级可视化输出"""
    with open(path, "w") as f:
        for i, cluster in enumerate(clusters):
            f.write(f"\n=== 主协议格式 {i+1} ===\n")
            f.write(f"字段划分：{cluster['fields']}\n")
            f.write(f"总出现次数：{cluster['total']}\n")
            
            for j, sub in enumerate(cluster['sub_clusters']):
                f.write(f"\n  ■ 函数链子类 {j+1}：\n")
                f.write(f"  调用链：{sub['func_chain']}\n")
                f.write(f"  数据包数量：{sub['total']}\n")
                
                for k, con in enumerate(sub['constraints']):
                    f.write(f"\n    约束组 {k+1}（出现{con['count']}次）:\n")
                    
                    # 自然排序约束键
                    sorted_keys = sorted(con['constraint_keys'],
                                       key=lambda x: [int(n) if n.isdigit() else n 
                                                    for n in x.split(',')])
                    f.write(f"    约束键：{sorted_keys}\n")
                    
                    # 自然排序约束值
                    f.write("    约束值范围：\n")
                    sorted_cons = sorted(con['constraint_values'].items(),
                                       key=lambda x: [int(n) if n.isdigit() else n 
                                                    for n in x[0].split(',')])
                    for key, val in sorted_cons:
                        f.write(f"      {key}: {val}\n")

def get_format(output_path, save_path):
    parsed_data = extract_format(output_path)
    clusters = cluster_fields(parsed_data)
    print_clusters_2_file(clusters, save_path)


# # 运行聚类分析
# output_path = "/home/juhua/experiment/MY/protocoltaint/result/libmodbus/output.txt"
# save_path = "/home/juhua/experiment/MY/protocoltaint/result/libmodbus/format.txt"
# get_format(output_path, save_path)

