import os

# 将info文件按照不同数据包的执行跟踪分割
def capture_execution_info(path, output_dir, last_file_size, index): 
    # 假设程序A会在 `path` 文件中记录执行信息
    # 程序B可以在每次发送数据包后，读取程序A的执行信息

    # 记录文件当前大小
    current_file_size = os.path.getsize(path)
    # print(last_file_size, current_file_size)
    
    # 只读取新增的内容
    if current_file_size > last_file_size:
        with open(path, 'r') as f:
            # 跳过文件中已读取部分
            f.seek(last_file_size)
            # 读取新增的执行信息
            new_lines = f.readlines()
            execution_info = ''.join(new_lines)
        
        # 创建一个新的文件名，按照数据包的index命名
        output_file = os.path.join(output_dir, f"packet_execute_info{index}.txt")
        
        # 将对应的数据包执行信息写入新文件
        with open(output_file, 'w') as f:
            f.write(execution_info)
        
        print(f"Captured execution info into {output_file}")
        return current_file_size, output_file

    return last_file_size, ""

# 通过BBL文件来统计不同数据包对应的基本块覆盖
def capture_bbl_count(path, last_file_size, last_count):
    current_file_size = os.path.getsize(path)
    if current_file_size > last_file_size:
        with open(path, 'r') as f:
            lines = f.readlines()
            count = len(lines)
        if last_count:
            return (str(round((count - last_count)/last_count * 100, 2)) + "%", count, current_file_size)
        else:
            return (str(round((count - last_count), 2)), count, current_file_size)
    return ("0%", last_count, current_file_size)

def capture_execution_bbltrace(path, output_dir, last_file_size, index): 
    # 假设程序A会在 `path` 文件中记录执行信息
    # 程序B可以在每次发送数据包后，读取程序A的执行信息

    # 记录文件当前大小
    current_file_size = os.path.getsize(path)
    # print(last_file_size, current_file_size)
    
    # 只读取新增的内容
    if current_file_size > last_file_size:
        with open(path, 'r') as f:
            # 跳过文件中已读取部分
            f.seek(last_file_size)
            # 读取新增的执行信息
            new_lines = f.readlines()
            execution_info = ''.join(new_lines)
        
        # 创建一个新的文件名，按照数据包的index命名
        output_file = os.path.join(output_dir, f"packet_bbltrace_{index}.txt")
        
        # 将对应的数据包执行信息写入新文件
        with open(output_file, 'w') as f:
            f.write(execution_info)
        
        print(f"Captured execution info into {output_file}")
        return current_file_size, output_file

    return last_file_size, ""