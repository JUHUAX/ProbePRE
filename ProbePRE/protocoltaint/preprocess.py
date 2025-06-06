import json

def preprocess(preprocess_path):
    with open(preprocess_path, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)
    
    for func_name in loaded_data:
        value_list = []
        for value in loaded_data[func_name][0]:
            value_list.append((value[0], value[1]))
        loaded_data[func_name][0] = value_list
    return loaded_data

# {"func_name":[case, value, list], [addr, list]}
