import random
import traceback
import sys
import re
import Extract_constraint

class Packet():

    def __init__(self, id, payload, fields):
        self.id = id
        self.payload = self.strtopayload(payload) if isinstance(payload, str) else payload ##形如[0x01, 0x11, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01] 
        self.fields = fields ## class Fields
        self.mutate_strategy = None ## str
        self.mutate_field = None #clase field
    

    def get_payload(self):
        return self.payload
    

    def update_fields(self, fields):
        self.fields = fields
    

    def strtopayload(self, payload):
        payload = payload.replace(' ', '')
        payload = payload.replace('0x', '')
        tmp = []
        for i in range(0, len(payload) - 1, 2):
            tmp.append(int("0x" + payload[i] + payload[i + 1], 16))
        return tmp
    

    def set_fields(self, fields):
        self.fields = fields


class Constraint:

    def __init__(self, constraint):
        self.constraint = constraint ## 一个区间元组
        self.bbl_increase = 0
    

    def update_selected_times(self, value=1):
        self.selected_times = self.selected_times + value
    

    def set_bbl_increase(self, bbl_increase):
        self.bbl_increase = bbl_increase

    

    def __hash__(self):
        return hash(self.constraint)
    

    def __eq__(self, other):
        return isinstance(other, Constraint) and self.constraint == other.constraint
    

    def get_value(self):
        return random.randint(self.constraint[0], self.constraint[1])
    

    def get_info(self):
        return f"约束{self.constraint}, 覆盖率提升{self.bbl_increase}"


class Field():
    # constraint_use = True

    def __init__(self, range_str, range_list, bbl_increase, constraints, position):
        self.range_str = range_str
        self.range_list = range_list
        self.bbl_increase = bbl_increase ## 该字段带来的基本块增加量
        self.constraint_use = True
        self.position = position ## 该字段被访问的顺序
        self.isLength = False ##该字段是否是长度字段
        self.constraints = set() ##set() 每个元素是约束取值范围元组
        self.constraints_with_info = {} ## 字段，key是约束取值范围，value是constraint类
        if constraints:
            self.set_constraints(constraints)


    def choose_value(self):
        index = random.randint(0, len(self.constraints_with_info) - 1)
        result = self.constraints_with_info[list(self.constraints_with_info)[index]]
        max_index = result.index
        for constraint in self.constraints_with_info:
            if self.constraints_with_info[constraint].selected_times == 0:
                result = self.constraints_with_info[constraint]
                break
            if max_index != max(max_index, self.constraints_with_info[constraint].index):
                max_index = self.constraints_with_info[constraint].index
                result = self.constraints_with_info[constraint]
        
        ## 选择好约束后要生成值
        return result.constraint, result.get_value() ## constraint类，int


    def validate_constraints(self, constraints:list):
        ## 将约束中的异常值剔除
        max_val = 2 ** ((self.range_list[1] - self.range_list[0] + 1) * 8)
        for i in reversed(range(len(constraints))):
            if constraints[i][0] > max_val:
                del constraints[i]
                continue
            if constraints[i][1] > max_val:
                constraints[i] = (constraints[i][0], max_val)
        return constraints
    

    def set_constraints(self, constraints):## constraints是cmp_offsets，是字典
        ## 如果字段是基于计算，或者是长度字段这种，不需要约束来更新值
        if self.constraint_use == False or self.isLength:
            self.constraints = {(0,0)}
            self.constraints_with_info = {(0,0): Constraint((0,0))}
            return
        if len(list(constraints)[0]) == 2: 
            ## 为switch打的补丁， 涉及switch的字段约束不需要处理
            self.constraints.clear()
            self.constraints_with_info.clear()
            for constraint in constraints:
                self.constraints.add(constraint)
                self.constraints_with_info[constraint] = Constraint(constraint)
        else:
            ## 首先将约束从符号表示转化为范围值
            constraints = self.constraints_to_ranges(constraints)
            ## 补足所有的范围
            constraints_ = self.integrate_ranges(constraints)
            while constraints_ != constraints:
                constraints = constraints_
                constraints_ = self.integrate_ranges(constraints)
            constraints = self.complete_ranges(constraints)
            constraints = self.validate_constraints(constraints)
            ## 将范围都实例化为constraint类
            self.constraints.clear()
            self.constraints_with_info.clear()
            for constraint in constraints:
                self.constraints.add(constraint)
                self.constraints_with_info[constraint] = Constraint(constraint)

    def update_constraints(self, constraints): ## constraints是cmp_offsets，是字典
        ## 如果字段是基于计算，或者是长度字段这种，不需要约束来更新值
        if self.constraint_use == False or self.isLength:
            self.constraints = {(0,0)}
            self.constraints_with_info = {(0,0): Constraint((0,0))}
            return
        if len(list(constraints)[0]) == 2: 
            ## 为switch打的补丁， 涉及switch的字段约束不需要处理
            self.constraints.clear()
            self.constraints_with_info.clear()
            for constraint in constraints:
                self.constraints.add(constraint)
                self.constraints_with_info[constraint] = Constraint(constraint)
        else:
            ## 首先将新约束转化为不重叠的范围元组
            constraints = self.constraints_to_ranges(constraints)
            constraints_ = self.integrate_ranges(constraints)
            while constraints_ != constraints:
                constraints = constraints_
                constraints_ = self.integrate_ranges(constraints)
            constraints = self.complete_ranges(constraints)

            ## 将原有元组和新的元组合并
            constraints = set(constraints) | self.constraints
            constraints_ =  self.integrate_ranges(constraints)
            while constraints_ != constraints:
                constraints = constraints_
                constraints_ = self.integrate_ranges(constraints)
            constraints = self.complete_ranges(constraints)
            constraints = self.validate_constraints(constraints)

            ## 添加新增约束，删去废弃约束
            to_remove = self.constraints - set(constraints)
            for constraint in to_remove:
                if constraint in self.constraints_with_info:
                    del self.constraints_with_info[constraint]
            for constraint in constraints:
                if constraint not in self.constraints:
                    self.constraints_with_info[constraint] = Constraint(constraint)
            self.constraints = set(constraints)
        

    def constraint_to_range(self, var, op, val, size):
        # 2字节的最大值
        max_val = 2 ** (size * 8)

        if op == '<':
            return (0, val - 1)
        elif op == '<=':
            return (0, val)
        elif op == '>':
            return (val + 1, max_val)
        elif op == '>=':
            return (val, max_val)
        elif op == '==':
            return (val, val)
        elif op == '!=':
            # 不等于条件拆分成两个范围
            return {(0, val - 1), (val + 1, max_val)}
        else:
            raise ValueError(f"Unsupported operator: {op}")


    def constraints_to_ranges(self, constraints: dict):
        ## 将('2,3', '>=', 6)转化为(6, max)
        ranges = set()
        for var, op, val in constraints:
            if isinstance(val, str):
                ## 将约束值是字段的过滤，理论上来说，应该处理这个。
                continue
            result = self.constraint_to_range(var, op, val, self.range_list[1] - self.range_list[0] + 1)
            if isinstance(result, tuple):
                ranges.add(result)
            else:
                ranges.update(result)  # 处理不等于条件返回的集合
        return ranges


    def split_ranges(self, a, b):
        """拆分两个重叠的范围，返回不重叠的范围集合"""
        a_start, a_end = a
        b_start, b_end = b

        # 情况 1: a 和 b 完全不重叠
        if a_end < b_start or b_end < a_start:
            return {a, b}

        # 情况 2: a 和 b 完全重叠
        if a_start == b_start and a_end == b_end:
            return {a}

        # 情况 3: a 包含 b
        if a_start <= b_start and a_end >= b_end:
            ranges = set()
            if a_start < b_start:
                ranges.add((a_start, b_start - 1))
            ranges.add((b_start, b_end))
            if b_end < a_end:
                ranges.add((b_end + 1, a_end))
            return ranges

        # 情况 4: b 包含 a
        if b_start <= a_start and b_end >= a_end:
            ranges = set()
            if b_start < a_start:
                ranges.add((b_start, a_start - 1))
            ranges.add((a_start, a_end))
            if a_end < b_end:
                ranges.add((a_end + 1, b_end))
            return ranges

        # 情况 5: a 和 b 部分重叠
        if a_start < b_start:
            return {
                (a_start, b_start - 1),
                (b_start, a_end),
                (a_end + 1, b_end)
            }
        else:
            return {
                (b_start, a_start - 1),
                (a_start, b_end),
                (b_end + 1, a_end)
            }


    def integrate_ranges(self, input_ranges: set):
        input_ranges = sorted(input_ranges)
        result = set()

        for a in input_ranges:
            to_remove = set()
            to_add = set()

            # 遍历结果集合中的每个范围
            for b in result:
                # 检查是否有重叠
                if not (a[1] < b[0] or b[1] < a[0]):
                    # 如果有重叠，拆分范围
                    split_result = self.split_ranges(a, b)
                    to_remove.add(b)
                    to_add.update(split_result)

            # 更新结果集合
            result.difference_update(to_remove)
            result.update(to_add)

            # 如果没有重叠，直接添加到结果集合
            if not to_add:
                result.add(a)

        # 过滤掉无效的范围(如 (0, -1))
        result = {(start, end) for start, end in result if start <= end}
        return result


    def complete_ranges(self, input_ranges):
        # 初始化全范围
        max_range = 2 ** ((self.range_list[1] - self.range_list[0] + 1) * 8) - 1
        full_range = set()
        full_range.add((0, max_range))

        # 遍历输入的范围
        for start, end in input_ranges:
            new_ranges = set()
            for r_start, r_end in full_range:
                # 如果输入范围与当前范围没有重叠，直接保留当前范围
                if end < r_start or start > r_end:
                    new_ranges.add((r_start, r_end))
                else:
                    # 拆分当前范围
                    if r_start < start:
                        new_ranges.add((r_start, start - 1))
                    if r_end > end:
                        new_ranges.add((end + 1, r_end))
            full_range = new_ranges

        # 合并输入范围和补全的范围
        result = input_ranges.union(full_range)

        # 按起始值排序并返回
        return sorted(result, key=lambda x: x[0])


    def set_bbl_increase(self, bbl_increase):
        self.bbl_increase = bbl_increase
    

    def set_mutate_num(self, mutate_num):
        self.mutate_num = mutate_num
    
    
    def set_used_value(self, used_value):
        self.used_value = used_value
    

    def get_range(self):
        return self.range_str
    

    def get_info(self):
        return f"字段范围{self.range_str}, 字段覆盖率提升{self.bbl_increase}, 字段约束{self.constraints}, 是否长度字段：{self.isLength}"

class Fields():

    fields_with_info = {} ## 字典，key为字段名，value为Field类
    fields = [] ## 字段划分  [[0, 1], [2, 3], [4], [5]]
    fields_position = [] ## 字段访问的先后顺序
    changed_offset = [] ## 已经计算过约束的offset 形如 [[2, 3], [6, 6], [13, 14]]


    def __init__(self, fields, cmp_offset):
        self.fields = fields
        self.set_fields_with_info(cmp_offset)
    
    def checked_changed_offset(self, changed_offset): 
        ## changed_offset形如 {'0x7f706b04d869': ([2, 3], 25), '0x7f706b04df03': ([2, 3], 25), '0x7f706b04dff8': ([6, 6], 128), '0x7f706b050b6a': ([13, 14], 8)}
        need_to_compute_offset = []
        for addr in changed_offset:
            if changed_offset[addr][0] not in self.changed_offset:
                need_to_compute_offset.append(changed_offset[addr][0])
        return need_to_compute_offset


    def update_changed_offset(self, need_to_update_offset, need_to_update_value):
        ## need_to_update_offset形如 [[2, 3], [6], [13, 14]]
        ## 更新已经修改过的offset
        for offset in need_to_update_offset:
            if offset not in self.changed_offset:
                self.changed_offset.append(offset)

        ## 更新offset对应的约束
        for offset in need_to_update_value:
            if offset[0] == offset[-1]:
                _offset = offset[0]
            else:
                _offset = offset
            field = self.fields_with_info[_offset]
            new_constraints = []
            exp = need_to_update_value[offset]
            for constraint in field.constraints:
                ct = Extract_constraint.reverse_operation(constraint, exp)
                if ct:
                    new_constraints.append(ct)
                # new_constraints.append(Extract_constraint.reverse_operation(constraint, exp))
            new_constraints = field.validate_constraints(new_constraints)
            field.constraints = set(new_constraints)
    
    def get_constraints(self):
        constraints = {}
        for field in self.fields_with_info:
            constraints[field] = sorted(list(self.fields_with_info[field].constraints))
        return constraints


    def set_fields_with_info(self, cmp_offset):
        p = 0
        for i in cmp_offset:
            p += 1
            if "," in i:
                l = i.split(",")[0]
                r = i.split(",")[1]
            else :
                l = i
                r = i
            field = Field(i, [int(l), int(r)], 0, cmp_offset[i], p)
            self.fields_with_info[i] = field
        self.fields_position = (list(cmp_offset.keys()))
        
    
    def update_fields_info(self, cmp_offset):
        p = 0
        for i in cmp_offset:
            p += 1
            if i not in self.fields_with_info: ## 如果是新字段
                if "," in i:
                    l = i.split(",")[0]
                    r = i.split(",")[1]
                else :
                    l = i
                    r = i
                field = Field(i, [int(l), int(r)], 0, cmp_offset[i], p)
                self.fields_with_info[i] = field
            else:
                ## 如果是旧字段，直接替换原来的约束
                self.fields_with_info[i].update_constraints(cmp_offset[i])
                
        self.fields_position = (list(cmp_offset.keys()))

    
    def choose_field(self):
        ## 选择index2最大的field
        
        index = random.randint(0, len(self.fields_position) - 1)
        result = self.fields_with_info[self.fields_position[index]]
        max_index2 = result.index2
        for field in self.fields_position:
            # print(self.fields_with_info[field].range_str, self.fields_with_info[field].index2)
            if self.fields_with_info[field].isLength:
                continue
            if max_index2 != max(max_index2, self.fields_with_info[field].index2):
                result = self.fields_with_info[field]
                max_index2 = result.index2
        return result ## class Field


    def __str__(self):
        return str(self.fields)


    def print_fields_with_info(self):
        for i in self.fields_with_info:
            print(self.fields_with_info[i].get_info())


    def get_fields_with_info(self):
        for i in self.fields_with_info:
            yield (self.fields_with_info[i].get_info() + "\n")
    

class Mutate:
    constraint_combination = {}
    status = "mutate value"
    stack = []
    length_field_recognize = False
    length_times = 0
    
    def init(self, fields: Fields):
        self.fields = fields
        self.field_sequence = self.fields.fields_position
        self.constraints = fields.get_constraints()
        self.stack = []  # DFS状态栈，元素格式：(当前字段索引, 当前约束索引, 路径字典)
        self._init_stack()
    
    def _field_to_key(self, field):
        return ",".join(map(str, field))

    def _init_stack(self):
        """初始化栈：压入第一个字段的第一个约束"""
        if self.field_sequence:
            self.stack.append((0, 0, {}))


    def get_next_mutation(self, recall=False):
        print("get_next_mutation-recall", recall)

        if recall:
            self.stack = self.reserve.copy()
        print("get_next_mutation-self.field_sequence", self.field_sequence)
        print("get_next_mutation-self.constraints", self.constraints)
        while self.stack:
            self.reserve = self.stack.copy()
            print("stack: ", self.stack)
            field_idx, constr_idx, path = self.stack.pop()

            if field_idx >= len(self.field_sequence):
                print("跳过无效字段索引", field_idx)
                continue

            field_key = self.field_sequence[field_idx]
            constraints = self.constraints.get(field_key, [])

            print("当前信息：", field_idx, field_key, constraints, constr_idx, path)

            # 跳过无效约束索引
            if constr_idx >= len(constraints):
                print("跳过无效约束索引", constr_idx)
                continue

            # 更新路径
            new_path = path.copy()
            new_path[field_key] = constraints[constr_idx]

            # 压入当前字段的下一个约束（无论是否最后一个字段）
            if constr_idx + 1 < len(constraints):
                self.stack.append((field_idx, constr_idx + 1, path))

            # 如果当前不是最后一个字段，压入下一个字段的初始约束
            if field_idx < len(self.field_sequence) - 1:
                next_field_idx = field_idx + 1
                self.stack.append((next_field_idx, 0, new_path))
            else:
                # 直接返回最后一个字段的当前约束
                # print("new_path: ", new_path)
                # print()
                return new_path

        return None
    
    def update_mutate(self, fields: Fields):
        self.fileds = fields
        self.constraints = fields.get_constraints()

        #for iec104 8 for bacnet 14
        position = 14
        sequence_change = False
        position_change = False
        if str(position) in self.field_sequence:
            print("sequence 修改")
            self.field_sequence = self.field_sequence[:self.field_sequence.index(str(position)) + 1]
            sequence_change = True
        
        if str(position) in self.fields.fields_position:
            self.fields.fields_position = self.fields.fields_position[:self.fields.fields_position.index(str(position)) + 1]
            position_change = True
            print("position 修改")

        if len(self.field_sequence) < len(fields.fields_position):
            print("update_mutate-field_sequence", self.field_sequence)
            print("update_mutate-fields_position: ", fields.fields_position)
            self.field_sequence = self.fields.fields_position
            return True
        elif self.field_sequence != fields.fields_position:
            self.field_sequence = self.fields.fields_position
        
        if sequence_change or position_change:
            for key in list(self.constraints.keys()):  # 转换为列表避免迭代时修改字典
                if key not in self.field_sequence:
                    del self.constraints[key]
                ## for iec104
                # if key == '0':
                #     self.constraints[key] = [(104, 104)]
        ## for enip
        for key in list(self.constraints.keys()):
            if key == '0,1':
                self.constraints[key] = [(4, 4), (99, 99), (100, 100), (101, 101), (102, 102), (103, 110), (111, 111), (112, 112)]
                

        return False
        
    
    def replace_value_by_range(self, start, end, payload, value):
        ## payload是list，start和end是替换的范围，value是替换的值
        try:
            ## S7
            # v = (len(payload) - 17).to_bytes(2, byteorder="big")
            # payload[13] = v[0]
            # payload[14] = v[1]
            # payload[15] = 0
            # payload[16] = 0
            # payload[6] = 0x80

            # if (start == 13 and end ==14) or (start == 15 and end == 16) or (start == 6 and end == 6):
            #     return payload

            # replace_length = end - start + 1
            # if value <= int(replace_length * 2 * 'f', 16):
            #     value = value.to_bytes(replace_length, byteorder="big")
            # else:
            #     value = int(replace_length * 2 * 'f', 16)
            #     value = value.to_bytes(replace_length, byteorder="big")
            
            # enip 小端序读取
            replace_length = end - start + 1
            if value <= int(replace_length * 2 * 'f', 16):
                value = value.to_bytes(replace_length, byteorder="little")
            else:
                value = int(replace_length * 2 * 'f', 16)
                value = value.to_bytes(replace_length, byteorder="little")
            
            # value = value.to_bytes(replace_length, byteorder="big")
            for i in range(replace_length):
                if (start + i) < len(payload):
                    payload[start + i] = value[i]
        except:
            print(traceback.format_exc())
            print("value", (value))
            print("replace_length 长度：", str(replace_length))
            print("start", start)
            print("end", end)
            sys.exit(0)
        return payload ## list


    def value_generate(self, fields: Field, field: str, payload_length: int, constraint: tuple):
        
        if self.length_field_recognize:
            if fields.fields_with_info[field].isLength:
                value =  payload_length
            else:
                value = random.randint(constraint[0], constraint[1])
        else:
            if payload_length >= constraint[0] and payload_length <= constraint[1]:
                value = payload_length
            else:
                value = random.randint(constraint[0], constraint[1])
        return value


    def mutate_value(self, payload: list, fields: Fields):
        mutated_payload = payload
        res = self.get_next_mutation(self.update_mutate(fields))
        print("mutate_value-res:", res)
        if res:
            for field in res:
                if fields.fields_with_info[field].isLength:
                    continue
                if field in self.constraint_combination:
                    if res[field] == self.constraint_combination[field]:
                        continue
                    else:
                        value = self.value_generate(fields, field, len(payload), res[field])
                        start = int(field.split(",")[0])
                        end = int(field.split(",")[1] if "," in field else field)
                        mutated_payload = self.replace_value_by_range(start, end, payload, value)
                else:
                    value = self.value_generate(fields, field, len(payload), res[field])
                    start = int(field.split(",")[0])
                    end = int(field.split(",")[1] if "," in field else field)
                    mutated_payload = self.replace_value_by_range(start, end, payload, value)
            self.constraint_combination = res
            return mutated_payload
        else:
            print("res is None")
            return None
    
    def mutate_length(self, payload: list, fields: Fields):
        ## 长度变异，末尾增加两个字节，如果长度字段已经识别，则修改长度字段的值；如果长度字段没有识别，则将数据包的所有值进行替换
        mutated_payload = payload.copy()
        mutated_payload.append(0)
        mutated_payload.append(len(mutated_payload) + 1)
        length = None
        for field in fields.fields_with_info:
            if fields.fields_with_info[field].isLength:
                length = fields.fields_with_info[field].range_list
        if length:
            mutated_payload = self.replace_value_by_range(length[0], length[1], mutated_payload, len(mutated_payload))
        else: 
            for i in range(len(mutated_payload)):
                if mutated_payload[i] == len(mutated_payload) - 2:
                    mutated_payload[i] = len(mutated_payload)
        return mutated_payload
    
    def get_next_payload(self, payload: list, fields: Fields):
        # if fields.fields[-1][-1] > len(payload) - 6 and self.length_times < 2:
        #     print("mutate length", fields.fields[-1][-1], len(payload) - 6)
        #     self.status = "mutate length"
        #     mutated_payload = self.mutate_length(payload.copy(), fields)
        #     self.length_times += 1
        # else:
        #     self.status = "mutate value"
        #     mutated_payload = self.mutate_value(payload.copy(), fields)
        #     self.length_times = 0
        mutated_payload = self.mutate_value(payload.copy(), fields)
        return mutated_payload

    
    def get_start_packet(self, protocol, length=10):
        ## 初始化一个长度为length的packet
        
        
        # payload = []
        # for _ in range(length // 2):
        #     payload.append(0)
        #     payload.append(length)
        ## S7
        # payload = [0x3, 0x0, 0x0, 0x19, 0x2, 0xf0, 0x80, 0x32, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0xf0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1, 0xe0]
        ## bacnet
        # payload = [0x81, 0x0a, 0x00, 0x16, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x07, 0x3d, 0x08, 0x00, 0x53, 0x59, 0x4e, 0x45, 0x52, 0x47, 0x59]
        ## opcua
        # payload = [0x48, 0x45, 0x4c, 0x46, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x40, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30]
        # payload = [0x4d, 0x53, 0x47, 0x46, 0x5d, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, 0x0, 0xac, 0x1, 0x0, 0x0, 0xe8, 0x3c, 0x1c, 0xc1, 0xa5, 0x98, 0xdb, 0x1, 0xa3, 0x86, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0x10, 0x27, 0x0, 0x0, 0x0, 0x0, 0x0, 0x18, 0x0, 0x0, 0x0, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        ## ftp
        # payload = [0xff, 0xff, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ## iec104
        # payload = [0x68, 0x04, 0x01, 0x00, 0x00, 0x08]
        # payload = [0x68, 0xe, 0x0, 0x0, 0x0, 0x0, 0x64, 0x1, 0x6, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x14]
        if protocol == "Enip":
            payload = [112, 0, 44, 0, 0, 1, 2, 16, 0, 0, 0, 0, 164, 168, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 2, 0, 161, 0, 4, 0, 1, 3, 139, 0, 177, 0, 24, 0, 114, 236, 10, 2, 32, 2, 36, 1, 1, 0, 4, 0, 76, 2, 32, 114, 36, 0, 156, 103, 7, 0, 9, 0]
        elif protocol == "Libmodbus":
            payload = [87, 222, 0, 0, 0, 8, 255, 23, 235, 28, 0, 1, 1, 0]
        elif protocol == "Freemodbus":
            payload = [0x57, 0xde, 0x00, 0x00, 0x00, 0x08, 0xff, 0x0f, 0x00, 0x05, 0x00, 0x01, 0x01, 0x00]
        elif protocol == "S7comm":
            payload = [0x3, 0x0, 0x0, 0x19, 0x2, 0xf0, 0x80, 0x32, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0xf0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1, 0xe0]
        elif protocol == "Iec104":
            # payload = [0x68, 0xe, 0x0, 0x0, 0x0, 0x0, 0x64, 0x1, 0x6, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x14]
            payload = [104, 14, 0, 0, 0, 0, 101, 1, 8, 0, 10, 0, 0, 0, 0, 20]
        elif protocol == "Cip":
            payload = [112, 0, 44, 0, 0, 1, 2, 16, 0, 0, 0, 0, 164, 168, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 2, 0, 161, 0, 4, 0, 1, 3, 139, 0, 177, 0, 24, 0, 114, 236, 10, 2, 32, 2, 36, 1, 1, 0, 4, 0, 76, 2, 32, 114, 36, 0, 156, 103, 7, 0, 9, 0]
        elif protocol == "Bacnet":
            # payload = [0x81, 0x0a, 0x00, 0x16, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x07, 0x3d, 0x08, 0x00, 0x53, 0x59, 0x4e, 0x45, 0x52, 0x47, 0x59]
            payload = [0x81, 0x04, 0x00, 0x18, 0xc0, 0xa8, 0xde, 0x80, 0xba, 0xc0, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08, 0x0a, 0x30, 0x39, 0x1a, 0x30, 0x39]
        elif protocol == "Ftp":
            payload = [0xff, 0xff, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        elif protocol == "Dnp3":
            payload = []
        
        return Packet(0, payload, [])