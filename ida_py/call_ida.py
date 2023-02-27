import random
import sys
import os
import time
import json
import tlsh
import difflib

ida_path = "/home/chengrui/.wine/drive_c/tools/ida/idat64.exe"
wine_prefix = "wine"
tlsh_threshold = 50

class tlsh_hash(object):
    def __init__(self, value):
        self.v = value

    def __hash__(self):
        return self.v.__hash__()

    def __eq__(self, other):
        if isinstance(other, tlsh_hash):
            return tlsh.diff(self.v, other.v) <= tlsh_threshold
        else:
            return False

def set_tlsh_threshold(v):
    global tlsh_threshold
    tlsh_threshold = v

def set_ida(path):
    global ida_path
    ida_path = path

def set_wine(wine):
    wine_prefix = wine + " "

def func_inst_to_func_hash(func_inst):
    func_hash = []
    i = 0
    while i < len(func_inst):
        if tlsh.hash(func_inst[i]) == 'TNULL':
            cur_t = func_inst[i]
            i += 1
            while tlsh.hash(cur_t) == 'TNULL' and i < len(func_inst):
                cur_t += func_inst[i]
                i += 1
            if tlsh.hash(cur_t) != 'TNULL':
                func_hash.append(tlsh.hash(cur_t))
        else:
            func_hash.append(tlsh.hash(func_inst[i]))
            i += 1
    return func_hash

# 提取可执行文件、静态库文件的签名
def get_sign(exe):
    file_path = os.path.join(os.path.realpath(os.path.curdir), str(time.time_ns()) + ".txt")
    while os.path.exists(file_path):
        file_path = os.path.join(os.path.realpath(os.path.curdir), str(time.time_ns() + random.randint(0, 99999)) + ".txt")
    os.system("%s %s -B -S\"enum_inst.py %s\" '%s'" % (wine_prefix, ida_path, linux_path_to_wine_path(file_path), exe))
    print("%s %s -B -S\"enum_inst.py %s\" '%s'" % (wine_prefix, ida_path, linux_path_to_wine_path(file_path), exe))
    while True:
        if not (os.path.exists(file_path)):
            time.sleep(1)
            continue
        with open(file_path, "r") as f:
            func_inst = json.load(f)
            func_inst = [i.encode("ascii") for i in func_inst]
            break
    os.remove(file_path)
    return func_inst_to_func_hash(func_inst)

# 保存签名到文件
def save_sign(sign, file):
    with open(file, "w") as f:
        json.dump(sign, f)

# 从文件中读取签名
def load_sign(sign):
    func_hash = json.load(sign)
    return func_hash
#
# 在签名1中匹配签名2，如果存在，返回(True, 相似度)，不存在，返回(False, 相似度)
# radio参数指明匹配阈值，如果签名2的radio部分在签名1中出现过，则视为存在
def match_sign(sign1, sign2, radio=0.9):
    sq = difflib.SequenceMatcher(a=sign1, b=sign2)
    matching = sq.get_matching_blocks()
    sum_size = 0
    for a_i, b_i, m_size in matching:
        sum_size += m_size
    return (sum_size / len(sign2) >= radio, sum_size / len(sign2))

# 将linux系统的目录转换为wine下的目录
def linux_path_to_wine_path(path: str):
    return "Z:" + path.replace("/", "\\")