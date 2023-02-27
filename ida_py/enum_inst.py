import ida_auto
import idc
import idautils
import ida_funcs
import json

ida_auto.auto_wait()
func_hash = []
for ea in idautils.Functions():
    func_inst = ""
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            disasm = idc.GetDisasm(head)
            if len(disasm) == 0: #
                continue
            if disasm.split(" ")[0] == "extrn": # 导出函数,跳出
                break
            func_inst += (disasm.split(" ")[0] + ",")

    if len(func_inst) > 100: # 把短函数过滤掉,因为没办法准确匹配,过滤少于30条指令的函数
        func_hash.append(func_inst)

if len(idc.ARGV) == 2:
    f = open(idc.ARGV[1], "w")
    f.write(json.dumps(func_hash))
    f.close()

idc.qexit(0)