from threading import Thread
import os
import ida_py.call_ida

def extrac(base, paths, output, step):
    for i in range(step, len(paths), step):
        s = ida_py.call_ida.get_sign(os.path.join(base, paths[i]))
        ida_py.call_ida.save_sign(s, os.path.join(output, paths[i] + ".sign"))
# 提取lib_path中的所有库的sign，并保存至output目录下
# threads表示开几个目录提取
def extract_sign(lib_path, output, threads=16):
    paths = os.listdir(lib_path)
    th = []
    for i in range(threads):
        t = Thread(target=extrac, args=(lib_path, paths, output, i + 1))
        t.start()
        th.append(t)
        #t.start()

    for i in range(threads):
        th[i].join()

