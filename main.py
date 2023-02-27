import difflib
import ida_py.call_ida
import os
import sys
from threading import Thread
import gen_sign.gen_sign

gen_sign.gen_sign.extract_sign("/home/chengrui/Documents/WeChat Files/wxid_1w93femnnmqm22/FileStorage/MsgAttach/659d319948c255cbdbb53f19c1199505/File/2023-02/lib/tbox_lib", "./sign_libs")