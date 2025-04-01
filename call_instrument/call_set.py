#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import struct

def parse_fstate_files(fstate_dir):

    home = os.environ.get("HOME", "")
    if not home:
        print("no $HOME")
        return

    func_count_path = os.path.join(home, "func_count.txt")
    try:
        with open(func_count_path, "r", encoding="ascii") as f:
            line = f.read()
            num = ''
            for x in line:
                if x != '\x00':
                    num+=x
            count = int(num)
    except Exception as e:
        print(f"read count err: {e}")
        return

    bool_block_size = (count + 3) & ~3

    func_list_path = os.path.join(home, "func_list.txt")
    func_names = []
    try:
        with open(func_list_path, "r", encoding="utf-8") as f:
            for i in range(count):
                line = f.readline()
                if not line:
                    break
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    func_names.append(parts[1])
                else:
                    func_names.append(parts[0])
    except Exception as e:
        print(f"read func_list.txt err: {e}")
        return

    if len(func_names) < count:
        print("func_list.txt count err!")


    for filename in os.listdir(fstate_dir):
        if not filename.startswith("fstate"):
            continue

        full_path = os.path.join(fstate_dir, filename)
        if not os.path.isfile(full_path):
            continue

        print(f"\nparsing: {full_path}")
        try:
            with open(full_path, "rb") as binf:
                while True:
                    header = binf.read(4)
                    if len(header) < 4:
                        break

                    state, = struct.unpack("<I", header)

                    bool_block = binf.read(bool_block_size)
                    if len(bool_block) < bool_block_size:
                        break

                    bool_part = bool_block[:count]

                    called_funcs = []
                    for i, bval in enumerate(bool_part):
                        if bval == 1:
                            if i < len(func_names):
                                called_funcs.append(func_names[i])
                            else:
                                called_funcs.append(f"<未知函数索引 {i}>")

                    print(f"  状态码: {state}, 调用函数: {called_funcs}")

        except Exception as e:
            print(f"解析文件 {filename} 出错: {e}")


if __name__ == "__main__":
    fstate_dir = "/home/ubuntu/experiments/aflnet_out"
    parse_fstate_files(fstate_dir)
