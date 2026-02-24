
import idaapi
import idautils
import idc
import ida_funcs
import ida_name

INPUT_FUNCS = {
    "fread", "fscanf", "read", "recv", "recvfrom", "gets", "fgets",
    "scanf", "sscanf", "ReadFile"
}

DANGEROUS_FUNCS = {
    "strcpy", "strncpy", "sprintf", "snprintf", "vsprintf", "strcat", "strncat",
    "memcpy", "memmove", "wcscpy", "wcsncpy"
}

def get_parent_func(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return "<no_func>"
    return ida_funcs.get_func_name(f.start_ea)

def get_called_name(call_ea):

    dst = idc.get_operand_value(call_ea, 0)
    if dst:
        n = ida_name.get_name(dst)
        if n:
            return n


    t = idc.print_operand(call_ea, 0)
    return t or ""

def main():
    for ea in idautils.Heads():
        if idc.print_insn_mnem(ea).lower() != "call":
            continue

        name = get_called_name(ea)
        if not name:
            continue


        if name.startswith("__imp_"):
            name = name[len("__imp_"):]
        if "@" in name:
            name = name.split("@", 1)[0]

        if name in INPUT_FUNCS:
            idaapi.msg(f"INPUT {name} call@{ea:08X} in {get_parent_func(ea)}\n")

        if name in DANGEROUS_FUNCS:
            idaapi.msg(f"DANGEROUS {name} call@{ea:08X} in {get_parent_func(ea)}\n")

if __name__ == "__main__":
    main()