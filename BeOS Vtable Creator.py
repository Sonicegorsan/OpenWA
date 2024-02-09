import idautils
import idaapi
import idc
import ida_name
import ida_bytes
import ida_struct
import ida_typeinf

def find_all_vtbl():
    vtbl_list = []
    for name in idautils.Names():
        if name[1].startswith("_vt.") and not "_ptr" in name[1] and not '<' in name[1] and not '>' in name[1]:
            vtbl_list.append(name)
    return vtbl_list

def calculate_struct_size(base_address):
    i = 0
    while (not idc.get_name(base_address+1 + 1*i, ida_name.GN_VISIBLE)):
        i += 1
    return i+1

def get_vtable_methods_list(name_object):
    method_list = []
    for i in range(int(calculate_struct_size((name_object[0]))/4)):
        pointer_data = (ida_bytes.get_dword(name_object[0]+i*4))
        func = idaapi.get_name(pointer_data)
        if pointer_data != 0 and func:
            method_list.append(func)
    return method_list

def get_name_type(mangled_name):
    prefixes = ("__tf", "_vt.", "__", "_._")

    for prefix in prefixes:
        if mangled_name.startswith(prefix):
            name_without_prefix = mangled_name[len(prefix):]
            for i, char in enumerate(name_without_prefix):
                if not char.isdigit():
                    return name_without_prefix[i:int(name_without_prefix[:i])+i]
            return name_without_prefix

    parts = mangled_name.split('__')
    if len(parts) == 2:
        for i, char in enumerate(parts[1]):
            if not char.isdigit():
                return parts[1][i:int(parts[1][:i])+i]
    elif len(parts) == 1:
        return None
    elif len(parts) > 2:
        raise RuntimeError(
            "Nested namespace mangling occur, this needs to be handled by programmer")
    return None

def get_method_name(mangled_name):

    if mangled_name.startswith("__tf"):
        return "rtti_constructor"
    if mangled_name.startswith("_vt."):
        raise RuntimeError(
            "Virtual table object name shouldn't appear in virtual table struct itself, fix required")
        return "virtual_table"
    if mangled_name.startswith("__"):
        return "constructor"
    if mangled_name.startswith("_._"):
        return "destructor"

    parts = mangled_name.split('__')
    return parts[0]

def create_vtable_struct(name_object,methods_list):
    addr, name = name_object
    struct_size = calculate_struct_size(addr)

    sid = ida_struct.add_struc(idaapi.BADADDR, get_name_type(name) + "_vtbl", False)
    if sid == idaapi.BADADDR:
        print(f"Unable to create struct for {name}")
        return None
    
    struc = ida_struct.get_struc(sid)
    

    offset = 0
    for idx, method in enumerate(methods_list, start=1):
        ida_struct.add_struc_member(struc, f"reserved_{idx}", offset, idaapi.FF_DWORD, None, 4)
        offset += 4
        ida_struct.add_struc_member(struc, get_method_name(method), offset, idaapi.FF_DWORD, None, 4)
        offset += 4

    padding_size = struct_size - offset
    if padding_size > 0:
        ida_struct.add_struc_member(struc, "alignment_padding", offset, ida_bytes.byte_flag(), None, padding_size)

    print(f"Structure {name}_vtbl created with size {struct_size} bytes.")
    return struc


def get_local_type_by_name(name):
    for ordinal in range(1, ida_typeinf.get_ordinal_qty(ida_typeinf.get_idati())+1):
        ti = ida_typeinf.tinfo_t()
        if ti.get_numbered_type(ida_typeinf.get_idati(), ordinal) and ti.get_type_name() == name:
            return ti

def add_vptr_to_struct(name_object, vtable_struct):
    struct_id = ida_struct.get_struc_id(get_name_type(name_object[1]))
    if struct_id == idaapi.BADADDR:
        print(f"Struct {name_object} not found.")
        return None

    target_struct = ida_struct.get_struc(struct_id)
    if not target_struct:
        print(f"Cannot obtain {name_object} struct.")
        return None

    res = ida_struct.add_struc_member(target_struct, "reserved", 0, idaapi.FF_BYTE, None, 1)
    if res != idaapi.STRUC_ERROR_MEMBER_OK:
        print("Cannot add reserved field.")
        return None

    res = ida_struct.add_struc_member(target_struct, "__vftable", 1, idaapi.FF_DWORD, None, 4)
    if res != idaapi.STRUC_ERROR_MEMBER_OK:
        print("Cannot add vtable field.")
        return None

    if vtable_struct:
        vtable_struct_id = vtable_struct.id
        vtable_struct_name = ida_struct.get_struc_name(vtable_struct_id)

        ptr_type = ida_typeinf.tinfo_t()
        if ptr_type.get_named_type(ida_typeinf.get_idati(), vtable_struct_name):
            ptr_type.create_ptr(ptr_type)
            member_offset = ida_struct.get_member_by_name(target_struct, "__vftable")
            ida_struct.set_member_tinfo(target_struct, member_offset, 0, ptr_type, 0)
            print(f"Vtable added to {name_object}")


def main():
    breakpoint()
    vtbl_list = find_all_vtbl()
    for vtable in vtbl_list:
        print(vtable, vtable[1],vtable[1][4])
        if not vtable[1][4].isdigit():
            continue
        methods_list = get_vtable_methods_list(vtable)
        created_struct = create_vtable_struct(vtable,methods_list)
        if created_struct:
            sid = ida_struct.add_struc(idaapi.BADADDR, get_name_type(vtable[1]), False)
            if sid == idaapi.BADADDR:
                print(f"Unable to create struct from local type")
                continue
            add_vptr_to_struct(vtable,created_struct)

if __name__ == "__main__":
    main()