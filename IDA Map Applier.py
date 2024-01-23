import re
import idc
import idaapi

try:
    import ida_bytes
except ImportError:
    ida_bytes = None

try:
    import ida_name
except ImportError:
    ida_name = None

try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None

try:
    import ida_nalt
except ImportError:
    ida_nalt = None

try:
    import ida_ua
except ImportError:
    ida_ua = None

try:
    import ida_funcs
except ImportError:
    ida_funcs = None


def _get_fn_by_version(lib, curr_fn, archive_fn, archive_lib=None):
    '''
    Determine which function should be called based on the version of IDA.

    :param curr_fn: 7.X version of the function.

    :param archive_fn: 6.X version of the function.

    :param archive_lib: If the archive lib is different than the current lib,
                        set it here.

    :return: Function based on the version of IDA.
    '''
    if idaapi.IDA_SDK_VERSION >= 700:
        try:
            return getattr(lib, curr_fn)
        except AttributeError:
            raise Exception('%s is not a valid function in %s' %
                            (curr_fn, lib))
    use_lib = lib if archive_lib is None else archive_lib
    try:
        return getattr(use_lib, archive_fn)
    except AttributeError:
        raise Exception('%s is not a valid function in %s' %
                        (archive_fn, use_lib))


def get_func_name(ea):
    '''
    Retrieve function name.

    :param ea: Any address belonging to the function.
    :type ea: int

    :return: Null string if not found, otherwise the functions name.
    '''
    fn = _get_fn_by_version(idc, 'get_func_name', 'GetFunctionName')
    return fn(ea)


def set_name(ea, name):
    '''
    Rename an address.

    :param ea: Linear address.
    :type ea: int

    :param name: New name of address. If name == "" then delete old name.
    :type name: str

    :return: 1-ok, 0-failure
    '''
    fn = _get_fn_by_version(idc, 'set_name', 'MakeName')
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, name, ida_name.SN_CHECK)
    return fn(ea, name)


def set_name_ex(ea, name):
    '''
    Rename an address.

    :param ea: Linear address.
    :type ea: int

    :param name: New name of address. If name == "" then delete old name.
    :type name: str

    :return: 1-ok, 0-failure
    '''
    fn = _get_fn_by_version(idc, 'set_name', 'MakeNameEx')
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, name, ida_name.SN_CHECK)
    return fn(ea, name)


def ask_file(for_saving, default, dialog):
    '''
    Get file from user.

    :param for_saving: File is for saving.
    :type for_saving: int

    :param default: File extension.
    :type default: str

    :param dialog: Dialog box to display to the user.
    :type dialog: str

    :return: file path.
    '''
    fn = _get_fn_by_version(ida_kernwin, 'ask_file', 'AskFile', idc)
    return fn(for_saving, default, dialog)


def msg(message):
    """
    Display a UTF-8 string in the message window.

    :param message: Message to print.
    :type message: str

    :return: PyObject * (what?)
    """
    fn = _get_fn_by_version(ida_kernwin, 'msg', 'Message', idc)
    return fn(message)


def namespace_recast(namespace_string):
    namespace_string_split = namespace_string.split("::")
    if len(namespace_string_split) != 2:
        raise RuntimeError("Incorrect namespace string passed,split size: " +
                           str(len(namespace_string_split)) + ".\n")
    return namespace_string_split[1] + "__" + str(len(namespace_string_split[0])) + namespace_string_split[0]


"""
UpdateFunctionName
    Identifier: new name of the sub
    RVA: relative virtual address of the sub
    
    Only updates a function that's undefined (check against string "sub")
"""


def UpdateFunctionName(Identifier, RVA):
    if "::" in Identifier:
        try:
            Identifier = namespace_recast(Identifier)
        except RuntimeError as err:
            msg("Recast Fail: " + str(err))
            return

    var = get_func_name(RVA)
    if var[:3] == "sub":
        set_name_ex(RVA, Identifier)


"""
parse
    line: line to parse
    
    Parses a line and updates the function name.
    Skips entries of the map which value is 0 (0000:00000000)
    
    example line:
    0002:0000004c       __imp__GetLocaleInfoA@16   0072304c     kernel32:KERNEL32.dll
"""


def parse(line):
    parts = line.split()
    global text_segment

    if len(parts) < 2:
        msg("Insufficient record string: " + line + '\n')
        return

    address_part = parts[0]
    identifier = parts[1]

    if ':' in address_part:
        function_sel, offset_hex = address_part.split(':')
    else:
        msg("In line: \"" + line +
            "\" address sectioon do not have segment \':\' separator, it might be a bug\n")
        return

    if text_segment.sel != int(function_sel):
        msg("Line: \"" + line + "\" do not belong to a .text segment, skipping...\n")
        return

    try:
        offset = int(offset_hex, 16)
    except ValueError:
        msg("Hex cast offset error in line: \"" + line + "\".\n")
        return

    text_segment_start = text_segment.start_ea
    RVA = text_segment_start + offset

    if RVA is not None and identifier:
        UpdateFunctionName(identifier, RVA)


"""
handleLine
    line: input line to handle
    
    Handles a line of a map file to search for the beginning block of the symbols.
    (After the string "Address" is found)
    If the beginning of the block is found the following lines will be parsed by the function parse.
"""
parseBlockFound = False


def handleLine(line):
    global parseBlockFound
    if parseBlockFound:
        parse(line)
    else:
        splitted = line.split()
        if len(splitted) >= 4 and splitted[0] == "Address":
            msg("parseBlockFound\n")
            parseBlockFound = True


def main():
    breakpoint()

    global text_segment
    text_segment = idaapi.get_segm_by_name('.text')
    if not text_segment:
        msg("Cannot obtain .text segment base address")
        exit()

    fileName = ask_file(0, "*.map", "Map File")

    if fileName:
        msg("Open File\n")
        with open(fileName, "r") as mapFile:
            for line in mapFile:
                handleLine(line)
            mapFile.close()
    else:
        msg("No file selected!\n")


if __name__ == "__main__":
    main()
