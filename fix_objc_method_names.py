import logging
from typing import Iterable, Optional, Generator, Union

import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_search
import ida_ua
import ida_xref
import idautils
import idc
from idadex import ea_t

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CSTRING_ENCODING = 0x7C8
WIDE_STRING_ENCODING = 0x7D0
RET_OPCODE = 0xd65f03c0

OUTLINED_FUNCTION_NAME = '_OUTLINED_FUNCTION'
LAST_OUTLINED_FUNCTION_INDEX = 1


def remove_items(s: str, remove: Iterable[str]) -> str:
    for r in remove:
        s = s.replace(r, '')
    return s


def set_name(ea: ea_t, name: str) -> None:
    global LAST_OUTLINED_FUNCTION_INDEX

    name = remove_items(name, ['(', ')', '[', ']', '#', '@PAGEOFF'])
    for c in ',+- ':
        name = name.replace(c, '_')

    for suffix in range(LAST_OUTLINED_FUNCTION_INDEX + 1, 0xffffffff):
        new_name = name if suffix == 0 else f"{name}${suffix}"
        if ida_name.set_name(ea, new_name, ida_name.SN_NOWARN):
            name = new_name
            LAST_OUTLINED_FUNCTION_INDEX = suffix
            break
    logger.debug(f'name set: 0x{ea:x} {name}')


def get_func_start(ea: ea_t) -> Union[ea_t, None]:
    """
    Gets the start address of the function that includes ``ea``
    """
    return ida_funcs.get_func(ea).start_ea


def get_func_end(ea: ea_t) -> int:
    """
    Gets the end address of the function that includes ``ea``
    """
    return ida_funcs.get_func(ea).end_ea


def set_type(ea: ea_t, new_type: str) -> None:
    if idc.SetType(ea, new_type) is None:
        raise ValueError(f'failed to set: "0x{ea:x} {new_type}"')


def get_type(ea: ea_t) -> str:
    return idc.get_type(ea)


def data_refs_from(ea: ea_t) -> Generator[ea_t, None, None]:
    next_ea = ida_xref.get_first_dref_from(ea)
    while next_ea != ida_idaapi.BADADDR:
        yield next_ea
        next_ea = ida_xref.get_next_dref_from(ea, next_ea)


def data_refs_to(ea: ea_t) -> Generator[ea_t, None, None]:
    next_ea = ida_xref.get_first_dref_to(ea)
    while next_ea != ida_idaapi.BADADDR:
        yield next_ea
        next_ea = ida_xref.get_next_dref_to(ea, next_ea)


def code_refs_to(ea: ea_t) -> Generator[ea_t, None, None]:
    next_ea = ida_xref.get_first_cref_to(ea)
    while next_ea != ida_idaapi.BADADDR:
        yield next_ea
        next_ea = ida_xref.get_next_cref_to(ea, next_ea)


def code_refs_from(ea: ea_t) -> Generator[ea_t, None, None]:
    next_ea = ida_xref.get_first_cref_from(ea)
    while next_ea != ida_idaapi.BADADDR:
        yield next_ea
        next_ea = ida_xref.get_next_cref_from(ea, next_ea)


def get_mnemonic(ea: ea_t) -> str:
    return idc.print_insn_mnem(ea)


def get_operand(ea: ea_t, operand: int) -> str:
    return idc.print_operand(ea, operand)


def get_func_name(ea: ea_t) -> str:
    return idc.get_func_name(ea)


def get_segment_ea(segment_name: str) -> Optional[int]:
    """
    Get the start EA (Effective Address) of a segment identified by its name.

    :param segment_name: Name of the segment
    :return: Starting EA of the segment or None if not found
    """
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == segment_name:
            return idc.get_segm_start(seg)
    return None


def search_bytes(start_ea: ea_t, end_ea: ea_t, bytes_pattern: str) -> Generator[ea_t, None, None]:
    """
    Binary search of ``bytes_pattern`` in bytes between ``start_ea`` and ``end_ea``
    """
    ea = start_ea - 1
    while ea != ida_idaapi.BADADDR:
        ea = ida_search.find_binary(ea + 1, end_ea, bytes_pattern, 16, ida_search.SEARCH_DOWN)
        if ea != ida_idaapi.BADADDR:
            yield ea


def unname() -> None:
    seg_start = get_segment_ea('__text')
    seg_end = idc.get_segm_end(seg_start)
    for func_start in idautils.Functions(seg_start, seg_end):
        func_name = get_func_name(func_start)
        if 'GADGET' in func_name:
            set_name(func_start, '')
            set_type(func_start, '')


def is_leaf(func_start: ea_t) -> bool:
    for item in idautils.FuncItems(func_start):
        if get_mnemonic(item) in ('BL', 'BR'):
            return False
    return True


def should_function_be_outlined(func_start: ea_t) -> bool:
    func_name = get_func_name(func_start)
    if func_name.startswith('j_') and get_mnemonic(func_start) == 'B':
        return True
    if (not func_name.startswith('sub_')) and (not func_name.startswith(OUTLINED_FUNCTION_NAME)):
        return False
    if not is_leaf(func_start):
        return False
    return True


def define_ip_branches() -> None:
    """
    fix branches using x16

    TODO: support x17 branches
    """

    seg_start = get_segment_ea('__text')
    seg_end = idc.get_segm_end(seg_start)

    for ea in search_bytes(seg_start, seg_end, '00 02 5f d6'):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea - 4):
            # Failed to decode instruction
            continue

        if insn.get_canon_mnem() != 'ADD':
            continue

        # Check if the first operand (Rd) is a register and is x29
        if insn.ops[0].type != ida_ua.o_reg or insn.ops[0].reg != 0x9e:
            continue

        ea = get_func_start(ea)
        set_name(ea, 'branch_using_x16')
        set_type(ea, 'void __usercall __spoils<> branch_using_x16'
                     '(void *address@<X16>, void *param1, void *param2, void *param3)')

        for ref_ea in code_refs_to(ea):
            prev_ea = ref_ea - 4
            if get_mnemonic(prev_ea) != 'ADR':
                continue
            name = f'detoured_{get_func_name(prev_ea)}'
            set_name(next(data_refs_from(prev_ea)), name)


def fix_function_name_if_needed(func_start: ea_t) -> None:
    current_name = get_func_name(func_start)
    if ']_' not in current_name:
        return
    for dref in data_refs_to(func_start):
        if idc.get_segm_name(dref) not in ('__objc_const', '__objc_data'):
            continue
        
        class_name = None
        for offset in range(0, 0x10000, 8):
            ea = dref - offset
            name = idc.get_name(ea)
            if '_METHODS' not in name:
                continue
            if '_OBJC_INSTANCE_METHODS_' in name:
                operator = '-'
                class_name = name.split('_OBJC_INSTANCE_METHODS_', 1)[1]
            else:
                operator = '+'
                class_name = name.split('METHODS_', 1)[1]
            break
        assert class_name is not None

        sel_name_bytes = idc.get_strlit_contents(idc.get_qword(dref))
        if sel_name_bytes is None:
            continue

        sel_name = sel_name_bytes.decode()
        new_name = f'{operator}[{class_name} {sel_name}]'
        print(f'set {hex(func_start)} name: {current_name} -> {new_name}')
        set_name(func_start, new_name)


def fix_objc_method_names() -> None:
    logger.info('fixing objc method names')

    seg_start = get_segment_ea('__text')
    seg_end = idc.get_segm_end(seg_start)

    for func_start in idautils.Functions(seg_start, seg_end):
        fix_function_name_if_needed(func_start)

    # Edit->Plugins->Objective-C->Reload Objective-C Info
    ida_loader.load_and_run_plugin('objc', 1)


if __name__ == '__main__':
    fix_objc_method_names()
