from typing import List

import idc
import idautils
from pathlib import Path


def set_name_with_suffix(ea: int, name: str) -> None:
    count = 0
    suffix = ''
    while not idc.set_name(ea, name + suffix, idc.SN_CHECK):
        suffix = f'_{count}'
        count += 1


def get_functions_in_range(start: int, end: int) -> set[int]:
    print('parsing __stubs')

    functions = set()
    for ea in range(start, end):
        function_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if function_ea != idc.BADADDR:
            functions.add(function_ea)

    return functions


def handle_stubs(start: int, end: int) -> None:
    print('parsing __stubs')

    for ea in get_functions_in_range(start, end):
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem != 'adrl':
            continue

        ref = list(idautils.DataRefsFrom(ea))[0]
        name = idc.get_name(ref)
        if name:
            set_name_with_suffix(ea, name)
            type_ = idc.get_type(ref)
            if type_:
                idc.SetType(ea, type_)
            print(f'0x{ea:x} {name} {type_}')


def handle_auth_stubs() -> None:
    print('parsing __auth_stubs')

    for ea in idautils.Functions():
        name = idc.get_name(ea)
        if 'objc_retain_x' in name:
            reg_name = 'x' + name.split('_x', 1)[1].split('_', 1)[0]
            if idc.get_name_ea_simple(name) != idc.BADADDR:
                idc.SetType(
                    ea, f'id __usercall __spoils<> objc_retain_{reg_name}<X0>(id {reg_name}@<{reg_name.upper()}>)')
        elif 'objc_release_x' in name:
            reg_name = 'x' + name.split('_x', 1)[1].split('_', 1)[0]
            if idc.get_name_ea_simple(name) != idc.BADADDR:
                idc.SetType(
                    ea, f'id __usercall __spoils<> objc_release_{reg_name}<X0>(id {reg_name}@<{reg_name.upper()}>)')


def handle_objc_stubs(start: int, end: int):
    print('parsing __objc_stubs')

    for ea in get_functions_in_range(start, end):
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem != 'adrp':
            continue
        selector_ea = list(idautils.DataRefsFrom(ea))
        if not selector_ea:
            continue
        selector_ea = selector_ea[0]

        # deref
        selector_ea = idc.get_qword(selector_ea)
        string_type = idc.get_str_type(selector_ea)
        if string_type is None:
            continue
        selector_str = idc.get_strlit_contents(selector_ea, strtype=string_type).decode()

        # name the function and set its type
        name = f'_objc_msgSend${selector_str}'
        args = ['id object']
        if ':' in selector_str:
            args.append('__unused SEL selector')
            for arg in selector_str.split(':'):
                if arg:
                    args.append(f'id {arg}')
        type_ = f'int __spoils<X0,X1,X2,X3,X4,X5,X6,X7> {name}({", ".join(args)})'.replace(':', '_')
        print(f'0x{ea:x} {name} {type_}')
        idc.set_name(ea, name, idc.SN_CHECK)
        idc.SetType(ea, type_)


def locate_and_set_type(name: str, type_: str) -> None:
    ea = idc.get_name_ea_simple(name)
    if ea != idc.BADADDR:
        idc.SetType(ea, type_)


def fix_specific_objc_functions() -> None:
    locate_and_set_type('_objc_claimAutoreleasedReturnValue',
                        'id __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_claimAutoreleasedReturnValue(id)')

    locate_and_set_type('_objc_msgSend$floatValue',
                        'float __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend_floatValue(id object, __unused SEL selector')

    locate_and_set_type('_objc_msgSend$doubleValue',
                        'double __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend_doubleValue(id object, __unused SEL selector')

    locate_and_set_type('_objc_msgSend$timeIntervalSinceDate:',
                        'double __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend$timeIntervalSinceDate_(id object, __unused SEL selector, id timeIntervalSinceDate')

    locate_and_set_type('_objc_msgSend$countByEnumeratingWithState:objects:count:',
                        'id __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend_countByEnumeratingWithState_objects_count_(id object, __unused SEL selector, NSFastEnumerationState *state, id *objects, size_t count')

    locate_and_set_type('_objc_msgSend$stringWithFormat:',
                        'id __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend_stringWithFormat_(id object, __unused SEL selector, id stringWithFormat, ...')


def main() -> None:
    # DSC optimization
    processed_sections = []
    processed_sections_file = Path(idc.get_idb_path()).parent / 'objc_stubs_cache.txt'
    if processed_sections_file.exists():
        processed_sections = processed_sections_file.read_text().splitlines()

    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if seg_name.endswith('__objc_stubs'):
            handle_objc_stubs(seg, idc.get_segm_end(seg))
        elif seg_name.endswith(':__stubs') and seg_name not in processed_sections:
            # DSC
            handle_stubs(seg, idc.get_segm_end(seg))
            processed_sections.append(seg_name)
            processed_sections_file.write_text('\n'.join(processed_sections))

    handle_auth_stubs()
    fix_specific_objc_functions()


if __name__ == '__main__':
    main()
