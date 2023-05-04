import ida_kernwin
import idautils
import idc

SELECTOR_XREF_HOTKEY = 'Ctrl+4'

IGNORED_SECTIONS = ('__objc_const',)


def print_ea(ea: int) -> None:
    func_name = idc.get_func_name(ea)
    func_address = idc.get_name_ea_simple(func_name)
    if ea == func_address:
        name = func_name
    else:
        name = f'{func_name} + {ea - func_address}'
    print(f'0x{ea:08x} {name}')


def locate_selector_xrefs() -> None:
    current_ea = idc.get_screen_ea()
    func_name = idc.get_func_name(current_ea)
    try:
        selector = func_name.split(' ')[1].split(']')[0]
    except IndexError:
        print('Failed to find current selector')
        return
    print(f'looking for references to: {selector}')

    for ea in idautils.XrefsTo(idc.get_name_ea_simple(f'_objc_msgSend${selector}')):
        print_ea(ea.frm)


def main() -> None:
    ida_kernwin.del_idc_hotkey(SELECTOR_XREF_HOTKEY)
    ida_kernwin.add_hotkey(SELECTOR_XREF_HOTKEY, locate_selector_xrefs)


if __name__ == '__main__':
    main()
