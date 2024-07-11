import dataclasses
import re

import idaapi
import idc
import ida_hexrays
HOTKEY = 'Ctrl+0'


@dataclasses.dataclass
class Arg:
    a_type: str = 'id'
    a_name: str = 'no_name'

    def __str__(self):
        return f'{self.a_type} {self.a_name}'


class Function:
    def __init__(self, objc_name: str, sig: str):
        self.start = None
        self.objc_class = None
        self.args = []
        self.sig_name = objc_name.replace('[', '__').replace(']', '_').replace(':', '_').replace(' ', '_').strip(
            '+').strip('-')
        self._parse_signature(sig)
        self._parse_objc_name(objc_name)

    def _parse_objc_name(self, objc_name: str):
        pattern = re.compile(r'\[(?P<class_name>\S+)\s+(?P<selector>[^]]+)]')
        key_words = ['With', 'From', 'At', 'Using', 'Writing', 'set']
        name_parts = pattern.search(objc_name)

        self.objc_class = name_parts.group('class_name')
        selector = name_parts.group('selector')

        parts = [p for p in selector.split(':') if p]
        args = []
        for k in parts:
            special_case_match = re.search(fr'(?i)({"|".join(key_words)})([A-Z][a-z]*)', k)
            if special_case_match:
                args.append(special_case_match.group(2))
            else:
                args.append(k)

        for i in range(len(self.args)):
            self.args[i].a_name = camel_to_snake(args[i])

    def _parse_signature(self, sig: str):
        pattern = re.compile(r'^(?P<start>[^\(]+)\((?P<args>.*)\)$')
        sig_parts = pattern.search(sig)
        self.start = sig_parts.group('start')
        self.args = [Arg(a_type=t.strip(' ')) for t in sig_parts.group('args').split(',')[2:]]

    def __str__(self):
        args = ', ' + ', '.join(str(a) for a in self.args) if self.args else ''
        return f'{self.start} {self.sig_name}({self.objc_class} *self, SEL selector{args})'


def camel_to_snake(name: str):
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def rename_objc_method_params():
    objc_method_pattern = re.compile(r'\[(?P<class_name>\S+)\s+(?P<selector>[^\]]+)\]')

    ea = idaapi.get_screen_ea()
    if ea == idaapi.BADADDR:
        print('No function is currently displayed on the screen.')
        return

    function_name = idc.get_func_name(ea)
    match = objc_method_pattern.search(function_name)
    if not match:
        print(f'Function {function_name} does not match the Objective-C pattern.')
        return

    func_type = idc.get_type(ea)
    if not func_type:
        print(f'No type information for function {function_name}.')
        return

    func = Function(function_name, func_type)

    idc.SetType(ea, str(func))
    print(f'Renamed {function_name} to {func}')
    vdui = ida_hexrays.open_pseudocode(ea, 0)
    if vdui:
        vdui.refresh_view(True)


class RenameObjCParamsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = 'Rename Objective-C method parameters and function name according to the selector'
    help = 'Rename Objective-C method parameters and function name according to the selector'
    wanted_name = 'RenameObjCParams'
    wanted_hotkey = HOTKEY

    def init(self):
        idaapi.msg('RenameObjCParams plugin initialized.\n')
        return idaapi.PLUGIN_OK

    def run(self, arg):
        rename_objc_method_params()

    def term(self):
        idaapi.msg('RenameObjCParams plugin terminated.\n')


def PLUGIN_ENTRY():
    return RenameObjCParamsPlugin()
