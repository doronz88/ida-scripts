import ida_segment
import idautils
import idc
import ida_bytes
import ida_name
from ida_nalt import REF_OFF32, REFINFO_SIGNEDOP, REFINFO_SELFREF
from idc import FF_DATA, FF_DWORD

class PCDStruct:
    tif = 0
    size = 0
    PCD_IDA_STRUCT_TYPE_NAME = "ProtConfDescriptor"

    def _create_pcd_struct(self):
        SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF
        tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        udm = ida_typeinf.udm_t()

        tif.create_udt(udt)
        tif.set_named_type(None, self.PCD_IDA_STRUCT_TYPE_NAME)
        udm.name = "ProtocolDescriptor"
        udm.offset = 0
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
        udm.size = udm.type.get_size() * 8
        udm.repr.set_vtype(ida_typeinf.FRB_OFFSET)
        udm.repr.ri.init(ida_nalt.REF_OFF32 | SELFREF)
        tif.add_udm(udm)

        udm.name = "NominalTypeDescriptor"
        udm.offset = tif.get_unpadded_size() * 8
        tif.add_udm(udm)

        udm.name = "PWT"
        udm.offset = tif.get_unpadded_size() * 8
        tif.add_udm(udm)

        udm = ida_typeinf.udm_t()
        udm.name = "Flags"
        udm.offset = tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
        udm.size = udm.type.get_size() * 8
        tif.add_udm(udm)
        return tif

    def __init__(self):  
        #Delete existing PCD struct
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, self.PCD_IDA_STRUCT_TYPE_NAME):
            ida_typeinf.del_named_type(None, self.PCD_IDA_STRUCT_TYPE_NAME, ida_typeinf.NTF_TYPE)

        self.tif = self._create_pcd_struct()
        self.size = 4*4
            
    def get_name(self):
        return self.tif.get_type_name()

    def get_size(self):
        #4 dwords (16 bytes)
        return self.tif.get_unpadded_size()

def parse_pcd(pcd_addr, pcd_struct):

    idc.create_struct(pcd_addr, pcd_struct.get_size(), pcd_struct.get_name())

    idc.op_offset(pcd_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr, 0)
    idc.op_offset(pcd_addr+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr+4, 0)
    
    pwt_val = idc.get_wide_dword(pcd_addr+8)
    if pwt_val>0:
        #create the offset reference only if it is defined
        idc.op_offset(pcd_addr+8, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr+8, 0)
    
    flags_value = idc.get_wide_dword(pcd_addr+12)

    if flags_value not in (0x30000, 0x300c0, 0x30080):
        print("Unsupported flag value: ",hex(flags_value),". Not parsing this... (WIP!)")
        return

    ida_bytes.create_dword(pcd_addr+16, 4)
    base_relwitness_addr = 0
    flag_mask_res = flags_value & 0x000c0
    if flag_mask_res == 0xc0:
        idc.set_cmt(pcd_addr+16, "Retroactive string", 0)
        idc.op_offset(pcd_addr+16, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr+16, 0)
        base_relwitness_addr = pcd_addr + 20
    else:
        base_relwitness_addr = pcd_addr + 16

    ida_bytes.create_dword(base_relwitness_addr, 4)
    numWitnesses = idc.get_wide_dword(base_relwitness_addr)
    idc.set_cmt(base_relwitness_addr, "NumWitnesses", 0)
    base_relwitness_addr += 4
    
    for idx in range(numWitnesses):
        #create the rel offsets to their definitions
        ida_bytes.create_dword(base_relwitness_addr, 4)
        idc.op_offset(base_relwitness_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_relwitness_addr, 0)
        requirement_offset = idc.get_wide_dword(base_relwitness_addr)
        requirement_addr = base_relwitness_addr + ( ((requirement_offset & 0xffffffff)^0x80000000)-0x80000000 )
        definition_addr = idc.get_qword(requirement_addr-1)
        name = ida_name.get_name(definition_addr)
        idc.set_cmt(base_relwitness_addr, idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN)), 0)
        ida_bytes.create_dword(base_relwitness_addr+4, 4)
        idc.op_offset(base_relwitness_addr+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_relwitness_addr+4, 0)
        base_relwitness_addr += 8

    base_generic = base_relwitness_addr
    ida_bytes.create_word(base_generic, 2)
    idc.set_cmt(base_relwitness_addr, "Witness table size in words", 0)
    ida_bytes.create_word(base_generic+2, 2)
    idc.set_cmt(base_generic+2, "Witness table private size and requires instantiation", 0)
    ida_bytes.create_dword(base_generic+4, 4)
    idc.set_cmt(base_generic+4, "Instantiator", 0)
    ida_bytes.create_dword(base_generic+8, 4)
    idc.set_cmt(base_generic+8, "Private data", 0)
    instantiator = idc.get_wide_dword(base_generic+4)
    if instantiator > 0:
        idc.op_offset(base_generic+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_generic+4, 0)

    idc.op_offset(base_generic+8, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_generic+8, 0)

def main():
    seg = None
    found = False
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg)
        if(seg_name == "__swift5_proto"):
            found = True
            break

    if not found:
        print("Couldn't find the __swift5_proto segment")
        return

    min_addr = seg.start_ea
    max_addr = seg.end_ea

    pcd_struct = PCDStruct()
    for curr_addr in range(min_addr, max_addr, 4):
        ida_bytes.create_dword(curr_addr, 4)
        idc.op_offset(curr_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, curr_addr, 0)
        offset = idc.get_wide_dword(curr_addr)
        pcd_addr = curr_addr + ( ((offset & 0xffffffff)^0x80000000)-0x80000000 )
        parse_pcd(pcd_addr, pcd_struct)

if __name__=="__main__":
    main()