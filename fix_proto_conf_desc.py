import ida_segment
import idautils
import idc
import ida_bytes
import ida_name
from ida_nalt import REF_OFF32, REFINFO_SIGNEDOP, REFINFO_SELFREF
from idc import FF_DATA, FF_DWORD

class CStruct: 
    SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF

    def __init__(self):
        self.tif = ida_typeinf.tinfo_t()

    def _append_member(self, name: str, ida_type: int) -> ida_typeinf.udm_t:
        """
        Append a udm_t into `self.tif` and return it so user is able to add his
        own modifications.
        """
        udm = ida_typeinf.udm_t()
        udm.name = name
        udm.offset = self.tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(ida_type)
        udm.size = udm.type.get_size() * 8
        return udm

    def append_int16_member(self, name: str):
        udm = self._append_member(name, ida_typeinf.BT_INT16)
        self.tif.add_udm(udm)

    def append_int32_member(self, name: str):
        udm = self._append_member(name, ida_typeinf.BT_INT32)
        self.tif.add_udm(udm)

    def append_reloffset_member(self, name: str) -> None:
        udm = self._append_member(name, ida_typeinf.BT_INT32)
        udm.repr.set_vtype(ida_typeinf.FRB_OFFSET)
        udm.repr.ri.init(ida_nalt.REF_OFF32 | self.SELFREF)
        self.tif.add_udm(udm)

    def get_name(self):
        return self.tif.get_type_name()

    def get_size(self):
        return self.tif.get_unpadded_size()

class PCDStruct(CStruct): 
    PCD_BASE_IDA_STRUCT_TYPE_NAME = "ProtConfDescriptor"

    def _create_pcd(self, pcd_address: int):
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, f"{self.PCD_BASE_IDA_STRUCT_TYPE_NAME}_{pcd_address:x}")
        self.append_reloffset_member("ProtocolDescriptor")
        self.append_reloffset_member("NominalTypeDescriptor")
        #If PWT field creates a reloffset to itself (PWT dword = 0) it means it doesn't have PWT.
        self.append_reloffset_member("PWT")
        self.append_int32_member("Flags")

    def __init__(self, pcd_address: int):  
        super().__init__()
        self._create_pcd(pcd_address)

class RelWitnessTableStruct(CStruct):
    RWT_BASE_IDA_STRUCT_TYPE_NAME = "RelWitTable"

    def _create_rwt(self, rwt_addr: int, rel_wit_num: int):
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, f"{self.RWT_BASE_IDA_STRUCT_TYPE_NAME}_{rwt_addr:x}")
        self.append_int32_member("NumWitnesses")
        rwt_addr += 4
        for idx in range(rel_wit_num):
            req_addr = rwt_addr+(idx*2*4)
            req_name = get_symbol_name_from_address(req_addr)
            self.append_reloffset_member("req_"+req_name)
            self.append_reloffset_member("impl_"+req_name)

    def __init__(self, rwt_addr: int):
        super().__init__()
        rel_wit_num = ida_bytes.get_wide_dword(rwt_addr)
        self._create_rwt(rwt_addr, rel_wit_num)

class GenWitnessTableStruct(CStruct):
    GWT_BASE_IDA_STRUCT_TYPE_NAME = "GenWitTable"

    def _create_gwt(self, gwt_addr: int):
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, f"{self.GWT_BASE_IDA_STRUCT_TYPE_NAME}_{gwt_addr:x}")
        self.append_int16_member("WitnessTableSizeInWords")
        self.append_int16_member("WitnessTablePrivateSizeInWords")
        #If Instantiator field creates a reloffset to itself (Instantiator dword = 0) it means it doesn't have Instantiator.
        self.append_reloffset_member("Instantiator")
        self.append_reloffset_member("PrivateData")

    def __init__(self, gwt_addr: int):
        super().__init__()
        self._create_gwt(gwt_addr)

def get_symbol_name_from_address(ea: int) -> str:
    requirement_offset = ida_bytes.get_wide_dword(ea)
    requirement_addr = ea + ( ((requirement_offset & 0xffffffff)^0x80000000)-0x80000000 )
    definition_addr = ida_bytes.get_qword(requirement_addr-1)
    name = ida_name.get_name(definition_addr)
    try:
        return idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN)) 
    except Exception as e:
        #Could not demangle the symbol. Just return the address 
        return hex(requirement_addr)

def make_offset(ea: int):
    idc.op_offset(ea, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, ea, 0)

def parse_pcd(pcd_addr: int):
    pcd_struct = PCDStruct(pcd_addr)
    idc.create_struct(pcd_addr, pcd_struct.get_size(), pcd_struct.get_name())
    
    flags_value = ida_bytes.get_wide_dword(pcd_addr+12)
    if flags_value not in (0x30000, 0x300c0, 0x30080):
        print("Unsupported flag value: ",hex(flags_value),". Not parsing this... (WIP!)")
        return

    base_relwitness_addr = pcd_addr + 16
    flag_mask_res = flags_value & 0x000c0
    if flag_mask_res == 0xc0:
        #Create Retroactive string reference
        ida_bytes.create_dword(pcd_addr+16, 4)
        idc.set_cmt(pcd_addr+16, "Retroactive string", 0)
        make_offset(pcd_addr+16)
        base_relwitness_addr += 4

    #Relative Witness Table casting
    rwt_struct = RelWitnessTableStruct(base_relwitness_addr)
    idc.create_struct(base_relwitness_addr, rwt_struct.get_size(), rwt_struct.get_name())
    
    #Generic Witness Table casting
    base_gwt_addr = base_relwitness_addr +  rwt_struct.get_size()
    gwt_struct = GenWitnessTableStruct(base_gwt_addr)
    idc.create_struct(base_gwt_addr, gwt_struct.get_size(), gwt_struct.get_name())

def get_swift5_proto_segment() -> ida_segment.segment_t:
    seg = None
    found = False
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg)
        if(seg_name == "__swift5_proto"):
            return seg

    return None

def main():
    swift5_proto_seg = get_swift5_proto_segment()
    if not swift5_proto_seg:
        print("Couldn't find the __swift5_proto segment")
        return

    min_addr = swift5_proto_seg.start_ea
    max_addr = swift5_proto_seg.end_ea

    for curr_addr in range(min_addr, max_addr, 4):
        ida_bytes.create_dword(curr_addr, 4)
        make_offset(curr_addr)
        offset = idc.get_wide_dword(curr_addr)
        pcd_addr = curr_addr + ( ((offset & 0xffffffff)^0x80000000)-0x80000000 )
        parse_pcd(pcd_addr)

if __name__=="__main__":
    main()