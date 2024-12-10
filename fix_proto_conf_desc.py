import ida_segment
import idautils
import idc
import ida_bytes
import ida_name
from ida_nalt import REF_OFF32, REFINFO_SIGNEDOP, REFINFO_SELFREF
from idc import FF_DATA, FF_DWORD

class CStruct: 
    def append_int16_member(self, name):
        udm = ida_typeinf.udm_t()
        udm.name = name
        udm.offset = self.tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT16)
        udm.size = udm.type.get_size() * 8
        self.tif.add_udm(udm)

    def append_int32_member(self, name):
        udm = ida_typeinf.udm_t()
        udm.name = name
        udm.offset = self.tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
        udm.size = udm.type.get_size() * 8
        self.tif.add_udm(udm)

    def append_reloffset_member(self, name):
        udm = ida_typeinf.udm_t()
        udm.name = name
        udm.offset = self.tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
        udm.size = udm.type.get_size() * 8
        udm.repr.set_vtype(ida_typeinf.FRB_OFFSET)
        udm.repr.ri.init(ida_nalt.REF_OFF32 | self.SELFREF)
        self.tif.add_udm(udm)

    def get_name(self):
        return self.tif.get_type_name()

    def get_size(self):
        return self.tif.get_unpadded_size()

class PCDStruct(CStruct): 
    tif = 0
    PCD_BASE_IDA_STRUCT_TYPE_NAME = "ProtConfDescriptor"
    SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF

    def _create_pcd_struct(self, pcd_address):
        self.tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, self.PCD_BASE_IDA_STRUCT_TYPE_NAME+"_"+hex(pcd_address))
        self.append_reloffset_member("ProtocolDescriptor")
        self.append_reloffset_member("NominalTypeDescriptor")
        #If PWT field creates a reloffset to itself (PWT dword = 0) it means it doesn't have PWT.
        self.append_reloffset_member("PWT")
        self.append_int32_member("Flags")

    def __init__(self, pcd_address):  
        self._create_pcd_struct(pcd_address)

class RelWitnessTableStruct(CStruct):
    tif = 0
    RWT_BASE_IDA_STRUCT_TYPE_NAME = "RelWitTable"
    SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF

    def _create_rwt(self, rwt_addr, rel_wit_num):
        self.tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, self.RWT_BASE_IDA_STRUCT_TYPE_NAME+"_"+hex(rwt_addr))
        self.append_int32_member("NumWitnesses")
        rwt_addr += 4
        for idx in range(rel_wit_num):
            req_addr = rwt_addr+(idx*2*4)
            req_name = get_symbol_name_from_address(req_addr)
            self.append_reloffset_member("req_"+req_name)
            self.append_reloffset_member("impl_"+req_name)

    def __init__(self, rwt_addr):
        rel_wit_num = get_word_with_size(rwt_addr, 4)
        self._create_rwt(rwt_addr, rel_wit_num)

class GenWitnessTableStruct(CStruct):
    tif = 0
    GWT_BASE_IDA_STRUCT_TYPE_NAME = "GenWitTable"
    SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF

    def _create_gwt(self, gwt_addr):
        self.tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, self.GWT_BASE_IDA_STRUCT_TYPE_NAME+"_"+hex(gwt_addr))
        self.append_int16_member("WitnessTableSizeInWords")
        self.append_int16_member("WitnessTablePrivateSizeInWords")
        #If Instantiator field creates a reloffset to itself (Instantiator dword = 0) it means it doesn't have Instantiator.
        self.append_reloffset_member("Instantiator")
        self.append_reloffset_member("PrivateData")

    def __init__(self, gwt_addr):
        self._create_gwt(gwt_addr)

def get_symbol_name_from_address(ea):
    requirement_offset = get_word_with_size(ea, 4)
    requirement_addr = ea + ( ((requirement_offset & 0xffffffff)^0x80000000)-0x80000000 )
    definition_addr = get_word_with_size(requirement_addr-1, 8)
    name = ida_name.get_name(definition_addr)
    try:
        return idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN)) 
    except Exception as e:
        #Could not demangle the symbol. Just return the address 
        return str(requirement_addr)

def get_word_with_size(ea, size):
    if(size == 4):
        return ida_bytes.get_wide_dword(ea)
    elif(size == 8):
        return ida_bytes.get_qword(ea)

def create_word_with_size(ea, size):
    if(size == 2):
        ida_bytes.create_word(ea, 2)
    elif(size == 4):
        ida_bytes.create_dword(ea, 4)

def make_offset(ea):
    idc.op_offset(ea, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, ea, 0)

def parse_pcd(pcd_addr):

    pcd_struct = PCDStruct(pcd_addr)
    idc.create_struct(pcd_addr, pcd_struct.get_size(), pcd_struct.get_name())
    
    flags_value = get_word_with_size(pcd_addr+12, 4)

    if flags_value not in (0x30000, 0x300c0, 0x30080):
        print("Unsupported flag value: ",hex(flags_value),". Not parsing this... (WIP!)")
        return

    base_relwitness_addr = 0
    flag_mask_res = flags_value & 0x000c0
    if flag_mask_res == 0xc0:
        #Create Retroactive string reference
        create_word_with_size(pcd_addr+16, 4)
        idc.set_cmt(pcd_addr+16, "Retroactive string", 0)
        make_offset(pcd_addr+16)
        base_relwitness_addr = pcd_addr + 20
    else:
        base_relwitness_addr = pcd_addr + 16

    #Relative Witness Table casting
    rwt_struct = RelWitnessTableStruct(base_relwitness_addr)
    idc.create_struct(base_relwitness_addr, rwt_struct.get_size(), rwt_struct.get_name())

    base_gwt_addr = base_relwitness_addr +  rwt_struct.get_size()
    
    #Generic Witness Table casting
    gwt_struct = GenWitnessTableStruct(base_gwt_addr)
    idc.create_struct(base_gwt_addr, gwt_struct.get_size(), gwt_struct.get_name())

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

    for curr_addr in range(min_addr, max_addr, 4):
        ida_bytes.create_dword(curr_addr, 4)
        idc.op_offset(curr_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, curr_addr, 0)
        offset = idc.get_wide_dword(curr_addr)
        pcd_addr = curr_addr + ( ((offset & 0xffffffff)^0x80000000)-0x80000000 )
        parse_pcd(pcd_addr)

if __name__=="__main__":
    main()