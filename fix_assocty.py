import ida_segment
import idautils
import idc
import ida_bytes
import ida_name
from ida_nalt import REF_OFF32, REFINFO_SIGNEDOP, REFINFO_SELFREF
from idc import FF_DATA, FF_DWORD

class AssocTypeCStruct: 
    SELFREF = REFINFO_SIGNEDOP | REFINFO_SELFREF

    ASSOCTYPE_BASE_IDA_STRUCT_TYPE_NAME = "AssocType"

    def _create_assoctype(self, assoctype_addr: int, num_assoc_types: int):
        udt = ida_typeinf.udt_type_data_t()
        self.tif.create_udt(udt)
        self.tif.set_named_type(None, f"{self.ASSOCTYPE_BASE_IDA_STRUCT_TYPE_NAME}_{assoctype_addr:x}")
        self.append_reloffset_member("ConformingTypeNameOffset")
        self.append_reloffset_member("ProtocolTypeNameOffset")
        self.append_int32_member("NumAssociatedTypes")
        self.append_int32_member("AssociatedTypeRecordSize")
        for idx in range(num_assoc_types):
            req_addr = assoctype_addr+(idx*2*2)
            self.append_reloffset_member("NameOffset_"+str(idx))
            self.append_reloffset_member("SubstitutedTypeNameOffset_"+str(idx))

    def __init__(self, assoctype_addr: int):  
        self.tif = ida_typeinf.tinfo_t()
        num_assoc_types = ida_bytes.get_wide_dword(assoctype_addr+8)
        self._create_assoctype(assoctype_addr, num_assoc_types)

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

def get_swift5_assocty_segment() -> ida_segment.segment_t:
    seg = None
    found = False
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg)
        #if you are analyzing the DSC you need to adapt this comparison to all segments or one library in specific
        if(seg_name == "__swift5_assocty"):
            return seg

    return None

#returns the struct size. since assocty may have different sizes we need this return value to properly parse the segment
def parse_assocty(assoctype_addr: int) -> int:
    assoc_type_struct = AssocTypeCStruct(assoctype_addr)
    idc.create_struct(assoctype_addr, assoc_type_struct.get_size(), assoc_type_struct.get_name())
    return assoc_type_struct.get_size()

def main():
    swift5_proto_seg = get_swift5_assocty_segment()
    if not swift5_proto_seg:
        print("Couldn't find the __swift5_assocty segment")
        return

    min_addr = swift5_proto_seg.start_ea
    max_addr = swift5_proto_seg.end_ea

    curr_addr = min_addr
    
    while(curr_addr < max_addr):
        assocty_struct_size = parse_assocty(curr_addr)
        curr_addr += assocty_struct_size

if __name__=="__main__":
    main()