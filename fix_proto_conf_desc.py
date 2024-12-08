import ida_segment
import idautils
import idc
import ida_bytes

seg = None
found = False
for seg_ea in idautils.Segments():
	seg = ida_segment.getseg(seg_ea)
	seg_name = ida_segment.get_segm_name(seg)
	print(seg_name)
	if(seg_name == "__swift5_proto"):
		print("found it!")
		found = True
		break
if(not found):
	print("Couldn't find the __swift5_proto segment")
else:
	print(seg)
	min_addr = seg.start_ea
	max_addr = seg.end_ea
	print(min_addr, max_addr)
	for curr_addr in range(min_addr, max_addr, 4):
	   ida_bytes.create_dword(curr_addr, 4)
	for curr_addr in range(min_addr, max_addr, 4):
	   idc.op_offset(curr_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, curr_addr, 0)
	   offset = idc.get_wide_dword(curr_addr)
	   pcd_addr = curr_addr + ( ((offset & 0xffffffff)^0x80000000)-0x80000000 ) 
	   #create comments for the PCD struct
	   ida_bytes.create_dword(pcd_addr, 4)
	   idc.set_cmt(pcd_addr, "Protocol Descriptor", 0)
	   ida_bytes.create_dword(pcd_addr+4, 4)
	   idc.set_cmt(pcd_addr+4, "Nominal Type Descriptor", 0)
	   ida_bytes.create_dword(pcd_addr+8, 4)
	   idc.set_cmt(pcd_addr+8, "PWT", 0)
	   ida_bytes.create_dword(pcd_addr+12, 4)
	   idc.set_cmt(pcd_addr+12, "Flags", 0)
	   
	   #create the offsets. in case the PWT is 0 we should not create the offset
	   idc.op_offset(pcd_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr, 0)
	   idc.op_offset(pcd_addr+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr+4, 0)
	   pwt_val = idc.get_wide_dword(pcd_addr+8)
	   if(pwt_val>0):
	     #create the offset reference only if it is defined
	     idc.op_offset(pcd_addr+8, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, pcd_addr+8, 0)
	   
	   if(idc.get_wide_dword(pcd_addr+12) & 0x30000 != 0x30000):
	     print("Unsupported flag type. Not parsing this... (WIP!)")
	     continue

	   ida_bytes.create_dword(pcd_addr+16, 4)
	   base_relwitness_addr = 0
	
	   flag_mask_res = idc.get_wide_dword(pcd_addr+12) & 0x000c0
	   if(flag_mask_res == 0xc0):
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
	     ida_bytes.create_dword(base_relwitness_addr+4, 4)
	     idc.op_offset(base_relwitness_addr, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_relwitness_addr, 0)
	     idc.op_offset(base_relwitness_addr+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, base_relwitness_addr+4, 0)
	     base_relwitness_addr += 8
	  

	   baseGeneric = base_relwitness_addr
	   ida_bytes.create_word(baseGeneric, 2)
	   idc.set_cmt(base_relwitness_addr, "Witness table size in words", 0)
	   ida_bytes.create_word(baseGeneric+2, 2)
	   idc.set_cmt(baseGeneric+2, "Witness table private size and requires instantiation", 0)
	   ida_bytes.create_dword(baseGeneric+4, 4)
	   idc.set_cmt(baseGeneric+4, "Instantiator", 0)
	   ida_bytes.create_dword(baseGeneric+8, 4)
	   idc.set_cmt(baseGeneric+8, "Private data", 0)
	   instantiator = idc.get_wide_dword(baseGeneric+4)
	   if(instantiator > 0):
	     idc.op_offset(baseGeneric+4, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, baseGeneric+4, 0)
	     
	   idc.op_offset(baseGeneric+8, 0, REF_OFF32|REFINFO_SIGNEDOP, -1, baseGeneric+8, 0)
