#TODO write a description for this script
#@author SlidingWindow (Twitter: @Kapil_Khot)
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.data import Structure, DataTypeManager

# Get the current program's Data Type Manager
target_struct_name = "_MDL"	# Search for this structure in all available structures.
dtm = currentProgram.getDataTypeManager()
components = ""
field_name = ""
data_type_name = ""
struct_name = ""

for dt in dtm.getAllDataTypes():
    if isinstance(dt, Structure):  # Only process structures
        struct_name = dt.getName()
	components = dt.getComponents()      
	
	for comp in components:
		field_name = comp.getFieldName()
		data_type_name = comp.getDataType().getName()

		if target_struct_name in data_type_name:
			# print("[+]The following structure contains the structure {} you're looking for:\n{}".format(target_struct_name, struct_name))
			print("Structure '{}' contains '{}' ({}) at DECIMAL offset {}".format(struct_name, field_name, data_type_name, comp.getOffset()))
		else:
			continue
