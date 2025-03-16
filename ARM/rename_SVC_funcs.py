import idc, ida_ua, idautils, ida_idp, ida_bytes, ida_funcs ,ida_allins, ida_idaapi, ida_name
import csv
import os

### What this code does:
# Iterate through already defined functions
# Search for the SVC Opcode in ARM64 
# Look for the first previous setting or the R8 register
# Maps its value with the syscall name 
# note: Syscall data is from https://arm64.syscall.sh/ 
###

### What this code does NOT:
# Takes in account the SWC opcode 
# Parses the parameters sent with the syscall
###

# IDA can't just be ctrl+C, adding some protectors for dev purposes
i = 0

# Update with your working DIR
csv_fullpath = "$YOUR_PATH/SVC_opcodes.csv"
# Convert CSV file to array object
svc_code_array = []
# Convert CSV syscalls to matrix
with open(csv_fullpath, mode="r", newline="") as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        sub_element = [element for element in row]
        svc_code_array.append(sub_element)
    svc_code_array.pop(0)
    file.close()


def has_SVC(func):
    # Iterates through each head within func boundaries
    # returns EA of SVC call if found. Else, returns false
    ea = func.start_ea
    end_ea = func.end_ea
    
    # For each head of a function
    while ea < end_ea:
        ins = idautils.DecodeInstruction(ea)
        if (hasattr(ins, 'itype') and ins.itype == ida_allins.ARM_svc):
            return ea
        ea = ida_bytes.next_head(ea, end_ea)
    return False

def rename_SVC_func(func, SVC_ea):
    # Takes in a func_t and ea_t at SVC pos.
    # Assumes SVC and MOV R8 XX exists in the FUNC
    # If not the case, I hope you have a snapshot ready

    ea = SVC_ea
    start_ea = func.start_ea

    # Protect against endless whiles
    a = 0

    # Iterates back from SVC EA
    while ea >= start_ea and ea != ida_idaapi.BADADDR:
        a = a + 1
        ins = idautils.DecodeInstruction(ea)
        func_name = ida_funcs.get_func_name(start_ea)
        if  not (hasattr(ins, 'itype') and ins.itype == ida_allins.ARM_mov):
            pass
        # 137 = R8, could not find a way to set the op_t.R8 to work properly
        elif ins.Op1.reg == 137:
            syscall_name = svc_code_array[ins.Op2.value][1]
            func_new_name = ''.join(['FUNC_SVC_', syscall_name, '_', '{:x}'.format(ea)])
            print(f'Renaming {func_name} to {func_new_name} at  {hex(start_ea)}')
            ida_name.set_name(start_ea, func_new_name)
        
        # Some protections against endless whiles
        if a > 1000:
            print("you fucked up")
            break

        # Next head
        ea = ida_bytes.prev_head(ea, start_ea)
    return 

def main():
    func = ida_funcs.get_next_func(0)
    # Iterate through functions
    while func:
        ea = has_SVC(func)
        if ea:
            rename_SVC_func(func, ea)
        if i > 1000:
            print("you fucked up")
            break
        # Next func
        func = ida_funcs.get_next_func(func.start_ea)


main()
