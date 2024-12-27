#include <mach/mach.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>

mach_port_t gTask = 0;

vm_address_t task_map() {
    gTask = mach_task_self();
    vm_address_t addr = 0;  

    // Map virtual memory
    vm_map(gTask, &addr, PAGE_SIZE, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,VM_PROT_READ | VM_PROT_WRITE,VM_INHERIT_DEFAULT);
    printf("[*] Mapped memory at 0x%llx, size is %d bytes\n", (uint64_t)addr, PAGE_SIZE);

    return addr;
}

void virtRead(vm_address_t addr) {
    vm_size_t read_size = PAGE_SIZE;
    vm_offset_t data;
    mach_msg_type_number_t bytes;

    vm_read(gTask, addr, read_size, &data, &bytes);
    
    printf("[*] Read %d bytes from address 0x%llx\n", bytes, (uint64_t)addr);
}

void virtWrite(vm_address_t addr, uint64_t value) {
    mach_msg_type_number_t bytes = sizeof(value);

    // The vm_write API expects a pointer to the data being written, not the raw value; hence, 
    // we pass (pointer_t)&value to point to the address where the value is stored
    // otherwise we will get a invalid memory error
    vm_write(gTask, addr, (pointer_t)&value, bytes);
    printf("[*] Wrote 0x%llx to 0x%llx\n", value, (uint64_t)addr);
}

int main() {
    vm_address_t addr = task_map();

    if(addr != 0)  {
        virtRead(addr);
        uint64_t value;
        printf("[>] Enter a 64-bit hex value to write to 0x%llx: ", (uint64_t)addr);
        scanf("0x%llx", &value);

        virtWrite(addr, value);
        return 0;
    } else {
        printf("[!] Cannot proceed, bailing...");
        return -1;
    }
}