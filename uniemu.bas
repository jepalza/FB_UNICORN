/' Unicorn Emulator Engine '/
/' By Nguyen Anh Quynh & Dang Hoang Vu, 2015 '/

' Adapted to FB for Joseba Epaza <jepalza@gmail.com> (2021)

/' Sample code to demonstrate how to emulate X86 code '/

' varios opcionales, usados tipicamente en "C"
#include "crt\math.bi" ' ceil(), floor(), M_PI, pow(), fabs(), sqrt(), etc
#Include "crt\stdio.bi" ' printf(!), scanf(), fopen(), etc
#Include "crt\stdlib.bi" ' malloc(),calloc(), etc


#include "unicorn.bi"
'#include "string.bi"


' code to be emulated
Dim shared as UByte X86_CODE32(5) = {&h41, &h4a, &h66, &h0f, &hef, &hc1 } ' INC ecx; DEC edx; PXOR xmm0, xmm1
Dim shared as UByte X86_CODE32_JUMP(7) = {&heb, &h02, &h90, &h90, &h90, &h90, &h90, &h90 } ' jmp 4; nop; nop; nop; nop; nop; nop
Dim shared as UByte X86_CODE32_LOOP(3) = {&h41, &h4a, &heb, &hfe } ' INC ecx; DEC edx; JMP self-loop
Dim shared as UByte X86_CODE32_MEM_WRITE(7) = {&h89, &h0D, &hAA, &hAA, &hAA, &hAA, &h41, &h4a } ' mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
Dim shared as UByte X86_CODE32_MEM_READ(7)  = {&h8B, &h0D, &hAA, &hAA, &hAA, &hAA, &h41, &h4a } ' mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
Dim shared as UByte X86_CODE32_JMP_INVALID(6) = {&he9, &he9, &hee, &hee, &hee, &h41, &h4a } '  JMP outside; INC ecx; DEC edx
Dim shared as UByte X86_CODE32_INOUT(6) = {&h41, &hE4, &h3F, &h4a, &hE6, &h46, &h43 } ' INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
Dim shared as UByte X86_CODE32_INC(0) = {&h40 } ' INC eax
Dim shared as UByte X86_CODE64(74) = {&h41, &hBC, &h3B, &hB0, &h28, &h2A, &h49, &h0F, &hC9, &h90, &h4D, &h0F, &hAD, &hCF, &h49, _
												  &h87, &hFD, &h90, &h48, &h81, &hD2, &h8A, &hCE, &h77, &h35, &h48, &hF7, &hD9, &h4D, &h29, _
												  &hF4, &h49, &h81, &hC9, &hF6, &h8A, &hC6, &h53, &h4D, &h87, &hED, &h48, &h0F, &hAD, &hD2, _
												  &h49, &hF7, &hD4, &h48, &hF7, &hE1, &h4D, &h19, &hC5, &h4D, &h89, &hC5, &h48, &hF7, &hD6, _
												  &h41, &hB8, &h4F, &h8D, &h6B, &h59, &h4D, &h87, &hD0, &h68, &h6A, &h1E, &h09, &h3C, &h59 } ' code
Dim shared as UByte X86_CODE16(1) = {&h00, &h00 } ' add   byte ptr [bx + si], al
Dim shared as UByte X86_CODE64_SYSCALL(1) = {&h0f, &h05 } ' SYSCALL

' memory address where emulation starts
#define addrini &h1000000

' callback for tracing basic blocks
Sub hook_block cdecl(ByVal uc As uc_engine Ptr ,ByVal addr As uint64_t ,ByVal size As uint32_t)' ,ByVal user_data As integer Ptr)
    printf(!">>> Tracing basic block at 0x%" PRIx64 !", block size = 0x%x\n", addr, size) 
End Sub

' callback for tracing instruction
Sub hook_code cdecl(byval uc As uc_engine ,ByVal addr As uint64_t ,ByVal size As uint32_t)' ,ByVal user_data As integer Ptr)

    Dim As Integer eflags 
    printf(!">>> Tracing instruction at 0x%" PRIx64 !", instruction size = 0x%x\n", addr, size) 

    fb_uc_reg_read(uc, UC_X86_REG_EFLAGS, @eflags) 
    printf(!">>> --- EFLAGS is 0x%x\n", eflags) 

    ' Uncomment below code to stop the emulation using uc_emu_stop()
    ' if (addr == 0x1000009)
    '    uc_emu_stop(uc);
End Sub

' callback for tracing instruction
Sub hook_code64 Cdecl(ByVal uc As uc_engine ,ByVal addr As uint64_t ,ByVal size As uint32_t)' , user_data As integer Ptr)

    Dim As uint64_t rip 

    fb_uc_reg_read(uc, UC_X86_REG_RIP, @rip) 
    printf(!">>> Tracing instruction at 0x%" PRIx64 !", instruction size = 0x%x\n", addr, size) 
    printf(!">>> RIP is 0x%" PRIx64 !"\n", rip) 

    ' Uncomment below code to stop the emulation using uc_emu_stop()
    ' if (addr == 0x1000009)
    '    uc_emu_stop(uc);
End Sub

' callback for tracing memory access (READ or WRITE)
Function hook_mem_invalid Cdecl(ByVal uc As uc_engine ,ByVal type_ As uc_mem_type ,ByVal addr As uint64_t ,ByVal size As Integer ,ByVal value As int64_t) As BOOL ' , user_data As integer Ptr) As bool

    Select Case (type_)  
        case UC_MEM_WRITE_UNMAPPED 
                 printf(!">>> Missing memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 !"\n",addr, size, value) 
                 ' map this memory in with 2MB in size
                 fb_uc_mem_map(uc, &haaaa0000, 2 * 1024*1024, UC_PROT_ALL) 
                 ' return true to indicate we want to continue
                 return true 
        case else 
            ' return false to indicate we want to stop emulation
            return false     
   End Select

End Function

Sub hook_mem64 Cdecl(ByVal uc As uc_engine ,ByVal type_ As uc_mem_type ,ByVal addr As uint64_t ,ByVal size As Integer ,ByVal value As int64_t)' , user_data As integer Ptr)

    Select Case (type_)  

        case UC_MEM_READ 
                 printf(!">>> Memory is being READ at 0x%" PRIx64 !", data size = %u\n",addr, size) 
                  
        case UC_MEM_WRITE 
                 printf(!">>> Memory is being WRITE at 0x%" PRIx64 !", data size = %u, data value = 0x%" PRIx64 !"\n",addr, size, value) 
                  
    End Select

End Sub

' callback for IN instruction (X86).
' this returns the data read from the port
Function hook_in Cdecl(ByVal uc As uc_engine ,ByVal port As uint32_t ,ByVal size As Integer) As uint32_t ' , user_data As integer Ptr) As uint32_t

    Dim As UInteger eip 

    fb_uc_reg_read(uc, UC_X86_REG_EIP, @eip) 

    printf(!"--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size, eip) 

    Select Case (size)  

        case 1  ' read 1 byte to AL
            return &hf1 
        case 2  ' read 2 byte to AX
            return &hf2 
    	  Case 4  ' read 4 byte to EAX
            return &hf4   
        case else 
            return 0    ' should never reach this    
   End Select

End Function

' callback for OUT instruction (X86).
Sub hook_out Cdecl(ByVal uc As uc_engine ,ByVal port As uint32_t ,ByVal size As Integer ,ByVal value As uint32_t)' , user_data As integer Ptr)

    Dim As uint32_t tmp = 0 
    Dim As UInteger eip 

    fb_uc_reg_read(uc, UC_X86_REG_EIP, @eip) 

    printf(!"--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x\n", port, size, value, eip) 

    ' confirm that value is indeed the value of AL/AX/EAX
    Select Case (size)  

        case 1 
            fb_uc_reg_read(uc, UC_X86_REG_AL, @tmp) 
             
        case 2 
            fb_uc_reg_read(uc, UC_X86_REG_AX, @tmp) 
             
        case 4 
            fb_uc_reg_read(uc, UC_X86_REG_EAX, @tmp) 
             
    	  Case else 
            return    ' should never reach this    
   End Select


    printf(!"--- register value = 0x%x\n", tmp) 
End Sub

' callback for SYSCALL instruction (X86).
Sub hook_syscall Cdecl(byval uc As uc_engine Ptr)' , user_data As Integer Ptr)

    Dim As uint64_t rax 

    fb_uc_reg_read(uc, UC_X86_REG_RAX, @rax) 
    if (rax = &h100) Then 
        rax = &h200 
        fb_uc_reg_write(uc, UC_X86_REG_RAX, @rax) 
    Else
        printf(!"ERROR: was not expecting rax=0x%" PRIx64 !" in syscall\n", rax)
	EndIf
  
End Sub

Sub test_i386()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uint32_t tmp 
    Dim As uc_hook trace1, trace2 

    Dim As Short r_ecx = &h1234      ' ECX register
    Dim As Short r_edx = &h7890      ' EDX register
    ' XMM0 and XMM1 registers, low qword then high qword
    Dim As uint64_t r_xmm0(1) = {&h08090a0b0c0d0e0f, &h0001020304050607} 
    Dim As uint64_t r_xmm1(1) = {&h8090a0b0c0d0e0f0, &h0010203040506070} 

    printf(!"Emulate i386 code\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32(0), UBound(X86_CODE32)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX , @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX , @r_edx) 
    fb_uc_reg_write(uc, UC_X86_REG_XMM0, @r_xmm0(0)) 
    fb_uc_reg_write(uc, UC_X86_REG_XMM1, @r_xmm1(0)) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instruction by having @begin > @end
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE , @hook_code , NULL, 1, 0) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32)+1, 0, 0) 
    if (err_) Then 
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_)) 
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    fb_uc_reg_read(uc, UC_X86_REG_XMM0, @r_xmm0(0)) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 
    printf(!">>> XMM0 = 0x%.16" PRIx64 !"%.16" PRIx64 !"\n", r_xmm0(1), r_xmm0(0)) 

    ' read from memory
    if ( fb_uc_mem_read(uc, addrini, @tmp, sizeof(tmp)) =0) Then 
        printf(!">>> Read 4 bytes from [0x%x] = 0x%x\n", addrini, tmp) 
    Else
        printf(!">>> Failed to read 4 bytes from [0x%x]\n", addrini)
    EndIf
  

    fb_uc_close(uc) 
End Sub

Sub test_i386_map_ptr()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uint32_t tmp 
    Dim As uc_hook trace1, trace2 
    Dim As UByte Ptr mem 

    Dim As Integer r_ecx = &h1234      ' ECX register
    Dim As Integer r_edx = &h7890      ' EDX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code - use uc_mem_map_ptr()\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' malloc 2MB memory for this emulation
    mem = calloc(1,2 * 1024 * 1024) 
    if (mem = NULL) Then 
  
        printf(!"Failed to malloc()\n") 
        return 
    
    EndIf
  

    fb_uc_mem_map_ptr(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL, mem) 

    ' write machine code to be emulated to memory
    if ( memcpy(mem, @X86_CODE32(0), UBound(X86_CODE32)+1 )=0) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX, @r_edx) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instruction by having @begin > @end
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, 1, 0) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 

    ' read from memory
    if ( fb_uc_mem_read(uc, addrini, @tmp, sizeof(tmp))=0) Then 

        printf(!">>> Read 4 bytes from [0x%x] = 0x%x\n", addrini, tmp) 
    else
       
        printf(!">>> Failed to read 4 bytes from [0x%x]\n", addrini)
    EndIf
  

    fb_uc_close(uc) 
    free(mem) 
End Sub

Sub test_i386_jump()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uc_hook trace1, trace2 

    printf(!"===================================\n") 
    printf(!"Emulate i386 code with jump\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    If (fb_uc_mem_write(uc, addrini, @X86_CODE32_JUMP(0), UBound(X86_CODE32_JUMP)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' tracing 1 basic block with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, addrini, addrini) 

    ' tracing 1 instruction at addr
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, addrini, addrini) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_JUMP)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_close(uc) 
End Sub

' emulate code that loop forever
Sub test_i386_loop()

    Dim as uc_engine uc 
     Dim as uc_err err_ 

    Dim As Integer r_ecx = &h1234      ' ECX register
    Dim As Integer r_edx = &h7890      ' EDX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code that loop forever\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_LOOP(0), UBound(X86_CODE32_LOOP)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX, @r_edx) 

    ' emulate machine code in 2 seconds, so we can quit even
    ' if the code loops
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_LOOP)+1, 2 * UC_SECOND_SCALE, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 

    fb_uc_close(uc) 
End Sub

' emulate code that read invalid memory
Sub test_i386_invalid_mem_read()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uc_hook trace1, trace2 

    Dim As Short r_ecx = &h1234      ' ECX register
    Dim As short r_edx = &h7890      ' EDX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code that read from invalid memory\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_MEM_READ(0), UBound(X86_CODE32_MEM_READ)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX, @r_edx) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instruction by having @begin > @end
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, 1, 0) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_MEM_READ)+1 , 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 

    fb_uc_close(uc) 
End Sub

' emulate code that write invalid memory
Sub test_i386_invalid_mem_write()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uc_hook trace1, trace2, trace3 
    Dim As uint32_t tmp 

    Dim As uint32_t r_ecx = &h1234      ' ECX register
    Dim As uint32_t r_edx = &h7890      ' EDX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code that write to invalid memory\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_MEM_WRITE(0), UBound(X86_CODE32_MEM_WRITE)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX, @r_edx) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instruction by having @begin > @end
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, 1, 0) 

    ' intercept invalid memory events
    fb_uc_hook_add(uc, @trace3, UC_HOOK_MEM_READ_UNMAPPED Or UC_HOOK_MEM_WRITE_UNMAPPED, @hook_mem_invalid, NULL, 1, 0) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_MEM_WRITE)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 

    ' read from memory
    if ( fb_uc_mem_read(uc, &haaaaaaaa, @tmp, sizeof(tmp))=0) Then 

        printf(!">>> Read 4 bytes from [0x%x] = 0x%x\n", &haaaaaaaa, tmp) 
    else
       
        printf(!">>> Failed to read 4 bytes from [0x%x]\n", &haaaaaaaa)
    EndIf
  

    if ( fb_uc_mem_read(uc, &hffffffaa, @tmp, sizeof(tmp))=0) Then 

        printf(!">>> Read 4 bytes from [0x%x] = 0x%x\n", &hffffffaa, tmp) 
    else
       
        printf(!">>> Failed to read 4 bytes from [0x%x]\n", &hffffffaa)
    EndIf
  

    fb_uc_close(uc) 
End Sub

' emulate code that jump to invalid memory
Sub test_i386_jump_invalid()

    Dim as uc_engine uc 
    Dim as uc_err err_ 
    Dim as uc_hook trace1, trace2 

    Dim As Integer r_ecx = &h1234      ' ECX register
    Dim As Integer r_edx = &h7890      ' EDX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code that jumps to invalid memory\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_JMP_INVALID(0), UBound(X86_CODE32_JMP_INVALID)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_write(uc, UC_X86_REG_EDX, @r_edx) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instructions by having @begin > @end
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, 1, 0) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_JMP_INVALID)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    fb_uc_reg_read(uc, UC_X86_REG_EDX, @r_edx) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 
    printf(!">>> EDX = 0x%x\n", r_edx) 

    fb_uc_close(uc) 
End Sub

Sub test_i386_inout()

    Dim as uc_engine uc 
    Dim as uc_err Err_
    Dim as uc_hook trace1, trace2, trace3, trace4 


    Dim As Integer r_eax = &h1234      ' EAX register
    Dim As Integer r_ecx = &h6789      ' ECX register

    printf(!"===================================\n") 
    printf(!"Emulate i386 code with IN/OUT instructions\n") 

    ' Initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_INOUT(0), UBound(X86_CODE32_INOUT)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_EAX, @r_eax) 
    fb_uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instructions
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code, NULL, 1, 0) 

    ' uc IN instruction
    fb_uc_hook_add(uc, @trace3, UC_HOOK_INSN, @hook_in, NULL, 1, 0, UC_X86_INS_IN) 
    
    ' uc OUT instruction
    fb_uc_hook_add(uc, @trace4, UC_HOOK_INSN, @hook_out, NULL, 1, 0, UC_X86_INS_OUT) 

    ' emulate machine code in infinite time
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_INOUT)+1, 0, 0) 
    if (err_) Then 
  
        '' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_EAX, @r_eax) 
    fb_uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx) 
    printf(!">>> EAX = 0x%x\n", r_eax) 
    printf(!">>> ECX = 0x%x\n", r_ecx) 

    fb_uc_close(uc) 
End Sub

' emulate code and save/restore the CPU context
Sub test_i386_context_save()

    Dim as uc_engine uc 
    Dim As uc_context Ptr CONTEXT 
    Dim As uc_err Err_ 

    Dim As Integer r_eax = &h1     ' EAX register

    printf(!"===================================\n") 
    printf(!"Save/restore CPU context in opaque blob\n") 

    ' initialize emulator in X86-32bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_32, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 8KB memory for this emulation
    fb_uc_mem_map(uc, addrini, 8 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE32_INC(0), UBound(X86_CODE32_INC)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_EAX, @r_eax) 

    ' emulate machine code in infinite time
    printf(!">>> Running emulation for the first time\n") 

    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_INC)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_EAX, @r_eax) 
    printf(!">>> EAX = 0x%x\n", r_eax) 

    ' allocate and save the CPU context
    printf(!">>> Saving CPU context\n") 

    err_ = fb_uc_context_alloc(uc, @CONTEXT) 
    if (err_) Then 
  
        printf(!"Failed on uc_context_alloc() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    err_ = fb_uc_context_save(uc, context) 
    if (err_) Then 
  
        printf(!"Failed on uc_context_save() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' emulate machine code again
    printf(!">>> Running emulation for the second time\n") 

    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE32_INC)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_)) 
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_EAX, @r_eax) 
    printf(!">>> EAX = 0x%x\n", r_eax) 

    ' restore CPU context
    err_ = fb_uc_context_restore(uc, context) 
    if (err_) Then 
  
        printf(!"Failed on uc_context_restore() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' now print out some registers
    printf(!">>> CPU context restored. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_EAX, @r_eax) 
    printf(!">>> EAX = 0x%x\n", r_eax) 

    ' free the CPU context
	' nota, da error en uc_context_free, lo elimino, pero igual no es bueno. estufiaro
    ' err = uc_context_free(context);
    ' if (err) {
        ' printf(!"Failed on uc_free() with error returned: %u\n", err);
        ' return;
    ' }

    fb_uc_close(uc) 
End Sub


Sub test_x86_64()

    Dim as uc_engine uc 
    Dim As uc_err err_ 
    Dim As uc_hook trace1, trace2, trace3, trace4 

    Dim As int64_t rax = &h71f3029efd49d41d 
    Dim As int64_t rbx = &hd87b45277f133ddb 
    Dim As int64_t rcx = &hab40d1ffd8afc461 
    Dim As int64_t rdx = &h0919317b4a733f01 
    Dim As int64_t rsi = &h4c24e753a17ea358 
    Dim As int64_t rdi = &he509a57d2571ce96 
    Dim As int64_t r8  = &hea5b108cc2b9ab1f 
    Dim As int64_t r9  = &h19ec097c8eb618c1 
    Dim As int64_t r10 = &hec45774f00c5f682 
    Dim As int64_t r11 = &he17e9dbec8c074aa 
    Dim As int64_t r12 = &h80f86a8dc0f6d457 
    Dim As int64_t r13 = &h48288ca5671c5492 
    Dim As int64_t r14 = &h595f72f6e4017f6e 
    Dim As int64_t r15 = &h1efd97aea331cccc 

    Dim As int64_t rsp = addrini + &h200000 


    printf(!"Emulate x86_64 code\n") 

    ' Initialize emulator in X86-64bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_64, @uc) 
    if (Err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE64(0), UBound(X86_CODE64)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
	EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_RSP, @rsp) 

    fb_uc_reg_write(uc, UC_X86_REG_RAX, @rax) 
    fb_uc_reg_write(uc, UC_X86_REG_RBX, @rbx) 
    fb_uc_reg_write(uc, UC_X86_REG_RCX, @rcx) 
    fb_uc_reg_write(uc, UC_X86_REG_RDX, @rdx) 
    fb_uc_reg_write(uc, UC_X86_REG_RSI, @rsi) 
    fb_uc_reg_write(uc, UC_X86_REG_RDI, @rdi) 
    fb_uc_reg_write(uc, UC_X86_REG_R8 , @r8 ) 
    fb_uc_reg_write(uc, UC_X86_REG_R9 , @r9 ) 
    fb_uc_reg_write(uc, UC_X86_REG_R10, @r10) 
    fb_uc_reg_write(uc, UC_X86_REG_R11, @r11) 
    fb_uc_reg_write(uc, UC_X86_REG_R12, @r12) 
    fb_uc_reg_write(uc, UC_X86_REG_R13, @r13) 
    fb_uc_reg_write(uc, UC_X86_REG_R14, @r14) 
    fb_uc_reg_write(uc, UC_X86_REG_R15, @r15) 

    ' tracing all basic blocks with customized callback
    fb_uc_hook_add(uc, @trace1, UC_HOOK_BLOCK, @hook_block, NULL, 1, 0) 

    ' tracing all instructions in the range [addr, addr+20]
    fb_uc_hook_add(uc, @trace2, UC_HOOK_CODE, @hook_code64, NULL, addrini, addrini+20) 

    ' tracing all memory WRITE access (with @begin > @end)
    fb_uc_hook_add(uc, @trace3, UC_HOOK_MEM_WRITE, @hook_mem64, NULL, 1, 0) 

    ' tracing all memory READ access (with @begin > @end)
    fb_uc_hook_add(uc, @trace4, UC_HOOK_MEM_READ, @hook_mem64, NULL, 1, 0) 

    ' emulate machine code in infinite time (last param = 0), or when
    ' finishing all the code.
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE64)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_RAX, @rax) 
    fb_uc_reg_read(uc, UC_X86_REG_RBX, @rbx) 
    fb_uc_reg_read(uc, UC_X86_REG_RCX, @rcx) 
    fb_uc_reg_read(uc, UC_X86_REG_RDX, @rdx) 
    fb_uc_reg_read(uc, UC_X86_REG_RSI, @rsi) 
    fb_uc_reg_read(uc, UC_X86_REG_RDI, @rdi) 
    fb_uc_reg_read(uc, UC_X86_REG_R8 , @r8) 
    fb_uc_reg_read(uc, UC_X86_REG_R9 , @r9) 
    fb_uc_reg_read(uc, UC_X86_REG_R10, @r10) 
    fb_uc_reg_read(uc, UC_X86_REG_R11, @r11) 
    fb_uc_reg_read(uc, UC_X86_REG_R12, @r12) 
    fb_uc_reg_read(uc, UC_X86_REG_R13, @r13) 
    fb_uc_reg_read(uc, UC_X86_REG_R14, @r14) 
    fb_uc_reg_read(uc, UC_X86_REG_R15, @r15) 

    printf(!">>> RAX = 0x%" PRIx64 !"\n", rax) 
    printf(!">>> RBX = 0x%" PRIx64 !"\n", rbx) 
    printf(!">>> RCX = 0x%" PRIx64 !"\n", rcx) 
    printf(!">>> RDX = 0x%" PRIx64 !"\n", rdx) 
    printf(!">>> RSI = 0x%" PRIx64 !"\n", rsi) 
    printf(!">>> RDI = 0x%" PRIx64 !"\n", rdi) 
    printf(!">>> R8  = 0x%" PRIx64 !"\n", r8) 
    printf(!">>> R9  = 0x%" PRIx64 !"\n", r9) 
    printf(!">>> R10 = 0x%" PRIx64 !"\n", r10) 
    printf(!">>> R11 = 0x%" PRIx64 !"\n", r11) 
    printf(!">>> R12 = 0x%" PRIx64 !"\n", r12) 
    printf(!">>> R13 = 0x%" PRIx64 !"\n", r13) 
    printf(!">>> R14 = 0x%" PRIx64 !"\n", r14) 
    printf(!">>> R15 = 0x%" PRIx64 !"\n", r15) 

    fb_uc_close(uc) 
End Sub

Sub test_x86_64_syscall()

    Dim as uc_engine uc 
    Dim As uc_hook trace1 
    Dim As uc_err err_ 

    Dim As int64_t rax = &h100 

    printf(!"===================================\n") 
    printf(!"Emulate x86_64 code with 'syscall' instruction\n") 

    ' Initialize emulator in X86-64bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_64, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 2MB memory for this emulation
    fb_uc_mem_map(uc, addrini, 2 * 1024 * 1024, UC_PROT_ALL) 

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, addrini, @X86_CODE64_SYSCALL(0), UBound(X86_CODE64_SYSCALL)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' hook interrupts for syscall
    fb_uc_hook_add(uc, @trace1, UC_HOOK_INSN, @hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL) 

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_RAX, @rax) 

    ' emulate machine code in infinite time (last param = 0), or when
    ' finishing all the code.
    err_ = fb_uc_emu_start(uc, addrini, addrini + UBound(X86_CODE64_SYSCALL)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    fb_uc_reg_read(uc, UC_X86_REG_RAX, @rax) 

    printf(!">>> RAX = 0x%" PRIx64 !"\n", rax) 

    fb_uc_close(uc) 
End Sub

Sub test_x86_16()

    Dim as uc_engine uc 
    Dim as uc_err err_ 
    Dim As UByte tmp 

    Dim As Integer eax = 7 
    Dim As Integer ebx = 5 
    Dim As Integer esi = 6 

    printf(!"Emulate x86 16-bit code\n") 

    ' Initialize emulator in X86-16bit mode
    err_ = fb_uc_open(UC_ARCH_X86, UC_MODE_16, @uc) 
    if (err_) Then 
  
        printf(!"Failed on uc_open() with error returned: %u\n", err_) 
        return 
    
    EndIf
  

    ' map 8KB memory for this emulation
    err_=fb_uc_mem_map(uc, 0, 8 * 1024, UC_PROT_ALL) 
    '' pon_err(err_)

    ' write machine code to be emulated to memory
    if (fb_uc_mem_write(uc, 0, @X86_CODE16(0), UBound(X86_CODE16)+1 )) Then 
  
        printf(!"Failed to write emulation code to memory, quit!\n") 
        return 
    
    EndIf
  

    ' initialize machine registers
    fb_uc_reg_write(uc, UC_X86_REG_EAX, @eax) 
    fb_uc_reg_write(uc, UC_X86_REG_EBX, @ebx) 
    fb_uc_reg_write(uc, UC_X86_REG_ESI, @esi) 

    ' emulate machine code in infinite time (last param = 0), or when
    ' finishing all the code.
    err_ = fb_uc_emu_start(uc, 0, UBound(X86_CODE16)+1, 0, 0) 
    if (err_) Then 
  
         ' pon_err(err_) 
         printf(!"Failed on uc_emu_start() with error returned %u: %s\n",err_, fb_uc_strerror(err_))
    
    EndIf
  

    ' now print out some registers
    printf(!">>> Emulation done. Below is the CPU context\n") 

    ' read from memory
    if ( fb_uc_mem_read(uc, 11, @tmp, 1)=0) Then 

        printf(!">>> Read 1 bytes from [0x%x] = 0x%x\n", 11, tmp) 
    else
       
        printf(!">>> Failed to read 1 bytes from [0x%x]\n", 11)
	EndIf
  

    fb_uc_close(uc) 
End Sub







' -----------------------------------------------------------------------------


			Print
			Print
			Print "TEST 16BIT"
			Print "----------"
  				' test 16
            test_x86_16() 


			Print
			Print
			Print "TEST 32BIT"
			Print "----------"
   			' test 32
            test_i386()
            test_i386_map_ptr() 
            test_i386_inout() 
            test_i386_context_save() 
            test_i386_jump() 
            test_i386_loop() 
            test_i386_invalid_mem_read() 
            test_i386_invalid_mem_write() 
            test_i386_jump_invalid() 
            'test_i386_invalid_c6c7();
       
        
			Print
			Print
			Print "TEST 64BIT"
			Print "----------"
  				' test 64
            test_x86_64() 
            test_x86_64_syscall() 
         
sleep