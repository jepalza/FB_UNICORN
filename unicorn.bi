
#Inclib "unicorn"

#include "platform.bi"

'struct uc_struct
'typedef struct uc_struct uc_engine
'typedef SIZE_T uc_hook





#include "m68k.bi"
#include "x86.bi"
#include "arm.bi"
#include "arm64.bi"
#include "mips.bi"
#include "sparc.bi"


' Scales to calculate timeout on microsecond unit
' 1 second = 1000,000 microseconds
#define UC_SECOND_SCALE 1000000
' 1 milisecond = 1000 nanoseconds
#define UC_MILISECOND_SCALE 1000

 

Enum uc_arch 
    UC_ARCH_ARM = 1,    ' ARM architecture (including Thumb, Thumb-2)
    UC_ARCH_ARM64,      ' ARM-64, also called AArch64
    UC_ARCH_MIPS,       ' Mips architecture
    UC_ARCH_X86,        ' X86 architecture (including x86 & x86-64)
    UC_ARCH_PPC,        ' PowerPC architecture (currently unsupported)
    UC_ARCH_SPARC,      ' Sparc architecture
    UC_ARCH_M68K,       ' M68K architecture
    UC_ARCH_MAX
End enum 

' Mode type
Enum uc_mode 
    UC_MODE_LITTLE_ENDIAN = 0,       ' little-endian mode (default mode)
    UC_MODE_BIG_ENDIAN = 1  Shl  30, ' big-endian mode

    ' arm / arm64
    UC_MODE_ARM = 0,               ' ARM mode
    UC_MODE_THUMB  = 1  Shl  4,    ' THUMB mode (including Thumb-2)
    UC_MODE_MCLASS = 1  Shl  5,    ' ARM´s Cortex-M series (currently unsupported)
    UC_MODE_V8     = 1  Shl  6,    ' ARMv8 A32 encodings for ARM (currently unsupported)

    ' arm (32bit) cpu types
    UC_MODE_ARM926  = 1  Shl  7,	  ' ARM926 CPU type
    UC_MODE_ARM946  = 1  Shl  8,	  ' ARM946 CPU type
    UC_MODE_ARM1176 = 1  Shl  9,	  ' ARM1176 CPU type

    ' mips
    UC_MODE_MICRO    = 1  Shl  4,  ' MicroMips mode (currently unsupported)
    UC_MODE_MIPS3    = 1  Shl  5,  ' Mips III ISA (currently unsupported)
    UC_MODE_MIPS32R6 = 1  Shl  6,  ' Mips32r6 ISA (currently unsupported)
    UC_MODE_MIPS32   = 1  Shl  2,  ' Mips32 ISA
    UC_MODE_MIPS64   = 1  Shl  3,  ' Mips64 ISA

    ' x86 / x64
    UC_MODE_16 = 1  Shl  1,        ' 16-bit mode
    UC_MODE_32 = 1  Shl  2,        ' 32-bit mode
    UC_MODE_64 = 1  Shl  3,        ' 64-bit mode

    ' ppc
    UC_MODE_PPC32 = 1  Shl  2,     ' 32-bit mode (currently unsupported)
    UC_MODE_PPC64 = 1  Shl  3,     ' 64-bit mode (currently unsupported)
    UC_MODE_QPX   = 1  Shl  4,     ' Quad Processing eXtensions mode (currently unsupported)

    ' sparc
    UC_MODE_SPARC32 = 1  Shl  2,   ' 32-bit mode
    UC_MODE_SPARC64 = 1  Shl  3,   ' 64-bit mode
    UC_MODE_V9      = 1  Shl  4   ' SparcV9 mode (currently unsupported)

    ' m68k
 End Enum 

' All type of errors encountered by Unicorn API.
' These are values returned by uc_errno()
Enum uc_err 
    UC_ERR_OK = 0,   ' No error: everything was fine
    UC_ERR_NOMEM,      ' Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,     ' Unsupported architecture: uc_open()
    UC_ERR_HANDLE,   ' Invalid handle
    UC_ERR_MODE,     ' Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,  ' Unsupported version (bindings)
    UC_ERR_READ_UNMAPPED, ' Quit emulation due to READ on unmapped memory: uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, ' Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, ' Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    UC_ERR_HOOK,    ' Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID, ' Quit emulation due to invalid instruction: uc_emu_start()
    UC_ERR_MAP, ' Invalid memory mapping: uc_mem_map()
    UC_ERR_WRITE_PROT, ' Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    UC_ERR_READ_PROT, ' Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    UC_ERR_FETCH_PROT, ' Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    UC_ERR_ARG,     ' Inavalid argument provided to uc_xxx function (See specific function API)
    UC_ERR_READ_UNALIGNED,  ' Unaligned read
    UC_ERR_WRITE_UNALIGNED,  ' Unaligned write
    UC_ERR_FETCH_UNALIGNED,  ' Unaligned fetch
    UC_ERR_HOOK_EXIST,  ' hook for this event already existed
    UC_ERR_RESOURCE,    ' Insufficient resource: uc_emu_start()
    UC_ERR_EXCEPTION ' Unhandled CPU exception
End Enum 



/'
  Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)

  @address: address where the code is being executed
  @size: size of machine instruction(s) being executed, or 0 when size is unknown
  @user_data: user data passed to tracing APIs.
'/
Enum uc_mem_type 
     UC_MEM_READ = 16,   	' Memory is read from
     UC_MEM_WRITE,       	' Memory is written to
     UC_MEM_FETCH,       	' Memory is fetched
     UC_MEM_READ_UNMAPPED, ' Unmapped memory is read from
     UC_MEM_WRITE_UNMAPPED,' Unmapped memory is written to
     UC_MEM_FETCH_UNMAPPED,' Unmapped memory is fetched
     UC_MEM_WRITE_PROT,  	' Write to write protected, but mapped, memory
     UC_MEM_READ_PROT,   	' Read from read protected, but mapped, memory
     UC_MEM_FETCH_PROT,  	' Fetch from non-executable, but mapped, memory
     UC_MEM_READ_AFTER   	' Memory is read from (successful access)
End Enum 

' All type of hooks for uc_hook_add() API.
Enum uc_hook_type 
    ' Hook all interrupt/syscall events
    UC_HOOK_INTR = 1  Shl  0,
    ' Hook a particular instruction - only a very small subset of instructions supported here
    UC_HOOK_INSN = 1  Shl  1,
    ' Hook a range of code
    UC_HOOK_CODE = 1  Shl  2,
    ' Hook basic blocks
    UC_HOOK_BLOCK = 1  Shl  3,
    ' Hook for memory read on unmapped memory
    UC_HOOK_MEM_READ_UNMAPPED = 1  Shl  4,
    ' Hook for invalid memory write events
    UC_HOOK_MEM_WRITE_UNMAPPED = 1  Shl  5,
    ' Hook for invalid memory fetch for execution events
    UC_HOOK_MEM_FETCH_UNMAPPED = 1  Shl  6,
    ' Hook for memory read on read-protected memory
    UC_HOOK_MEM_READ_PROT = 1  Shl  7,
    ' Hook for memory write on write-protected memory
    UC_HOOK_MEM_WRITE_PROT = 1  Shl  8,
    ' Hook for memory fetch on non-executable memory
    UC_HOOK_MEM_FETCH_PROT = 1  Shl  9,
    ' Hook memory read events.
    UC_HOOK_MEM_READ = 1  Shl  10,
    ' Hook memory write events.
    UC_HOOK_MEM_WRITE = 1  Shl  11,
    ' Hook memory fetch for execution events
    UC_HOOK_MEM_FETCH = 1  Shl  12,
    ' Hook memory read events, but only successful access.
    ' The callback will be triggered after successful read.
    UC_HOOK_MEM_READ_AFTER = 1  Shl  13,
    ' Hook invalid instructions exceptions.
    UC_HOOK_INSN_INVALID = 1  Shl  14
 End Enum 

' Hook type for all events of unmapped memory access
#define UC_HOOK_MEM_UNMAPPED (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED + UC_HOOK_MEM_FETCH_UNMAPPED)
' Hook type for all events of illegal protected memory access
#define UC_HOOK_MEM_PROT (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
' Hook type for all events of illegal read memory access
#define UC_HOOK_MEM_READ_INVALID (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
' Hook type for all events of illegal write memory access
#define UC_HOOK_MEM_WRITE_INVALID (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
' Hook type for all events of illegal fetch memory access
#define UC_HOOK_MEM_FETCH_INVALID (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
' Hook type for all events of illegal memory access
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
' Hook type for all events of valid memory access
' NOTE: UC_HOOK_MEM_READ is triggered before UC_HOOK_MEM_READ_PROT and UC_HOOK_MEM_READ_UNMAPPED, so
'       this hook may technically trigger on some invalid reads.
#define UC_HOOK_MEM_VALID (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)

/'
  Callback function for hooking memory (READ, WRITE & FETCH)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs
'/
Type uc_mem_region 
    As uint64_t begin  ' begin address of the region (inclusive)
    As uint64_t end_    ' end address of the region (inclusive)
    As uint32_t perms  ' memory permissions of the region
End Type 

' All type of queries for uc_query() API.
Enum uc_query_type 
    ' Dynamically query current hardware mode.
    UC_QUERY_MODE = 1,
    UC_QUERY_PAGE_SIZE, ' query pagesize of engine
    UC_QUERY_ARCH,   ' query architecture of engine (for ARM to query Thumb mode)
    UC_QUERY_TIMEOUT  ' query if emulation stops due to timeout (indicated if result = True)
End Enum 

' Opaque storage for CPU context, used with uc_context_*()
#define uc_context  Integer


enum uc_prot 
   UC_PROT_NONE = 0,
   UC_PROT_READ = 1,
   UC_PROT_WRITE = 2,
   UC_PROT_EXEC = 4,
   UC_PROT_ALL = 7 ' este es el total de los 3 anteriores
End Enum 



' typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
' typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);
' typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);
' typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size, void *user_data);
' typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);
' typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
' typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,uint64_t address, int size, int64_t value, void *user_data);

Declare Function fb_uc_version 			Cdecl Alias "uc_version"(ByVal major As uInteger  ,ByVal minor As UInteger ) As Integer 
Declare Function fb_uc_arch_supported 	Cdecl Alias "uc_arch_supported"(ByVal arch As uc_arch) As bool 
Declare Function fb_uc_strerror 			Cdecl Alias "uc_strerror"(ByVal code As uc_err) As Byte ptr
Declare Function fb_uc_context_size 	Cdecl Alias "uc_context_size"(ByVal uc As uc_engine ) As SIZE_T 

Declare Function fb_uc_open  Cdecl Alias "uc_open" (ByVal arch As uc_arch ,ByVal mode As uc_mode ,ByVal uc As uc_engine Ptr) As uc_err 
Declare Function fb_uc_close Cdecl Alias "uc_close"(ByVal uc As uc_engine ) As uc_err 
Declare Function fb_uc_query Cdecl Alias "uc_query"(ByVal uc As uc_engine  ,ByVal type_ As uc_query_type ,ByVal result As SIZE_T ) As uc_err 
Declare Function fb_uc_errno Cdecl Alias "uc_errno"(ByVal uc As uc_engine ) As uc_err 

Declare Function fb_uc_reg_write Cdecl Alias "uc_reg_write"(ByVal uc As uc_engine  ,ByVal regid As Integer ,ByVal value As integer ) As uc_err 
Declare Function fb_uc_reg_read  Cdecl Alias "uc_reg_read" (ByVal uc As uc_engine  ,ByVal regid As Integer ,ByVal value As Integer ) As uc_err 

Declare Function fb_uc_reg_write_batch Cdecl Alias "uc_reg_write_batch"(ByVal uc As uc_engine  ,ByVal regs As Integer  ,ByVal vals As Integer  ,ByVal count As Integer) As uc_err 
Declare Function fb_uc_reg_read_batch  Cdecl Alias "uc_reg_read_batch" (ByVal uc As uc_engine  ,ByVal regs As Integer  ,ByVal vals As Integer  ,ByVal count As Integer) As uc_err 

Declare Function fb_uc_emu_start Cdecl Alias "uc_emu_start"(ByVal uc As uc_engine  ,ByVal begin As uint64_t ,ByVal until_ As uint64_t ,ByVal timeout As uint64_t ,ByVal count As SIZE_T) As uc_err 
Declare Function fb_uc_emu_stop  Cdecl Alias "uc_emu_stop" (ByVal uc As uc_engine ) As uc_err 

Declare Function fb_uc_hook_add  Cdecl Alias "uc_hook_add" (ByVal uc As uc_engine  ,ByVal hh As uc_hook  ,ByVal type_ As Integer ,ByVal callback As Integer  ,ByVal user_data As Integer  ,ByVal begin As uint64_t ,ByVal end_ As uint64_t, variable As Integer=0 ) As uc_err 
Declare Function fb_uc_hook_del  Cdecl Alias "uc_hook_del" (ByVal uc As uc_engine  ,ByVal hh As uc_hook) As uc_err 

Declare Function fb_uc_mem_map     Cdecl Alias "uc_mem_map"    (byval uc As uc_engine  ,ByVal addr as uint64_t ,size As SIZE_T ,ByVal perms As uint32_t) As uc_err 
Declare Function fb_uc_mem_map_ptr Cdecl Alias "uc_mem_map_ptr"(ByVal uc As uc_engine  ,ByVal addr as uint64_t ,ByVal size As SIZE_T ,ByVal perms As uint32_t ,ByVal ptr_ As Integer ) As uc_err 
Declare Function fb_uc_mem_unmap   Cdecl Alias "uc_mem_unmap"  (ByVal uc As uc_engine  ,ByVal address As uint64_t ,ByVal size As SIZE_T) As uc_err 
Declare Function fb_uc_mem_protect Cdecl Alias "uc_mem_protect"(ByVal uc As uc_engine  ,ByVal addr as uint64_t ,ByVal size As SIZE_T ,ByVal perms As uint32_t) As uc_err 
Declare Function fb_uc_mem_regions Cdecl Alias "uc_mem_regions"(ByVal uc As uc_engine  ,ByVal regions As uc_mem_region  ,ByVal  count As uint32_t ) As uc_err 
Declare Function fb_uc_mem_read    Cdecl Alias "uc_mem_read"   (ByVal uc As uc_engine  ,ByVal addr as uint64_t ,ByVal bytes As Integer  ,ByVal size As SIZE_T) As uc_err 
Declare Function fb_uc_mem_write   Cdecl Alias "uc_mem_write"  (ByVal uc As uc_engine  ,ByVal addr as uint64_t ,ByVal bytes As Integer  ,ByVal size As SIZE_T) As uc_err 

Declare Function fb_uc_context_alloc   Cdecl Alias "uc_context_alloc"  (ByVal uc As uc_engine  ,ByVal context_ As uc_context ) As uc_err 
Declare Function fb_uc_context_save    Cdecl Alias "uc_context_save"   (ByVal uc As uc_engine  ,ByVal context_ As uc_context ) As uc_err 
Declare Function fb_uc_context_restore Cdecl Alias "uc_context_restore"(ByVal uc As uc_engine  ,ByVal context_ As uc_context ) As uc_err 
Declare Function fb_uc_context_free    Cdecl Alias "uc_context_free"   (ByVal context_ As uc_context ) As uc_err 

Declare Function fb_uc_free Cdecl Alias "uc_free"(ByVal mem As Integer) As uc_err 





Sub pon_err(aa As Integer)
	Color 11,0
	 If aa= 0 Then Color 14,0:Print " OK":Color 7,0:Exit Sub
    If aa= 1 Then Print "Out-Of-Memory error: uc_open(), uc_emulate()";
    If aa= 2 Then Print "Unsupported architecture: uc_open()";
    If aa= 3 Then Print "Invalid handle";
    If aa= 4 Then Print "Invalid/unsupported mode: uc_open()";
    If aa= 5 Then Print "Unsupported version (bindings)";
    If aa= 6 Then Print "Quit emulation due to READ  on unmapped memory: uc_emu_start()";
    If aa= 7 Then Print "Quit emulation due to WRITE on unmapped memory: uc_emu_start()";
    If aa= 8 Then Print "Quit emulation due to FETCH on unmapped memory: uc_emu_start()";
    If aa= 9 Then Print "Invalid hook type: uc_hook_add()";
    If aa=10 Then Print "Quit emulation due to invalid instruction: uc_emu_start()";
    If aa=11 Then Print "Invalid memory mapping: uc_mem_map()";
    If aa=12 Then Print "Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()";
    If aa=13 Then Print "Quit emulation due to UC_MEM_READ_PROT  violation: uc_emu_start()";
    If aa=14 Then Print "Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()";
    If aa=15 Then Print "Invalid argument provided to uc_xxx function.";
    If aa=16 Then Print "Unaligned read";
    If aa=17 Then Print "Unaligned write";
    If aa=18 Then Print "Unaligned fetch";
    If aa=19 Then Print "hook for this event already existed";
    If aa=20 Then Print "Insufficient resource: uc_emu_start()";
    If aa=21 Then Print "Unhandled CPU exception";
    Color 12,0
    Print aa
   Color 7,0
End Sub


' usado unicamente para la rutina "fb_uc_mem_map_ptr()"
' sirve para copiar una zona de datos/codigo en la RAM y apuntar su inicio a un puntero de UC_MEM_MAP
Function memcpy(dest As byte Ptr, ori As Byte Ptr, lon As Integer) As BOOL
	Dim As Integer f
	For f=0 To lon-1
		*(dest+f)=*(ori+f)
		'Print Hex(*(dest+f),2)
	Next
	' no compruebo nada, por lo que siempre devuelve "1"
	Return 1
End Function


