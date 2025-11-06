import ctypes
import ctypes.wintypes

WORDSIZE = ctypes.sizeof(ctypes.c_void_p)  # 4 or 8 bytes depending on x86 or x64
WORDPACK = "I" if WORDSIZE == 4 else "Q"  # struct pack format for word size
MAXINT = 0x7FFFFFFF if WORDSIZE == 4 else 0x7FFFFFFFFFFFFFFF
MAXUINT = 0xFFFFFFFF if WORDSIZE == 4 else 0xFFFFFFFFFFFFFFFF


class STARTUPINFO(ctypes.Structure):
    """
    Used for CreateProcessW() so we can start a process suspended.
    """

    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.wintypes.LPWSTR),
        ("lpDesktop", ctypes.wintypes.LPWSTR),
        ("lpTitle", ctypes.wintypes.LPWSTR),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.wintypes.LPBYTE),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]


CreateProcessW = ctypes.windll.kernel32.CreateProcessW
CreateProcessW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO),
    ctypes.POINTER(PROCESS_INFORMATION),
)
CreateProcessW.restype = ctypes.wintypes.BOOL

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = ctypes.c_void_p

TH32CS_SNAPPROCESS = 0x00000002


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot

Process32First = ctypes.windll.kernel32.Process32First

Process32Next = ctypes.windll.kernel32.Process32Next

CloseHandle = ctypes.windll.kernel32.CloseHandle

IsWow64Process = ctypes.windll.kernel32.IsWow64Process
IsWow64Process.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.BOOL))

ResumeThread = ctypes.windll.kernel32.ResumeThread
ResumeThread.argtypes = (ctypes.wintypes.HANDLE,)

try:
    EnumProcessModules = ctypes.windll.psapi.EnumProcessModules
except:
    EnumProcessModules = ctypes.windll.kernel32.EnumProcessModules
EnumProcessModules.restype = ctypes.c_bool
EnumProcessModules.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HMODULE),
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD),
]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


try:
    GetModuleInformation = ctypes.windll.psapi.GetModuleInformation
except:
    GetModuleInformation = ctypes.windll.kernel32.GetModuleInformation
GetModuleInformation.restype = ctypes.c_bool
GetModuleInformation.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HMODULE,
    ctypes.POINTER(MODULEINFO),
    ctypes.wintypes.DWORD,
)

GetModuleFileNameA = ctypes.windll.kernel32.GetModuleFileNameA
GetModuleFileNameA.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPSTR,
    ctypes.wintypes.DWORD,
)

GetModuleFileNameExA = ctypes.windll.psapi.GetModuleFileNameExA
GetModuleFileNameExA.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPSTR,
    ctypes.wintypes.DWORD,
)

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = (
    ctypes.wintypes.DWORD,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
)
OpenProcess.restype = ctypes.wintypes.HANDLE

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.argtypes = (ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR)
GetProcAddress.restype = ctypes.c_void_p

VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
VirtualAlloc.argtypes = (
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
)
VirtualAlloc.restype = ctypes.wintypes.LPVOID

VirtualFree = ctypes.windll.kernel32.VirtualFree
VirtualFree.argtypes = (ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD)
VirtualFree.restype = ctypes.wintypes.BOOL

VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
)
VirtualAllocEx.restype = ctypes.wintypes.LPVOID

VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD),
)
VirtualProtectEx.restype = ctypes.wintypes.LPVOID

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = ctypes.wintypes.BOOL
ReadProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = ctypes.wintypes.BOOL
WriteProcessMemory.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)

LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
LoadLibraryA.restype = ctypes.wintypes.HMODULE
LoadLibraryA.argtypes = (ctypes.wintypes.LPSTR,)

SetDllDirectoryA = ctypes.windll.kernel32.SetDllDirectoryA
SetDllDirectoryA.restype = ctypes.wintypes.BOOL
SetDllDirectoryA.argtypes = (ctypes.wintypes.LPSTR,)

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = ctypes.wintypes.HANDLE
CreateRemoteThread.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPDWORD,
)

WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
WaitForSingleObject.restype = ctypes.wintypes.DWORD
WaitForSingleObject.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD)

GetExitCodeThread = ctypes.windll.kernel32.GetExitCodeThread
GetExitCodeThread.restype = ctypes.wintypes.BOOL
GetExitCodeThread.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPDWORD)

CreateFile = ctypes.windll.kernel32.CreateFileW
CreateFile.argtypes = (
    ctypes.c_wchar_p,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_void_p,
)
CreateFile.restype = ctypes.wintypes.HANDLE
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GetCurrentThreadId = ctypes.windll.kernel32.GetCurrentThreadId
GetCurrentThreadId.argtypes = ()
GetCurrentThreadId.restype = ctypes.wintypes.DWORD


WriteFile = ctypes.windll.kernel32.WriteFile
WriteFile.argtypes = (
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_void_p,
)
WriteFile.restype = ctypes.c_uint32

ReadFile = ctypes.windll.kernel32.ReadFile
ReadFile.argtypes = (
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_void_p,
)
ReadFile.restype = ctypes.c_uint32

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010
DETACHED_PROCESS = 0x00000008

SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = 0x101FFB

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000

# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366786%28v=vs.85%29.aspx
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08

PyMemoryView_FromMemory = ctypes.pythonapi.PyMemoryView_FromMemory
PyMemoryView_FromMemory.restype = ctypes.py_object
PyMemoryView_FromMemory.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int)
PyBUF_READ = 0x100
PyBUF_WRITE = 0x200

strnlen = ctypes.cdll.msvcrt.strnlen
strnlen.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
strnlen.restype = ctypes.c_size_t

MessageBoxA = ctypes.windll.user32.MessageBoxA
MessageBoxA.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
MessageBoxA.restype = ctypes.c_int

SetEnvironmentVariableA = ctypes.windll.kernel32.SetEnvironmentVariableA
SetEnvironmentVariableA.restype = ctypes.wintypes.BOOL
SetEnvironmentVariableA.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
