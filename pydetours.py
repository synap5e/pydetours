import binascii
import ctypes
import ctypes.wintypes
import os
import struct
import sys
import traceback
import ctypes.util
from collections import defaultdict
from functools import wraps
from typing import NamedTuple, Union

try:
	from functools import cached_property
except ImportError:
	from threading import RLock
	_NOT_FOUND = object()
	class cached_property:
		def __init__(self, func):
			self.func = func
			self.attrname = None
			self.lock = RLock()
		def __set_name__(self, owner, name):
			assert name is not None
			self.attrname = name
		def __get__(self, instance, owner=None):
			cache = instance.__dict__
			val = cache.get(self.attrname, _NOT_FOUND)
			if val is _NOT_FOUND:
				with self.lock:
					val = cache.get(self.attrname, _NOT_FOUND)
					if val is _NOT_FOUND:
						val = self.func(instance)
						cache[self.attrname] = val
			return val


PYTHON_DLL = f'python{sys.version_info.major}{sys.version_info.minor}.dll'
WORDSIZE = ctypes.sizeof(ctypes.c_void_p)
WORDPACK = 'I' if WORDSIZE == 4 else 'Q'
REX1 = b'' if WORDSIZE == 4 else b'\x48'


# --- ctypes functions, structures, and constants ---
class STARTUPINFO(ctypes.Structure):
	_fields_ = [
		('cb', ctypes.wintypes.DWORD),
		('lpReserved', ctypes.wintypes.LPWSTR),
		('lpDesktop', ctypes.wintypes.LPWSTR),
		('lpTitle', ctypes.wintypes.LPWSTR),
		('dwX', ctypes.wintypes.DWORD),
		('dwY', ctypes.wintypes.DWORD),
		('dwXSize', ctypes.wintypes.DWORD),
		('dwYSize', ctypes.wintypes.DWORD),
		('dwXCountChars', ctypes.wintypes.DWORD),
		('dwYCountChars', ctypes.wintypes.DWORD),
		('dwFillAttribute', ctypes.wintypes.DWORD),
		('dwFlags', ctypes.wintypes.DWORD),
		('wShowWindow', ctypes.wintypes.WORD),
		('cbReserved2', ctypes.wintypes.WORD),
		('lpReserved2', ctypes.wintypes.LPBYTE),
		('hStdInput', ctypes.wintypes.HANDLE),
		('hStdOutput', ctypes.wintypes.HANDLE),
		('hStdError', ctypes.wintypes.HANDLE),
	]
class PROCESS_INFORMATION(ctypes.Structure):
	_fields_ = [
		('hProcess', ctypes.wintypes.HANDLE),
		('hThread', ctypes.wintypes.HANDLE),
		('dwProcessId', ctypes.wintypes.DWORD),
		('dwThreadId', ctypes.wintypes.DWORD),
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
	_fields_ = [('dwSize', ctypes.wintypes.DWORD),
				('cntUsage', ctypes.wintypes.DWORD),
				('th32ProcessID', ctypes.wintypes.DWORD),
				('th32DefaultHeapID', ctypes.POINTER(ctypes.wintypes.ULONG)),
				('th32ModuleID', ctypes.wintypes.DWORD),
				('cntThreads', ctypes.wintypes.DWORD),
				('th32ParentProcessID', ctypes.wintypes.DWORD),
				('pcPriClassBase', ctypes.wintypes.LONG),
				('dwFlags', ctypes.wintypes.DWORD),
				('szExeFile', ctypes.c_char * 260)]
CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot

Process32First = ctypes.windll.kernel32.Process32First

Process32Next = ctypes.windll.kernel32.Process32Next

CloseHandle = ctypes.windll.kernel32.CloseHandle

IsWow64Process = ctypes.windll.kernel32.IsWow64Process
IsWow64Process.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.BOOL))

ResumeThread = ctypes.windll.kernel32.ResumeThread
ResumeThread.argtypes = (ctypes.wintypes.HANDLE, )

try:
	EnumProcessModules = ctypes.windll.psapi.EnumProcessModules    
except:
	EnumProcessModules = ctypes.windll.kernel32.EnumProcessModules    
EnumProcessModules.restype = ctypes.c_bool
EnumProcessModules.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]

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
GetModuleInformation.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.POINTER(MODULEINFO), ctypes.wintypes.DWORD)

GetModuleFileNameA = ctypes.windll.kernel32.GetModuleFileNameA
GetModuleFileNameA.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPSTR, ctypes.wintypes.DWORD)

GetModuleFileNameExA = ctypes.windll.psapi.GetModuleFileNameExA
GetModuleFileNameExA.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE, ctypes.wintypes.LPSTR, ctypes.wintypes.DWORD)

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
OpenProcess.restype = ctypes.wintypes.HANDLE

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.argtypes = (ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR)
GetProcAddress.restype = ctypes.c_void_p

VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
VirtualAlloc.argtypes = (ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
VirtualAlloc.restype = ctypes.wintypes.LPVOID

VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
VirtualAllocEx.restype = ctypes.wintypes.LPVOID

VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD))
VirtualProtectEx.restype = ctypes.wintypes.LPVOID

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = ctypes.wintypes.BOOL
ReadProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = ctypes.wintypes.BOOL
WriteProcessMemory.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))

LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
LoadLibraryA.restype = ctypes.wintypes.HMODULE
LoadLibraryA.argtypes = (ctypes.wintypes.LPSTR, )

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = ctypes.wintypes.HANDLE
CreateRemoteThread.argtypes = (ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPDWORD)

WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
WaitForSingleObject.restype = ctypes.wintypes.DWORD
WaitForSingleObject.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD)

GetExitCodeThread = ctypes.windll.kernel32.GetExitCodeThread
GetExitCodeThread.restype = ctypes.wintypes.BOOL
GetExitCodeThread.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPDWORD)

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010
DETACHED_PROCESS = 0x00000008

PROCESS_ALL_ACCESS = 0x101ffb

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000

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

ALLOWED_PADDING = b'\xcc\x90'
ALLOWED_PROLOGUES = [
	'55 8b ec',  # push ebp; mov ebp, esp - only 3 bytes but can work with padding
	'55 89 e5',  # alternate encoding

	'8b ff 55 8b ec',  # windows dlls prepend noop before to allow easy hooking
	
	'55 8b ec 83 ec ??',  #  push ebp; mov ebp, esp; sub esp, ?? - allocating space for stack variables is a common pattern that results in PIC bytes
	'55 8b ec 83 e4 ??',  #  push ebp; mov ebp, esp; and esp, ?? - or aligning the stack

	'55 89 e5 83 ec ??',  #  push ebp; mov ebp, esp; sub esp, ?? - as above but with alternate encodings for mov
	'55 89 e5 83 e4 ??',  #  push ebp; mov ebp, esp; and esp, ??

	'90 90 90 90 90',
]
if WORDSIZE == 8:
	ALLOWED_PROLOGUES += [
		'55 48 8b ec 48 83 ec ??',  #  push rbp; mov rbp, rsp; sub rsp, ?? - allocating space for stack variables is a common pattern that results in PIC bytes
		'55 48 8b ec 48 83 e4 ??',  #  push rbp; mov rbp, rsp; and rsp, ?? - or aligning the stack

		'55 48 89 e5 48 83 ec ??',  #  push rbp; mov rbp, rsp; sub rsp, ?? - as above but with alternate encodings for mov
		'55 48 89 e5 48 83 e4 ??',  #  push rbp; mov rbp, rsp; and rsp, ??
	]


class Memory:

	def __init__(self, handle=None):
		self.handle = handle

	def read(self, addr, length):
		if not self.handle:
			buf = (ctypes.c_uint8 * length)()
			ctypes.memmove(buf, addr, length)
			return bytes(buf)
		else:
			buf = (ctypes.c_uint8 * length)()
			bytes_read = ctypes.c_size_t()
			ReadProcessMemory(self.handle, addr, ctypes.byref(buf), length, ctypes.byref(bytes_read))
			return bytes(buf[:bytes_read.value])

	def __getitem__(self, s):
		if isinstance(s, int):
			s = slice(s, None, None)

		if s.stop is not None:
			ln = s.stop - s.start
		elif s.step:
			ln = s.step
		else:
			ln = 1

		# data = bytes(PyMemoryView_FromMemory(s.start, ln, PyBUF_READ))

		data = self.read(s.start, ln)

		if s.step is None or s.step == 1:
			pass
		elif s.step == 8:
			data = struct.unpack('<' + 'Q' * (ln // 8), data)
		elif s.step == 4:
			data = struct.unpack('<' + 'I' * (ln // 4), data)
		elif s.step == 2:
			data = struct.unpack('<' + 'H' * (ln // 2), data)
		else:
			raise ValueError('Don\'t know how to support step=%s' % (s.step, ))

		if s.stop is None:
			return data[0]
		else:
			return data

	def __setitem__(self, s, v):
		if self.handle:
			raise ValueError('Not implemented for foreign processes')
		if isinstance(s, int):
			ln = 1
		else:
			ln = s.stop - s.start
		data = ctypes.create_string_buffer(v)
		ctypes.memmove(s.start, data, ln)

	def cstr(self, addr, maxlen=1024):
		if not self.handle:
			return ctypes.string_at(addr).decode('ascii')
		else:
			data = self.read(addr, maxlen)
			if 0 in data:
				data = data[:data.find(0)]
			return data.decode('ascii')


class Module:

	def __init__(self, hModule, process_handle=None):
		self.hModule = hModule
		self.handle = process_handle or handle
		self.memory = memory if not process_handle else Memory(process_handle)
		cPath = ctypes.create_string_buffer(1024)
		if process_handle:
			assert GetModuleFileNameExA(process_handle, self.hModule, cPath, ctypes.c_ulong(1024)), f'GetModuleFileNameExA got {ctypes.windll.kernel32.GetLastError():x}'
		else:
			assert GetModuleFileNameA(self.hModule, cPath, ctypes.c_ulong(1024)), f'GetModuleFileNameA got {ctypes.windll.kernel32.GetLastError():x}'
		self.path = cPath.value.decode()
		self.name = os.path.basename(self.path.lower())

		self.lpBaseOfDll = self.SizeOfImage = self.EntryPoint = None
		self.export_directory_data = self.import_directory_data = None

		module_info = MODULEINFO()
		res = GetModuleInformation(self.handle, self.hModule, ctypes.byref(module_info), ctypes.sizeof(module_info))
		if res:
			self.lpBaseOfDll = module_info.lpBaseOfDll
			self.SizeOfImage = module_info.SizeOfImage
			self.EntryPoint = module_info.EntryPoint

			if self.lpBaseOfDll:
				DosHeader = self.lpBaseOfDll
				MZSignature = self.memory[DosHeader:DosHeader + 2]
				assert MZSignature == b'\x4d\x5a'
				AddressOfNewExeHeader = DosHeader + 60

				# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
				# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
				NtHeader = DosHeader + self.memory[AddressOfNewExeHeader::4]
				Signature = self.memory[NtHeader:NtHeader + 4]
				assert Signature == b'\x50\x45\x00\x00'

				# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
				# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
				OptionalHeader = NtHeader + 24
				Magic = self.memory[OptionalHeader:OptionalHeader + 2]
				if Magic == b'\x0b\x01':
					if WORDSIZE != 4:
						raise ValueError('OptionalHeader magic specifies module as 32bit, but we are a 64bit process')
					DataDirectory = OptionalHeader + 96
				elif Magic == b'\x0b\x02':
					if WORDSIZE != 8:
						raise ValueError('OptionalHeader magic specifies module as 64bit, but we are a 32bit process')
					DataDirectory = OptionalHeader + 112
				else:
					raise ValueError(f'OptionalHeader magic mismatch: got {Magic.hex()}')

				self.export_directory_data = tuple(self.memory[DataDirectory:DataDirectory + 8:4])
				self.import_directory_data = tuple(self.memory[DataDirectory + 8:DataDirectory + 16:4])

	class Exports(list):
		@cached_property
		def by_name(self):
			return {e.name: e for e in self}
		@cached_property
		def by_ordinal(self):
			return {e.ordinal: e for e in self}
		@cached_property
		def by_name_and_ordinal(self):
			r = self.by_name
			r.update(self.by_ordinal)
			return r
		def __getitem__(self, e):
			if isinstance(e, str):
				return self.by_name[e]
			else:
				return super().__getitem__(e)

	class Export(NamedTuple):
		ordinal: int
		name: str
		address: int

		address_ptr: int

	@cached_property
	def exports(self):
		exports = []
		# Some modules might fail GetModuleInformation, so have export_directory_data=None, some modules (e.g. exes) might have no exports (export_directory_data.VirtualAddress = 0)
		if self.export_directory_data and self.export_directory_data[0] != 0:
			ExportDir = self.base + self.export_directory_data[0]
			NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals = self.memory[ExportDir + 20:ExportDir + 40:4]

			function_addrs = self.memory[self.base + AddressOfFunctions:self.base + AddressOfFunctions + 4 * NumberOfFunctions:4]
			name_addrs = self.memory[self.base + AddressOfNames: self.base + AddressOfNames + 4 * NumberOfNames:4]
			name_ordinals = self.memory[self.base + AddressOfNameOrdinals: self.base + AddressOfNameOrdinals + 2 * NumberOfNames:2]

			functions = []
			for i, func_addr in enumerate(function_addrs):
				functions.append((i, None, self.base + func_addr))

			for i, name_addr in zip(name_ordinals, name_addrs):
				# If an export only has an ordinal, ignore it...
				# This means we might miss some exports, but some windows DLLs have 100s of junk ordinal-only exports
				function_addr = functions[i][2]
				exports.append(self.Export(i + 1, self.memory.cstr(self.base + name_addr), function_addr, self.base + AddressOfFunctions + 4 * i))

			exports.sort()
		return self.Exports(exports)

	class FunctionImport(NamedTuple):
		name_or_ordinal: Union[str, int]
		thunk: int

	class Imports(list):
		@property
		def by_name(self):
			return {m.name.lower(): m for m in self}
		def __getitem__(self, e):
			if isinstance(e, str):
				return self.by_name[e]
			else:
				return super().__getitem__(e)

	class ModuleImport:

		class ResolvedFunctionImport(NamedTuple):
			ordinal: int
			name: str
			by_ordinal: bool
			
			thunk: int
			resolved_address: int

		def __init__(self, name, unresolved):
			self.name = name
			self.unresolved = unresolved

		@cached_property
		def resolved(self):
			resolved_imports = []
			if self.name.lower() in modules:
				exports = modules[self.name.lower()].exports.by_name_and_ordinal
				for i, a in self.unresolved:
					exp = exports.get(i)
					resolved_imports.append(self.ResolvedFunctionImport(exp.ordinal, exp.name, i is int, a, exp.address))

			return resolved_imports

		@cached_property
		def by_name(self):
			return {i.name: i for i in self.resolved}
		@cached_property
		def by_ordinal(self):
			return {i.ordinal: i for i in self.resolved}
		@cached_property
		def by_name_and_ordinal(self):
			r = self.by_name
			r.update(self.by_ordinal)
			return r
		def __getitem__(self, e):
			if isinstance(e, str):
				return self.by_name[e]
			else:
				return self.resolved[e]

		def __str__(self):
			return f'ModuleImport({self.name!r}, <{len(self.unresolved)} functions>)'
		__repr__ = __str__

	@cached_property
	def imports(self):
		imports = []
		ImportDir = self.base + self.import_directory_data[0]
		current_import_descriptor = ImportDir
		for _ in range(self.import_directory_data[1] // 20):
			OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk = self.memory[current_import_descriptor:current_import_descriptor + 20:4]
			if not OriginalFirstThunk:
				break

			module_name = self.memory.cstr(self.base + Name)
			# print(f'{module_name.ljust(42)} OriginalFirstThunk=0x{self.base + OriginalFirstThunk:016x}, FirstThunk=0x{self.base + FirstThunk:016x}')

			functions = []
			for i in range(4096):
				original_thunk_rva = self.memory[self.base + OriginalFirstThunk + i * WORDSIZE::WORDSIZE]
				func_ptr_addr = self.base + FirstThunk + i * WORDSIZE
				if not original_thunk_rva:
					break

				if original_thunk_rva & 1 << (WORDSIZE * 8 - 1):
					# ordinal
					func_name_ord = original_thunk_rva & 0xffff
				else:
					func_name_ord = self.memory.cstr(self.base + original_thunk_rva + 2)

				functions.append(self.FunctionImport(func_name_ord, func_ptr_addr))

			imports.append(self.ModuleImport(module_name, functions))

			current_import_descriptor += 20
		return self.Imports(imports)

	@property
	def base(self):
		return self.lpBaseOfDll or self.hModule
	
	def __str__(self):
		return f'Module(name={self.name!r}, path={self.path!r}, <{len(self.imports)} imports>, <{len(self.exports)})'
	__repr__ = __str__


class Modules(dict):

	def __init__(self, handle):
		self.handle = handle
		super().__init__(self._load_modules())

	def _load_modules(self):
		r = {}
		hMods = (ctypes.c_void_p * 1024)()
		cbNeeded = ctypes.c_ulong()
		if not EnumProcessModules(self.handle, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
			raise ValueError(f'EnumProcessModules failed. Error=0x{ctypes.windll.kernel32.GetLastError():x}')
		for m in hMods[:cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)]:
			mod = Module(m, self.handle)
			r[mod.name] = mod
		return r

	def reload(self):
		r = self._load_modules()
		for k in self:
			if k not in r:
				del self[k]
		for k, v in r.items():
			self[k] = v


class Patch:

	def __init__(self, address, process_handle=None):
		self.address = address
		if not process_handle:
			process_handle = handle
		self.process_handle = process_handle
		self.bytecode = b''

	def __enter__(self):
		return self

	def set_args(self, args):
		if WORDSIZE == 4:
			# push args in reverse order
			for a in args[::-1]:
				self.bytecode += b'\x68' + struct.pack('<I', a)
		else:
			assert len(args) <= 4
			for a, rcode in zip(args, (b'\x48\xb9', b'\x48\xba', b'\x49\xb8', b'\x49\xb9')):
				if isinstance(a, int):
					self.bytecode += rcode + struct.pack('<Q', a)
				else:
					raise ValueError(f"Don't know how to set arg {a!r}")

	def call_indirect(self, funcptr, *args, cleanup_in_32bit=True):
		self.set_args(args)
		if WORDSIZE == 4:
			self.bytecode += b'\xff\x15' + struct.pack('<I', funcptr)  # call [&funcptr]
			if cleanup_in_32bit and len(args):
				self.bytecode += b'\x83\xc4' + struct.pack('<B', len(args) * 4)  # add esp
		else:
			self.bytecode += b'\x48\x83\xec\x20'  # sub rsp, 32; shadow space
			self.bytecode += b'\xff\x15' + struct.pack('<i', funcptr - (self.cursor + 6))  # call [&funptr] (RIP relative)
			self.bytecode += b'\x48\x83\xc4\x20'  # add rsp, 32 ; shadow space

	def call_regrelative(self, register, offset, *args, cleanup_in_32bit=True):
		self.set_args(args)

		if register[1:] == 'ax':
			call_reg = b'\xff\xd0'
			add_reg = b'\x05'
		else:
			raise ValueError(f"Don't know how to call {register!r}")
		if WORDSIZE == 4:
			if cleanup_in_32bit and len(args):
				call_reg += b'\x83\xc4' + struct.pack('<B', len(args) * 4)  # add esp
		else:
			call_reg = (
				b'\x48\x83\xec\x20' + # sub rsp, 32; shadow space
				call_reg + 
				b'\x48\x83\xc4\x20'   # add rsp, 32 ; shadow space
			)
			add_reg = REX1 + add_reg
		self.bytecode += add_reg + struct.pack('<I', offset)
		self.bytecode += call_reg

	def call(self, funcaddr, *args, cleanup_in_32bit=True):
		self.set_args(args)
		if WORDSIZE == 4:
			# call funcaddr (relative) 
			self.bytecode += b'\xe8' + struct.pack('<i', funcaddr - (self.cursor + 5))

			# unwind stack
			if cleanup_in_32bit and len(args):
				self.bytecode += b'\x83\xc4' + struct.pack('<B', len(args) * 4)  # add esp
		else:
			self.bytecode += b'\x48\xb8' + struct.pack('<Q', funcaddr)  # mov rax, funcaddr
			self.bytecode += b'\x48\x83\xec\x20'  # sub rsp, 32; shadow space
			self.bytecode += b'\xff\xd0'  # call rax
			self.bytecode += b'\x48\x83\xc4\x20'   # add rsp, 32 ; shadow space

	PREFIX = {
		'*': REX1,
		'r': b'\x48',
		'e': b'',
	}
	def asm(bytecode):
		if isinstance(bytecode, bytes):
			def func(self):
				self.bytecode += bytecode
		else:
			def func(self, a):
				aa = '?' + a[1:]
				if aa in bytecode:
					a = aa
				self.bytecode += bytecode[a]
		return func
	def jmp(self, rel):
		self.bytecode += b'\xeb' + struct.pack('b', rel)
	def jne(self, rel):
		self.bytecode += b'\x75' + struct.pack('b', rel)
	def add(self, a1, a2):
		if a1 == 'esp':
			self.bytecode += b'\x83\xc4' + struct.pack('b', a2)
		else:
			raise ValueError(f'Unknown asm "add {a1}, {a2}"')
	def sub(self, a1, a2):
		if a1[1:] == 'sp':
			self.bytecode += self.PREFIX[a1[0]] + b'\x83\xec' + struct.pack('B', a2)
		else:
			raise ValueError(f'Unknown asm "sub {a1}, {a2}"')
	push = asm({
		'?ax': b'\x50',
		'?sp': b'\x54',
		'?bp': b'\x55',
		'?cx': b'\x51',
	})
	pop = asm({
		'?bp': b'\x5d',
	})
	MOV = {
		('bx', 'ax'): b'\x8b\xd8',
		('cx', 'sp'): b'\x8b\xcc',
		('bp', 'sp'): b'\x8b\xec',
		('sp', 'bp'): b'\x8b\xe5',
		('cx', 'bp'): b'\x8b\xcd',

		('r12', 'rax'): b'\x4c\x8b\xe0',
		('r13', 'rax'): b'\x4c\x8b\xe8',
		('r14', 'rax'): b'\x4c\x8b\xf0',
		('rdx', 'r13'): b'\x49\x8B\xD5',
		('rdx', 'r14'): b'\x49\x8B\xD6',
		('rcx', 'r14'): b'\x49\x8B\xCE',
		('rcx', 'r13'): b'\x49\x8B\xCD',
		('rcx', 'r12'): b'\x49\x8B\xCC',
	}
	def mov(self, a1, a2):
		if a1[1:] == 'ax':
			if a1[0] == '*':
				size = WORDPACK
			elif a1[0] == 'r':
				size = 'Q'
			else:
				size = 'I'
			try:
				self.bytecode += self.PREFIX[a1[0]] + b'\xb8' + struct.pack('<' + size, int(a2))
				return
			except:
				pass
		sk = a1[1:], a2[1:]
		if a1[0] == '[' and a1[2:4] == 'bp' and a2[1:] == 'ax' and a1[1] == a2[0]:
			# mov [?bp+?], ?ax
			ofs = int(a1[4:-1])
			pre = self.PREFIX[a1[1]]
			self.bytecode += pre + b'\x89\x45' + struct.pack('b', ofs)
		elif a2[0] == '[' and a2[2:4] == 'bp' and a1[1:] in ['ax', 'cx'] and a2[1] == a1[0]:
			# mov ?ax, [?bp+?] / mov ?cx, [?bp+?]
			ofs = int(a2[4:-1])
			pre = self.PREFIX[a2[1]]
			dst = b'\x45' if a1[1:] == 'ax' else b'\x4d'
			self.bytecode += pre + b'\x8b' + dst + struct.pack('b', ofs)
		elif sk in self.MOV and a1[0] == a2[0]:
			# support all of {*ax, eax, rax} by determining what prefix we need
			self.bytecode += self.PREFIX[a1[0]] + self.MOV[sk]
		else:
			self.bytecode += self.MOV[(a1, a2)]
	def pushad(self):
		if WORDSIZE == 4:
			self.bytecode += b'\x60'
		else:
			self.bytecode += b'PQRSTUVWAPAQARASATAUAVAW'
	def popad(self):
		if WORDSIZE == 4:
			self.bytecode += b'\x61'
		else:
			self.bytecode += b'A_A^A]A\x5cA[AZAYAX_^]\x5c[ZYX'
	def test(self, a1, a2):
		if a1 == a2 and a1[1:] == 'ax':
			self.bytecode += self.PREFIX[a1[0]] + b'\x85\xc0'
		else:
			raise ValueError(f'Unknown asm "test {a1}, {a2}"')
	pushfd = asm(b'\x9c')
	popfd = asm(b'\x9d')
	ret = asm(b'\xc3')
	int8 = asm(b'\xcc')

	@property
	def cursor(self):
		return self.address + len(self.bytecode)

	def __exit__(self, exc_type, exc_value, tb):
		old_permissions = ctypes.wintypes.DWORD()
		if not VirtualProtectEx(self.process_handle, self.address, len(self.bytecode), PAGE_EXECUTE_READWRITE, ctypes.byref(old_permissions)):
			raise ValueError('Error: VirtualProtectEx %04x' % ctypes.windll.kernel32.GetLastError())
		if self.process_handle == handle:
			ctypes.memmove(self.address, self.bytecode, len(self.bytecode))
		else:
			if not WriteProcessMemory(self.process_handle, self.address, self.bytecode, len(self.bytecode), None):
				raise ValueError('Error: WriteProcessMemory %d' % ctypes.windll.kernel32.GetLastError())
		if not VirtualProtectEx(self.process_handle, self.address, len(self.bytecode), old_permissions.value, ctypes.byref(old_permissions)):
			raise ValueError('Error: VirtualProtectEx %d' % ctypes.windll.kernel32.GetLastError())


class Registers:
	REGISTERS = ['eflags'] 
	if WORDSIZE == 8:
		REGISTERS += ['r15', 'r14', 'r13', 'r12', 'r11', 'r10', 'r9', 'r8']
	REGISTERS += ['edi', 'esi', 'ebp', 'esp', 'ebx', 'edx', 'ecx', 'eax']
	def __init__(self, buf, eip):
		for rname, rval in zip(self.REGISTERS, struct.unpack(
			'<' + WORDPACK * len(self.REGISTERS),
			buf,
		)):
			setattr(self, rname, rval)
		self.eip = eip
	def pack(self):
		vals = [
			getattr(self, rname) for rname in self.REGISTERS
		]
		return struct.pack(
			'<' + ''.join(WORDPACK if v >= 0 else WORDPACK.lower() for v in vals),
			*vals			
		)
	@classmethod
	def getsize(cls):
		return WORDSIZE * len(cls.REGISTERS)
	def __str__(self):
		return 'Registers(' + ', '.join(
			f'{rname}=0x{getattr(self, rname):08x}'
			for rname
			in reversed(self.REGISTERS)
		) + ')'
	__repr__ = __str__


class Arguments:
	def __init__(self, reg, argcount=None):
		self.reg = reg
		self.argcount = argcount

	def argaddr(self, i):
		if self.argcount is not None and i >= self.argcount:
			raise IndexError(f'Argument {i} is out of bounds for Arguments with argcount={self.argcount}')
		if WORDSIZE == 8 and i <= 3:
			return ['ecx', 'edx', 'r8', 'r9'][i]
		else:
			return self.reg.esp + (i + 1) * WORDSIZE

	def __getitem__(self, i):
		a = self.argaddr(i)
		if isinstance(a, str):
			return getattr(self.reg, a)
		else:
			return struct.unpack('<' + WORDPACK, memory[a:a + WORDSIZE])[0]

	def __setitem__(self, i, v):
		a = self.argaddr(i)
		if isinstance(a, str):
			setattr(self.reg, a, v)
		else:
			memory[a:a + WORDSIZE] = struct.pack('<' + WORDPACK, v)

	def __str__(self):
		if self.argcount is not None:
			return 'Arguments[' + ', '.join(hex(self[i]) for i in range(self.argcount)) + ']'
		else:
			return 'Arguments[...? ' + ', '.join(hex(self[i]) for i in range(4)) + ', ...?]'
	__repr__ = __str__


in_hooked_process = getattr(sys, 'in_hooked_process', False)
handle = GetCurrentProcess()
memory = Memory()
modules = Modules(handle)

_dontgc = []  # don't garbage collect otherwise dangling objects - they are needed in the hooks
_already_hooked = set()


def make_patch_to_py(patch, pyfunc):
	PyGILState_Ensure = modules[PYTHON_DLL].exports['PyGILState_Ensure'].address
	PyGILState_Release = modules[PYTHON_DLL].exports['PyGILState_Release'].address
	Py_DecRef = modules[PYTHON_DLL].exports['Py_DecRef'].address
	PyTuple_Pack = modules[PYTHON_DLL].exports['PyTuple_Pack'].address
	PyLong_FromVoidPtr = modules[PYTHON_DLL].exports['PyLong_FromVoidPtr'].address
	PyObject_CallObject = modules[PYTHON_DLL].exports['PyObject_CallObject'].address

	if WORDSIZE == 4:
		patch.call(PyGILState_Ensure)
		patch.push('eax')  # ret from PyGILState_Ensure

		# use ebp (holds esp's value after pushads) as the argument instead of hardcoded value...
		# this means we need to restore the stack after, instead of having patch.call do that since patch.call
		# thinks we arent using any args
		patch.push('ebp')
		patch.call(PyLong_FromVoidPtr)
		patch.add('esp', 4)

		# again, handle arguments "manually" since we need the result of the last call
		# dont clean up stack this time, we will use it later when decref'ing
		patch.push('eax')  # ret from PyLong_FromVoidPtr
		patch.call(PyTuple_Pack, 1)

		# as above
		patch.push('eax')  # ret from PyTuple_Pack
		patch.call(PyObject_CallObject, id(pyfunc))

		# save return val
		patch.mov('ebx', 'eax')

		# decref using the non-cleaned-up result from PyTuple_Pack, clean up "manually"
		patch.call(Py_DecRef)
		patch.add('esp', 4)
		
		# decref using the non-cleaned-up result from PyLong_FromVoidPtr, clean up "manually"
		patch.call(Py_DecRef)
		patch.add('esp', 4)

		# PyGILState_Ensure retval is already on stack, use it then clean it up
		patch.call(PyGILState_Release)
		patch.add('esp', 4)

	else:
		# r12 = PyGILState_Ensure()
		patch.call(PyGILState_Ensure)
		patch.mov('r12', 'rax')

		# r13 = PyLong_FromVoidPtr(rbp)  - rbp holds esp's value after pushads
		patch.mov('rcx', 'rbp')
		patch.call(PyLong_FromVoidPtr)
		patch.mov('r13', 'rax')

		# r14 = PyTuple_Pack(1, r13)
		patch.mov('rdx', 'r13')  # 2nd arg (rdx) = r13 from created pylong
		patch.call(PyTuple_Pack, 1)
		patch.mov('r14', 'rax')

		# rbx = PyObject_CallObject(pyfunc, r14)
		patch.mov('rdx', 'r14')  # 2nd arg (rdx) = r14 from created pytuple
		patch.call(PyObject_CallObject, id(pyfunc))
		patch.mov('rbx', 'rax')

		# Py_DecRef(r14)
		patch.mov('rcx', 'r14')
		patch.call(Py_DecRef)

		# Py_DecRef(r13)
		patch.mov('rcx', 'r13')
		patch.call(Py_DecRef)

		# PyGILState_Release(r12)
		patch.mov('rcx', 'r12')
		patch.call(PyGILState_Release)


def make_landing(func, addr, addr_desc, landing_exit_address, return_pop=0, func_prologue=b''):
	if WORDSIZE == 4:
		landing_address = VirtualAlloc(None, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)
	else:
		# in 64bit we need memory nearby to allow reljmping to work
		granularity = 0x100000
		maxdist = 0x80000000  # max jump is 0x80000000
		start = max(addr - maxdist, 0)
		start -= start % granularity
		end = min(addr + maxdist, 2**64 - 1)
		end -= end % granularity
		# start from almost maxdist above address, to somewhat minimize retries
		for a in range(end - granularity, start + granularity, -granularity):
			print(f'   ~ Trying to allocate at 0x{a:016x}')
			landing_address = VirtualAlloc(a, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)
			if landing_address:
				break
		else:
			raise ValueError(f'Failed to allocate memory near 0x{addr:x}')

	print(f'  - Created landing at 0x{landing_address:08x}')

	def func_wrapper(esp):
		try:
			# load registers object from pushad'd registers
			stackdata = memory[esp:esp + Registers.getsize()]
			registers = Registers(stackdata[:Registers.getsize()], addr)
			pushed_sp = registers.esp
			registers.esp = esp + Registers.getsize()  # actual esp at time of hook is before push of registers

			# ret_from_func = struct.unpack('<' + WORDPACK, stackdata[Registers.getsize() + WORDSIZE:])[0]

			force_return = False
			rval = func(registers)
			if rval is not False and rval is not None:
				if not isinstance(rval, int):
					raise ValueError(f'Invalid return type/value for c function: {type(rval)} {rval}')
				force_return = True
				registers.eax = rval

			# we can't actually modify esp (yet?) because it would break the popping of the next registers
			registers.esp = pushed_sp
			memory[esp:esp + Registers.getsize()] = registers.pack()
		except Exception as e:
			print(f'[!] Got exception running hook {func} for {addr_desc} (0x{addr:08x}): {e}')
			traceback.print_exc()
			print(f'[!] Hooked code will be run now with no register writeback')
			force_return = False

		# If the function returns an int, then return immediatly from where we are in asm (hopefully just called a function),
		# using this as the return value. See the conditional in the generated landing code
		# Let's hope the user set return_pop correctly for the calling convention...
		return force_return
	_dontgc.append(func_wrapper)

	print(f'  - Writing function hook landing bytecode to run {func} (0x{id(func):x})')
	with Patch(landing_address) as patch:
		# save regs
		patch.pushad()
		patch.pushfd()

		# ensure stack is 16byte aligned - store original sp in bp so make_patch_to_py can see pushad'd regs
		patch.mov('*bp', '*sp')
		if WORDSIZE == 8:
			patch.bytecode += b'\x48\x83\xE4\xF0'  # and rsp, -16

		make_patch_to_py(patch, func_wrapper)

		# If func_wrapper returned True (compare to _Py_TrueStruct aka id(True)), restore registers but then ret immediatly
		patch.bytecode += REX1 + b'\xb8' + struct.pack('<' + WORDPACK, id(True))  # mov *ax, _Py_TrueStruct
		patch.bytecode += REX1 + b'\x3b\xc3'  # cmp *ax, *bx
		if return_pop and WORDSIZE == 4:
			patch.jne(5)
			patch.popfd()
			patch.popad()
			patch.bytecode += b'\xc2' + struct.pack('<H', return_pop)
		else:
			patch.jne(26 if WORDSIZE == 8 else 3)
			patch.popfd()
			patch.popad()
			patch.ret()

		# Otherwise restore registers then run original function
		patch.popfd()
		patch.popad()

		# record where the original (lifted) code starts on the function
		func.original_code_start = patch.cursor

		# run prologue that got overwritten
		patch.bytecode += func_prologue

		# jmp landing_exit_address
		patch.bytecode += b'\xe9' + struct.pack('<i', landing_exit_address - (patch.cursor + 5))

		patch.int8()

	return landing_address


def resolve_addr(address_desc):
	if isinstance(address_desc, int):
		return address_desc
	elif '+' in address_desc:
		module, offset = address_desc.split('+')
		if offset.startswith('0x'):
			offset = int(offset[2:], 16)
		else:
			offset = int(offset)
		return modules[module].lpBaseOfDll + offset
	else:
		raise ValueError('Don\'t know how to support address description %r' % address_desc)


def insert_hook(addr_desc, func, position_independent_bytes=None, return_pop=0):
	print(f' * Hooking {addr_desc} to run {func}')

	addr = resolve_addr(addr_desc)
	if addr in _already_hooked:
		raise ValueError(f'{addr_desc} is already hooked')

	print(f'  - Resolved {addr_desc} -> 0x{addr:08x}')

	func.hooked_code_start = addr

	if position_independent_bytes and position_independent_bytes >= 5:
		print(f'  - Using custom length of position independent bytes, lifting {position_independent_bytes} bytes from function head')
		func_prologue = bytes(PyMemoryView_FromMemory(addr, position_independent_bytes, PyBUF_READ))
	else:
		allowed_prologue_maxlen = max(len(p.split()) for p in ALLOWED_PROLOGUES)
		func_start_mem = bytes(PyMemoryView_FromMemory(addr - 5, 5 + allowed_prologue_maxlen, PyBUF_READ))
		func_prologue = func_start_mem[5:]
		print(f'  - Checking prologue: {binascii.hexlify(func_prologue).decode()}')
		
		for check_prologue in sorted(ALLOWED_PROLOGUES, key=lambda p: len(p), reverse=True):
			expected_pattern = [int(e, 16) if e != '??' else None for e in check_prologue.split()]
			if all(not e or b == e for (b, e) in zip(func_prologue, expected_pattern)):
				print(f'  - Matched prologue pattern {check_prologue}')
				func_prologue = func_prologue[:len(expected_pattern)]
				break
		else:
			raise ValueError('Function prologue did not match expected "PUSH EBP; MOV EBP, ESP"')

		if len(func_prologue) < 5:
			func_padding = func_start_mem[:5]
			print(f'  - Prologue less than 5 bytes - checking pre-function padding: {binascii.hexlify(func_padding).decode()}')
			if not all(b in ALLOWED_PADDING for b in func_padding):
				raise ValueError(f'Function pre-padding did not consist of 5 bytes of allowed padding')
		else:
			func_padding = b''

	landing_address = make_landing(func, addr, addr_desc, addr + len(func_prologue), return_pop=return_pop, func_prologue=func_prologue)

	if len(func_prologue) >= 5:
		print(f'  - Patching function with trampoline to func_wrapper landing - using {len(func_prologue)} liftable bytes')
		with Patch(addr) as patch:
			# call dword ptr[landing_ptr]
			patch.bytecode += b'\xe9' + struct.pack('<i', (landing_address - addr) - 5)  # subtract 5 because this is relative to *after* the jump

			for _ in range(len(func_prologue) - 5):
				patch.int8()
	else:
		print(f'  - Patching function with trampoline to func_wrapper landing - using function padding')
		with Patch(addr - 5) as patch:
			# call dword ptr[landing_ptr]
			patch.bytecode += b'\xe9' + struct.pack('<i', landing_address - addr)  # dont subtract 5, since we are jumping from 5 bytes earlier so this cancels the subtraction

			# function enters here:
			patch.jmp(-7)

			patch.int8()

	_already_hooked.add(addr)
	return func


def hook(addr_desc, position_independent_bytes=None, return_pop=0):
	def try_insert_hook(func):
		if not in_hooked_process:
			func.original_code_start = 0
			return func
		try:
			return insert_hook(addr_desc, func, position_independent_bytes=position_independent_bytes, return_pop=return_pop)
		except Exception as e:
			print(f' ! Failed to hook {addr_desc}')
			traceback.print_exc()
			return func

	return try_insert_hook


def insert_iat_hook(target_module, func_desc, func, return_pop=0, resolve_ordinal_imports=True):
	print(f' * Hooking {target_module}:{func_desc} to run {func}')

	target = modules[target_module.lower()]
	module_name, func_name_ord = func_desc.split('!')
	module_imports = target.imports[module_name]
	if resolve_ordinal_imports:
		iat_entry = module_imports.by_name_and_ordinal[func_name_ord]
	else:
		try:
			func_ord = int(func_name_ord)
		except ValueError:
			iat_entry = module_imports.by_name[func_name_ord]
		else:
			iat_entry = module_imports.by_ordinal[func_ord]

	print(f'  - Resolved {target_module}:{func_desc} -> thunk=0x{iat_entry.thunk:08x}')

	landing_address = make_landing(func, iat_entry.resolved_address, target_module + ':' + func_desc, iat_entry.resolved_address, return_pop=return_pop)

	print(f'  - Patching thunk to point to landing')
	old_permissions = ctypes.wintypes.DWORD()
	if not VirtualProtectEx(handle, iat_entry.thunk, WORDSIZE, PAGE_READWRITE, ctypes.byref(old_permissions)):
		raise ValueError('Error: VirtualProtectEx %04x' % ctypes.windll.kernel32.GetLastError())
	ctypes.memmove(iat_entry.thunk, ctypes.create_string_buffer(struct.pack('<' + WORDPACK, landing_address)), WORDSIZE)
	if not VirtualProtectEx(handle, iat_entry.thunk, WORDSIZE, old_permissions.value, ctypes.byref(old_permissions)):
		raise ValueError('Error: VirtualProtectEx %d' % ctypes.windll.kernel32.GetLastError())

	return func


def hook_iat(target_module, func_desc, return_pop=0, resolve_ordinal_imports=True):
	def try_insert_iat_hook(func):
		if not in_hooked_process:
			func.original_code_start = 0
			return func
		try:
			return insert_iat_hook(target_module, func_desc, func, return_pop=return_pop, resolve_ordinal_imports=resolve_ordinal_imports)
		except Exception as e:
			print(f' ! Failed to hook iat {target_module} {func_desc}')
			traceback.print_exc()
			return func

	return try_insert_iat_hook


def getpid(processname):
	pid = None
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	try:
		pe32 = PROCESSENTRY32()
		pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
		if not Process32First(hProcessSnap, ctypes.byref(pe32)):
			raise ValueError('Failed getting first process entry')
		while True:
			exe_file = pe32.szExeFile.decode()
			if exe_file.lower() == processname.lower() or exe_file.lower() + '.exe' == processname.lower():
				print(f'  - Found process {exe_file!r} with pid={pe32.th32ProcessID}')
				pid = int(pe32.th32ProcessID)
				break
			if not Process32Next(hProcessSnap, ctypes.byref(pe32)):
				break
	except:
		raise ValueError('Failed to enumerate/check processes')
	finally:
		CloseHandle(hProcessSnap)
	if not pid:
		raise ValueError(f"Can't find process matching {pid_or_processname}")

	return pid


def inject(pid_or_processname, module_or_filename=None, process_handle=None, alloc_console=False, wait_for_thread=False):
	if not process_handle:
		print(f' * Injecting into {pid_or_processname}')

	if isinstance(pid_or_processname, int):
		pid = pid_or_processname
	else:
		print(f'  - Looking for process')
		pid = getpid(pid_or_processname)

	process_is_suspended = process_handle is not None
	if not process_handle:
		process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		if not process_handle:
			raise ValueError(f'Failed to open process pid={pid}: Error=0x{ctypes.windll.kernel32.GetLastError():x}')
		print(f'  - Opened process 0x{process_handle:x}')

	is_target_wow64 = ctypes.wintypes.BOOL(False)
	IsWow64Process(process_handle, ctypes.byref(is_target_wow64))
	if WORDSIZE == 4 and not is_target_wow64.value:
		raise ValueError(f'Process is 64bit (IsWow64Process=False) but python executable used is 32bit - cannot inject')
	elif WORDSIZE == 8 and is_target_wow64.value:
		raise ValueError(f'Process is 32bit (IsWow64Process=True) but python executable used is 64bit - cannot inject')

	if not module_or_filename:
		module_or_filename = __file__
	if isinstance(module_or_filename, str):
		if module_or_filename in sys.modules:
			filename = sys.modules[module_or_filename].__file__
		filename = module_or_filename
	else:
		filename = module_or_filename.__file__

	print(f'  - Got file to run in process: {filename!r}')
	if not os.path.exists(filename):
		raise ValueError('Could not find file to inject')

	alloc_console_source = ''
	if alloc_console:
		alloc_console_source = '''
import sys
if not getattr(sys, 'alloced_console', False):
	print('[@] Stub allocating console')
	sys.alloced_console = True

	import ctypes

	kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
	kernel32.FreeConsole()
	kernel32.AllocConsole()
	kernel32.AttachConsole(kernel32.GetCurrentProcessId())

	sys.stdout = sys.stderr = open('con', 'w')

	print('[@] Stub allocated console')
else:
	print('[@] Stub not allocating console - process is already hooked with allocated console')
'''

	python_stub = f'''
print('[@] Python stub started')

{alloc_console_source}

import os
import runpy
import sys
import traceback

sys.in_hooked_process = True
sys.argv = [sys.executable]

os.chdir({repr(os.getcwd())})
for p in {repr(sys.path)}:
	if p not in sys.path:
		sys.path.append(p)

print('[@] Stub running', {repr(os.path.abspath(filename))})
try:
	runpy.run_path({repr(os.path.abspath(filename))}, run_name='__hooks__')
except:
	print('[@] Stub got exception running hooks')
	traceback.print_exc()
'''

	# n.b. if we need to enum the modules for a suspended process, we can just create and wait for a noop (ret only) remote thread as this will init the modules
	python_lib = None
	if not process_is_suspended:
		process_modules = Modules(process_handle)
		for mname, m in process_modules.items():
			if m.name == PYTHON_DLL:
				print(f'  - Process already has {mname} loaded - using existing module\'s path to prevent conflicts')
				python_lib = m.path
				break
			elif m.name.startswith('python') and m.name.endswith('.dll') and len(m.name) > len('python3.dll'):
				raise ValueError(f'Process already has {m.name} loaded, but we want to inject {PYTHON_DLL}')
	if not python_lib:
		print(f'  - Resolving {PYTHON_DLL}\'s path')
		python_lib = modules[PYTHON_DLL].path

	print(f'  - Need to inject {python_lib}')

	LoadLibraryA_addr = ctypes.cast(LoadLibraryA, ctypes.c_void_p).value
	print(f'   ~ Resolved LoadLibraryA to 0x{LoadLibraryA_addr:08x}')

	python_dll = modules[PYTHON_DLL]
	Py_IsInitialized = python_dll.exports['Py_IsInitialized'].address - python_dll.base
	Py_InitializeEx = python_dll.exports['Py_InitializeEx'].address - python_dll.base
	PyGILState_Ensure = python_dll.exports['PyGILState_Ensure'].address - python_dll.base
	PyRun_SimpleString = python_dll.exports['PyRun_SimpleString'].address - python_dll.base
	PyEval_SaveThread = python_dll.exports['PyEval_SaveThread'].address - python_dll.base
	PyGILState_Release = python_dll.exports['PyGILState_Release'].address - python_dll.base

	injection_stub = VirtualAllocEx(process_handle, None, len(python_stub) + 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	print(f'  - Created injection stub in remote process 0x{injection_stub:08x}')
	with Patch(injection_stub, process_handle) as patch:
		python_lib_str_address = patch.cursor
		patch.bytecode += python_lib.encode('utf-8') + b'\x00'

		python_stub_address = patch.cursor
		patch.bytecode += python_stub.encode('utf-8') + b'\x00'

		LoadLibraryA_addr_ptr = patch.cursor
		patch.bytecode += struct.pack('<' + WORDPACK, LoadLibraryA_addr)

		# NOPs before code start to make dissasembly easy to read
		# Otherwise the python_lib string is hard to separate out and can mangle actual instructions
		patch.bytecode += b'\xcc' * 8

		injection_stub_entry = patch.cursor

		patch.push('*bp')
		patch.mov('*bp', '*sp')

		# variables: handle, is_initialized, state
		patch.sub('*sp', 32)
		handle = '[*bp-8]'
		is_initialized = '[*bp-16]'
		state =  '[*bp-24]'

		# align stack
		if WORDSIZE == 8:
			patch.bytecode += b'\x48\x83\xE4\xF0'  # and rsp, -16

		# handle = LoadLibraryA(python_lib)
		patch.call_indirect(LoadLibraryA_addr_ptr, python_lib_str_address, cleanup_in_32bit=False)
		patch.mov(handle, '*ax')

		# is_initialized = Py_IsInitialized()
		patch.call_regrelative('*ax', Py_IsInitialized)
		patch.mov(is_initialized, '*ax')

		# if is_initialized == 0:
		patch.test('eax', 'eax')
		if WORDSIZE == 4:
			patch.jne(0x14)
		else:
			patch.jne(0x20)

		# Py_InitializeEx(0)
		patch.mov('*ax', handle)
		patch.call_regrelative('*ax', Py_InitializeEx, 0)

		# else:
		if WORDSIZE == 4:
			patch.jmp(0x0d)
		else:
			patch.jmp(0x18)

		# state = PyGILState_Ensure()
		patch.mov('*ax', handle)
		patch.call_regrelative('*ax', PyGILState_Ensure)
		patch.mov(state, '*ax')

		# endif

		# PyRun_SimpleString(python_stub)
		patch.mov('*ax', handle)
		patch.call_regrelative('*ax', PyRun_SimpleString, python_stub_address)

		# if is_initialized == 0:
		patch.mov('*ax', is_initialized)  # is_initialized
		patch.test('eax', 'eax')
		if WORDSIZE == 4:
			patch.jne(0x0c)
		else:
			patch.jne(0x16)

		# PyEval_SaveThread()
		patch.mov('*ax', handle)
		patch.call_regrelative('*ax', PyEval_SaveThread)

		# else:
		if WORDSIZE == 4:
			patch.jmp(0x11)
		else:
			patch.jmp(0x18)

		# PyGILState_Release(state)
		patch.mov('*cx', state)
		patch.mov('*ax', handle)
		# handle args manually: if x64 state is already in rcx, otherwise push it
		if WORDSIZE == 4:
			patch.push('ecx')
		patch.call_regrelative('*ax', PyGILState_Release)
		if WORDSIZE == 4:
			patch.add('esp', 4)
 
		# endif

		# restore stack pointer
		patch.mov('*sp', '*bp')
		patch.pop('*bp')

		# return 1
		patch.mov('eax', 1)
		patch.ret()

		patch.int8()

	print(f'   ~ Calling CreateRemoteThread (function=0x{injection_stub_entry:08x})')
	remote_thread = CreateRemoteThread(process_handle, None, 0, injection_stub_entry, None, 0, None)
	assert remote_thread
	print(f'   ~ Created remote thread 0x{remote_thread:x}')
	if wait_for_thread:
		print(f'   ~ Waiting for thread')
		WaitForSingleObject(remote_thread, 0xffffffff)
		exitcode = ctypes.wintypes.DWORD(0)
		assert GetExitCodeThread(remote_thread, ctypes.byref(exitcode))
		print(f'   ~ Got thread exit code 0x{exitcode.value:08x}')

	CloseHandle(process_handle)


def launch(cmdline, file_to_inject, alloc_console=False):
	print(f' * Starting and injecting into {cmdline!r}')
	if isinstance(cmdline, list):
		cmdline = ' '.join(cmdline)

	print(f'  - Creating process in SUSPENDED state')
	creation_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE
	startupinfo = STARTUPINFO()
	startupinfo.cb = ctypes.sizeof(startupinfo)
	processinfo = PROCESS_INFORMATION()
	p = CreateProcessW(None, cmdline, None, None, False, creation_flags, None, None, ctypes.byref(startupinfo), ctypes.byref(processinfo))
	if not p:
		raise ValueError(f'CreateProcessW failed. Error=0x{ctypes.windll.kernel32.GetLastError():x}')

	print(f'  - Process created with pid={processinfo.dwProcessId}, handle=0x{processinfo.hProcess:x}')

	inject(processinfo.dwProcessId, file_to_inject, process_handle=processinfo.hProcess, alloc_console=alloc_console, wait_for_thread=True)

	print(f'  - Resuming main thread')
	ResumeThread(processinfo.hThread)

	CloseHandle(processinfo.hThread)
	CloseHandle(processinfo.hProcess)
