from __future__ import annotations

from ast import Not
import ctypes
import ctypes.wintypes
import logging
import os
from dataclasses import dataclass
from functools import cached_property

from pydetours.ctypedefs import (
    MODULEINFO,
    WORDSIZE,
    EnumProcessModules,
    GetCurrentProcess,
    GetModuleFileNameA,
    GetModuleFileNameExA,
    GetModuleInformation,
)
from pydetours.memory import Memory, memory

logger = logging.getLogger(__name__)


@dataclass
class FunctionImport:
    """
    Represents an element in a module's import table (name/ordinal only).
    See ResolvedFunctionImport for resolving to an actual function in memory.
    """

    name_or_ordinal: str | int
    thunk: int
    addr: int

    def __str__(self) -> str:
        return f"FunctionImport(name_or_ordinal={self.name_or_ordinal!r}, thunk={self.thunk:#x}, addr={self.addr:#x})"

    __repr__ = __str__


class ModuleImport:
    """
    Represents a module that is imported/referenced by a module.
    This class stores the name of the imported module and the list of functions imported from that module.
    """

    def __init__(
        self,
        name: str,
        unresolved: list[FunctionImport],
        imported_by: Module,
        handle: int | None = None,
    ):
        self.name = name
        self.unresolved = unresolved
        self.imported_by = imported_by
        self.memory = memory if not handle else Memory(handle)

    @cached_property
    def resolved(self) -> list[ResolvedFunctionImport]:
        """
        Resolve all  imports in the import table for this module to actual functions in memory.
        """
        resolved_imports = list[ResolvedFunctionImport]()
        if self.name.lower() in modules:
            exports = modules[self.name.lower()].exports.by_name_and_ordinal
            for func in self.unresolved:
                exp = exports.get(func.name_or_ordinal)
                if not exp:
                    # TODO: if we fix ordinal resolution this is worth warning over
                    if isinstance(func.name_or_ordinal, str):
                        logf = logger.warning
                    else:
                        logf = logger.debug
                    logf(
                        f" {self.imported_by.name} imports {self.name}!{func.name_or_ordinal} (thunk=0x{func.thunk:08x}), but {self.name} has no matching export"
                    )
                    continue
                new_resolved_address = self.memory.native_word(func.thunk)
                # if exp.address != new_resolved_address:
                #     logger.debug(
                #         f" > {self.name}!{exp.name} (thunk=0x{func.thunk:08x}) has changed resolved address: expected 0x{exp.address:08x} but got 0x{new_resolved_address:08x}"
                #     )
                resolved_imports.append(
                    ResolvedFunctionImport(
                        ordinal=exp.ordinal,
                        name=exp.name,
                        by_ordinal=func.name_or_ordinal is int,
                        thunk=func.thunk,
                        original_address=exp.address,
                        resolved_address=new_resolved_address,
                        from_module_imports=self,
                        baddr=func.addr,
                    )
                )

        return resolved_imports

    @cached_property
    def by_name(self) -> dict[str, ResolvedFunctionImport]:
        return {i.name: i for i in self.resolved}

    @cached_property
    def by_ordinal(self) -> dict[int, ResolvedFunctionImport]:
        return {i.ordinal: i for i in self.resolved}

    @cached_property
    def by_name_and_ordinal(self) -> dict[int | str, ResolvedFunctionImport]:
        return self.by_name | self.by_ordinal

    def __getitem__(self, e: int | str) -> ResolvedFunctionImport:
        if isinstance(e, str):
            return self.by_name[e]
        else:
            return self.resolved[e]

    def __str__(self):
        return f"ModuleImport({self.name!r}, <{len(self.unresolved)} functions>)"

    __repr__ = __str__


class ModuleImports(list[ModuleImport]):
    @property
    def by_name(self):
        return {m.name.lower(): m for m in self}

    def __getitem__(self, e: int | str) -> ModuleImport:
        if isinstance(e, str):
            return self.by_name[e.lower()]
        else:
            return super().__getitem__(e)


@dataclass
class ResolvedFunctionImport:
    ordinal: int
    name: str
    by_ordinal: bool

    thunk: int
    original_address: int
    resolved_address: int

    from_module_imports: ModuleImport

    baddr: int

    def __str__(self) -> str:
        return f"ResolvedFunctionImport(ordinal={self.ordinal}, name={self.name!r}, by_ordinal={self.by_ordinal}, thunk={self.thunk:#x}, original_address={self.original_address:#x}, resolved_address={self.resolved_address:#x})"

    __repr__ = __str__


@dataclass
class ModuleExport:
    """
    Represents an exported function in a module.
    """

    ordinal: int
    name: str
    address: int

    address_ptr: int

    module: Module

    def __str__(self) -> str:
        return f"Export(ordinal={self.ordinal}, name={self.name!r}, address={self.address:#x}, address_ptr={self.address_ptr:#x})"

    __repr__ = __str__

    def __lt__(self, other: ModuleExport) -> bool:
        return self.astuple() < other.astuple()

    def astuple(self) -> tuple[int, str, int, int]:
        return (self.ordinal, self.name, self.address, self.address_ptr)


class ModuleExports(list[ModuleExport]):
    @cached_property
    def by_name(self) -> dict[str, ModuleExport]:
        return {e.name: e for e in self}

    @cached_property
    def by_ordinal(self) -> dict[int, ModuleExport]:
        return {e.ordinal: e for e in self}

    @cached_property
    def by_name_and_ordinal(self) -> dict[int | str, ModuleExport]:
        return self.by_name | self.by_ordinal

    def __getitem__(self, e: str | int) -> ModuleExport:
        if isinstance(e, str):
            return self.by_name[e]
        else:
            return super().__getitem__(e)


class Module:
    """
    Represents a loaded module i.e. PE32 in a local or remote process.
    Imports and exports are also parsed (lazily).
    """

    def __init__(
        self,
        module_handle: int,
        process_handle: int | None = None,
    ):
        """
        Constructs a new Module object from the given module handle in the given process (or the current process if None).
        """
        self.module_handle = module_handle
        self.process_handle = process_handle or own_process_handle
        self.memory = memory if not process_handle else Memory(self.process_handle)

        cPath = ctypes.create_string_buffer(1024)
        self.name_parsed = False
        if process_handle and process_handle != own_process_handle:
            # Read from remote process
            if GetModuleFileNameExA(
                process_handle, self.module_handle, cPath, ctypes.c_ulong(1024)
            ):
                self.name_parsed = True
            else:
                logger.warning(
                    f"GetModuleFileNameExA(..., {self.module_handle:#x}, ...) got {ctypes.windll.kernel32.GetLastError():#x} : {ctypes.FormatError()}"
                )
        else:
            if GetModuleFileNameA(self.module_handle, cPath, ctypes.c_ulong(1024)):
                self.name_parsed = True
            else:
                logger.warning(
                    f"GetModuleFileNameA(..., {self.module_handle:#x}, ...) got {ctypes.windll.kernel32.GetLastError():#x} : {ctypes.FormatError()}"
                )
        if self.name_parsed:
            self.path = cPath.value.decode()
            self.name = str(os.path.basename(self.path.lower()))
        else:
            self.path = "<unknown path>"
            self.name = f"<unnamed module {module_handle:#x}>"

        self.lpBaseOfDll: int | None = None
        self.SizeOfImage = self.EntryPoint = None
        self.export_directory_data: tuple[int, int] | None = None
        self.import_directory_data: tuple[int, int] | None = None

        self.parsed = False

        module_info = MODULEINFO()
        res = GetModuleInformation(
            self.process_handle,
            self.module_handle,
            ctypes.byref(module_info),
            ctypes.sizeof(module_info),
        )
        if res:
            self.lpBaseOfDll = module_info.lpBaseOfDll
            self.SizeOfImage = module_info.SizeOfImage
            self.EntryPoint = module_info.EntryPoint
        else:
            # print(self.process_handle)
            # if self.process_handle == own_process_handle:
            # 	print(f'GetModuleInformation(..., {self.module_handle}, ...) got {ctypes.windll.kernel32.GetLastError():#x}: {ctypes.FormatError()} - using lpBaseOfDll = module_handle for local process')
            # 	self.lpBaseOfDll = self.module_handle
            # else:
            logger.warning(
                f"GetModuleInformation(..., {self.module_handle}, ...) got {ctypes.windll.kernel32.GetLastError():#x}: {ctypes.FormatError()} - cannot infer lpBaseOfDll"
            )

        if self.module_handle:
            DosHeader = int(self.module_handle)
            MZSignature = self.memory.read(DosHeader, 2)
            # print(MZSignature)
            if MZSignature != b"\x4d\x5a":
                logger.warning(
                    f"{self.name} ({self.module_handle:#x}) is not a PE32 module - unable to parse: MZSignature={MZSignature.hex()}"
                )
                return

            AddressOfNewExeHeader = DosHeader + 60

            # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
            # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
            NtHeader = DosHeader + self.memory.uint32(AddressOfNewExeHeader)
            Signature = self.memory.read(NtHeader, 4)
            assert Signature == b"\x50\x45\x00\x00"

            # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
            # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
            OptionalHeader = NtHeader + 24
            Magic = self.memory.read(OptionalHeader, 2)
            if Magic == b"\x0b\x01":
                if WORDSIZE != 4:
                    raise ValueError(
                        "OptionalHeader magic specifies module as 32bit, but we are a 64bit process"
                    )
                DataDirectory = OptionalHeader + 96
            elif Magic == b"\x0b\x02":
                if WORDSIZE != 8:
                    raise ValueError(
                        "OptionalHeader magic specifies module as 64bit, but we are a 32bit process"
                    )
                DataDirectory = OptionalHeader + 112
            else:
                raise ValueError(f"OptionalHeader magic mismatch: got {Magic.hex()}")

            self.export_directory_data = self.memory.read_array(DataDirectory, 2, 4)
            self.import_directory_data = self.memory.read_array(DataDirectory + 8, 2, 4)
            self.parsed = True

    @cached_property
    def exports(self) -> ModuleExports:
        """
        Read (and cache) the exports of this module using the IMAGE_EXPORT_DIRECTORY structure.
        """
        exports = list[ModuleExport]()
        # Some modules might fail GetModuleInformation, so have export_directory_data=None, some modules (e.g. exes) might have no exports (export_directory_data.VirtualAddress = 0)
        if self.export_directory_data and self.export_directory_data[0] != 0:
            ExportDir = self.base + self.export_directory_data[0]
            try:
                (
                    NumberOfFunctions,
                    NumberOfNames,
                    AddressOfFunctions,
                    AddressOfNames,
                    AddressOfNameOrdinals,
                ) = self.memory[ExportDir + 20 : ExportDir + 40 : 4]
            except:
                logger.warning(f"Failed to read export directory for {self.name}")
                return ModuleExports()

            function_addrs = self.memory.read_array(
                self.base + AddressOfFunctions, NumberOfFunctions, 4
            )
            name_addrs = self.memory.read_array(self.base + AddressOfNames, NumberOfNames, 4)
            name_ordinals = self.memory.read_array(
                self.base + AddressOfNameOrdinals, NumberOfNames, 2
            )

            # function_addrs, name_addrs, name_ordinals are RVA to self.base

            for i, name_addr in zip(name_ordinals, name_addrs):
                # If an export only has an ordinal, ignore it...
                # This means we might miss some exports, but some windows DLLs have 100s of junk ordinal-only exports
                exports.append(
                    ModuleExport(
                        i + 1,  # FIXME: this doesn't seem right?
                        self.memory.cstr(self.base + name_addr),
                        self.base + function_addrs[i],
                        self.base + AddressOfFunctions + 4 * i,
                        self,
                    )
                )

            exports.sort()
        return ModuleExports(exports)

    @cached_property
    def imports(self) -> ModuleImports:
        """
        Read (and cache) the import table of this module.
        """
        imports = list[ModuleImport]()
        if self.import_directory_data:
            ImportDir = self.base + self.import_directory_data[0]
            current_import_descriptor = ImportDir
            for i in range(self.import_directory_data[1] // 20):
                try:
                    OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk = (
                        self.memory[current_import_descriptor : current_import_descriptor + 20 : 4]
                    )
                except:
                    # FIXME: what is happening here?
                    logger.error(f"Failed to data for {self.name}'s imports: {i=}")
                    continue
                if not OriginalFirstThunk:
                    break

                # logger.info(f'Reading {self.name}\'s imports: {i=} : {OriginalFirstThunk=:#x}, {self.base=:#x} {Name=:#x} {FirstThunk=:#x}')
                try:
                    module_name = self.memory.cstr(self.base + Name)
                except:
                    # FIXME: what is happening here?
                    logger.error(
                        f"Failed to read module name for {self.name}'s imports: {i=} : {OriginalFirstThunk=:#x}, {self.base=:#x} {Name=:#x} {FirstThunk=:#x}"
                    )
                    continue
                # logger.info(f'{module_name.ljust(42)} OriginalFirstThunk=0x{self.base + OriginalFirstThunk:016x}, FirstThunk=0x{self.base + FirstThunk:016x}')

                functions = list[FunctionImport]()
                for i in range(4096):
                    original_thunk_rva = self.memory.native_word(
                        self.base + OriginalFirstThunk + i * WORDSIZE
                    )
                    func_ptr_addr = self.base + FirstThunk + i * WORDSIZE
                    if not original_thunk_rva:
                        break

                    func_name_ord: int | str
                    if original_thunk_rva & 1 << (WORDSIZE * 8 - 1):
                        # ordinal
                        func_name_ord = original_thunk_rva & 0xFFFF
                    else:
                        func_name_ord = self.memory.cstr(self.base + original_thunk_rva + 2)

                    functions.append(
                        FunctionImport(func_name_ord, func_ptr_addr, self.base + original_thunk_rva)
                    )

                imports.append(
                    ModuleImport(
                        module_name, functions, imported_by=self, handle=self.process_handle
                    )
                )

                current_import_descriptor += 20
        return ModuleImports(imports)

    @property
    def base(self) -> int:
        return self.lpBaseOfDll or int(self.module_handle)

    def __str__(self) -> str:
        if self.name_parsed:
            name = f"name={self.name!r}, "
        else:
            name = ""
        if self.parsed:
            return f"Module({name}base={self.base:#x}, path={self.path!r}, <{len(self.imports)} imports>, <{len(self.exports)} exports>)"
        else:
            return f"Module({name}base={self.base:#x}, <invalid parse>)"

    __repr__ = __str__


class Modules(dict[str, Module]):
    def __init__(self, handle: int) -> None:
        self.handle = handle
        super().__init__(self._load_modules())

    def _load_modules(self) -> dict[str, Module]:
        r = dict[str, Module]()
        hMods = (ctypes.c_void_p * 1024)()
        cbNeeded = ctypes.c_ulong()
        if not EnumProcessModules(self.handle, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
            raise ValueError(
                f"EnumProcessModules failed. Error=0x{ctypes.windll.kernel32.GetLastError():x}"
            )
        for m in hMods[: cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)]:
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


own_process_handle = GetCurrentProcess()

modules = Modules(own_process_handle)


class FindPattern:
    def __init__(self, module_name: str, pattern: str):
        self.module_name: str = module_name
        self.pattern: str = pattern

    def find(self) -> int:
        raise NotImplementedError()


def resolve_addr(address_desc: ModuleExport | FindPattern | int | str) -> int:
    if isinstance(address_desc, ModuleExport):
        return address_desc.address
    elif isinstance(address_desc, int):
        return address_desc
    elif isinstance(address_desc, FindPattern):
        return address_desc.find()
    elif "+" in address_desc:
        module, offset_s = address_desc.split("+")
        if offset_s.startswith("0x"):
            offset = int(offset_s[2:], 16)
        else:
            offset = int(offset_s)
        base = modules[module].lpBaseOfDll
        assert base is not None
        return base + offset
    else:
        raise ValueError("Don't know how to support address description %r" % address_desc)


__all__ = [
    "FunctionImport",
    "ResolvedFunctionImport",
    "ModuleImport",
    "ModuleImports",
    "ModuleExport",
    "ModuleExports",
    "Module",
    "Modules",
    "modules",
    "own_process_handle",
    "resolve_addr",
]
