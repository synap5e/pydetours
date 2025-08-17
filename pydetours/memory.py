import ctypes
import ctypes.wintypes
import logging
import struct
import typing
import warnings

from pydetours.ctypedefs import (
    PAGE_EXECUTE_READWRITE,
    WORDSIZE,
    GetCurrentProcess,
    ReadProcessMemory,
    VirtualProtectEx,
)

own_process_handle = GetCurrentProcess()
logger = logging.getLogger("pydetours.memory")
StructFmt = typing.Literal["Q", "I", "H", "q", "i", "h", "B", "b"]
ITEM_SIZE_TO_STRUCT_FMT = {1: "B", 2: "H", 4: "I", 8: "Q"}


class Memory:
    """
    Represents the memory space of a process.
    """

    def __init__(self, process_handle: int | None = None) -> None:
        """
        Creates a new Memory object.
        :param process_handle: The process handle to use. If None, the current process is used.
        """
        self.process_handle = process_handle

    def read(self, addr: int, length: int) -> bytes:
        """
        Reads data from the process memory.
        """
        if not self.process_handle:
            buf = (ctypes.c_uint8 * length)()
            ctypes.memmove(buf, addr, length)
            return bytes(buf)
        else:
            buf = (ctypes.c_uint8 * length)()
            bytes_read = ctypes.c_size_t()
            ReadProcessMemory(
                self.process_handle,
                addr,
                ctypes.byref(buf),
                length,
                ctypes.byref(bytes_read),
            )
            assert bytes_read.value == length, f"Read {bytes_read.value} bytes, expected {length}"
            return bytes(buf[: bytes_read.value])
        
    def read_element(self, addr: int, item_size: int | StructFmt = 1) -> int:
        item_struct_fmt: str
        if isinstance(item_size, str):
            item_struct_fmt = item_size
            item_size = struct.calcsize(item_size)
        else:
            item_struct_fmt = ITEM_SIZE_TO_STRUCT_FMT[item_size]
        data = self.read(addr, item_size)
        return struct.unpack("<" + item_struct_fmt, data)[0]
        
    def read_array(self, addr: int, count: int, item_size: int | StructFmt) -> tuple[int, ...]:
        item_struct_fmt: str
        if isinstance(item_size, str):
            item_struct_fmt = item_size
            item_size = struct.calcsize(item_size)
        else:
            item_struct_fmt = ITEM_SIZE_TO_STRUCT_FMT[item_size]
        data = self.read(addr, count * item_size)
        return typing.cast(tuple[int, ...], struct.unpack("<" + (item_struct_fmt * count), data))

    @typing.overload
    def __getitem__(self, s: int) -> int: ...
    @typing.overload
    def __getitem__(self, s: slice) -> tuple[int, ...]: ...
    def __getitem__(self, s: int | slice) -> int | tuple[int, ...]:
        """
        Read memory according to the slice.
        Step may a word size (e.g. 2 for 16-bit words, 4, 8) - memory is unpacked accordingly.
        """
        if isinstance(s, int):
            return self.read_element(s)
        
        if s.start is None:
            raise ValueError("Start address must be specified")
        
        if s.stop is None:
            return self.read_element(s.start, s.step)

        if s.step is None:
            return self.read_array(s.start, s.stop - s.start, 1)

        # memory[] differs from .read_array in that start and end are both memory addresses
        element_size = s.step
        if isinstance(element_size, str):
            element_size = struct.calcsize(element_size)
        if not isinstance(element_size, int):
            raise ValueError("Step must be an integer or struct format string")
        return self.read_array(s.start, (s.stop - s.start) // element_size, element_size)

    def write(self, address: int, data: bytes, make_writable: bool = False) -> None:
        """
        Writes data to the process memory.
        """
        if self.process_handle:
            raise ValueError("Not implemented for foreign processes")
        data_sb = ctypes.create_string_buffer(data)
        
        old_permissions = ctypes.wintypes.DWORD()
        if make_writable:
            old_permissions = ctypes.wintypes.DWORD()
            if not VirtualProtectEx(
                own_process_handle,
                address,
                len(data),
                PAGE_EXECUTE_READWRITE,  # TODO: only RWX if it was X before
                ctypes.byref(old_permissions),
            ):
                raise ValueError(
                    f"Error: VirtualProtectEx {ctypes.windll.kernel32.GetLastError():#x}"
                )
        ctypes.memmove(address, data_sb, len(data))
        if make_writable:
            if not VirtualProtectEx(
                own_process_handle,
                address,
                len(data),
                old_permissions,
                ctypes.byref(old_permissions),
            ):
                raise ValueError(
                    f"Error: VirtualProtectEx {ctypes.windll.kernel32.GetLastError():#x}"
                )
            
    def write_native_word(self, address: int, data: int, make_writable: bool = False) -> None:
        if WORDSIZE == 8:
            self.write(address, struct.pack("<Q", data), make_writable)
        else:
            self.write(address, struct.pack("<I", data), make_writable)

    def __setitem__(self, s: int | slice, v: int | bytes) -> None:
        """
        Write memory.
        Step is not supported. Writing to a remote process is not supported.
        :param s:
        :param v:
        :return:
        """
        if self.process_handle:
            raise ValueError("Not implemented for foreign processes")
        if isinstance(s, int):
            if isinstance(v, int):
                v = bytes([v, ])
            s = slice(s, s + len(v))
        if s.step is not None:
            raise NotImplementedError("Step is not supported")
        ln = s.stop - s.start
        data = ctypes.create_string_buffer(v)
        ctypes.memmove(s.start, data, ln)

    def cstr(self, addr: int, maxlen: int = 1024) -> str:
        """
        Reads a null-terminated string from the process memory, decoded as ascii
        """
        if not self.process_handle:
            return ctypes.string_at(addr).decode("ascii")
        else:
            data = self.read(addr, maxlen)
            if 0 in data:
                data = data[: data.find(0)]
            return data.decode("ascii", "replace")

    def ptr(self, addr: int) -> int:
        return self.native_word(addr)

    def cstr_p(self, addr: int, maxlen: int =1024) -> str:
        return self.cstr(self.ptr(addr), maxlen=maxlen)

    def struct(self, addr: int, fmt: str) -> tuple[typing.Any, ...]:
        warnings.warn("Memory.struct() is deprecated, use unpack() instead")
        return self.unpack(addr, fmt)

    def unpack(self, addr: int, fmt: str) -> tuple[typing.Any, ...]:
        return struct.unpack(fmt, self.read(addr, struct.calcsize(fmt)))

    def int32(self, addr: int) -> int:
        return self.unpack(addr, "<i")[0]

    def uint32(self, addr: int) -> int:
        return self.unpack(addr, "<I")[0]

    def int64(self, addr: int) -> int:
        return self.unpack(addr, "<q")[0]

    def uint64(self, addr: int) -> int:
        return self.unpack(addr, "<Q")[0]

    def native_word(self, addr: int) -> int:
        if WORDSIZE == 8:
            return self.uint64(addr)
        else:
            return self.uint32(addr)


memory = Memory()

__all__ = ["Memory", "memory"]
