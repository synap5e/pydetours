from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import types
import typing

from pydetours.ctypedefs import (
    PAGE_EXECUTE_READWRITE,
    WORDPACK,
    WORDSIZE,
    VirtualProtectEx,
    WriteProcessMemory,
)
from pydetours.memory import memory
from pydetours.pe32_module import own_process_handle


@typing.overload
def asm(bytecode: bytes) -> typing.Callable[[Patch], None]: ...
@typing.overload
def asm(bytecode: dict[str, bytes]) -> typing.Callable[[Patch, str], None]: ...
def asm(bytecode: bytes | dict[str, bytes]) -> typing.Any:
    _bytecode = bytecode
    if isinstance(_bytecode, bytes):

        def make_asm(self: Patch) -> None:
            assert isinstance(_bytecode, bytes), "I hate mypy I hate mypy I hate mypy"
            self.bytecode += _bytecode

        return make_asm
    else:

        def make_asm_arg(self: Patch, a: str) -> None:
            assert isinstance(_bytecode, dict)
            aa = "?" + a[1:]
            if aa in _bytecode:
                a = aa
            self.bytecode += _bytecode[a]

        return make_asm_arg


REX1 = b"" if WORDSIZE == 4 else b"\x48"  # REX prefix for x64 - converts r/m32 to r64


RegisterName = typing.Literal[
    "*ax",
    "rax",
    "eax",
    "ax",
    "al",
    "*cx",
    "rcx",
    "ecx",
    "cx",
    "cl",
    "*dx",
    "rdx",
    "edx",
    "dx",
    "dl",
    "*bx",
    "rbx",
    "ebx",
    "bx",
    "bl",
    "*si",
    "rsi",
    "esi",
    "si",
    "sil",
    "*di",
    "rdi",
    "edi",
    "di",
    "dil",
    "*sp",
    "rsp",
    "esp",
    "sp",
    "spl",
    "*bp",
    "rbp",
    "ebp",
    "bp",
    "bpl",
    "*8",
    "r8",
    "r8d",
    "r8w",
    "r8b",
    "*9",
    "r9",
    "r9d",
    "r9w",
    "r9b",
    "*10",
    "r10",
    "r10d",
    "r10w",
    "r10b",
    "*11",
    "r11",
    "r11d",
    "r11w",
    "r11b",
    "*12",
    "r12",
    "r12d",
    "r12w",
    "r12b",
    "*13",
    "r13",
    "r13d",
    "r13w",
    "r13b",
    "*14",
    "r14",
    "r14d",
    "r14w",
    "r14b",
    "*15",
    "r15",
    "r15d",
    "r15w",
    "r15b",
]


class Patch:
    def __init__(self, address: int, process_handle: ctypes.wintypes.HANDLE | None = None) -> None:
        self.address = address
        if not process_handle:
            process_handle = own_process_handle
        self.process_handle = process_handle
        self.bytecode = b""

    def __enter__(self) -> Patch:
        return self

    def set_args(self, args: typing.Sequence[int]) -> None:
        if WORDSIZE == 4:
            # push args in reverse order
            for a in args[::-1]:
                self.bytecode += b"\x68" + struct.pack("<I", a)
        else:
            assert len(args) <= 4
            for a, rcode in zip(args, (b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")):
                if isinstance(a, int):
                    self.bytecode += rcode + struct.pack("<Q", a)
                else:
                    raise ValueError(f"Don't know how to set arg {a!r}")

    def call_indirect(self, funcptr: int, *args: int, cleanup_in_32bit: bool = True) -> None:
        self.set_args(args)
        if WORDSIZE == 4:
            self.bytecode += b"\xff\x15" + struct.pack("<I", funcptr)  # call [&funcptr]
            if cleanup_in_32bit and len(args):
                self.bytecode += b"\x83\xc4" + struct.pack("<B", len(args) * 4)  # add esp
        else:
            self.bytecode += b"\x48\x83\xec\x20"  # sub rsp, 32; shadow space
            self.bytecode += b"\xff\x15" + struct.pack(
                "<i", funcptr - (self.cursor + 6)
            )  # call [&funptr] (RIP relative)
            self.bytecode += b"\x48\x83\xc4\x20"  # add rsp, 32 ; shadow space

    def call_regrelative(
        self, register: str, offset: int, *args: int, cleanup_in_32bit: bool = True
    ) -> None:
        self.set_args(args)

        if register[1:] == "ax":
            call_reg = b"\xff\xd0"
            add_reg = b"\x05"
        else:
            raise ValueError(f"Don't know how to call {register!r}")
        if WORDSIZE == 4:
            if cleanup_in_32bit and len(args):
                call_reg += b"\x83\xc4" + struct.pack("<B", len(args) * 4)  # add esp
        else:
            call_reg = (
                b"\x48\x83\xec\x20"
                + call_reg  # sub rsp, 32; shadow space
                + b"\x48\x83\xc4\x20"  # add rsp, 32 ; shadow space
            )
            add_reg = REX1 + add_reg
        self.bytecode += add_reg + struct.pack("<I", offset)
        self.bytecode += call_reg

    def call(self, funcaddr: int, *args: int, cleanup_in_32bit: bool = True) -> None:
        self.set_args(args)
        if WORDSIZE == 4:
            # call funcaddr (relative)
            self.bytecode += b"\xe8" + struct.pack("<i", funcaddr - (self.cursor + 5))

            # unwind stack
            if cleanup_in_32bit and len(args):
                self.bytecode += b"\x83\xc4" + struct.pack("<B", len(args) * 4)  # add esp
        else:
            self.bytecode += b"\x48\xb8" + struct.pack("<Q", funcaddr)  # mov rax, funcaddr
            self.bytecode += b"\x48\x83\xec\x20"  # sub rsp, 32; shadow space
            self.bytecode += b"\xff\xd0"  # call rax
            self.bytecode += b"\x48\x83\xc4\x20"  # add rsp, 32 ; shadow space

    PREFIX = {
        "*": REX1,
        "r": b"\x48",
        "e": b"",
    }

    def jmp(self, rel: int) -> None:
        self.bytecode += b"\xeb" + struct.pack("b", rel)

    def jne(self, rel: int) -> None:
        self.bytecode += b"\x75" + struct.pack("b", rel)

    def add(self, a1: str, a2: int) -> None:
        if a1 == "esp":
            self.bytecode += b"\x83\xc4" + struct.pack("b", a2)
        else:
            raise ValueError(f'Unknown asm "add {a1}, {a2}"')

    def sub(self, a1: str, a2: int) -> None:
        if a1[1:] == "sp":
            self.bytecode += self.PREFIX[a1[0]] + b"\x83\xec" + struct.pack("B", a2)
        else:
            raise ValueError(f'Unknown asm "sub {a1}, {a2}"')

    push = asm(
        {
            "?ax": b"\x50",
            "?sp": b"\x54",
            "?bp": b"\x55",
            "?cx": b"\x51",
        }
    )
    pop = asm(
        {
            "?bp": b"\x5d",
        }
    )
    MOV: dict[tuple[RegisterName, RegisterName], bytes] = {
        ("bx", "ax"): b"\x8b\xd8",
        ("cx", "sp"): b"\x8b\xcc",
        ("bp", "sp"): b"\x8b\xec",
        ("sp", "bp"): b"\x8b\xe5",
        ("cx", "bp"): b"\x8b\xcd",
        ("r12", "rax"): b"\x4c\x8b\xe0",
        ("r13", "rax"): b"\x4c\x8b\xe8",
        ("r14", "rax"): b"\x4c\x8b\xf0",
        ("rdx", "r13"): b"\x49\x8b\xd5",
        ("rdx", "r14"): b"\x49\x8b\xd6",
        ("rcx", "r14"): b"\x49\x8b\xce",
        ("rcx", "r13"): b"\x49\x8b\xcd",
        ("rcx", "r12"): b"\x49\x8b\xcc",
    }

    def mov(self, a1: RegisterName | str, a2: RegisterName | str | int) -> None:
        if a1[1:] == "ax":
            if a1[0] == "*":
                size = WORDPACK
            elif a1[0] == "r":
                size = "Q"
            else:
                size = "I"
            try:
                self.bytecode += self.PREFIX[a1[0]] + b"\xb8" + struct.pack("<" + size, int(a2))
                return
            except:
                pass
        assert isinstance(a2, str)
        sk = a1[1:], a2[1:]
        if a1[0] == "[" and a1[2:4] == "bp" and a2[1:] == "ax" and a1[1] == a2[0]:
            # mov [?bp+?], ?ax
            ofs = int(a1[4:-1])
            pre = self.PREFIX[a1[1]]
            self.bytecode += pre + b"\x89\x45" + struct.pack("b", ofs)
        elif a2[0] == "[" and a2[2:4] == "bp" and a1[1:] in ["ax", "cx"] and a2[1] == a1[0]:
            # mov ?ax, [?bp+?] / mov ?cx, [?bp+?]
            ofs = int(a2[4:-1])
            pre = self.PREFIX[a2[1]]
            dst = b"\x45" if a1[1:] == "ax" else b"\x4d"
            self.bytecode += pre + b"\x8b" + dst + struct.pack("b", ofs)
        elif sk in self.MOV and a1[0] == a2[0]:
            # support all of {*ax, eax, rax} by determining what prefix we need
            self.bytecode += self.PREFIX[a1[0]] + self.MOV[sk]
        elif (a1, a2) in self.MOV:
            self.bytecode += self.MOV[(a1, a2)]
        else:
            raise ValueError(f'Can\'t assemblt "mov {a1}, {a2}"')

    def pushad(self) -> None:
        if WORDSIZE == 4:
            self.bytecode += b"\x60"
        else:
            self.bytecode += b"PQRSTUVWAPAQARASATAUAVAW"

    def popad(self) -> None:
        if WORDSIZE == 4:
            self.bytecode += b"\x61"
        else:
            self.bytecode += b"A_A^A]A\x5cA[AZAYAX_^]\x5c[ZYX"

    def test(self, a1: str, a2: str) -> None:
        if a1 == a2 and a1[1:] == "ax":
            self.bytecode += self.PREFIX[a1[0]] + b"\x85\xc0"
        else:
            raise ValueError(f'Unknown asm "test {a1}, {a2}"')

    pushfd = asm(b"\x9c")
    popfd = asm(b"\x9d")
    ret = asm(b"\xc3")
    int3 = asm(b"\xcc")
    nop = asm(b"\x90")

    @property
    def cursor(self):
        return self.address + len(self.bytecode)

    def __exit__(self, *_: typing.Any) -> None:
        if len(self.bytecode) == 0:
            return
        old_permissions = ctypes.wintypes.DWORD()
        if not VirtualProtectEx(
            self.process_handle,
            self.address,
            len(self.bytecode),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_permissions),
        ):
            raise ValueError("Error: VirtualProtectEx %04x" % ctypes.windll.kernel32.GetLastError())
        if self.process_handle == own_process_handle:
            ctypes.memmove(self.address, self.bytecode, len(self.bytecode))
        else:
            if not WriteProcessMemory(
                self.process_handle,
                self.address,
                self.bytecode,
                len(self.bytecode),
                None,
            ):
                raise ValueError(
                    "Error: WriteProcessMemory %d" % ctypes.windll.kernel32.GetLastError()
                )
        if not VirtualProtectEx(
            self.process_handle,
            self.address,
            len(self.bytecode),
            old_permissions.value,
            ctypes.byref(old_permissions),
        ):
            raise ValueError("Error: VirtualProtectEx %d" % ctypes.windll.kernel32.GetLastError())


class Registers:
    if typing.TYPE_CHECKING:
        eflags: int
        r15: int
        r14: int
        r13: int
        r12: int
        r11: int
        r10: int
        r9: int
        r8: int
        edi: int
        esi: int
        ebp: int
        esp: int
        ebx: int
        edx: int
        ecx: int
        eax: int

    REGISTERS_64BIT_PUSHAD_ORDER = ["r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8"]
    REGISTERS_32BIT_PUSHAD_ORDER = ["edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax"]
    REGISTERS_PUSHAD_ORDER = (
        (["eflags"] + REGISTERS_64BIT_PUSHAD_ORDER + REGISTERS_32BIT_PUSHAD_ORDER)
        if WORDSIZE == 8
        else (["eflags"] + REGISTERS_32BIT_PUSHAD_ORDER)
    )

    def __init__(self, buf: bytes | memoryview, eip: int) -> None:
        for rname, rval in zip(
            self.REGISTERS_PUSHAD_ORDER,
            struct.unpack(
                "<" + WORDPACK * len(self.REGISTERS_PUSHAD_ORDER),
                buf,
            ),
        ):
            setattr(self, rname, rval)
        self.eip = eip
        if WORDSIZE == 8:
            self.rip = eip
            self.rdi = self.edi
            self.rsi = self.esi
            self.rbp = self.ebp
            self.rsp = self.esp
            self.rbx = self.ebx
            self.rdx = self.edx
            self.rcx = self.ecx
            self.rax = self.eax

    def pack(self) -> bytes:
        vals = [getattr(self, rname) for rname in self.REGISTERS_PUSHAD_ORDER]
        return struct.pack(
            "<" + "".join(WORDPACK if v >= 0 else WORDPACK.lower() for v in vals), *vals
        )

    @classmethod
    def getsize(cls) -> int:
        return WORDSIZE * len(cls.REGISTERS_PUSHAD_ORDER)

    def __str__(self) -> str:
        # TODO: this prints "e**" registers on x64
        return (
            "Registers("
            + ", ".join(
                f"{rname}=0x{getattr(self, rname):08x}"
                for rname in reversed(self.REGISTERS_PUSHAD_ORDER)
            )
            + ")"
        )

    __repr__ = __str__


class Arguments(typing.Iterable[int]):
    def __init__(
        self,
        registers: Registers,
        argcount: int | None = None,
        x86_convention: str | None = "stdcall",
    ):
        self.registers = registers
        self.argcount = argcount
        self.x86_convention = x86_convention

    @typing.overload
    def argaddr(self, i: int) -> int | str: ...
    @typing.overload
    def argaddr(self, i: slice) -> tuple[int | str, ...]: ...
    def argaddr(self, i: int | slice) -> int | str | tuple[int | str, ...]:
        if isinstance(i, slice):
            if not i.stop or not self.argcount:
                raise ValueError("Cannot iterate over Arguments with unknown argcount")
            return tuple(
                self[j]
                for j in range(
                    i.start or 0,
                    i.stop or self.argcount,
                    1 if i.step is None else i.step,
                )
            )
        if self.argcount is not None and i >= self.argcount:
            raise IndexError(
                f"Argument {i} is out of bounds for Arguments with argcount={self.argcount}"
            )
        if WORDSIZE == 8 and i <= 3:
            return ["ecx", "edx", "r8", "r9"][i]
        elif WORDSIZE == 4 and self.x86_convention == "fastcall":
            if i <= 1:
                return ["ecx", "edx"][i]
            else:
                return self.registers.esp + (i - 2) * WORDSIZE
        elif WORDSIZE == 4 and self.x86_convention == "thiscall":
            if i == 0:
                return "ecx"
            else:
                return self.registers.esp + (i) * WORDSIZE
        else:
            return self.registers.esp + (i + 1) * WORDSIZE

    def __getitem__(self, i: int) -> int:
        a = self.argaddr(i)
        if isinstance(a, str):
            return getattr(self.registers, a)
        else:
            return memory.native_word(a)

    def __setitem__(self, i: int, v: int) -> None:
        a = self.argaddr(i)
        if isinstance(a, str):
            setattr(self.registers, a, v)
        else:
            memory[a : a + WORDSIZE] = struct.pack("<" + WORDPACK, v)

    def __iter__(self) -> typing.Iterator[int]:
        if not self.argcount:
            raise ValueError("Cannot iterate over Arguments with unknown argcount")
        return (self[i] for i in range(self.argcount))

    def __str__(self) -> str:
        if self.argcount is not None:
            return "Arguments[" + ", ".join(hex(self[i]) for i in range(self.argcount)) + "]"
        else:
            return "Arguments[...? " + ", ".join(hex(self[i]) for i in range(4)) + ", ...?]"

    __repr__ = __str__


class ArgumentsStackAdjust(Arguments):
    def __init__(
        self, registers: Registers, adjust: int, argcount: int, x86_convention: str = "stdcall"
    ):
        freg = Registers(registers.pack(), registers.eip)
        freg.esp += adjust
        return super().__init__(registers=freg, argcount=argcount, x86_convention=x86_convention)


__all__ = ["Patch", "Registers", "Arguments", "ArgumentsStackAdjust"]
