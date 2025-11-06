from __future__ import annotations

import atexit
import binascii
import ctypes
import ctypes.wintypes
import logging
import struct
import sys
import threading
import traceback
import typing

from pydetours.ctypedefs import (
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    WORDPACK,
    WORDSIZE,
    PyBUF_READ,
    PyMemoryView_FromMemory,
    VirtualAlloc,
    VirtualProtectEx,
)
from pydetours.memory import memory
from pydetours.patch import REX1, Arguments, Patch, Registers
from pydetours.pe32_module import (
    Module,
    ModuleExport,
    ResolvedFunctionImport,
    modules,
    own_process_handle,
    resolve_addr,
    FindPattern,
)
from pydetours.pointer import BasePointer, is_pointer
from pydetours.thiscall import make_thiscall

# from pydetours.typing.hook_typing import (
#     HookableFunction,
#     HookableFunctionConvertableArg,
#     HookableFunctionReturn,
#     HookedFunction,
#     HookFuncT,
# )


if typing.TYPE_CHECKING:
    CData = ctypes._CData  # type: ignore
    SimpleCData = ctypes._SimpleCData  # type: ignore
else:
    CData = typing.Any
    T = typing.TypeVar("T")

    class SimpleCData(typing.Generic[T]):
        pass


logger = logging.getLogger("pydetours.patcher")
in_hooked_process = getattr(sys, "in_hooked_process", False)


_dontgc = list[
    object
]()  # don't garbage collect otherwise dangling objects - they are needed in the hooks
_already_hooked = getattr(sys, "_already_hooked", {})
setattr(sys, "_already_hooked", _already_hooked)


HEXDIGITS = "0123456789abcdefABCDEF"

ALLOWED_PADDING = [  # Function padding/alignments bytes that are allowed to be overwritten without consequence.
    b"\xcc",  # INT3: padding between functions - not used by normal code.
    b"\x90",  # NOP
    # GCC's alignments
    # 00007FF6DE7319F9 | 0F1F80 00000000                           | nop dword ptr ds:[rax],eax                     |
    b"\x0f\x1f\x80\x00\x00\x00\x00",  # nop dword ptr ds:[rax],eax
    # 00007FF6DE731A37 | 66:0F1F8400 00000000                      | nop word ptr ds:[rax+rax],ax                   |
    b"\x66\x0f\x1f\x84\x00\x00\x00\x00",  # nop word ptr ds:[rax+rax],ax
    # 00007FF6DE731A73 | 66662E:0F1F8400 00000000                  | nop word ptr cs:[rax+rax],ax                   |
    b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # nop word ptr ds:[rax+rax],ax
    # 00007FF6DE731A73 | 66662E:0F1F8400 00000000                  | nop word ptr cs:[rax+rax],ax                   |
    # 00007FF6DE731A7E | 66:90                                     | nop                                            |
    b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90",  # nop word ptr ds:[rax+rax],ax; nop
    # 00007FF7AFCC1872 | 66662E:0F1F8400 00000000                  | nop word ptr cs:[rax+rax],ax                   |
    #   00007FF7AFCC187D | 0F1F00                                    | nop dword ptr ds:[rax],eax                     |
    b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x00",  # nop word ptr ds:[rax+rax],ax; nop dword ptr ds:[rax],eax
]
ALLOWED_PROLOGUES = [
    "55 8b ec",  # push ebp; mov ebp, esp - only 3 bytes (normal jump requires 5, but if there is padding bytes above, we can reljmp -7)
    "55 89 e5",  # alternate encoding
    "55 48 89 e5",  # x64 variant of above
    "55 48 8b ec",  # x64 variant of above
    "8b ff 55 8b ec",  # windows dlls prepend noop before to allow easy hooking
    "4c 8b d1 b8 ?? ?? ?? ??",  # ntdll's syscalls
    "55 8b ec 83 ec ??",  #  push ebp; mov ebp, esp; sub esp, ?? - allocating space for stack variables is a common pattern that results in PIC bytes
    "55 8B ec 81 ec ?? ?? ?? ??",  #  push ebp; mov ebp, esp; sub esp, ?? ?? ?? ??
    "55 8b ec 83 e4 ??",  #  push ebp; mov ebp, esp; and esp, ?? - or aligning the stack
    "55 89 e5 83 ec ??",  #  push ebp; mov ebp, esp; sub esp, ?? - as above but with alternate encodings for mov
    "55 8B e5 81 ec ?? ?? ?? ??",  #  push ebp; mov ebp, esp; sub esp, ?? ?? ?? ??
    "55 89 e5 83 e4 ??",  #  push ebp; mov ebp, esp; and esp, ??
    "53 8b dc 83 ec ??",  # push ebx; mov ebx, esp; sub esp, ?? - as above but with ebx instead of ebp
    "90 90 90 90 90",  # maybe someone has done our work for us...
]
if WORDSIZE == 8:
    ALLOWED_PROLOGUES += [
        "55 48 8b ec 48 83 ec ??",  #  push rbp; mov rbp, rsp; sub rsp, ?? - allocating space for stack variables is a common pattern that results in PIC bytes
        "55 48 8b ec 48 83 e4 ??",  #  push rbp; mov rbp, rsp; and rsp, ?? - or aligning the stack
        "55 48 89 e5 48 83 ec ??",  #  push rbp; mov rbp, rsp; sub rsp, ?? - as above but with alternate encodings for mov
        "55 48 89 e5 48 83 e4 ??",  #  push rbp; mov rbp, rsp; and rsp, ??
        "48 89 4C 24 08 56 57",  #  mov qword ptr [rsp+8], rcx; push rsi; push rdi
        "40 55 53 57 48 8b ec",  #  push rbp; push rbx; push rdi; mov rbp, rsp
        "40 53 b8 ?? ?? ?? ??",  #  push rbx; mov eax, ??
        "40 56 b8 ?? ?? ?? ??",  #  push rsi; mov eax, ??
        "40 57 b8 ?? ?? ?? ??",  #  push rdi; mov eax, ??
    ]
    # 40 55 53 57 48 8b ec 48 83
# TODO: parse asm directly to find length of PIC - like https://github.com/lunarjournal/cdl86/blob/master/cdl.c#L814 but also detect IP-relative instructions


class InHook:
    """
    N.B. This does NOT prevent multiple hooks running at once or make any re-entry guarantees.
    It is simply a counter of the number of threads running hooks, and the ability to wait for entry/exit/finished
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()

        self.entered = threading.Condition(self.lock)
        self.exited = threading.Condition(self.lock)
        self._count = 0

    def enter(self) -> None:
        with self.lock:
            self._count += 1
            self.entered.notify_all()

    def exit(self) -> None:
        with self.lock:
            self._count -= 1
            self.exited.notify_all()

    @property
    def count(self) -> int:
        with self.lock:
            return self._count

    def wait(self, timeout: float | None = None) -> bool:
        """
        Wait for the hook to have 0 threads running it, or for timeout (if specified).
        Returns True if the hook is finished, False if timeout.
        """
        with self.lock:
            if self._count == 0:
                return True
            return self.exited.wait_for(lambda: self._count == 0, timeout=timeout)


in_hook: InHook
if not getattr(sys, "in_hook", None):
    in_hook = InHook()
    setattr(sys, "in_hook", in_hook)
else:
    in_hook = getattr(sys, "in_hook")


def make_patch_to_py(patch: Patch, pyfunc: typing.Callable[[int], bool]) -> None:
    # PyGILState_Ensure = modules[PYTHON_DLL].exports['PyGILState_Ensure'].address
    # PyGILState_Release = modules[PYTHON_DLL].exports['PyGILState_Release'].address
    # Py_DecRef = modules[PYTHON_DLL].exports['Py_DecRef'].address
    # PyTuple_Pack = modules[PYTHON_DLL].exports['PyTuple_Pack'].address
    # PyLong_FromVoidPtr = modules[PYTHON_DLL].exports['PyLong_FromVoidPtr'].address
    # PyObject_CallObject = modules[PYTHON_DLL].exports['PyObject_CallObject'].address
    PyGILState_Ensure = ctypes.cast(ctypes.pythonapi.PyGILState_Ensure, ctypes.c_void_p).value
    PyGILState_Release = ctypes.cast(ctypes.pythonapi.PyGILState_Release, ctypes.c_void_p).value
    Py_DecRef = ctypes.cast(ctypes.pythonapi.Py_DecRef, ctypes.c_void_p).value
    PyTuple_Pack = ctypes.cast(ctypes.pythonapi.PyTuple_Pack, ctypes.c_void_p).value
    PyLong_FromVoidPtr = ctypes.cast(ctypes.pythonapi.PyLong_FromVoidPtr, ctypes.c_void_p).value
    PyObject_CallObject = ctypes.cast(ctypes.pythonapi.PyObject_CallObject, ctypes.c_void_p).value

    assert (
        PyGILState_Ensure
        and PyGILState_Release
        and Py_DecRef
        and PyTuple_Pack
        and PyLong_FromVoidPtr
        and PyObject_CallObject
    )

    if WORDSIZE == 4:
        patch.call(PyGILState_Ensure)
        patch.push("eax")  # ret from PyGILState_Ensure

        # use ebp (holds esp's value after pushads) as the argument instead of hardcoded value...
        # this means we need to restore the stack after, instead of having patch.call do that since patch.call
        # thinks we arent using any args
        patch.push("ebp")
        patch.call(PyLong_FromVoidPtr)
        patch.add("esp", 4)

        # again, handle arguments "manually" since we need the result of the last call
        # dont clean up stack this time, we will use it later when decref'ing
        patch.push("eax")  # ret from PyLong_FromVoidPtr
        patch.call(PyTuple_Pack, 1)

        # as above
        patch.push("eax")  # ret from PyTuple_Pack
        patch.call(PyObject_CallObject, id(pyfunc))

        # save return val
        patch.mov("ebx", "eax")

        # decref using the non-cleaned-up result from PyTuple_Pack, clean up "manually"
        patch.call(Py_DecRef)
        patch.add("esp", 4)

        # decref using the non-cleaned-up result from PyLong_FromVoidPtr, clean up "manually"
        patch.call(Py_DecRef)
        patch.add("esp", 4)

        # PyGILState_Ensure retval is already on stack, use it then clean it up
        patch.call(PyGILState_Release)
        patch.add("esp", 4)

    else:
        # r12 = PyGILState_Ensure()
        patch.call(PyGILState_Ensure)
        patch.mov("r12", "rax")

        # r13 = PyLong_FromVoidPtr(rbp)  - rbp holds esp's value after pushads
        patch.mov("rcx", "rbp")
        patch.call(PyLong_FromVoidPtr)
        patch.mov("r13", "rax")

        # r14 = PyTuple_Pack(1, r13)
        patch.mov("rdx", "r13")  # 2nd arg (rdx) = r13 from created pylong
        patch.call(PyTuple_Pack, 1)
        patch.mov("r14", "rax")

        # rbx = PyObject_CallObject(pyfunc, r14)
        patch.mov("rdx", "r14")  # 2nd arg (rdx) = r14 from created pytuple
        patch.call(PyObject_CallObject, id(pyfunc))
        patch.mov("rbx", "rax")

        # Py_DecRef(r14)
        patch.mov("rcx", "r14")
        patch.call(Py_DecRef)

        # Py_DecRef(r13)
        patch.mov("rcx", "r13")
        patch.call(Py_DecRef)

        # PyGILState_Release(r12)
        patch.mov("rcx", "r12")
        patch.call(PyGILState_Release)


Encoding = typing.TypeVar("Encoding")


class StringArg(str, typing.Generic[Encoding]):
    pass


HookableFunctionConvertableArg = (
    int
    | bool
    | bytes
    | SimpleCData[typing.Any]
    | BasePointer[typing.Any]
    | StringArg[typing.Any]
    | None
)
# TODO: as soon as we get value constraints on TypeVarTuple we can make this actually types
HookableFunction = typing.Callable[..., int | None]


class HookedFunction(typing.Protocol):
    in_hook: InHook
    original_code_start: int
    original: typing.Callable[..., CData | None]
    hooked_code_start: int
    unhook: typing.Callable[[], None]

    @staticmethod
    def __call__(*args: typing.Any) -> CData | None: ...


HookFuncT = typing.TypeVar("HookFuncT", bound=HookedFunction)

CallingConventions = typing.Literal["stdcall", "thiscall", "fastcall"]  # TODO: cdecl?


def make_landing(
    func: HookedFunction,
    near_addr: int | None,
    addr_desc: typing.Any,
    landing_exit_address: int,
    forward_only: bool = False,
    return_pop: int | None = None,
    func_prologue: bytes = b"",
    x86_calling_convention: CallingConventions | None = None,
) -> int:
    if WORDSIZE == 4 or near_addr is None:
        landing_address = int(
            VirtualAlloc(None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)
        )
    else:
        # in 64bit we need memory nearby to allow reljmping to work
        granularity = 0x100000
        maxdist = 0x80000000  # max jump is 0x80000000
        if forward_only:
            start = near_addr + granularity
        else:
            start = max(near_addr - maxdist, 0)
        start -= start % granularity
        end = min(near_addr + maxdist, 2**64 - 1)
        end -= end % granularity

        logger.debug(
            f"   ~ Want to allocate near {near_addr:#x} - searching {start:#x} -> {end:#x}"
        )
        # start from almost maxdist above address, to somewhat minimize retries
        for a in range(end - granularity, start + granularity, -granularity):
            logger.debug(f"   ~ Trying to allocate at 0x{a:016x}")
            landing_address = int(
                VirtualAlloc(a, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ) or 0
            )
            if landing_address:
                break
        else:
            raise ValueError(f"Failed to allocate memory near 0x{near_addr:x}")

    logger.debug(f"  - Created landing at 0x{landing_address:08x}")
    func.in_hook = InHook()
    func.hooked_code_start = landing_address

    func_arg_types = [v for k, v in func.__annotations__.items() if k != "return"]
    func_arg_type_converters = func_arg_types
    func_arg_type_converters_start = 0
    include_registers = False
    include_arguments = False
    convert_arguments = False
    if len(func_arg_type_converters) and func_arg_type_converters[0] is Registers:
        func_arg_type_converters = func_arg_type_converters[1:]
        func_arg_type_converters_start += 1
        include_registers = True
    if len(func_arg_type_converters) and func_arg_type_converters[0] is Arguments:
        func_arg_type_converters = func_arg_type_converters[1:]
        func_arg_type_converters_start += 1
        include_arguments = True
        convert_arguments = True
    if len(func_arg_type_converters):
        convert_arguments = True
        for t in func_arg_type_converters:
            if t is int or t is bool:
                continue
            elif t is bytes:
                continue
            elif t is str:
                raise TypeError(
                    f"Cannot use python-strings as function arguments - use StringArg[<encoding>] or bytes instead"
                )
            elif t is StringArg:
                raise TypeError(f'StringArg types must specify an encoding e.g. StringArg["utf-8"]')
            elif typing.get_origin(t) is StringArg:
                encoding = typing.get_args(t)[0]
                if not isinstance(encoding, typing.ForwardRef):
                    raise TypeError(
                        f"StringArg[encoding] should have string encoding as argument, not {encoding}"
                    )
            elif is_pointer(t):
                continue
            elif issubclass(t, SimpleCData):
                continue
            else:
                raise TypeError(f"Invalid type for hook function argument: {t}")

    def func_wrapper(esp: int) -> bool:
        # logger.debug(f"  - Thread {GetCurrentThreadId()} running func_wrapper for {addr_desc} (0x{landing_address:08x}): {func}")
        force_return = False
        try:
            in_hook.enter()
            func.in_hook.enter()

            try:
                # load registers object from pushad'd registers
                # stackdata = memory[esp : esp + Registers.getsize()]
                # registers = Registers(stackdata[: Registers.getsize()], addr)
                registers = Registers(memory.read(esp, Registers.getsize()), landing_address)

                pushed_sp = registers.esp
                # actual esp at time of hook is before push of registers
                registers.esp = esp + Registers.getsize()

                func_args = list[Registers | Arguments | HookableFunctionConvertableArg]()
                if include_registers:
                    func_args.append(registers)
                if convert_arguments:
                    arguments = Arguments(registers, x86_convention=x86_calling_convention)
                    if include_arguments:
                        func_args.append(arguments)
                    for i, t in enumerate(func_arg_type_converters):
                        a = arguments[i]
                        if typing.get_origin(t) is StringArg:
                            if not a:
                                func_args.append(None)
                            else:
                                encoding = typing.get_args(t)[0].__forward_arg__
                                func_args.append(t(ctypes.string_at(a).decode(encoding)))
                        elif t is bytes:
                            if not a:
                                func_args.append(None)
                            else:
                                func_args.append(ctypes.string_at(arguments[i]))
                        else:
                            func_args.append(t(arguments[i]))
                assert len(func_args) == len(func_arg_types), (
                    f"Argument conversion failed for {func} - expected {len(func_arg_types)} but got {len(func_args)}: {func_args} vs {func_arg_types}"
                )

                rval: HookableFunctionReturn = func(*func_args)  # type: ignore
                if rval is not False and rval is not None:
                    if not isinstance(rval, int):
                        raise ValueError(
                            f"Invalid return type/value for c function: {type(rval)} {rval}"  # type: ignore
                        )
                    force_return = True
                    registers.eax = rval

                # we can't actually modify esp (yet?) because it would break the popping of the next registers
                registers.esp = pushed_sp
                memory[esp : esp + Registers.getsize()] = registers.pack()
            except Exception as e:
                logger.warning(
                    f"[!] Got exception running hook {func} for {addr_desc} (0x{near_addr:08x}): {e} - Register writeback will be skipped"
                )
                traceback.print_exc()
                force_return = False
            finally:
                func.in_hook.exit()
                in_hook.exit()

        except:
            logger.exception(
                f"[!] Got exception in func_wrapper for {addr_desc} (0x{landing_address:08x})"
            )

        if force_return and return_pop is None:
            logger.warning(
                f"[!] Function {func} for {addr_desc} (0x{landing_address:08x}) forced return value but return_pop was not specified - stack may be corrupted"
            )

        # If the function returns an int, then return immediately from where we are in asm (hopefully just called a function) using this as the return value.
        # See the conditional in the generated landing code.
        # Let's hope the user set return_pop correctly for the calling convention...
        return force_return

    func_wrapper.__name__ = f"func_wrapper_{hex(id(func))}__{func.__name__}"
    _dontgc.append(func_wrapper)

    logger.debug(
        f"  - Patching function hook landing bytecode to call python function @ 0x{id(func):x}"
    )
    with Patch(landing_address) as patch:
        # save regs - could use RtlCaptureContext?
        patch.pushad()
        patch.pushfd()
        # FIXME: xsave

        # ensure stack is 16byte aligned - store original sp in bp so make_patch_to_py can see pushad'd regs
        patch.mov("*bp", "*sp")
        if WORDSIZE == 8:
            patch.bytecode += b"\x48\x83\xe4\xf0"  # and rsp, -16

        make_patch_to_py(patch, func_wrapper)

        # If func_wrapper returned True (compare to _Py_TrueStruct aka id(True)), restore registers but then ret immediatly
        patch.bytecode += (
            REX1 + b"\xb8" + struct.pack("<" + WORDPACK, id(True))
        )  # mov *ax, _Py_TrueStruct
        patch.bytecode += REX1 + b"\x3b\xc3"  # cmp *ax, *bx
        if return_pop and WORDSIZE == 4:
            patch.jne(5)
            patch.popfd()
            patch.popad()
            patch.bytecode += b"\xc2" + struct.pack("<H", return_pop)
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

        # create a c function to call the original function - this may be replaced later e.g. by insert_hook / insert_iat_hook with a better specified (i.e. with arguments) function
        func.original = ctypes.CFUNCTYPE(ctypes.c_size_t)(func.original_code_start)

        # run prologue that got overwritten
        patch.bytecode += func_prologue

        # jmp landing_exit_address
        jmp_offset = landing_exit_address - (patch.cursor + 5)
        if abs(jmp_offset) < 2**31 - 1:
            patch.bytecode += b"\xe9" + struct.pack("<i", landing_exit_address - (patch.cursor + 5))
            patch.int3()
        else:
            # push landing_exit_address
            if WORDSIZE == 8:
                patch.bytecode += b"\xff\x25\x01\x00\x00\x00"  # jmp [rip+1]
                patch.int3()
                patch.bytecode += struct.pack("<Q", landing_exit_address)
            else:
                # FIXME: is this at all correct
                patch.bytecode += b"\x68" + struct.pack("<I", landing_exit_address)
                patch.int3()

    # caller can overwrite .unhook() if they support it
    def unhook():
        raise NotImplementedError(
            f"Unhook not implemented by make_landing() - wrapper functions such as insert_hook() may provide unhooking"
        )

    func.unhook = unhook

    return landing_address


# TRetType = typing.TypeVar("TRetType", bound=CData)
# TArgTypes = typing.TypeVarTuple("TArgTypes")

# def make_thiscall(address: int, rtype: type[TRetType] | None, *argtypes: *TArgTypes) -> typing.Callable[[ctypes.c_void_p, *TArgTypes], None]: ...

#     global thiscall_addr
#     if not thiscall_addr:
#         thiscall_addr = int(VirtualAlloc(None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))
#         with Patch(thiscall_addr) as p:
#             # Stack: ret addr, func addr, arg1, arg2, arg3, ...
#             #        [esp]     [esp+4]    ...
#             # p.int3()
#             # p.mov("ecx", "[esp+8]")
#             p.bytecode += b"\x8b\x4c\x24\x08"  # mov    ecx,DWORD PTR [esp+0x8]
#             p.bytecode += b"\x8f\x44\x24\x04"  # pop    dword ptr [esp+4]
#             # Stack: func addr, ret addr, arg2, arg3, ...
#             p.ret()
#         logger.info(f"  - Created thiscall trampoline at 0x{thiscall_addr:08x}")

#     thiscall_cfunc = ctypes.CFUNCTYPE(
#         rtype,
#         ctypes.c_void_p,
#         *argtypes
#     )(thiscall_addr)

#     def thiscall_pyfunc(this: typing.Any, *args: typing.Any) -> typing.Any:
#         return thiscall_cfunc(address, this, *args)

#     logger.info(f"  - Created thiscall_pyfunc(this, ...) => thiscall({address:#x}, this, ...)")
#     return thiscall_pyfunc


def insert_hook(
    addr_desc: ModuleExport | FindPattern | int | str,
    func: HookFuncT,
    position_independent_bytes: int | None = None,
    return_pop: int | None = None,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    remove_atexit: bool = True,
) -> HookFuncT:
    logger.info(f" * Hooking {addr_desc} to run {func}")

    addr = resolve_addr(addr_desc)
    if addr in _already_hooked:
        logger.warning(
            f"{addr_desc} is already hooked by {_already_hooked[addr]} - performing unhook"
        )
        _already_hooked[addr].unhook()

    logger.info(f"  - Resolved {addr_desc} -> 0x{addr:08x}")

    func.hooked_code_start = addr

    allowed_prologues = list(ALLOWED_PROLOGUES)

    if position_independent_bytes:
        if position_independent_bytes < 3:
            raise ValueError(
                "position_independent_bytes must be at least 3 (to allow for a relative jump)"
            )
        custom = binascii.hexlify(
            bytes(PyMemoryView_FromMemory(addr, position_independent_bytes, PyBUF_READ))
        ).decode()
        logger.info(
            f"  - Using custom length of position independent bytes - {position_independent_bytes} bytes from {addr:#x}: {custom}"
        )
        allowed_prologues.insert(0, custom)

    allowed_prologue_maxlen = max(len(p.split()) for p in allowed_prologues)
    func_start_mem = bytes(
        PyMemoryView_FromMemory(addr - 5, 5 + allowed_prologue_maxlen, PyBUF_READ)
    )
    func_prologue = func_start_mem[5:]
    logger.info(f"  - Checking prologue:       {func_prologue.hex()}")

    for check_prologue in sorted(allowed_prologues, key=lambda p: len(p), reverse=True):
        if any(c not in HEXDIGITS + "? " for c in check_prologue):
            raise ValueError(
                f"Invalid prologue pattern: {check_prologue} - must be hex digits or ?"
            )
        check_prologue = "".join(check_prologue.split())
        expected_pattern = [
            int(e, 16) if e != "??" else None
            for e in (check_prologue[i : i + 2] for i in range(0, len(check_prologue), 2))
        ]
        if all(not e or b == e for (b, e) in zip(func_prologue, expected_pattern)):
            logger.info(f"  - Matched prologue pattern {check_prologue}")
            func_prologue = func_prologue[: len(expected_pattern)]
            break
        logger.debug(f"  - Did not match prologue pattern {check_prologue}")
    else:
        if func_prologue[0] == 0xCC:
            raise ValueError(
                f"Bro's trying to hook a breakpointed function: {func_prologue[:8].hex()} (Function prologue did not match any of the allowed prologues)"
            )
        else:
            raise ValueError(
                f"Function prologue did not match any of the allowed prologues - try specifying position_independent_bytes: {func_prologue[:8].hex()}..."
            )

    if len(func_prologue) < 5:
        func_padding = func_start_mem[:5]
        logger.info(
            f"  - Prologue less than 5 bytes - checking pre-function padding: {binascii.hexlify(func_padding).decode()}"
        )
        for allowed in ALLOWED_PADDING:
            if len(allowed) == 1:
                if all(b == allowed[0] for b in func_padding):
                    logger.info(f"  - Matched padding repeating byte {binascii.hexlify(allowed)}")
                    break
            else:
                assert len(allowed) >= 5, (
                    "Require at least 5 bytes of padding, but got ALLOWED_PADDING entry with less"
                )
                potential_padding = bytes(
                    PyMemoryView_FromMemory(addr - len(allowed), len(allowed), PyBUF_READ)
                )
                if potential_padding == allowed:
                    logger.info(f"  - Matched padding byte pattern {binascii.hexlify(allowed)}")
                    break

        else:
            raise ValueError(f"Function pre-padding did not consist of 5 bytes of allowed padding")
    else:
        func_padding = b""

    landing_address = make_landing(
        func,
        addr,
        addr_desc,
        addr + len(func_prologue),
        return_pop=return_pop,
        func_prologue=func_prologue,
    )

    patch_start_addr = addr
    if len(func_prologue) >= 5:
        logger.info(
            f"  - Patching function with trampoline to func_wrapper landing - using {len(func_prologue)} PIC bytes"
        )
        with Patch(patch_start_addr) as patch:
            # jmp landing_address
            patch.bytecode += b"\xe9" + struct.pack(
                "<i", (landing_address - addr) - 5
            )  # subtract 5 because this is relative to *after* the jump

            for _ in range(len(func_prologue) - len(patch.bytecode)):
                patch.int3()

            original_bytecode = memory.read(patch_start_addr, len(patch.bytecode))
    else:
        # hook specified with explicit PIC bytes < 5
        # construct trampoline st.
        # 				int3
        # 				...
        #  				int3
        # target_func:	<instruction 1>
        # 				<instruction 2>
        # 				...
        # becomes
        # 				jmp landing_address		-> <instruction 1>
        # target_func:  jmp -7
        # 				<instruction 2>
        logger.info(
            f"  - Patching function with trampoline to func_wrapper landing - using function padding"
        )
        patch_start_addr -= 5
        with Patch(patch_start_addr) as patch:
            # jmp landing_address
            patch.bytecode += (
                b"\xe9" + struct.pack("<i", landing_address - addr)
            )  # dont subtract 5, since we are jumping from 5 bytes earlier so this cancels the subtraction

            # function enters here:
            patch.jmp(-7)

            for _ in range(len(func_prologue) - len(patch.bytecode[5:])):
                patch.int3()

            original_bytecode = memory.read(patch_start_addr, len(patch.bytecode))

    if orignal_function_spec:
        if len(orignal_function_spec) == 3:
            calltype = orignal_function_spec[2]
            if calltype == "thiscall":
                # global thiscall_addr
                # if not thiscall_addr:
                #     thiscall_addr = int(VirtualAlloc(None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))
                #     with Patch(thiscall_addr) as p:
                #         # Stack: ret addr, func addr, arg1, arg2, arg3, ...
                #         #        [esp]     [esp+4]    ...
                #         # p.int3()
                #         # p.mov("ecx", "[esp+8]")
                #         p.bytecode += b"\x8b\x4c\x24\x08"  # mov    ecx,DWORD PTR [esp+0x8]
                #         p.bytecode += b"\x8f\x44\x24\x04"  # pop    dword ptr [esp+4]
                #         # Stack: func addr, ret addr, arg2, arg3, ...
                #         p.ret()
                #     logger.info(f"  - Created thiscall trampoline at 0x{thiscall_addr:08x}")

                # thiscall = ctypes.CFUNCTYPE(orignal_function_spec[0], ctypes.c_void_p, *orignal_function_spec[1])(thiscall_addr)

                # logger.info(f"  - Created thiscall function to call at 0x{func.original_code_start:08x}")
                # def call_original(*args: CData) -> ctypes.c_void_p:
                #     return thiscall(func.original_code_start, *args)

                # func.original = call_original
                func.original = make_thiscall(
                    func.original_code_start, orignal_function_spec[0], *orignal_function_spec[1]
                )

            else:
                raise ValueError(f"Unknown calltype: {calltype}")
        else:
            func.original = ctypes.CFUNCTYPE(orignal_function_spec[0], *orignal_function_spec[1])(
                func.original_code_start
            )
    else:
        func.original = ctypes.CFUNCTYPE(ctypes.c_size_t)(func.original_code_start)

    _already_hooked[addr] = func

    def unhook() -> None:
        if addr in _already_hooked:
            logger.info(
                f" * Unhooking {addr_desc} ({func}) - restoring {len(original_bytecode)} bytes @ {patch_start_addr:#x} ({binascii.hexlify(original_bytecode).decode()})"
            )

            # If this hook is called frequently then, ironically, the safest place for EIP to be is inside the hooked function
            # (other threads: "allow us to introduce ourselves")
            with func.in_hook.lock:
                if func.in_hook.count:
                    # in_hook.count > 0 means in_hook.enter() was called. Because we took the lock, it can't exit until we release it
                    logger.info(
                        f"  - EIP captured (exit) in hook! Performing unpatch of bytecode in peace"
                    )
                    captured = True
                else:
                    captured = func.in_hook.entered.wait(0.1)
                    if captured:
                        logger.info(
                            f"  - EIP captured (entry) in hook! Performing unpatch of bytecode in peace"
                        )

                # If we didn't capture EIP in 100ms, then it's unlikely to call while we are unpatching

                with Patch(patch_start_addr) as patch:
                    patch.bytecode = original_bytecode

                if func.in_hook.count or captured:
                    logger.warning(
                        f"  - Function hook is still running (exit={func.in_hook.count}, entry={captured}) - waiting for it to finish"
                    )
                    # TODO: in entry capture case should we exited.wait() instead? Or do this for both?
                    # What about re-entrant case? Use predicate?
                    if not func.in_hook.wait(3):
                        logger.warning(
                            f"  - Function hook still running - not deallocating landing address. Good luck..."
                        )
                        return
                    else:
                        logger.info(f"  - Function hook finished - deallocating landing address")

            # This must be in a timer or it can dealloc memory before the thread wakes up

            # In fact, it's only a few bytes so safer not to dealloc it at all
            # threading.Timer(1, lambda: VirtualFree(landing_address, 0, MEM_RELEASE)).start()

            # Let's just int3 it instead
            def dealloc_landing() -> None:
                with Patch(landing_address) as patch:
                    for _ in range(0x100):
                        patch.int3()

            threading.Timer(1, dealloc_landing).start()

            del _already_hooked[addr]

    func.unhook = unhook
    if remove_atexit:
        atexit.register(unhook)

    return func


all_hooks = list[HookedFunction]()


def _no_original_in_unhooked_process() -> ctypes.c_size_t:
    raise ValueError("Cannot call original function of a hook outside of the hooked process")


def _no_unhook_in_unhooked_process() -> None:
    raise ValueError("Cannot unhook a hook outside of the hooked process")


def hook(
    addr_desc: ModuleExport | FindPattern | int | str,
    position_independent_bytes: int | None = None,
    return_pop: int = 0,
    orignal_function_spec: tuple[type[CData], tuple[type[CData], ...]]
    | tuple[type[CData], tuple[type[CData], ...], str]
    | None = None,
    remove_atexit: bool = True,
) -> typing.Callable[[HookableFunction], HookedFunction]:
    """
    Insert a hook at the specified address.
    The hook function will be called with a Registers object containing the registers at the time of the hook.
    The hook may return an int, which will be used as the return value of the hooked function or return None to continue execution of the hooked function.

    The returned function will have additional attributes:
        original_code_start: The address of the original code that was overwritten by the hook.
        original: A function that will call the original code.
        hooked_code_start: The address of the start of the hooked function.
        unhook: A function that will remove the hook.

    args:
    position_independent_bytes:
        Assert that the first N bytes of the function are position independent (i.e. do not reference any absolute addresses) and consist of N instructions.
        If not specified, the first 5 bytes will be used and must match one of the known PIC prolouges.

    return_pop:
        If the hooked function returns an int, then return_pop will be used to pop the stack after the return value is set. Generally this should be the n from "ret n" at the end of the hooked function.
        If not specified, 0 will be assumed but a warning will be logged.

    orignal_function_spec:
        If specified, the original function will use this spec to call the original function.
        Format is [return type, (arg1 type, arg2 type, ...)] or [return type, (arg1 type, arg2 type, ...), calling spec (e.g. 'thiscall')].

    """

    def try_insert_hook(func: HookedFunction) -> HookedFunction:
        if not in_hooked_process:
            func.original_code_start = func.hooked_code_start = 0
            func.original = _no_original_in_unhooked_process
            func.unhook = _no_unhook_in_unhooked_process
            all_hooks.append(func)
            return func
        try:
            r = insert_hook(
                addr_desc,
                func,
                position_independent_bytes=position_independent_bytes,
                return_pop=return_pop,
                orignal_function_spec=orignal_function_spec,
                remove_atexit=remove_atexit,
            )
            all_hooks.append(r)
            return r
        except:
            logger.warning(f" ! Failed to hook {addr_desc}")
            traceback.print_exc()
            return func

    return try_insert_hook  # type: ignore


def insert_iat_hook(
    target_module_or_function: str | Module | ResolvedFunctionImport,
    func_desc: str | None,
    func_: HookableFunction,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    return_pop: int = 0,
    resolve_ordinal_imports: bool = True,
) -> HookedFunction:
    func = typing.cast(HookedFunction, func_)

    if isinstance(target_module_or_function, ResolvedFunctionImport):
        if func_desc is not None:
            raise ValueError(
                "func_desc must be None when target_module_or_function is a ResolvedFunctionImport"
            )
        iat_entry = target_module_or_function
        target_module_name = iat_entry.from_module_imports.imported_by.name
        func_desc = f"{iat_entry.from_module_imports.name}!{iat_entry.name}"
        logger.info(f" * Hooking {target_module_name}:{func_desc} to run {func}")
    else:
        if func_desc is None:
            raise ValueError(
                "func_desc must be specified when target_module_or_function is a module/module name"
            )

        if isinstance(target_module_or_function, str):
            target_module_name = target_module_or_function
            logger.info(f" * Hooking {target_module_name}:{func_desc} to run {func}")

            # FIXME: modules may be out of date
            target_module = modules[target_module_name.lower()]
        else:
            target_module = target_module_or_function
            target_module_name = target_module.name
            logger.info(f" * Hooking {target_module}:{func_desc} to run {func}")

        module_name, func_name_ord = func_desc.split("!")
        module_imports = target_module.imports[module_name]
        if resolve_ordinal_imports:
            iat_entry = module_imports.by_name_and_ordinal[func_name_ord]
        else:
            try:
                func_ord = int(func_name_ord)
            except ValueError:
                iat_entry = module_imports.by_name[func_name_ord]
            else:
                iat_entry = module_imports.by_ordinal[func_ord]

        logger.info(
            f"  - Resolved {target_module}:{func_desc} -> thunk=0x{iat_entry.thunk:08x} -> 0x{iat_entry.resolved_address:08x}"
        )

    landing_address = make_landing(
        func,
        iat_entry.resolved_address,
        target_module_name + ":" + func_desc,
        iat_entry.resolved_address,
        return_pop=return_pop,
    )

    func.original_code_start = iat_entry.resolved_address
    func.original = NotImplemented
    if orignal_function_spec:
        if len(orignal_function_spec) == 3:
            calltype = orignal_function_spec[2]
            if calltype == "thiscall":
                func.original = make_thiscall(
                    func.original_code_start, orignal_function_spec[0], *orignal_function_spec[1]
                )
            else:
                raise ValueError(f"Unknown calltype: {calltype}")
        else:
            func.original = ctypes.CFUNCTYPE(orignal_function_spec[0], *orignal_function_spec[1])(
                func.original_code_start
            )
    else:
        func.original = ctypes.CFUNCTYPE(ctypes.c_size_t)(func.original_code_start)
    func.unhook = NotImplemented

    logger.info(f"  - Patching thunk to point to landing")
    old_permissions = ctypes.wintypes.DWORD()
    if not VirtualProtectEx(
        own_process_handle,
        iat_entry.thunk,
        WORDSIZE,
        PAGE_READWRITE,
        ctypes.byref(old_permissions),
    ):
        raise ValueError("Error: VirtualProtectEx %04x" % ctypes.windll.kernel32.GetLastError())
    ctypes.memmove(
        iat_entry.thunk,
        ctypes.create_string_buffer(struct.pack("<" + WORDPACK, landing_address)),
        WORDSIZE,
    )
    if not VirtualProtectEx(
        own_process_handle,
        iat_entry.thunk,
        WORDSIZE,
        old_permissions.value,
        ctypes.byref(old_permissions),
    ):
        raise ValueError("Error: VirtualProtectEx %d" % ctypes.windll.kernel32.GetLastError())

    return func


@typing.overload
def hook_iat(
    target_module_or_function: str,
    func_desc: str,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    return_pop: int = 0,
    resolve_ordinal_imports: bool = True,
) -> typing.Callable[[HookableFunction], HookedFunction]: ...
@typing.overload
def hook_iat(
    target_module_or_function: Module,
    func_desc: str,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    return_pop: int = 0,
    resolve_ordinal_imports: bool = True,
) -> typing.Callable[[HookableFunction], HookedFunction]: ...
@typing.overload
def hook_iat(
    target_module_or_function: ResolvedFunctionImport,
    func_desc: None = None,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    return_pop: int = 0,
    resolve_ordinal_imports: bool = True,
) -> typing.Callable[[HookableFunction], HookedFunction]: ...
def hook_iat(
    target_module_or_function: str | Module | ResolvedFunctionImport,
    func_desc: str | None = None,
    orignal_function_spec: tuple[type[CData] | None, tuple[type[CData], ...]]
    | tuple[type[CData] | None, tuple[type[CData], ...], str]
    | None = None,
    return_pop: int = 0,
    resolve_ordinal_imports: bool = True,
) -> typing.Callable[[HookableFunction], HookedFunction]:
    def try_insert_iat_hook(func: HookedFunction) -> HookedFunction:
        if not in_hooked_process:
            func.original_code_start = 0
            return func
        try:
            return insert_iat_hook(
                target_module_or_function,
                func_desc,
                func,
                orignal_function_spec=orignal_function_spec,
                return_pop=return_pop,
                resolve_ordinal_imports=resolve_ordinal_imports,
            )
        except:
            logger.warning(f" ! Failed to hook iat {target_module_or_function} {func_desc}")
            traceback.print_exc()
            return func

    return try_insert_iat_hook  # type: ignore


def hook_self() -> None:
    sys.in_hooked_process = True  # type: ignore
    global in_hooked_process
    in_hooked_process = sys.in_hooked_process  # type: ignore


__all__ = [
    "InHook",
    "insert_hook",
    "insert_iat_hook",
    "hook",
    "hook_iat",
    "hook_self",
    "in_hooked_process",
    "in_hook",
    "all_hooks",
    "make_thiscall",
]
