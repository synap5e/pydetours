import ctypes
import logging
import typing

from pydetours.ctypedefs import MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, VirtualAlloc
from pydetours.patch import Patch

if typing.TYPE_CHECKING:
    CData = ctypes._CData
else:
    CData = typing.Any

logger = logging.getLogger(__name__)
thiscall_addr = None
ConvertableToCtype = int | None | bytes


TRetType = typing.TypeVar("TRetType", bound=CData)
TThisType = typing.TypeVar("TThisType", bound=CData)
# PEP 0646 doesn't let us do type[*Ts] -> Ts lmfao "Just use overload"
# This bullshit is the only reason this is a separate file
# if typing.TYPE_CHECKING:
#     TArgType1 = typing.TypeVar("TArgType1", bound=CData)
#     TArgType2 = typing.TypeVar("TArgType2", bound=CData)
#     TArgType3 = typing.TypeVar("TArgType3", bound=CData)
#     TArgType4 = typing.TypeVar("TArgType4", bound=CData)
#     TArgType5 = typing.TypeVar("TArgType5", bound=CData)
#     @typing.overload
#     def make_thiscall(address: int, rtype: None) -> typing.Callable[[ctypes.c_void_p | int], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType]) -> typing.Callable[[ctypes.c_void_p | int], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, arg1: type[TArgType1]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], arg1: type[TArgType1]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, arg1: type[TArgType1], arg2: type[TArgType2]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], arg1: type[TArgType1], arg2: type[TArgType2]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3], arg4: type[TArgType4]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype, TArgType4 | ConvertableToCtype], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3], arg4: type[TArgType4]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype, TArgType4 | ConvertableToCtype], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3], arg4: type[TArgType4], arg5: type[TArgType5]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype, TArgType4 | ConvertableToCtype, TArgType5 | ConvertableToCtype], None]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], arg1: type[TArgType1], arg2: type[TArgType2], arg3: type[TArgType3], arg4: type[TArgType4], arg5: type[TArgType5]) -> typing.Callable[[ctypes.c_void_p | int, TArgType1 | ConvertableToCtype, TArgType2 | ConvertableToCtype, TArgType3 | ConvertableToCtype, TArgType4 | ConvertableToCtype, TArgType5 | ConvertableToCtype], TRetType]: ...
#     # if you have 6 args you're on your own
#     @typing.overload
#     def make_thiscall(address: int, rtype: type[TRetType], *argtypes: *tuple[type[TArgType1], type[TArgType2], type[TArgType3], type[TArgType4], type[TArgType5], *tuple[type[CData], ...]]
#                     ) -> typing.Callable[[ctypes.c_void_p | int, TArgType1, TArgType2, TArgType3, TArgType4, TArgType5, *tuple[CData | ConvertableToCtype, ...]], TRetType]: ...
#     @typing.overload
#     def make_thiscall(address: int, rtype: None, *argtypes: *tuple[type[TArgType1], type[TArgType2], type[TArgType3], type[TArgType4], type[TArgType5], *tuple[type[CData], ...]]
#                     ) -> typing.Callable[[ctypes.c_void_p | int, TArgType1, TArgType2, TArgType3, TArgType4, TArgType5, *tuple[CData | ConvertableToCtype, ...]], None]: ...
def make_thiscall(address: int, rtype: type[TRetType] | None, *argtypes: type[CData]):  # type: ignore

    global thiscall_addr
    if not thiscall_addr:
        thiscall_addr = int(VirtualAlloc(None, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))
        with Patch(thiscall_addr) as p:
            # Stack: ret addr, func addr, arg1, arg2, arg3, ...
            #        [esp]     [esp+4]    ...
            # p.int3()
            # p.mov("ecx", "[esp+8]")
            p.bytecode += b"\x8b\x4c\x24\x08"  # mov    ecx,DWORD PTR [esp+0x8]
            p.bytecode += b"\x8f\x44\x24\x04"  # pop    dword ptr [esp+4]
            # Stack: func addr, ret addr, arg2, arg3, ...
            p.ret()
        logger.info(f"  - Created thiscall trampoline at 0x{thiscall_addr:08x}")

    assert not rtype or isinstance(rtype, type), f"rtype must be a type, not {rtype!r}"
    assert all(isinstance(a, type) for a in argtypes), f"argtypes must be types, not {argtypes!r}"

    thiscall_cfunc = ctypes.CFUNCTYPE(
        rtype,
        ctypes.c_void_p,
        ctypes.c_void_p,
        *argtypes
    )(thiscall_addr)

    def thiscall_pyfunc(this: ctypes.c_void_p | int, *args: CData | ConvertableToCtype) -> TRetType:
        return thiscall_cfunc(address, this, *args)
    
    logger.info(f"  - Created thiscall_pyfunc(this, ...) => thiscall({address:#x}, this, ...)")
    return thiscall_pyfunc


__all__ = [
    "make_thiscall",
]