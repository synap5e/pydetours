# from __future__ import annotations

# import ctypes
# import typing

# # My code look like this so user code can look like...


# if typing.TYPE_CHECKING:
#     CData = ctypes._CData
#     SimpleCData = ctypes._SimpleCData
#     from pydetours.hook import Arguments, InHook, ModuleExport, Registers, StringArg
#     from pydetours.pointer import BasePointer
# else:
#     CData = InHook = Registers = Arguments = typing.Any
#     _T = typing.TypeVar("_T")
#     class SubscriptableAny(typing.Generic[_T]):
#         pass
#     SimpleCData = StringArg = BasePointer = SubscriptableAny


# HookableFunctionConvertableArg = int | bool | bytes | SimpleCData[typing.Any] | BasePointer[typing.Any] | StringArg[typing.Any]
# HookableFunctionReturn = int | bool | None


# _A = typing.TypeVar("_A", int, bool, bytes, SimpleCData[typing.Any], BasePointer[typing.Any], StringArg[typing.Any])
# _R = typing.TypeVar("_R", int, bool, None)

# # HookableFunction = typing.Union[
# #     # For fucks sake python
# #     typing.Callable[[Registers], _R],
# #     typing.Callable[[Registers, _A], _R],
# #     typing.Callable[[Registers, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, _A, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Arguments], _R],
# #     typing.Callable[[Arguments, _A], _R],
# #     typing.Callable[[Arguments, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Arguments, _A, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments], _R],
# #     typing.Callable[[Registers, Arguments, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[Registers, Arguments, _A, _A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[_A], _R],
# #     typing.Callable[[_A, _A], _R],
# #     typing.Callable[[_A, _A, _A], _R],
# #     typing.Callable[[_A, _A, _A, _A], _R],
# #     typing.Callable[[_A, _A, _A, _A, _A], _R],
# #     typing.Callable[[_A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[_A, _A, _A, _A, _A, _A, _A], _R],
# #     typing.Callable[[_A, _A, _A, _A, _A, _A, _A, _A], _R],
# # ]
# class HookableFunction(typing.Protocol):
#     # @staticmethod
#     # @typing.overload
#     # def __call__(arg1: _A) -> _R: ...
#     # @staticmethod
#     # @typing.overload
#     # def __call__(arg1: _A, args: _A) -> _R: ...
#     @staticmethod
#     # @typing.overload
#     def __call__[_A](arg1: _A, args: _A, arg4: _A) -> None: ...
#     # @staticmethod
#     # @typing.overload
#     # def __call__(arg1: _A, args: _A, arg4: _A, arg5: _A) -> _R: ...
#     # @staticmethod
#     # @typing.overload
#     # def __call__(arg1: _A, args: _A, arg4: _A, arg5: _A, arg6: _A) -> _R: ...


# class HookedFunction(typing.Protocol):
#     in_hook: InHook
#     original_code_start: int
#     original: typing.Callable[..., CData | None]
#     hooked_code_start: int
#     unhook: typing.Callable[[], None]

#     # And to add insult to injury, we have to define __call__ for each overload
#     # No, we can't just make HookableFunction a protocol with overloaded __call__s then extend it with HookedFunction...
#     # Why? Because python.
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arg1: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arg1: _A, args2: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arg1: _A, args2: _A, arg3: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arg1: _A, args2: _A, arg3: _A, arg4: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arg1: _A, args2: _A, arg3: _A, arg4: _A, arg5: _A) -> _R: ...
    
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments, arg1: _A) -> _R: ... 
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments, arg1: _A, args2: _A) -> _R: ... 
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments, arg1: _A, args2: _A, arg3: _A) -> _R: ... 
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments, arg1: _A, args2: _A, arg3: _A, arg4: _A) -> _R: ... 
#     @staticmethod
#     @typing.overload
#     def __call__(arguments: Arguments, arg1: _A, args2: _A, arg3: _A, arg4: _A, arg5: _A) -> _R: ... 
    
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments, arg1: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments, arg1: _A, args2: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments, arg1: _A, args2: _A, arg3: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments, arg1: _A, args2: _A, arg3: _A, arg4: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(registers: Registers, arguments: Arguments, arg1: _A, args2: _A, arg3: _A, arg4: _A, arg5: _A) -> _R: ...

#     @staticmethod
#     @typing.overload
#     def __call__(arg1: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(arg1: _A, args: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(arg1: _A, args: _A, arg4: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(arg1: _A, args: _A, arg4: _A, arg5: _A) -> _R: ...
#     @staticmethod
#     @typing.overload
#     def __call__(arg1: _A, args: _A, arg4: _A, arg5: _A, arg6: _A) -> _R: ...


# HookFuncT = typing.TypeVar("HookFuncT", bound=HookedFunction)
