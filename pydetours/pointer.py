from __future__ import annotations

import collections
import ctypes
import dataclasses
import logging
import traceback
import typing
from abc import abstractmethod

from pydetours.ctypedefs import *
from pydetours.struct_dataclasses import DataclassInstance, dataclass_to_structure

logger = logging.getLogger(__name__)

StoredDerefType = typing.TypeVar("StoredDerefType")
CastDerefType = typing.TypeVar("CastDerefType")
DerefType = typing.TypeVar("DerefType")


class NullPointerDeref(ValueError):
    pass


class UntypedPointerDeref(ValueError):
    pass


@typing.runtime_checkable
class _HasFromAddress(typing.Protocol):
    @classmethod
    def from_buffer(cls, source: bytes, offset: int = ...) -> _HasFromAddress: ...

    @classmethod
    def from_buffer_copy(cls, source: bytes, offset: int = ...) -> _HasFromAddress: ...

    @classmethod
    def from_address(cls, address: int) -> _HasFromAddress: ...

    # value: typing.Any


HasFromAddress = typing.Type[_HasFromAddress]


class StructField(typing.Protocol):
    offset: int


class _UndefinedType:
    """
    Sentinal type for when a type is not specified.
    PRIVATE TYPE - DO NOT EXPORT.
    For "untyped" pointers, use `Pointer[None]` instead - this type is used internally to represent when a pointer must try to infer its type from its __orig_class__.
    """

    pass


def reprtype(type_: type) -> str:
    st = typing.get_origin(type_)
    if st:
        it = typing.get_args(type_)[0]
        return f"{st.__qualname__}[{reprtype(it)}]"
    else:
        return type_.__qualname__


def is_pointer(type_: type) -> bool:
    # if not isinstance(type_, type):
    #     return False
    logger.info(f"Checking if {type_} is a pointer")
    if issubclass(type_, BasePointer):
        return True
    origin = typing.get_origin(type_)
    if origin and issubclass(origin, BasePointer):
        return True
    return False


def pointer_type(type_: BasePointer[typing.Any]) -> type:
    if hasattr(type_, "__orig_class__"):
        return typing.get_args(type_.__orig_class__)[0]
    return type(None)


def get_final_arg(arg: typing.Any) -> type | None:
    if typing.get_origin(arg) in [SafePointer, UnsafePointer]:
        return get_final_arg(typing.get_args(arg)[0])
    else:
        return arg


class BasePointer(typing.Generic[StoredDerefType]):
    def __init__(
        self,
        base_address: int | BasePointer[type],
        type_: typing.Type[StoredDerefType] | typing.Type[_UndefinedType] = _UndefinedType,
        offset: int = 0,
        offsets: int | tuple[int, ...] = 0,
        length: int | None = None,
        encoding: str = "ascii",
    ) -> None:
        self.base_address = base_address
        if isinstance(offsets, int):
            offsets = (offsets,)
        if offset and sum(offsets):
            raise ValueError(f"Cannot specify both offset and offsets for {self.__class__}")
        if not isinstance(offsets, collections.abc.Sequence) or any(
            not isinstance(o, int) for o in offsets
        ):  # type: ignore
            raise TypeError(f"Invalid offset {offsets} for {self.__class__}")
        self.offsets: tuple[int, ...] = offsets
        self.length = length
        logger.debug(
            f"Creating {self.__class__} with {base_address=}, {type_=}, {offset=}, {offsets=}, {length=}, {encoding=}"
        )
        self.type_: type = type_
        self.encoding = encoding
        self._int_cache: int | None = None

    def at(self, index: int) -> BasePointer[BasePointer[StoredDerefType]]:
        """
        Create a new pointer at the given index, relative to this pointer.
        """
        origin = typing.get_origin(self.__class__) or self.__class__
        base_address = self.copy(offsets=self.offsets + (index * ctypes.sizeof(self.type),))
        return origin(
            base_address,
            self.type,
            (0,),
        )

    @typing.overload
    def copy(
        self,
        /,
        type_: typing.Type[CastDerefType] | None,
        offsets: int | tuple[int, ...] | None = None,
        length: int | None = None,
        encoding: str | None = None,
    ) -> BasePointer[CastDerefType]: ...
    @typing.overload
    def copy(
        self,
        /,
        type_: typing.Type[_UndefinedType] = _UndefinedType,
        offsets: int | tuple[int, ...] | None = None,
        length: int | None = None,
        encoding: str | None = None,
    ) -> typing.Self: ...
    def copy(
        self,
        /,
        type_: typing.Type[CastDerefType] | typing.Type[_UndefinedType] | None = _UndefinedType,
        offsets: int | tuple[int, ...] | None = None,
        length: int | None = None,
        encoding: str | None = None,
    ) -> BasePointer[CastDerefType]:
        base_address = self.base_address
        if offsets is None:
            offsets = self.offsets
        if length is None:
            length = self.length
        if type_ is _UndefinedType:
            type_ = self.type
        if encoding is None:
            encoding = self.encoding
        origin = typing.get_origin(self.__class__) or self.__class__
        return origin(
            base_address=base_address,
            offsets=offsets,
            length=length,
            type_=type_,  # type: ignore
            encoding=encoding,
        )  # type: ignore

    def cast(self, type_: typing.Type[DerefType]) -> BasePointer[DerefType]:
        return self.copy(type_=type_)

    @property
    def type(self) -> type:
        """
        The deref type for this pointer, or None if the pointer is untyped.
        """
        if self.type_ is not _UndefinedType:
            return self.type_
        else:
            self.type_ = pointer_type(self)
        return self.type_

    @property
    def offset(self) -> int:
        return sum(self.offsets)

    def __int__(self) -> int:
        if self._int_cache:
            return self._int_cache
        if isinstance(self.base_address, BasePointer):
            d = self.base_address.deref(ctypes.c_void_p).value
            if not d:
                raise ValueError(f"Cannot dereference null pointer")
            return d + self.offset
        else:
            return self.base_address + self.offset

    @property
    def addr_str(self) -> str:
        if isinstance(self.base_address, BasePointer):
            base_addr_str = "*" + self.base_address.addr_str
        elif self.base_address:
            base_addr_str = f"{self.base_address:#x}"
        else:
            base_addr_str = "null"
        if self.offset:
            return f"({base_addr_str}+" + "+".join(f"{o:#x}" for o in self.offsets if o) + ")"
        else:
            return f"{base_addr_str}"

    _CTYPE_MAPS: dict[typing.Type[typing.Any], HasFromAddress] = {
        int: ctypes.c_int,
        float: ctypes.c_float,
    }

    @typing.overload
    def deref(self) -> StoredDerefType: ...

    @typing.overload
    def deref(self, type_: typing.Type[DerefType]) -> DerefType: ...

    def deref(self, type_: typing.Type[DerefType] | None = None):
        if not type_:
            type_ = self.type
        if type_ is type(None):
            raise UntypedPointerDeref(f"Cannot dereference untyped {self.__class__}")

        assert type_ is not _UndefinedType

        if isinstance(self.base_address, BasePointer):
            d = self.base_address.deref(ctypes.c_void_p).value
            if not d:
                raise NullPointerDeref(f"Cannot dereference null pointer")
        else:
            d = self.base_address
        self._int_cache = d + self.offset
        if int(self) == 0:
            raise NullPointerDeref(f"Cannot dereference null pointer")

        r: typing.Any
        origin = typing.get_origin(type_)
        if origin and issubclass(origin, BasePointer):
            assert issubclass(type_, BasePointer)
            r = type_(self.deref_from_address(ctypes.c_void_p).value or 0)
        elif dataclasses.is_dataclass(type_):
            struct_type = dataclass_to_structure(type_, pointer_type=self.__class__)
            r = self.deref_from_address(struct_type).as_dataclass()
            # r = struct_type.from_buffer_copy(self.deref_bytes(ctypes.sizeof(struct_type))).as_dataclass()
        elif type_ == str:
            r = self.deref_string(encoding=self.encoding)
        elif type_ == bytes:
            r = self.deref_bytes()
        elif type_ == memoryview:
            r = self.readable_view
        elif type_ in self._CTYPE_MAPS:
            r = self.deref_from_address(self._CTYPE_MAPS[type_]).value
        elif isinstance(type_, type) and issubclass(type_, ctypes.Structure):
            r = self.deref_from_address(type_)
        elif hasattr(type_, "from_address"):
            r = self.deref_from_address(typing.cast(HasFromAddress, type_))
        else:
            raise NotImplementedError(f"Cannot dereference {repr(self)} to {type_}")

        logger.debug(
            f"Dereferencing {self.addr_str}={int(self):#x} as {type_.__qualname__} => {repr(r)}"
        )

        self._int_cache = None
        return r

    def resolve(self) -> typing.Self:
        """
        Resolve this pointer to a pointer of the same type, but with the offsets applied to the base address.
        This will recursively resolve all pointers in the chain.

        Returns a new pointer, does not modify this pointer.
        """
        return self.__class__(int(self), offset=0, type_=self.type, length=self.length)

    def deref_bytes(self, length: int | None = None) -> bytes:
        length = length or self.length
        if not length:
            raise ValueError(
                f"Refusing to convert {self.__class__} to bytes without length - consider using view or view_w"
            )
        r = self.read(length)
        if isinstance(r, memoryview):
            return r.tobytes()
        else:
            return r

    @typing.overload
    def deref_string(self, encoding: str, max_length: int | None = None) -> str: ...
    @typing.overload
    def deref_string(self, encoding: None, max_length: int | None = None) -> bytes: ...
    def deref_string(
        self, encoding: str | None = "ascii", max_length: int | None = None
    ) -> str | bytes:
        if not int(self):
            raise ValueError(f"Cannot read string from null pointer")
        # logger.debug(f'Dereferencing {self.addr_str} > {int(self):#x} as str')
        b = ctypes.string_at(int(self), max_length or self.length or -1)
        if encoding:
            return b.decode(encoding)
        else:
            return b

    def __str__(self) -> str:
        str_val = self.__class__.__qualname__ + "["
        if self.type:
            str_val += reprtype(self.type)
        else:
            str_val += "?"
        str_val += f"]("

        address_str = self.addr_str
        if address_str.startswith("("):
            str_val += address_str[1:-1]
        else:
            str_val += address_str

        if self.type is not type(None):
            str_val += ", deref()="
            a: int | None = None
            try:
                a = int(self)
            except:
                pass
            base_type = typing.get_origin(self.type) or self.type
            if a == 0:
                str_val += "null"
            elif base_type and issubclass(base_type, BasePointer):
                str_val += repr(self)
            elif self.type == ctypes.c_void_p:
                try:
                    str_val += (
                        f"{typing.cast(BasePointer[ctypes.c_void_p], self).deref().value or 0:#x}"
                    )
                except (NullPointerDeref, OSError) as e:
                    str_val += f"<ERROR IN DEREF: {e}>"
                    lines = "\n".join(traceback.format_exc().splitlines())
                    try:
                        v = hex(int(self))
                    except:
                        v = "?"
                    logger.debug(f"Error dereferencing {self.addr_str} > {v}: \n{lines}")
            else:
                try:
                    str_val += repr(self.deref())
                except (NullPointerDeref, OSError) as e:
                    str_val += f"<ERROR IN DEREF: {e}>"
                    lines = "\n".join(traceback.format_exc().splitlines())
                    try:
                        v = hex(int(self))
                    except:
                        v = "?"
                    logger.debug(f"Error dereferencing {self.addr_str} > {v}: \n{lines}")
        return str_val + ")"

    @property
    def type_name(self) -> str:
        if self.type:
            return f"{self.__class__.__qualname__}[{reprtype(self.type)}]"
        else:
            return f"{self.__class__.__qualname__}[?]"

    def __repr__(self):
        return self.type_name + "(" + self.addr_str + ")"

    # def __getitem__(self, type_: typing.Type[DerefType]) -> BasePointer[DerefType]:
    #     if self.type == type_:
    #         return typing.cast(BasePointer[DerefType], self)
    #     return self.cast(type_)

    def __getitem__(self, i: int) -> typing.Self:
        if isinstance(self.type, BasePointer) or typing.get_origin(self.type) is BasePointer:
            size = ctypes.sizeof(ctypes.c_void_p)
        else:
            logger.debug(f"Computing size of {self.type} for __getitem__")
            size = ctypes.sizeof(self.type)
        return self.copy(offsets=self.offsets + (i * size,))

    # def __getattr__[DerefType](self, name: str) -> BasePointer[DerefType]:
    def __getattr__(
        self, name: str, as_: typing.Type[DerefType] | None = None
    ) -> BasePointer[typing.Any]:
        """
        If this Pointer points to a dataclass, create an offset (i.e. relative to this) pointer to the dataclasses field `name`.

        If that field itself is a pointer, a "lazy" pointer is created to that field, which will perform all memory accesses (i.e. recursive derefecences) only when it is dereferenced.

        This can be performed recursively, i.e. `Pointer[MyStruct](0x1234).nested_struct.parent.struct_pointer` will create a pointer to `MyStruct.nested_struct.parent.struct_pointer`, which will be resolved when dereferenced.

        Example
        ```
        @dataclass
        class MyOtherStruct:
            pad1: ctypes.c_void_p
            pad2: ctypes.c_void_p
            parent: Pointer[MyStruct]

        @dataclass
        class MyStruct:
            pad: ctypes.c_void_p
            struct_pointer: Pointer[MyOtherStruct]
            nested_struct: MyOtherStruct

        p = Pointer[MyStruct](0x1234)
        print(p)                                      # Pointer[MyStruct          ](       0x1234                         ), ...
        print(p.struct_pointer)                       # Pointer[MyOtherStruct     ](    *( 0x1234 + 0x8 )                 ), ...
        print(p.struct_pointer.parent)                # Pointer[MyStruct          ]( *( *( 0x1234 + 0x8 ) + 0x10 )        ), ...
        print(p.nested_struct)                        # Pointer[MyOtherStruct     ](       0x1234 + 0x10                  ), ...
        print(p.nested_struct.parent)                 # Pointer[MyStruct          ](    *( 0x1234 + 0x10 + 0x10)          ), ...
        print(p.nested_struct.parent.struct_pointer)  # Pointer[MyOtherStruct     ]( *( *( 0x1234 + 0x10 + 0x10 ) + 0x8 ) ), ...
        ```

        """
        if name == "__orig_class__":
            # IMPORTANT: make sure this is checked *before* we attempt to access call pointer_type() (or access .type which calls pointer_type())
            raise AttributeError(name)

        type_ = self.type_
        if type_ is _UndefinedType:
            type_ = pointer_type(self)
        if type_ and dataclasses.is_dataclass(self.type):
            converted = dataclass_to_structure(
                typing.cast(DataclassInstance, self.type), pointer_type=self.__class__
            )
            if hasattr(converted, name):
                field: StructField = getattr(converted, name)
                field_type = converted.__struct_meta__.type_hints[name]
                field_origin = typing.get_origin(field_type) or field_type
                dataclass_type = get_final_arg(field_type)
                new_offsets = (*self.offsets, field.offset)
                if issubclass(field_origin, BasePointer):
                    # If it's a pointer, we first make a copy of our own pointer with the offsets updated to point into the struct
                    # i.e.   struct foo {       <- self
                    #           int a;
                    #           int *b;         <- adjusted_pointer
                    #         }
                    # Then we create a new pointer of the correct type, using the "value" (address) at the new pointer as its address
                    #           int *b;         <- adjusted_pointer <- result
                    # which is more or less
                    #           int b;          <- result
                    adjusted_pointer = self.copy(offsets=new_offsets, type_=ctypes.c_void_p)
                    result = field_origin(adjusted_pointer, type_=dataclass_type)  # type: ignore
                else:
                    # If it's not a pointer, we just create a copy of our own pointer with the offsets updated
                    # i.e.   struct foo {       <- self
                    #           int a;
                    #           int b;          <- result
                    #         }
                    result = self.copy(offsets=new_offsets, type_=dataclass_type)

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        f"Creating offset pointer {self.type_name}.{name} for field type={field_origin.__qualname__} offset={field.offset:#x}: "
                        f"{self!r} => {result!r}"
                    )
                return result
        return object.__getattribute__(self, name)

    # def __setattr__(self, name, value):
    #     logger.warning(f'__setattr__({name}, {value})')
    #     super().__setattr__(name, value)

    @abstractmethod
    def read(self, length: int | None = None) -> bytes | memoryview: ...

    @property
    @abstractmethod
    def readable_view(self) -> memoryview:
        raise NotImplementedError("Not implemented")

    @property
    @abstractmethod
    def writeable_view(self) -> memoryview:
        raise NotImplementedError("Not implemented")

    @abstractmethod
    def deref_from_address(self, type_: HasFromAddress) -> typing.Any:
        raise NotImplementedError("Not implemented")


class UnsafePointer(BasePointer[DerefType]):
    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        self._view: memoryview | None = None
        self._view_w: memoryview | None = None

        super().__init__(*args, **kwargs)

    @property
    def readable_view(self) -> memoryview:
        if not self._view:
            self._view = PyMemoryView_FromMemory(int(self), self.length or MAXINT, PyBUF_READ)
            assert self._view
        return self._view

    @property
    def writeable_view(self) -> memoryview:
        if not self._view_w:
            self._view_w = PyMemoryView_FromMemory(int(self), self.length or MAXINT, PyBUF_WRITE)
            assert self._view_w
        return self._view_w

    view = readable_view

    def read(self, length: int | None = None) -> bytes | memoryview:
        if length:
            return self.readable_view[:length]
        else:
            return self.readable_view

    def deref_from_address(self, type_: HasFromAddress) -> typing.Any:
        return type_.from_address(int(self))


class SafePointer(BasePointer[DerefType]):
    @property
    def readable_view(self) -> typing.NoReturn:
        raise ValueError(f"Cannot access memoryview of a SafePointer")

    @property
    def writeable_view(self) -> typing.NoReturn:
        raise ValueError(f"Cannot access memoryview of a SafePointer")

    def read(self, length: int | None = None) -> bytes:
        if length is None:
            length = self.length
        if length is None:
            raise ValueError(f"Cannot read unbound length from SafePointer")
        elif length == 0:
            return b""
        buf = (ctypes.c_uint8 * length)()
        ctypes.memmove(buf, int(self), length)
        return bytes(buf)

    def deref_from_address(self, type_: HasFromAddress) -> typing.Any:
        # FIXME: support write
        return type_.from_buffer_copy(self.read(ctypes.sizeof(typing.cast(typing.Any, type_))))


Pointer = SafePointer


__all__ = [
    "BasePointer",
    "SafePointer",
    "UnsafePointer",
    "Pointer",
    "is_pointer",
    "pointer_type",
    "NullPointerDeref",
    "UntypedPointerDeref",
]
