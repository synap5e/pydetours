from __future__ import annotations

import hexdump
from ast import Add, Not
import ctypes
from operator import add
import typing
from typing import Any
from loguru import logger


print(typing.__file__)

ValueType = typing.TypeVar("ValueType")
DerefType = typing.TypeVar("DerefType")
DerefAsType = typing.TypeVar("DerefAsType")
CastType = typing.TypeVar("CastType")


def is_pointer_type(type_: typing.Any, from_: str) -> bool:
    if typing.get_origin(type_) is Pointer:
        return True
    elif type_ is Pointer:
        # print(f"{type_} is a Pointer because it's type is Pointer {from_=}")
        return True
    elif isinstance(type_, Pointer):
        raise TypeError(f"is_pointer_type() is intended to be called on *types* - got a {type_}")
    return False


def c_fmt(address: Address | Reference | int, offset: tuple[int, ...] | int = ()) -> str:
    if isinstance(offset, int):
        offset = (offset,)
    # Flatten offset
    offset = tuple(x for x in offset if x != 0)
    # Resolve address to int if possible
    if isinstance(address, Address):
        base = address.base
        base_offset = address.offset
        base_str = c_fmt(base, base_offset)
        if offset:
            offset_str = " + " + " + ".join(map(hex, offset))
        else:
            offset_str = ""
        return f"({base_str}{offset_str})"
    elif isinstance(address, Reference):
        # Unwrap Reference to its address
        return c_fmt(address.address, address.offset)
    else:
        # address is int
        addr_str = f"0x{address:0x}"
        if offset:
            offset_str = " + " + " + ".join(map(hex, offset))
        else:
            offset_str = ""
        return f"({addr_str}{offset_str})"


def _fmt_offsets(offsets: tuple[int, ...]) -> str:
    if not offsets:
        return ""
    return " + " + " + ".join(map(hex, offsets))


def c_expr_address(address: Address | Reference | int) -> str:
    """
    Returns a compact C-style expression for an address that may include nested
    pointer dereferences and offsets, e.g. *(*(0xA + 0xB) + 0xC).
    This does NOT apply the final value dereference; it's for the address expr.
    """
    if isinstance(address, int):
        return f"0x{address:0x}"
    # Handle OffsetReference BEFORE Reference (since it's a subclass)
    if isinstance(address, OffsetReference):
        # Semantics: deref the pointer to get a base address, then add offsets.
        base = c_expr_address(address.address)
        offs = _fmt_offsets(address.offset)
        return f"*({base}){offs}"
    if isinstance(address, Reference):
        inner = c_expr_address(address.address)
        # For pointer-typed references, following the pointer requires a deref.
        if address.type is ctypes.c_void_p:
            return f"*({inner})"
        # For non-pointer types, inner already encodes any intermediate derefs.
        return f"{inner}"
    if isinstance(address, Address):
        inner = c_expr_address(address.base)
        return f"({inner}{_fmt_offsets(address.offset)})"
    return str(address)


class Address:
    def __init__(
        self,
        base: int | Address,
        offset: tuple[int, ...] | int = (),
    ):
        self.base: int | Address = base
        if isinstance(offset, int):
            offset = (offset,)
        self.offset: tuple[int, ...] = tuple(x for x in offset if x != 0)
        # logger.debug(f"Address created: {self}")

    def __int__(self) -> int:
        r = int(self.base) + sum(self.offset)
        # logger.debug(f"Resolving {self} -> {r:#x}")
        return r

    def __add__(self, other: int) -> Address:
        return Address(self.base, (*self.offset, other))

    # def as_ptr(self, to: type[CastType]) -> Pointer[CastType]:
    #     return Pointer(self, to)

    @property
    def resolved(self) -> bool:
        return isinstance(self.base, int) or (isinstance(self.base, Address) and self.base.resolved)

    def __str__(self) -> str:
        return c_fmt(self)

    __repr__ = __str__


class Reference(typing.Generic[ValueType]):
    def __init__(
        self,
        address: Address | int,
        type: type[ValueType] = ctypes.c_void_p,
        desc: str = "",
        typename: str | None = None,
        byval: bool = False,
    ):
        if isinstance(address, int):
            address = Address(address)
        self.address: Address = address
        self.type: type[ValueType] = type
        self.offset = ()
        self.desc = desc or type.__name__
        self.typename = typename
        self.byval = byval
        # logger.debug(f"Reference created: {self}")

    def __add__(self, offset: int) -> Reference[ctypes.c_void_p]:
        return OffsetReference(self.address, ctypes.c_void_p, offset)

    @property
    def contents(self) -> ValueType:
        return self.resolve()

    def __int__(self) -> None:
        if self.type not in [ctypes.c_void_p, ctypes.c_int]:
            raise TypeError(f"Cannot convert Reference[{self.type}] to int")
        r = self.resolve().value or 0
        logger.debug(f"Dereferencing {self=} -> {r:#x}")
        return r

    def resolve(self) -> ValueType:
        print(f"deref({self=}) {self.type=}")
        return self.type.from_address(int(self.address))

    def _format_chain(self) -> str:
        """Recursively format the full chain of lazy references."""
        chain = []
        ref = self
        while isinstance(ref, Reference):
            typename = ref.typename or ref.type.__name__
            addr_str = c_fmt(ref.address)
            desc = f", {ref.desc!r}" if ref.desc else ""
            chain.append(f"{typename} @ *{addr_str}{desc}")
            if not isinstance(ref.address, Reference):
                break
            ref = ref.address
        return " -> ".join(reversed(chain))

    def __str__(self) -> str:
        # Show a single top-level deref to indicate we're reading a value at the computed address.
        typename = self.typename or self.type.__name__
        expr = f"*({c_expr_address(self.address)})"
        desc = f", {self.desc!r}" if self.desc else ""
        return f"{self.__class__.__name__}({typename} @ {expr}{desc})"

    __repr__ = __str__

    def __getattr__(self, o: str) -> Reference[ctypes.c_void_p]:
        assert isinstance(o, str), f"Expected a string key - got {o!r}"
        f = getattr(self.type, o, None)
        t = dict(self.type._fields_)[o]
        if not f:
            raise TypeError(f"Field {o} not found in type {self.type}")
        if not hasattr(f, "offset"):
            raise TypeError(f"Field {o} in type {self.type} {f}is not a valid field")
        if not isinstance(f.offset, int):
            raise TypeError(f"Field {o} in type {self.type} is not a valid field with an offset")

        # If the field is a pointer, return a lazy Reference to the pointer value
        if str(type(t)) == "<class '_ctypes.PyCPointerType'>":
            # Reference to the pointer field itself (not dereferenced yet)
            return Reference(
                Reference(
                    self.address + f.offset,
                    ctypes.c_void_p,
                    desc="internal",
                ),
                t._type_,
                desc=f"{self.desc}->{o}",
                typename=t._type_.__name__,
            )

        # Non-pointer field: add offset as before
        return Reference(
            self.address + f.offset,
            t,
            desc=f"{self.desc}->{o}",
        )


class OffsetReference(Reference[ValueType]):
    def __init__(
        self,
        address: Address | int,
        type: type[ValueType] = ctypes.c_void_p,
        offset: tuple[int, ...] | int = 0,
    ):
        super().__init__(address, type)
        if isinstance(offset, int):
            offset = (offset,)
        self.offset: tuple[int, ...] = tuple(x for x in offset if x != 0)

    def __int__(self) -> int:
        value = ctypes.c_void_p.from_address(int(self.address)).value
        if not value:
            raise ValueError(
                f"Invalid address - got NULL at {self.address}: {int(self.address):#x}"
            )
        return value + sum(self.offset) or 0

    def __add__(self, offset: int) -> OffsetReference[ctypes.c_void_p]:
        return OffsetReference(self.address, ctypes.c_void_p, (*self.offset, offset))

    def __str__(self) -> str:
        typename = self.typename or self.type.__name__
        # Also show a top-level deref; OffsetReference contributes address arithmetic inside.
        expr = f"*({c_expr_address(self)})"
        return f"OffsetReference({typename} @ {expr})"

    __repr__ = __str__


SSL_MAX_KEY_ARG_LENGTH = 8  # Example value, adjust as needed


class Inner(ctypes.Structure):
    _fields_ = [
        ("a", ctypes.c_int),
        ("b", ctypes.c_int),
        ("c", ctypes.c_int),
    ]


class Outer(ctypes.Structure):
    _fields_ = [
        ("a", ctypes.c_int),
        ("inner_val", Inner),
        ("inner_ptr", ctypes.POINTER(Inner)),
        ("b", ctypes.c_int),
    ]


# Example usage:
true_inner = Inner()
true_inner.a = 1
true_inner.b = 2
true_inner.c = 3

true_outer = Outer()
true_outer.a = 12
true_outer.inner_val = true_inner
true_outer.inner_ptr = ctypes.pointer(true_inner)
true_outer.b = 34

true_inner.a = 777
true_inner.b = 888
true_inner.c = 999

buf = ctypes.create_string_buffer(0x1000)
ctypes.memmove(buf, ctypes.addressof(true_outer), ctypes.sizeof(true_outer))
print(f"true_outer: {ctypes.addressof(true_outer)=:#x} {true_outer}")
hexdump.hexdump(buf[: ctypes.sizeof(true_outer)])
print()

# true_outer.inner_val
ctypes.memmove(buf, ctypes.addressof(true_outer.inner_val), ctypes.sizeof(true_outer.inner_val))
print(f"true_outer.inner_val: {ctypes.addressof(true_outer.inner_val)=:#x} {true_outer.inner_val}")
hexdump.hexdump(buf[: ctypes.sizeof(true_outer.inner_val)])
print()

# true_outer.inner_ptr
ctypes.memmove(
    buf,
    ctypes.addressof(true_outer.inner_ptr.contents),
    ctypes.sizeof(true_outer.inner_ptr.contents),
)
print(
    f"true_outer.inner_ptr: {ctypes.addressof(true_outer.inner_ptr.contents)=:#x} {true_outer.inner_ptr.contents}"
)
hexdump.hexdump(buf[: ctypes.sizeof(true_outer.inner_ptr.contents)])
print("-" * 20)
print()


r_outer = Reference(ctypes.addressof(true_outer), type=Outer)
print(f"{r_outer=}")
print(f"{r_outer.a=}")
print(f"{r_outer.a.resolve()=}")
print(f"{r_outer.b=}")
print(f"{r_outer.b.resolve()=}")
print(f"{r_outer.resolve()=}")
print()

# v1_outer = r_outer.resolve()
# print(f"{v1_outer.a=}")
# print(f"{v1_outer.b=}")

print()
r1_inner_val = Reference(ctypes.addressof(true_outer.inner_val), type=Inner)
print(f"{r1_inner_val=}")
r2_inner_val = r_outer.inner_val
print(f"{r_outer.inner_val=}")
print(f"{r_outer.inner_val.resolve()=} {ctypes.addressof(r_outer.inner_val.resolve())=:#x}")
v1_inner_val = r1_inner_val.resolve()
print(f"r1_inner_val.resolve()={v1_inner_val} {ctypes.addressof(v1_inner_val)=:#x}")
print(f"{v1_inner_val.a=}")
print(f"{r1_inner_val.a=} {r1_inner_val.a.resolve()=}")
print(f"{v1_inner_val.b=}")
print(f"{r1_inner_val.b=} {r1_inner_val.b.resolve()=}")
print(f"{v1_inner_val.c=}")
print(f"{r1_inner_val.c=} {r1_inner_val.c.resolve()=}")
print()

r1_inner_ptr = r_outer.inner_ptr
print(f"r_outer.inner_ptr={r1_inner_ptr}")
r1_inner_ptr_deref = r1_inner_ptr.resolve()
print(
    f"r_outer.inner_ptr.resolve()={r1_inner_ptr_deref} {ctypes.addressof(r1_inner_ptr_deref)=:#x}"
)
print(f"{r_outer.inner_ptr.c=}")
print(f"{int(r_outer.inner_ptr.c.address)=:#x}")
print()
print(f"{r_outer.inner_ptr.c.resolve()=}")


class Node(ctypes.Structure):
    pass


Node._fields_ = [
    ("value", ctypes.c_int),
    ("left", ctypes.POINTER(Node)),
    ("right", ctypes.POINTER(Node)),
    ("leaf", ctypes.c_bool),
]


def create_bfs_tree(depth: int) -> Node:
    """Create a binary tree of given depth, value is BFS index."""
    from collections import deque

    # Create root node
    root = Node()
    root.value = 0
    root.leaf = False
    root.left = None
    root.right = None

    queue = deque()
    queue.append((root, 0))
    bfs_index = 1

    while queue:
        node, level = queue.popleft()
        if level + 1 < depth:
            # Create left child
            left = Node()
            left.value = bfs_index
            bfs_index += 1
            left.leaf = level + 2 == depth
            left.left = None
            left.right = None
            node.left = ctypes.pointer(left)
            queue.append((left, level + 1))

            # Create right child
            right = Node()
            right.value = bfs_index
            bfs_index += 1
            right.leaf = level + 2 == depth
            right.left = None
            right.right = None
            node.right = ctypes.pointer(right)
            queue.append((right, level + 1))
        else:
            node.left = None
            node.right = None
            node.leaf = True

    return root


def print_bfs_tree(root: Node):
    """Print tree nodes in BFS order."""
    from collections import deque

    queue = deque()
    queue.append(root)
    result = []
    while queue:
        node = queue.popleft()
        result.append(node.value)
        if node.left:
            queue.append(node.left.contents)
        if node.right:
            queue.append(node.right.contents)
    print("BFS values:", result)


# Create and print a 6-deep BFS-indexed tree
tree_root = create_bfs_tree(7)
print_bfs_tree(tree_root)

leaf = (
    tree_root.left.contents.right.contents.left.contents.right.contents.left.contents.left.contents
)
print(leaf.value)

r_root = Reference(ctypes.addressof(tree_root), type=Node)
leaf = r_root.left.right.left.right.left.left  # .left.left.left
print(leaf.value)
print(leaf.value.resolve())
