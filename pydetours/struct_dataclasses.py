"""
pydetours.struct_dataclasses

Purpose:
Convert dataclasses to ctypes.Structure.

Dataclasses can contain nested dataclasses, pointers to dataclasses, simple types (int, str, etc), or ctypes types.



"""

from __future__ import annotations

import collections
import ctypes
import dataclasses
import logging
import typing

if typing.TYPE_CHECKING:
    from ctypes import _CData as CData
else:
    CData = 'CData'


logger = logging.getLogger(__name__)


class DataclassInstance(typing.Protocol):
    __dataclass_fields__: typing.ClassVar[dict[str, dataclasses.Field[typing.Any]]]
    __name__: str

    def __call__(self, *args: typing.Any, **kwargs: typing.Any) -> DataclassInstance:
        ...



DataclassInstanceT = typing.TypeVar("DataclassInstanceT")


class ConvertedDataclassInstance(typing.Protocol, typing.Generic[DataclassInstanceT]):
    __dataclass_fields__: typing.ClassVar[dict[str, dataclasses.Field[typing.Any]]]
    __name__: str
    __struct_meta__: DataclassToStructureMeta[DataclassInstanceT]
    _address: int
    _struct: StructFromDataclass[DataclassInstanceT]

    def __call__(self, *args: typing.Any, **kwargs: typing.Any) -> DataclassInstanceT:
        ...


ConvertedDataclassInstanceT = typing.TypeVar(
    "ConvertedDataclassInstanceT", bound=ConvertedDataclassInstance[typing.Any]
)


class StructFromDataclass(ctypes.Structure, typing.Generic[DataclassInstanceT]):
    __struct_meta__: DataclassToStructureMeta[DataclassInstanceT]
    PointerType: typing.Any

    def _convert_field(self, field: str) -> typing.Any:
        from pydetours.pointer import BasePointer

        v: typing.Any = getattr(self, field)
        field_type = self.__struct_meta__.type_hints[field]

        assert not isinstance(
            field_type, (str, typing.ForwardRef)
        ), f"Field {field} has no type hint"
        # TODO: support for optional fields
        res: typing.Any
        if isinstance(v, StructFromDataclass):
            res = v.as_dataclass()
        elif issubclass(typing.get_origin(field_type) or field_type, BasePointer):
            res = self.PointerType(v or 0, type_=typing.get_args(field_type)[0])
            # if typing.get_args(field_type)[0] is str:
            #     res = v.deref()
        else:
            res = v
        logger.debug(
            f"Converting {self.__class__.__qualname__}.{field}: {v!r} (type={type(v).__qualname__}) => {res!r} (type={type(res).__qualname__})"
        )
        return res

    def as_dataclass(self) -> DataclassInstanceT:
        d = self.__struct_meta__.dataclass_type(
            **{
                f.name: self._convert_field(f.name)
                for f in dataclasses.fields(self.__struct_meta__.dataclass_type)
            }
        )
        d._address = ctypes.addressof(self)  # type: ignore
        d._struct = self  # type: ignore
        return d


class UnresolvedStruct(StructFromDataclass[typing.Any]):
    pass


@dataclasses.dataclass
class DataclassToStructureMeta(typing.Generic[DataclassInstanceT]):
    """
    The metadata for a dataclass that has been (or is being) converted to a structure.
    """

    name: str
    dataclass_type: ConvertedDataclassInstance[DataclassInstanceT]
    type_hints: dict[str, type]

    parents: set[ConvertedDataclassInstance[typing.Any]] = dataclasses.field(default_factory=set)
    children: set[ConvertedDataclassInstance[typing.Any]] = dataclasses.field(default_factory=set)
    pointer_children: set[ConvertedDataclassInstance[typing.Any]] = dataclasses.field(
        default_factory=set
    )

    structure_type: typing.Type[StructFromDataclass[DataclassInstanceT]] = UnresolvedStruct
    structure_completed: bool = False

    tsearch_parents: set[ConvertedDataclassInstance[typing.Any]] = dataclasses.field(
        default_factory=set
    )
    tsearch_children: set[ConvertedDataclassInstance[typing.Any]] = dataclasses.field(
        default_factory=set
    )

    visiter_id: int = 0

    def __str__(self):
        r = f"DataclassToStructureMeta(for={self.name}, parents=["
        r += ", ".join(p.__name__ for p in self.parents)
        r += "], children=["
        r += ", ".join(p.__name__ for p in self.children)
        r += "], pointer_children=["
        r += ", ".join(p.__name__ for p in self.pointer_children)
        r += "])"
        return r

    __repr__ = __str__


def is_optional(typ: type) -> type | None:
    if (
        typing.get_origin(typ) is typing.Union
        and len(typing.get_args(typ)) == 2
        and type(None) in typing.get_args(typ)
    ):
        return next(t for t in typing.get_args(typ) if t is not type(None))
    return None


SIMPLE_CTYPES: dict[typing.Any, typing.Type[CData]] = {
    int: ctypes.c_int,
    float: ctypes.c_float,
    # str: ctypes.c_char_p,
}


def issubclass_(cls: type | None, class_or_tuple: typing.Any):
    if not cls:
        return False
    try:
        return issubclass(cls, class_or_tuple)
    except TypeError:
        return False


def _converted_setattr(self: typing.Any, name: str, value: typing.Any) -> typing.Any:
    assert dataclasses.is_dataclass(self)
    f = next((f for f in dataclasses.fields(self) if f.name == name), None)
    if hasattr(self, "_struct") and f:
        logger.warning(f"Setting {self.__class__.__name__}.{f} = {value!r}")
        setattr(self._struct, name, value)
    return object.__setattr__(self, name, value)


def _dataclass_to_structure_walk(
    parent_: DataclassInstanceT, discovered_types: list[ConvertedDataclassInstance[DataclassInstanceT]]
) -> ConvertedDataclassInstance[DataclassInstanceT]:
    """
    Recursively walk a tree of nested/pointed dataclasses and record in `discovered_types`.

    Dataclasses should be fully resolved (i.e. all ForwardRefs resolve to their true type) before calling this function.

    """
    parent = typing.cast(ConvertedDataclassInstance[DataclassInstanceT], parent_)

    from pydetours.pointer import BasePointer

    if isinstance(parent, (typing.ForwardRef, str)):
        raise ValueError(
            f"Cannot discover dataclasses on ForwardRef {parent!r} - _dataclass_to_structure_walk must be called on fully resolved dataclasses/dataclass graphs"
        )

    if hasattr(parent, "__struct_meta__"):
        # FIXME: this hack helps if we walk a second dataclass graph and come across a dataclass that was already walked.
        # Unfortunatly the __struct_meta__ is fully overwritten on those shared dataclasses which might make the use of the __struct_meta__ on items in the first graph only unreliable.
        # Since __struct_meta__ is dundr it's not a huge deal, but it would be nice to be able to have __struct_meta__ have a more reliable contract.
        if parent.__struct_meta__.visiter_id != id(discovered_types):
            delattr(parent, "__struct_meta__")

    if dataclasses.is_dataclass(parent) and not hasattr(parent, "__struct_meta__"):
        name = getattr(parent, "__name__")
        logger.debug(f"Walking dataclass {name!r} to discover dataclass types")
        parent.__setattr__ = _converted_setattr  # type: ignore
        type_hints = typing.get_type_hints(parent)
        parent.__struct_meta__ = DataclassToStructureMeta(
            name=name,
            dataclass_type=parent,
            type_hints=type_hints,
            visiter_id=id(discovered_types),
        )
        discovered_types.append(parent)
        for field in dataclasses.fields(parent):
            if isinstance(field.type, (str, typing.ForwardRef)):
                field.type = type_hints[field.name]
            if issubclass_(typing.get_origin(field.type), BasePointer):
                pointee_type = typing.get_args(field.type)[0]
                if dataclasses.is_dataclass(pointee_type):
                    _dataclass_to_structure_walk(pointee_type, discovered_types)
                    parent.__struct_meta__.pointer_children.add(pointee_type)
                    logger.debug(
                        f' Creating structure field "{name}.{field.name}": type={field.type}'
                    )

            elif dataclasses.is_dataclass(field.type):
                field.type.__struct_meta__.parents.add(parent)  # type: ignore
                parent.__struct_meta__.children.add(field.type)  # type: ignore
    else:
        logger.debug(f"Skipping {parent!r} - not a dataclass or already walked")

    return parent


def dataclass_to_structure(
    root: typing.Callable[..., DataclassInstanceT],
    pointer_type: type,
    check: bool = True,
) -> typing.Type[StructFromDataclass[DataclassInstanceT]]:
    from pydetours.pointer import BasePointer, SafePointer

    if not dataclasses.is_dataclass(typing.cast(typing.Any, root)):
        # cast is required to break flow typing since we are using our own typing protocol for dataclass
        raise TypeError(f"{root} is not a dataclass")

    if hasattr(root, "__struct_meta__"):
        assert root.__struct_meta__ is not None  # type: ignore
        assert root.__struct_meta__.structure_type is not None  # type: ignore
        return root.__struct_meta__.structure_type  # type: ignore

    discovered_types: list[ConvertedDataclassInstance[typing.Any]] = []
    _dataclass_to_structure_walk(root, discovered_types)

    for dataclass_type in discovered_types:
        dataclass_type.__struct_meta__.tsearch_children = set(
            dataclass_type.__struct_meta__.children
        )
        dataclass_type.__struct_meta__.tsearch_parents = set(
            dataclass_type.__struct_meta__.parents
        )
        logger.debug(
            f"{dataclass_type} has children={dataclass_type.__struct_meta__.tsearch_children} parents={dataclass_type.__struct_meta__.tsearch_parents}"
        )

    logger.debug(f"Discovered types: {[t.__struct_meta__ for t in discovered_types]}")

    # Topological sort
    resolution_order = list[ConvertedDataclassInstance[typing.Any]]()
    root_nodes = [node for node in discovered_types if not node.__struct_meta__.parents]
    logger.debug(f'Root nodes: {", ".join(n.__name__ for n in root_nodes)}')
    assert root_nodes, "No parent nodes found"
    queue: typing.Deque[ConvertedDataclassInstance[typing.Any]] = collections.deque(root_nodes)
    while queue:
        node = queue.popleft()
        if node not in resolution_order:
            resolution_order.append(node)
        for child in list(node.__struct_meta__.tsearch_children):
            child.__struct_meta__.tsearch_parents.remove(node)
            node.__struct_meta__.tsearch_children.remove(child)
            if not child.__struct_meta__.tsearch_parents:
                queue.append(child)

    for dataclass_type in discovered_types:
        assert (
            not dataclass_type.__struct_meta__.tsearch_children
        ), f"{dataclass_type.__name__!r} has unresolved children - loop detected: {dataclass_type.__struct_meta__.tsearch_children}"
        assert (
            dataclass_type.__struct_meta__.structure_type is UnresolvedStruct
        ), f"{dataclass_type.__name__!r} already has a structure type"
        logger.debug(
            f"Defining dynamic subclass of StructFromDataclass for {dataclass_type.__name__!r}"
        )
        dataclass_type.__struct_meta__.structure_type = type(
            dataclass_type.__name__
            + "_"
            + "Safe" * (pointer_type is SafePointer)
            + "Struct",
            (StructFromDataclass,),
            {
                "__struct_meta__": dataclass_type.__struct_meta__,
                "PointerType": pointer_type,
            },
        )
        fields = getattr(
            dataclass_type.__struct_meta__.structure_type, "_fields_", None
        )
        logger.debug(f"{dataclass_type.__struct_meta__.structure_type=} {fields=}")

    # resolution_order = [converted_root]
    logger.debug(
        f'Struct {root.__name__!r} construction resolution order: [{", ".join(repr(e.__name__) for e in resolution_order)}]'
    )
    for dataclass_type in reversed(resolution_order):
        if dataclass_type.__struct_meta__.structure_completed:
            continue
        assert not hasattr(
            dataclass_type.__struct_meta__.structure_type, "_fields_"
        ), f"{dataclass_type.__struct_meta__.structure_type=} already has fields"

        fields = list[tuple[str, typing.Type[CData]] | tuple[str, typing.Type[CData], int]]()
        for field in dataclasses.fields(dataclass_type):
            field_type = field.type
            struct_field_type: typing.Type[CData]
            logger.debug(
                f"Field {field.name} of {dataclass_type.__name__} has type {field_type}"
            )
            if is_optional(field_type):
                field_type = typing.get_args(field_type)[0]
            assert not isinstance(
                field_type, (str, typing.ForwardRef)
            ), f"Field {field.name} of {dataclass_type.__name__} has unresolved type {field_type!r}. This should have been resolved in firstpass"
            if issubclass_(typing.get_origin(field_type), BasePointer):
                # pointer to a struct
                struct_field_type = ctypes.c_void_p
            elif dataclasses.is_dataclass(field_type):
                assert hasattr(field_type, "__struct_meta__")
                # nested struct
                struct_field_type = typing.cast(ConvertedDataclassInstance[typing.Any], field_type).__struct_meta__.structure_type
            elif field_type == str:
                raise TypeError(
                    f"Field {dataclass_type.__name__}.{field.name} is of type str. Use Pointer[str] instead."
                )
            elif field_type in SIMPLE_CTYPES:
                struct_field_type = SIMPLE_CTYPES[field_type]
            else:
                struct_field_type = field_type
            fields.append((field.name, struct_field_type))

        assert not hasattr(
            dataclass_type.__struct_meta__.structure_type, "_fields_"
        ), f"{dataclass_type.__struct_meta__.structure_type=} already has fields (2)"
        try:
            logger.debug(
                f'***Constructing {dataclass_type.__struct_meta__.structure_type.__name__!r} with fields {fields} | {getattr(dataclass_type.__struct_meta__.structure_type, "_fields_", None)=}'
            )
            dataclass_type.__struct_meta__.structure_type._fields_ = fields
        except:
            logger.error(
                f"Failed to construct {dataclass_type.__name__!r} with fields {fields} | {dataclass_type.__struct_meta__.structure_type._fields_=}"
            )
            raise
        else:
            logger.debug(
                f"Constructed {dataclass_type.__struct_meta__.structure_type.__name__!r} with fields {fields}"
            )
            dataclass_type.__struct_meta__.structure_completed = True

    # Now handle structs that are only pointed to
    # This will recurse into unreachable-by-nesting structs and perform `dataclass_to_structure`...
    #   hopefully tackling this in resolution_order doesn't end up in an unsatisfiable state (I'm not sure if it can on satisfiable structs...)
    for e in resolution_order:
        type_hints = typing.get_type_hints(e)
        for field in dataclasses.fields(e):
            typ = field.type
            assert not isinstance(typ, (str, typing.ForwardRef))
            if issubclass_(typing.get_origin(typ), BasePointer):
                p_type = typing.get_args(typ)[0]
                if isinstance(p_type, (str, typing.ForwardRef)):
                    p_type = typing.get_args(type_hints[field.name])[0]
                if dataclasses.is_dataclass(p_type):
                    if not p_type.__struct_meta__.structure_completed:
                        logger.debug(
                            f"Struct {e.__name__!r} has pointer-only struct {p_type.__name__!r} ({e.__name__}.{field.name}) - constructing {p_type.__name__!r}"
                        )
                        dataclass_to_structure(p_type, pointer_type, check=False)

    if check:
        for t in discovered_types:
            if not t.__struct_meta__.structure_completed:
                raise ValueError(
                    f"Struct {t.__name__!r} was referenced but not constructed"
                )

    assert hasattr(root, "__struct_meta__")
    assert root.__struct_meta__ is not None  # type: ignore
    assert root.__struct_meta__.structure_type is not None  # type: ignore
    return root.__struct_meta__.structure_type  # type: ignore
