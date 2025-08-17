from typing import *

CallType = Callable[
    [
        str, *tuple[int, ...],
    ],
    None | str
]

class CallType2(Protocol):
    @staticmethod
    def __call__(a: str, *bs: int) -> None:
        ...


def foo(a: str, b: int) -> None:
    print(a, b)


bar: CallType = foo
baz: CallType2 = foo

P = ParamSpec("P", bound=int | str)