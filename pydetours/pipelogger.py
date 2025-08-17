import ctypes
import io
import logging
import time
import typing

from pydetours.ctypedefs import (
    GENERIC_READ,
    GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    CreateFile,
    ReadFile,
)

logger = logging.getLogger("pydetours.pipelogger")


def read_pipelogger(output: io.StringIO, pipe_name: str):
    logger.info(f"Waiting for pipe: {pipe_name}")
    while True:
        pipe = CreateFile(
            pipe_name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None
        )
        if pipe != INVALID_HANDLE_VALUE:
            logger.info(f"Connected to pipe: {pipe_name}")
            break
        time.sleep(0.1)

    buf = ctypes.create_string_buffer(0x100)
    read = ctypes.c_uint32()
    while True:
        ReadFile(pipe, buf, 0x100, ctypes.byref(read), None)
        if read.value:
            data = typing.cast(bytes, buf[: read.value])
            output.write(data.decode())
        else:
            time.sleep(0.1)


__all__ = [
    "read_pipelogger",
]
