from __future__ import annotations

import ctypes
import logging
import sys
import time
import typing

from pydetours.ctypedefs import (
    GENERIC_READ,
    GENERIC_WRITE,
    OPEN_EXISTING,
    CloseHandle,
    CreateFile,
    WriteFile,
)

logger = logging.getLogger('pipeclient')

class PipeClient:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.pipe_name = f"\\\\.\\pipe\\pydetours_{pid}_commands"
        self.pipe = None

    def connect(self) -> None:
        logger.info(f'Waiting for pipe: {self.pipe_name}')
        while True:
            self.pipe = CreateFile(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if self.pipe == ctypes.c_void_p(-1).value:
                sys.stderr.write('.')
                time.sleep(1)
            else:
                sys.stderr.write('\n')
                break
        logger.info(f'Connected to pipe: {self.pipe_name}')

    def close(self) -> None:
        CloseHandle(self.pipe)

    def __enter__(self) -> PipeClient:
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def write(self, msg: str) -> None:
        WriteFile(self.pipe, (msg + '\n').encode(), len(msg) + 1, None, None)

    def read(self) -> str:
        raise NotImplementedError()
    
    def repl(self) -> None:
        while True:
            cmd = input('> ')
            self.write(cmd)


def connect_pipeclient(pid: int) -> typing.NoReturn:
    pipe_name = f"\\\\.\\pipe\\pydetours_{pid}_commands"

    logger.info(f'Waiting for pipe: {pipe_name}')
    while True:
        pipe = CreateFile(
            pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if pipe == ctypes.c_void_p(-1).value:
            print('.', end='')
            time.sleep(1)
        else:
            print()
            break
    logger.info(f'Connected to pipe: {pipe_name}')

    while True:
        cmd = input('> ')
        WriteFile(pipe, (cmd + '\n').encode(), len(cmd) + 1, None, None)

if __name__ == '__main__':
    connect_pipeclient(int(sys.argv[1]))


__all__ = [
    'PipeClient',
    'connect_pipeclient',
]