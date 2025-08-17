def old_setup_output() -> None:
    raise NotImplementedError(
        "Empty function for stub_setup_pipelogger defintion - should never be called (or even exist) at runtime"
    )


def setup_pipelogger() -> None:
    old_setup_output()

    import ctypes
    import os
    import sys
    import typing

    CreateNamedPipe = ctypes.windll.kernel32.CreateNamedPipeW
    CreateNamedPipe.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    CreateNamedPipe.restype = ctypes.c_void_p
    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_UNLIMITED_INSTANCES = 255
    NMPWAIT_USE_DEFAULT_WAIT = 0x00000000

    ConnectNamedPipe = ctypes.windll.kernel32.ConnectNamedPipe
    ConnectNamedPipe.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    ConnectNamedPipe.restype = ctypes.c_uint32

    DisconnectNamedPipe = ctypes.windll.kernel32.DisconnectNamedPipe
    DisconnectNamedPipe.argtypes = (ctypes.c_void_p,)
    DisconnectNamedPipe.restype = ctypes.c_uint32

    CreateFile = ctypes.windll.kernel32.CreateFileW
    CreateFile.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    CreateFile.restype = ctypes.c_void_p
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3

    WriteFile = ctypes.windll.kernel32.WriteFile
    WriteFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    WriteFile.restype = ctypes.c_uint32

    class PipeLogger(typing.TextIO):
        def __init__(self, base: typing.TextIO, pipe_name: str):
            super().__init__()
            self.base = base
            self.pipe_name = pipe_name
            self.pipe = CreateNamedPipe(
                pipe_name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                1024 * 16,
                1024 * 16,
                NMPWAIT_USE_DEFAULT_WAIT,
                None,
            )
            print(f"Created pipe: {pipe_name}")

        def write(self, d: str) -> int:
            r = self.base.write(d)
            bdata = d.encode()
            WriteFile(self.pipe, bdata, len(bdata), None, None)
            return r

        def writelines(self, lines: typing.Iterable[str]) -> None:
            return self.base.writelines(lines)

        def __getattr__(self, name: str) -> typing.Any:
            return getattr(self.base, name)

    sys.stdout = PipeLogger(sys.stdout, f"\\\\.\\pipe\\pydetours_{os.getpid()}_stdout")  # type: ignore
    sys.stderr = PipeLogger(sys.stderr, f"\\\\.\\pipe\\pydetours_{os.getpid()}_stderr")  # type: ignore

    sys.stdout.write("stdout: Pipelogger output created")
    sys.stderr.write("stderr: Pipelogger output created\n")
    print("print: Pipelogger output test")



__all__ = ["setup_pipelogger"]
