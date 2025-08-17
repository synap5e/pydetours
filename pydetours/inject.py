import ctypes
import ctypes.wintypes
import inspect
import logging
import os
import struct
import sys
import threading
import types
import typing

import pydetours.stub
from pydetours.ctypedefs import (
    CREATE_NEW_CONSOLE,
    CREATE_SUSPENDED,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    PROCESS_ALL_ACCESS,
    PROCESS_INFORMATION,
    PROCESSENTRY32,
    STARTUPINFO,
    TH32CS_SNAPPROCESS,
    WORDPACK,
    WORDSIZE,
    CloseHandle,
    CreateProcessW,
    CreateRemoteThread,
    CreateToolhelp32Snapshot,
    GetExitCodeThread,
    IsWow64Process,
    LoadLibraryA,
    MessageBoxA,
    OpenProcess,
    Process32First,
    Process32Next,
    ResumeThread,
    SetDllDirectoryA,
    VirtualAllocEx,
    WaitForSingleObject,
)
from pydetours.patch import Patch
from pydetours.pe32_module import Modules, modules
from pydetours.pipelogger import read_pipelogger

logger = logging.getLogger("pydetours.inject")
PYTHON_DLL = f"python{sys.version_info.major}{sys.version_info.minor}.dll"


class NoSuchProcess(ValueError):
    pass


class WrongArchitecture(ValueError):
    pass


def getpid(processname: str) -> int:
    pid = None
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    try:
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not Process32First(hProcessSnap, ctypes.byref(pe32)):
            raise ValueError("Failed getting first process entry")
        while True:
            exe_file = pe32.szExeFile.decode()
            if (
                exe_file.lower() == processname.lower()
                or exe_file.lower() + ".exe" == processname.lower()
            ):
                # logger.info(f'  - Found process {exe_file!r} with pid={pe32.th32ProcessID}')
                pid = int(pe32.th32ProcessID)
                break
            if not Process32Next(hProcessSnap, ctypes.byref(pe32)):
                break
    except:
        raise ValueError("Failed to enumerate/check processes")
    finally:
        CloseHandle(hProcessSnap)
    if not pid:
        raise NoSuchProcess(f"Can't find process matching {processname}")

    return pid


def inject(
    pid_or_processname: int | str,
    module_or_filename: str | types.ModuleType | None = None,
    process_handle: ctypes.wintypes.HANDLE | None = None,
    alloc_console: bool = False,
    stderr_file: str | None = None,
    stdout_file: str | None = None,
    loglevel: int = logging.INFO,
    wait_for_thread: bool = False,
    custom_python_stub: str | None = None,
    pipeserver: bool = False,
    pipelogger: bool = False,
    debug_injection: bool = False,
    exception_file: str | None = None,
    # delay_hooks=None,
) -> int:
    if alloc_console and (stderr_file or stdout_file):
        raise ValueError("alloc_console and stderr_file/stdout_file are mutually exclusive")

    if stderr_file and not stdout_file:
        raise ValueError("stderr_file also requires stdout_file")
    if stdout_file and not stderr_file:
        raise ValueError("stdout_file also requires stderr_file")

    if not process_handle:
        logger.info(f" * Injecting into {pid_or_processname}")

    if isinstance(pid_or_processname, int):
        pid = pid_or_processname
    else:
        logger.info(f"  - Looking for process")
        pid = getpid(pid_or_processname)

    process_is_suspended = process_handle is not None
    if not process_handle:
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            raise ValueError(
                f"Failed to open process pid={pid}: Error=0x{ctypes.windll.kernel32.GetLastError():x}"
            )
        logger.info(f"  - Opened process 0x{process_handle:x}")

    is_target_wow64 = ctypes.wintypes.BOOL(False)
    IsWow64Process(process_handle, ctypes.byref(is_target_wow64))
    if WORDSIZE == 4 and not is_target_wow64.value:
        raise WrongArchitecture(
            f"Process is 64bit (IsWow64Process=False) but python executable used is 32bit - cannot inject"
        )
    elif WORDSIZE == 8 and is_target_wow64.value:
        raise WrongArchitecture(
            f"Process is 32bit (IsWow64Process=True) but python executable used is 64bit - cannot inject"
        )

    if not module_or_filename:
        module_or_filename = __file__
    if isinstance(module_or_filename, str):
        if module_or_filename in sys.modules:
            filename = sys.modules[module_or_filename].__file__
        else:
            filename = module_or_filename
    else:
        filename = module_or_filename.__file__

    assert filename
    logger.info(f"  - Got file to run in process: {filename!r}")
    if not os.path.exists(filename):
        raise FileNotFoundError("Could not find file to inject")

    if custom_python_stub:
        python_stub = custom_python_stub
    else:
        parts = list[str]()
        final = list[str]()
        if alloc_console:
            parts += [
                inspect.getsource(pydetours.stub.alloc_console),
                "",
                "setup_output = alloc_console",
            ]
        elif stderr_file:
            parts += [
                inspect.getsource(pydetours.stub.redirect_output),
                "",
                f"setup_output = lambda: redirect_output({stdout_file!r}, {stderr_file!r})",
            ]
        else:
            parts += [
                inspect.getsource(pydetours.stub.open_console),
                "",
                "setup_output = open_console",
            ]
        if pipelogger:
            parts += [
                inspect.getsource(pydetours.stub.setup_pipelogger),
                "",
                "old_setup_output = setup_output",
                "setup_output = setup_pipelogger",  # setup_pipelogger will call old_setup_output
            ]
            # final += ["setup_pipelogger()"]
        parts += [
            inspect.getsource(pydetours.stub.setup_pydetours),
        ]
        if exception_file:
            final += [
                f"""try:
    setup_pydetours({os.getcwd()!r}, {filename!r}, {loglevel})
except Exception as e:
    with open({exception_file!r}, "w") as f:
        f.write(str(e) + "\\n")
        import traceback
        f.write(traceback.format_exc())
"""
            ]
        else:
            final += [
                f"""try:
    setup_pydetours({os.getcwd()!r}, {filename!r}, {loglevel})
except Exception as e:
    print(f'Failed to setup pydetours: {{e}}')
    import traceback
    traceback.print_exc()
"""
            ]

        if pipeserver:
            parts += [
                inspect.getsource(pydetours.stub.setup_pipeserver),
                "",
            ]
            final += [
                f"""
try:
    setup_pipeserver({filename!r})
except Exception as e:
    print(f'Failed to setup pipeserver: {{e}}')
    import traceback
    traceback.print_exc()
    raise
"""
            ]
        python_stub = "\n".join(parts)

        # Check for errors
        exec(python_stub)

        python_stub += "\n" + "\n".join(final)
        logger.debug(
            "Python stub:\n\n"
            + "\n".join(f"{i:04d} {l}" for i, l in enumerate(python_stub.splitlines()))
        )

    # n.b. if we need to enum the modules for a suspended process, we can just create and wait for a noop (ret only) remote thread as this will init the modules
    python_lib = None
    if not process_is_suspended:
        process_modules = Modules(process_handle)
        for mname, m in process_modules.items():
            if m.name == PYTHON_DLL:
                logger.info(
                    f"  - Process already has {mname} loaded - using existing module's path to prevent conflicts"
                )
                python_lib = m.path
                break
            elif (
                m.name.startswith("python")
                and m.name.endswith(".dll")
                and len(m.name) > len("python3.dll")
            ):
                raise ValueError(
                    f"Process already has {m.name} loaded, but we want to inject {PYTHON_DLL}"
                )
    if not python_lib:
        logger.info(f"  - Resolving {PYTHON_DLL}'s path")
        python_lib = modules[PYTHON_DLL].path

    python_lib_dir = os.path.dirname(python_lib)
    python_lib_name = os.path.basename(python_lib)

    logger.info(f"  - Need to inject {python_lib}")

    SetDllDirectoryA_addr = ctypes.cast(SetDllDirectoryA, ctypes.c_void_p).value
    logger.info(f"   ~ Resolved SetDllDirectoryA to 0x{SetDllDirectoryA_addr:08x}")

    LoadLibraryA_addr = ctypes.cast(LoadLibraryA, ctypes.c_void_p).value
    logger.info(f"   ~ Resolved LoadLibraryA to 0x{LoadLibraryA_addr:08x}")

    MessageBoxA_addr = ctypes.cast(MessageBoxA, ctypes.c_void_p).value
    logger.info(f"   ~ Resolved MessageBoxA to 0x{MessageBoxA_addr:08x}")

    python_dll = modules[PYTHON_DLL]
    Py_IsInitialized = python_dll.exports["Py_IsInitialized"].address - python_dll.base
    Py_InitializeEx = python_dll.exports["Py_InitializeEx"].address - python_dll.base
    PyGILState_Ensure = python_dll.exports["PyGILState_Ensure"].address - python_dll.base
    PyRun_SimpleString = python_dll.exports["PyRun_SimpleString"].address - python_dll.base
    PyEval_SaveThread = python_dll.exports["PyEval_SaveThread"].address - python_dll.base
    PyGILState_Release = python_dll.exports["PyGILState_Release"].address - python_dll.base

    injection_stub = VirtualAllocEx(
        process_handle,
        None,
        len(python_stub) + 1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    logger.info(f"  - Created injection stub in remote process 0x{injection_stub:08x}")
    with Patch(injection_stub, process_handle) as patch:
        python_lib_dir_str_address = patch.cursor
        patch.bytecode += python_lib_dir.encode("utf-8") + b"\x00"

        python_lib_name_str_address = patch.cursor
        patch.bytecode += python_lib_name.encode("utf-8") + b"\x00"

        python_stub_address = patch.cursor
        patch.bytecode += python_stub.encode("utf-8") + b"\x00"

        if debug_injection:
            message_str_address = patch.cursor
            patch.bytecode += (
                b"Successfully running in process pid=" + str(pid).encode("utf-8") + b"\x00"
            )
            MessageBoxA_addr_ptr = patch.cursor
            patch.bytecode += struct.pack("<" + WORDPACK, MessageBoxA_addr)
        else:
            MessageBoxA_addr_ptr = message_str_address = None

        # kernel32.dll exports are the same in all processes, so we can just use the local address
        SetDllDirectoryA_addr_ptr = patch.cursor
        patch.bytecode += struct.pack("<" + WORDPACK, SetDllDirectoryA_addr)

        LoadLibraryA_addr_ptr = patch.cursor
        patch.bytecode += struct.pack("<" + WORDPACK, LoadLibraryA_addr)

        # NOPs before code start to make dissasembly easy to read
        # Otherwise the python_lib_name string is hard to separate out and can mangle actual instructions
        patch.bytecode += b"\xcc" * 8

        injection_stub_entry = patch.cursor

        patch.push("*bp")
        patch.mov("*bp", "*sp")

        # variables: handle, is_initialized, state
        patch.sub("*sp", 32)
        handle = "[*bp-8]"
        is_initialized = "[*bp-16]"
        state = "[*bp-24]"

        # align stack
        if WORDSIZE == 8:
            patch.bytecode += b"\x48\x83\xe4\xf0"  # and rsp, -16

        if message_str_address:
            assert MessageBoxA_addr_ptr
            patch.call_indirect(
                MessageBoxA_addr_ptr,
                0,
                message_str_address,
                message_str_address,
                0,
                cleanup_in_32bit=False,
            )

        # SetDllDirectoryA(python_lib_dir)
        patch.call_indirect(
            SetDllDirectoryA_addr_ptr,
            python_lib_dir_str_address,
            cleanup_in_32bit=False,
        )

        # handle = LoadLibraryA(python_lib)
        patch.call_indirect(
            LoadLibraryA_addr_ptr, python_lib_name_str_address, cleanup_in_32bit=False
        )
        patch.mov(handle, "*ax")

        # is_initialized = Py_IsInitialized()
        patch.call_regrelative("*ax", Py_IsInitialized)
        patch.mov(is_initialized, "*ax")

        # if is_initialized == 0:
        patch.test("eax", "eax")
        if WORDSIZE == 4:
            patch.jne(0x14)
        else:
            patch.jne(0x20)

        # Py_InitializeEx(0)
        patch.mov("*ax", handle)
        patch.call_regrelative("*ax", Py_InitializeEx, 0)

        # else:
        if WORDSIZE == 4:
            patch.jmp(0x0D)
        else:
            patch.jmp(0x18)

        # state = PyGILState_Ensure()
        patch.mov("*ax", handle)
        patch.call_regrelative("*ax", PyGILState_Ensure)
        patch.mov(state, "*ax")

        # endif

        # PyRun_SimpleString(python_stub)
        patch.mov("*ax", handle)
        patch.call_regrelative("*ax", PyRun_SimpleString, python_stub_address)

        # if is_initialized == 0:
        patch.mov("*ax", is_initialized)  # is_initialized
        patch.test("eax", "eax")
        if WORDSIZE == 4:
            patch.jne(0x0C)
        else:
            patch.jne(0x16)

        # PyEval_SaveThread()
        patch.mov("*ax", handle)
        patch.call_regrelative("*ax", PyEval_SaveThread)

        # else:
        if WORDSIZE == 4:
            patch.jmp(0x11)
        else:
            patch.jmp(0x18)

        # PyGILState_Release(state)
        patch.mov("*cx", state)
        patch.mov("*ax", handle)
        # handle args manually: if x64 state is already in rcx, otherwise push it
        if WORDSIZE == 4:
            patch.push("ecx")
        patch.call_regrelative("*ax", PyGILState_Release)
        if WORDSIZE == 4:
            patch.add("esp", 4)

        # endif

        # restore stack pointer
        patch.mov("*sp", "*bp")
        patch.pop("*bp")

        # return 1
        patch.mov("eax", 1)
        patch.ret()

        patch.int3()

    logger.info(f"   ~ Calling CreateRemoteThread (function=0x{injection_stub_entry:08x})")
    remote_thread = CreateRemoteThread(process_handle, None, 0, injection_stub_entry, None, 0, None)
    assert remote_thread
    logger.info(f"   ~ Created remote thread 0x{remote_thread:x}")
    if wait_for_thread:
        logger.info(f"   ~ Waiting for thread")
        WaitForSingleObject(remote_thread, 0xFFFFFFFF)
        exitcode = ctypes.wintypes.DWORD(0)
        assert GetExitCodeThread(remote_thread, ctypes.byref(exitcode))
        logger.info(f"   ~ Got thread exit code 0x{exitcode.value:08x}")

    CloseHandle(process_handle)

    if pipelogger:
        threading.Thread(
            target=read_pipelogger,
            args=(
                sys.stdout,
                f"\\\\.\\pipe\\pydetours_{pid}_stdout",
            ),
            daemon=True,
        ).start()
        threading.Thread(
            target=read_pipelogger,
            args=(
                sys.stderr,
                f"\\\\.\\pipe\\pydetours_{pid}_stderr",
            ),
            daemon=True,
        ).start()

    return pid


def launch(
    cmdline: str | list[str] | tuple[str],
    module_or_filename: str | types.ModuleType | None = None,
    create_new_console: bool = True,
    **args: typing.Any,
) -> int:
    print(f" * Starting and injecting into {cmdline!r}")
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)

    print(f"  - Creating process in SUSPENDED state")
    creation_flags = CREATE_SUSPENDED
    if create_new_console:
        creation_flags |= CREATE_NEW_CONSOLE
    startupinfo = STARTUPINFO()
    startupinfo.cb = ctypes.sizeof(startupinfo)
    processinfo = PROCESS_INFORMATION()
    p = CreateProcessW(
        None,
        cmdline,
        None,
        None,
        False,
        creation_flags,
        None,
        None,
        ctypes.byref(startupinfo),
        ctypes.byref(processinfo),
    )
    if not p:
        raise ValueError(
            f"CreateProcessW failed. Error=0x{ctypes.windll.kernel32.GetLastError():x}"
        )

    print(
        f"  - Process created with pid={processinfo.dwProcessId}, handle=0x{processinfo.hProcess:x}"
    )

    pid = inject(
        processinfo.dwProcessId,
        module_or_filename=module_or_filename,
        process_handle=processinfo.hProcess,
        **args,
    )

    logger.info(f"  - Resuming main thread")
    ResumeThread(processinfo.hThread)

    CloseHandle(processinfo.hThread)
    CloseHandle(processinfo.hProcess)

    return pid


__all__ = [
    "NoSuchProcess",
    "WrongArchitecture",
    "inject",
    "launch",
    "getpid",
]
