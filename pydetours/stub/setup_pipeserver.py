def setup_pipeserver(file_to_reload: str) -> None:
    import ctypes
    import logging
    import os
    import queue
    import sys
    import threading
    import time
    import traceback
    import types
    import typing

    if typing.TYPE_CHECKING:
        from pydetours import InHook
    else:
        InHook = None

    logger = logging.getLogger("pydetours.pipeserver")

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

    ReadFile = ctypes.windll.kernel32.ReadFile
    ReadFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    ReadFile.restype = ctypes.c_uint32

    WriteFile = ctypes.windll.kernel32.WriteFile
    WriteFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    WriteFile.restype = ctypes.c_uint32

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3

    pipe_name = f"\\\\.\\pipe\\pydetours_{os.getpid()}_commands"
    pipe = CreateNamedPipe(
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

    def reader() -> typing.Generator[str, None, None]:
        buf = ctypes.create_string_buffer(0x100)
        read = ctypes.c_uint32()
        cmd: str = ""
        while ReadFile(pipe, buf, 0x100, ctypes.byref(read), None):
            if not read.value:
                continue
            logger.debug(f"[!] Pipeserver got {read.value} bytes")
            cmd += typing.cast(bytes, buf[: read.value]).decode()
            while "\n" in cmd:
                cmd, rest = cmd.split("\n", 1)
                yield cmd
                cmd = rest

    _pipeserver_queue: queue.Queue[object] = getattr(
        sys, "_pipeserver_queue", queue.Queue[object]()
    )
    setattr(sys, "_pipeserver_queue", _pipeserver_queue)

    def pipeserver() -> None:
        while True:
            if ConnectNamedPipe(pipe, None):
                logger = logging.getLogger("pydetours.pipeserver")
                logger.debug("Client connected to pipe")
                emsg = "ready\n"
                WriteFile(pipe, emsg.encode(), len(emsg), None, None)
                for line in reader():
                    if " " in line:
                        cmd, args = line.split(" ", 1)
                    else:
                        cmd = line
                        args = None
                    logger.debug(f"[!] Pipeserver got command: {cmd}")
                    _pipeserver_commands = getattr(sys, "_pipeserver_commands", {})
                    if cmd == "poll":
                        # TODO: can do this fancier with the lock, but this is fine for now
                        messages = list[object]()
                        while True:
                            try:
                                messages.append(_pipeserver_queue.get_nowait())
                            except queue.Empty:
                                break
                        messages.append(None)
                        for msg in messages:
                            emsg = f"{msg!r}\n"
                            WriteFile(pipe, emsg.encode(), len(emsg), None, None)

                    elif cmd == "close":
                        return
                    elif cmd == "unhook":
                        for hook in list(getattr(sys, "_already_hooked", {}).values()):
                            hook.unhook()
                    elif cmd == "reload":
                        logger.info("[@] Reloading " + file_to_reload)

                        # Unhook all hooks since the user probably wants to re-do them.
                        # This isn't 100% required since @hook/add_hook will detect and unhook when a hook is trying to replace another,
                        #   but combined with using in_hook.wait() it reduces the chance of unhooking a hook that is currently being called.
                        # Copy-constructor _already_hooked since hooks are removed from it when unhooked.
                        # Potential crash point if a hook is added after the copyconstruct but before the in_hook.wait(), or if a hook returns
                        #   to memory while that memory is being rewritten.
                        for hook in list(getattr(sys, "_already_hooked", {}).values()):
                            hook.unhook()

                        # CONSIDER: disablig hook creation *before* this step.

                        # Wait for any hooks to finish.
                        # Locking over in_hook is OK since it's an RLock, so we can still call .count or .wait(), and is required in case a hook is called between TOCTOU.
                        in_hook: InHook = getattr(sys, "in_hook")
                        if in_hook:
                            with in_hook.lock:
                                if in_hook.count:
                                    logger.warning(
                                        f"[@] Stub got reload command while in hook {in_hook.count} - waiting"
                                    )
                                    in_hook.wait()
                                    logger.info("[@] hook completed")
                        setattr(sys, "in_hook", None)

                        try:
                            # import runpy
                            # sys._hook_globals = runpy.run_path(file_to_reload, run_name='__hooks__')
                            from importlib.machinery import SourceFileLoader
                            from importlib.util import (
                                module_from_spec,
                                spec_from_loader,
                            )

                            spec = spec_from_loader(
                                "__hooks__",
                                SourceFileLoader("__hooks__", file_to_reload),
                            )
                            assert spec
                            mod = module_from_spec(spec)
                            sys.modules[spec.name] = mod
                            assert spec.loader
                            spec.loader.exec_module(mod)

                        except:
                            logger.warning(
                                "[@] Pipeserver got exception running " + file_to_reload
                            )  # well fuck
                            traceback.print_exc()
                        else:
                            logger.info("[@] Run complete")
                    elif cmd == "exec":
                        logger.info("[@] Executing " + repr(args))
                        if not args:
                            logger.warning('Nothing to exec')
                            continue
                        assert isinstance(args, str | types.CodeType), f'Got type {type(args)} for exec'
                        try:
                            exec(args)
                        except:
                            logger.warning("[@] Pipeserver got exception running exec")
                            traceback.print_exc()
                        else:
                            logger.info("[@] Exec complete")
                    elif cmd in _pipeserver_commands:
                        try:
                            _pipeserver_commands[cmd](args)
                        except Exception:
                            logger.warning("[@] Pipeserver got exception running exec")
                            traceback.print_exc()
                    else:
                        logger.warning(f"[@] Pipeserver got unknown command {cmd!r}")
                logger.debug(f"[@] Pipeserver client disconnect")
                DisconnectNamedPipe(pipe)
            else:
                time.sleep(1)

    import sys

    pipeserver_thread = getattr(sys, "pipeserver_thread", None)
    if pipeserver_thread and pipeserver_thread.is_alive():
        logger.warning("[@] Pipeserver already running!")
        return
    
    pipeserver_thread = threading.Thread(target=pipeserver)
    setattr(sys, "pipeserver_thread", pipeserver_thread)
    pipeserver_thread.start()
    logger.debug("[@] Pipeserver started")
