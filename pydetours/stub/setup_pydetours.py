def setup_pydetours(cwd: str, file_to_run: str, loglevel: int = 20) -> None:
    # Note: we could be in a process that doesn't have a console - even "print" could be deadly

    import logging

    global logger
    logger = logging.getLogger("pydetours.stub")

    logging.basicConfig(level=loglevel)
    logger.info("[@] Sub initialized logger")
    setup_output()

    # Make sure logger works after stub_alloc_console/stub_redirect_console has finished
    print("[!] Reloading logger")
    from importlib import reload

    logging.shutdown()
    reload(logging)
    logging.basicConfig(level=loglevel)
    logger = logging.getLogger("pydetours.stub")
    logger.info("[@] Log reloaded")

    import os
    import sys
    import traceback

    if hasattr(sys, "in_hooked_process"):
        logger.warning(
            "[@] Detected running in an already hooked process - consider using pipeserver reload command instead"
        )

    sys.in_hooked_process = True  # type: ignore
    sys.argv = [sys.executable]

    os.chdir(cwd)
    for p in {repr(sys.path)}:
        if p not in sys.path:
            sys.path.append(p)

    logger.info("[@] Running " + file_to_run)
    try:
        # namespace = runpy.run_path(file_to_run, run_name='__hooks__')
        # module = ModuleType('__hooks__')
        from importlib.machinery import SourceFileLoader
        from importlib.util import module_from_spec, spec_from_loader

        spec = spec_from_loader("__hooks__", SourceFileLoader("__hooks__", file_to_run))
        assert spec
        mod = module_from_spec(spec)
        sys.modules[spec.name] = mod
        assert spec.loader
        spec.loader.exec_module(mod)

    except:
        logger.warning("[@] Stub got exception running " + file_to_run)
        traceback.print_exc()
    else:
        logger.info("[@] Run complete")
        logger.debug(f' {"__hooks__" in sys.modules=}')


def setup_output() -> None:
    raise NotImplementedError(
        "Empty function for stub defintion - should never be called (or even exist) at runtime"
    )


logger = None
