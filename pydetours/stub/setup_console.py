def alloc_console():
    """
    Use AllocConsole to create a console for ordainarily-GUI processes
    """
    import sys

    if not getattr(sys, "alloced_console", False):
        print("[@] Stub allocating console")
        sys.alloced_console = True

        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.FreeConsole()
        kernel32.AllocConsole()
        kernel32.AttachConsole(kernel32.GetCurrentProcessId())

        sys.stdout = sys.stderr = open("con", "w")
        sys.stdin = open("con", "r")

        print("[@] Stub allocated console")
    else:
        print(
            "[@] Stub not allocating console - process is already hooked with allocated console"
        )


def open_console():
    import sys

    sys.stdout = sys.stderr = open("con", "w")


def redirect_output(stdout_file: str, stderr_file: str) -> None:
    import sys

    sys.stdout = open(stdout_file, "w")
    sys.stderr = open(stderr_file, "w")


__all__ = ["alloc_console", "open_console", "redirect_output"]
