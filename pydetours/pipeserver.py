import logging
import queue
import sys
import typing

logger = logging.getLogger("pydetours.pipeserver")


_pipeserver_commands = getattr(sys, "_pipeserver_commands", {})
setattr(sys, "_pipeserver_commands", _pipeserver_commands)


TCallable = typing.TypeVar("TCallable", bound=typing.Callable[[str], typing.Any])

def pipeserver_command(command: TCallable) -> TCallable:
    if command.__name__ in _pipeserver_commands:
        logger.warning(f"[@] Overwriting pipeserver command {command.__name__}")
    else:
        logger.info(f"[@] Registering pipeserver command {command.__name__}")
    _pipeserver_commands[command.__name__] = command
    return command


_pipeserver_queue: queue.Queue[object] = getattr(sys, "_pipeserver_queue", queue.Queue[object]())
setattr(sys, "_pipeserver_queue", _pipeserver_queue)


def pipeserver_send(msg: object) -> None:
    _pipeserver_queue.put(msg)


__all__ = [
    "pipeserver_command",
    "pipeserver_send",
]