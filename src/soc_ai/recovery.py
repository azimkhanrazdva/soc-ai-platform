"""Local-filesystem writer locks and cooperative export interruption."""
from contextlib import contextmanager, ExitStack
from pathlib import Path
import os
import signal
import threading


class ExportPaused(RuntimeError):
    pass


@contextmanager
def writer_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never unlink a lock file: another process could still hold its inode.
    with path.open("a+b") as fh:
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                fh.write(b"\0")
                fh.flush()
            fh.seek(0)
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeError("Another process holds the run writer lock") from None
        else:
            import fcntl
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another process holds the run writer lock") from None
        try:
            yield
        finally:
            if os.name == "nt":
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh, fcntl.LOCK_UN)


@contextmanager
def export_guard(paths):
    stop = threading.Event()
    handlers = {}
    with ExitStack() as stack:
        for path in sorted({Path(path).resolve() for path in paths}):
            stack.enter_context(writer_lock(path))
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, lambda *_: stop.set())
        try:
            yield stop
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
