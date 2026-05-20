# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# Software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# helpers.py

import os
import re
import sys
import time
import json
import logging
import itertools
import threading
import subprocess
from typing import List, Sequence, Optional
from config import get_base_dir


def _hidden_subprocess_kwargs() -> dict:
    """Hide transient console windows on Windows when running child processes."""
    if os.name != "nt":
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {
        "startupinfo": startupinfo,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
    }

BASE_DIR = get_base_dir()

# ----------------------------
# Progress UI (spinner) utils
# ----------------------------

class Spinner:
    def __init__(self, message: str = "Working"):
        self.message = message
        self._stop = False
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        self._t = threading.Thread(target=self._spin, daemon=True)
        self._t.start()

    def _spin(self) -> None:
        for ch in itertools.cycle(r"-\|/"):
            if self._stop:
                break
            sys.stdout.write(f"\r{self.message} {ch}")
            sys.stdout.flush()
            time.sleep(0.1)
        # clear the line
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")
        sys.stdout.flush()

    def stop(self, suffix: str = "done") -> None:
        self._stop = True
        if self._t:
            self._t.join()
        print(f"{self.message} ... {suffix}")


def run_command_with_progress(cmd: Sequence[str], message: str) -> None:
    """
    Run a command while showing a spinner. Streams combined stdout+stderr so
    OpenSSL progress (dots/lines) is visible. Raises CalledProcessError on failure.
    """
    sp = Spinner(message)
    sp.start()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **_hidden_subprocess_kwargs(),
        )
        last_line_time = time.time()
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                # print informative lines immediately; throttle noisy dot streams
                now = time.time()
                if line.strip() and (len(line.strip()) > 5 or (now - last_line_time) > 1.0):
                    print(line.rstrip())
                    last_line_time = now
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)
        sp.stop("ok")
    except Exception:
        sp.stop("failed")
        raise


# ----------------------------
# Existing helpers
# ----------------------------

def run_command(command: Sequence[str]) -> None:
    """
    Runs a system command and raises if it fails.
    """
    logging.debug(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            **_hidden_subprocess_kwargs(),
        )
        if result.stdout:
            logging.debug(result.stdout.strip())
        if result.stderr:
            # OpenSSL often writes useful progress to stderr; keep at debug level
            logging.debug(result.stderr.strip())
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(command)}")
        logging.error(f"Exit code: {e.returncode}")
        logging.error(f"Output: {e.stderr}")
        raise


def create_directory(path: str) -> None:
    """
    Creates a directory if it doesn't exist.
    """
    if not os.path.exists(path):
        os.makedirs(path)
        logging.info(f"Directory created: {path}")
    else:
        logging.debug(f"Directory already exists: {path}")


_SUBJ_FORBIDDEN = re.compile(r"[/\\\x00\n\r]")


def sanitize_subj_field(value: str, field_name: str) -> str:
    """
    Reject any certificate subject field that contains characters which could
    inject extra DN components into an OpenSSL -subj string ( / \\ NUL CR LF ).
    """
    if _SUBJ_FORBIDDEN.search(value):
        raise ValueError(
            f"Certificate field '{field_name}' contains forbidden characters "
            f"(/, \\, NUL, or newline)."
        )
    return value
