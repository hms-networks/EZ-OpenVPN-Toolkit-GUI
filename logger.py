# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# logger.py

import logging
import os
from helpers import get_base_dir


def setup_logging():
    """
    Sets up logging configuration.
    - Logs all messages of level INFO and above to 'master.log' file.
    - Does not output logs to the console.
    """
    BASE_DIR = get_base_dir()
    log_filename = os.path.join(BASE_DIR, "master.log")

    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Set the lowest severity level for the logger

    # Remove any existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create handlers
    # File handler to write logs to a file
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.INFO)

    # Create formatters and add them to the handlers
    formatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)

    # Console handler for ERROR and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
