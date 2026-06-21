# utils/logger.py

import logging
import os
from pathlib import Path


LOG_DIR = "logs"
LOG_FILE = os.path.join(os.getcwd(), LOG_DIR, "audit.log")

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
              logging.FileHandler(LOG_FILE),
              logging.StreamHandler()
             ]
)

logger = logging.getLogger(__name__)
