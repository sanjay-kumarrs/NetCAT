"""
Logging configuration for Cyber_NetCAT.
Supports console + file logging with configurable verbosity.
"""

import logging
import os
from datetime import datetime


_logger = None


def setup_logger(verbose=False, log_file=None):
    """
    Configure and return the application logger.

    Args:
        verbose: If True, set log level to DEBUG. Otherwise INFO.
        log_file: Optional path to a log file. If None, logs to console only.

    Returns:
        Configured logging.Logger instance.
    """
    global _logger

    if _logger is not None:
        return _logger

    logger = logging.getLogger("Cyber_NetCAT")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Prevent duplicate handlers
    if logger.handlers:
        logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_fmt = logging.Formatter(
        fmt="  %(levelname)-8s │ %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            fmt="%(asctime)s │ %(levelname)-8s │ %(module)s │ %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    _logger = logger
    return logger


def get_logger():
    """
    Get the existing logger, or create a default one.

    Returns:
        The application logger.
    """
    global _logger
    if _logger is None:
        return setup_logger()
    return _logger


def generate_report_path(module_name, output_dir="reports"):
    """
    Generate a timestamped report file path.

    Args:
        module_name: Name of the module generating the report.
        output_dir: Directory to store reports.

    Returns:
        Full path to the report file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{module_name}_{timestamp}.json"
    return os.path.join(output_dir, filename)
