import logging

"""
Logger utils
"""


def get_logger(
    name: str = "IocScraper",
    level: int = logging.INFO,
    log_format="%(asctime)s - %(levelname)s - %(message)s",
) -> logging.Logger:
    """
    Logger utility

    Args:
    - name (str): Logger name
    - level (int): Logging level (default: INFO)
    - log_format (str): Logging format

    Returns:
    - logging.Logger: Configured logger instance
    """

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
