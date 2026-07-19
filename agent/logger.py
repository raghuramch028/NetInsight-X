import logging
import sys

def setup_logger():
    """Sets up standard logger formatting for console and file log targets."""
    logger = logging.getLogger("netinsight_agent")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    # Log Formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s"
    )

    # Console output handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Local file output handler
    try:
        file_handler = logging.FileHandler("agent.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Failed to initialize file logger: {e}", file=sys.stderr)

    return logger

# Singleton logger instance
logger = setup_logger()
