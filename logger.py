import logging

def get_logger(name: str="", level=logging.INFO):
    """
    创建并返回一个控制台logger
    """
    logger = logging.getLogger(name)

    # 防止重复添加handler
    if logger.handlers:
        return logger

    logger.setLevel(level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger