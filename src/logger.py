import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("../phishing_monitor.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
