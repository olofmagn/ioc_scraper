from typing import Dict, Set, Tuple

# Processing limits
MAX_PROCESSING_LINES = 500
MAX_SECTION_LINES = 1000
MAX_LINES_WITHOUT_IOCS = 100
MAX_HEADER = 35

# Network configuration
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_DAYS = 7
MAX_RETRIES = 3
RETRY_DELAY = 2
IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# General categories/mappings/headers
IOC_CATEGORIES: Tuple[str, ...] = (
    "ips",
    "urls",
    "domains",
    "emails",
    "filenames",
    "hashes",
)

TYPE_MAPPING = {
    "ipv4": "ips",
    "ipv6": "ips",
    "url": "urls",
    "domain": "domains",
    "email": "emails",
    "filename": "filenames",
    "md5": "hashes",
    "sha1": "hashes",
    "sha256": "hashes",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def get_empty_ioc_dict() -> Dict[str, Set[str]]:
    """
    Return a fresh copy of the IOC categories dictionary

    Returns:
    - Dict[str, Set[str]]: Dictionary with IOC category names as keys and empty sets as values
    """

    return {category: set() for category in IOC_CATEGORIES}


def get_mapped_category(ioc_type: str) -> str:
    """
    Get the category for a given IOC type

    Args:
    - ioc_type (str): The IOC type to map (e.g., 'ipv4', 'md5', 'url')

    Returns:
    - str: The mapped category name (e.g., 'ips', 'hashes', 'urls') or the original type if no mapping exists
    """

    return TYPE_MAPPING.get(ioc_type, ioc_type)
