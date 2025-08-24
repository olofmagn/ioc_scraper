import json
import requests
import time

from .loggerutils import get_logger

from datetime import datetime, timedelta
from pathlib import Path
from typing import Set
from urllib.parse import urldefrag
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from utils.configutils import IOCConfig

"""
Network utils
"""

config = IOCConfig()

def get_valid_tlds(DEFAULT_CACHE_DAYS: int) -> Set[str]:
    """
    Get valid tlds

    Args:
    - DEFAULT_CACHE_DAYS (int): number of days to look for valid tlds

    Returns:
    - Set[str]: set of valid lowercase tlds strings (e.g., {'com', 'org', 'net'})
    """

    cache_file = Path("data/tld_cache.json")
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cached_tlds = _try_read_cache(cache_file, DEFAULT_CACHE_DAYS)

    if cached_tlds:
        return cached_tlds

    get_logger().info("Fetching fresh TLD data from IANA...")
    try:
        tlds = _fetch_fresh_tlds()

        _write_to_cache(tlds, cache_file)

        get_logger().info(f"Fetched {len(tlds)} TLDs from IANA")
        return tlds

    except requests.RequestException as e:
        get_logger().error(f"Failed to fetch TLD data: {e}")

        fallback_tlds = {
            "com",
            "org",
            "net",
            "edu",
            "gov",
            "mil",
            "int",
            "us",
            "uk",
            "ca",
            "au",
            "de",
            "fr",
            "jp",
            "cn",
            "in",
            "br",
            "ru",
            "it",
            "es",
            "nl",
            "ch",
            "at",
            "be",
            "dk",
            "fi",
            "no",
            "se",
            "pl",
            "by",
            "md",
            "ee",
            "id",
            "is",
            "as",
            "fm",
            "am",
            "to",
            "ws",
            "page",
        }
        get_logger().error(f"Using fallback TLD list ({len(fallback_tlds)} TLDs)")
        return fallback_tlds

def fetch_content(url: str) -> str:
    """
    Fetch content from a URL

    Args:
    - url (str): URL to fetch content from

    Returns:
    - str: HTML content of the webpage
    """

    if not url.startswith(("http", "https")):
        raise ValueError("URL must start with http or https")

    url, _ = urldefrag(url)

    # Avoid request rejection
    headers = config.headers

    for attempt in range(config.MAX_RETRIES):
        try:
            get_logger().info(f"Fetching (attempt {attempt + 1}): {url}")

            response = requests.get(url, headers=headers, timeout=config.DEFAULT_TIMEOUT)

            if response.status_code in (403, 429):
                if not _is_last_attempt(attempt, config.MAX_RETRIES):
                    wait = 2**attempt
                    get_logger().info(
                        f"Rate _get_ioc_patterns limited ({response.status_code}), waiting {wait}s..."
                    )
                    time.sleep(wait)
                    continue

            response.raise_for_status()

            content = response.text
            get_logger().info(f"Content length: {len(content)}")

            return content

        except requests.Timeout:
            get_logger().warning(f"Timeout on attempt {attempt + 1}")
            if _is_last_attempt(attempt, config.MAX_RETRIES):
                break
            time.sleep(config.RETRY_DELAY)

        except requests.ConnectionError:
            get_logger().warning(f"Connection error on attempt {attempt + 1}")
            if _is_last_attempt(attempt, config.MAX_RETRIES):
                break
            time.sleep(config.RETRY_DELAY)

        except requests.HTTPError as e:
            get_logger().warning(
                f"HTTP error {e.response.status_code} on attempt {attempt + 1}"
            )
            if _is_last_attempt(attempt, config.MAX_RETRIES):
                break
            time.sleep(config.RETRY_DELAY)

    get_logger().error("All requests failed, trying Selenium...")
    try:
        return _fetch_with_selenium(url)
    except Exception as selenium_error:
        get_logger().error(f"Selenium fallback failed: {selenium_error}")
        raise RuntimeError(
            f"All fetch methods failed for URL: {url}. "
            f"HTTP attempts: {config.MAX_RETRIES}"
        )


def _fetch_with_selenium(url: str) -> str | None:
    """
    Fetch content using Selenium
    Args:
    - url (str): URL to fetch

    Returns:
    - str: HTML content of the webpage
    """

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(options=chrome_options)
    try:
        driver.get(url)
        time.sleep(3)
        content = driver.page_source
        get_logger().info(f"Selenium success! Content length: {len(content)}")
        return content
    finally:
        driver.quit()

def _is_last_attempt(attempt: int, max_retries: int) -> bool:
    """
    Return True if the loop should break on the last retry attempt

    Args:
    - attempt (int): Number of attempts to fetch
    - max_retries (int): Number of attempts to fetch

    Returns:
    - True: if the loop should break
    """

    return attempt == max_retries - 1

def _try_read_cache(cache_file: Path, cache_days: int) -> Set[str] | None:
    """
    Try to read TLD data from cache

    Args:
    - cache_file (Path): Path to the cache file
    - cache_days (int): Number of days to cache

    Returns:
    - Set[str]: Set of TLD strings if cache is valid
    """

    if not cache_file.exists():
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            cache_time = datetime.fromisoformat(data["timestamp"])

            if datetime.now() - cache_time < timedelta(days=cache_days):
                get_logger().info(f"Using cached TLD data ({len(data['tlds'])} TLDs)")
                return set(data["tlds"])
            else:
                get_logger().info("Cache expired, fetching fresh data...")
                return None

    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        get_logger().warning(f"Cache data corrupted: {e}")
        return None

    except (OSError, PermissionError, UnicodeDecodeError) as e:
        get_logger().warning(f"Cache file read error: {e}")
        return None


def _write_to_cache(tlds: Set[str], cache_file: Path) -> None:
    """
    Write TLD data to cache file

    Args:
    - tlds (Set[str]): Set of TLD strings
    - cache_file (Path): Path to the cache file
    """

    cache_data = {
        "timestamp": datetime.now().isoformat(),
        "tlds": sorted(list(tlds)),
        "source": "IANA",
        "count": len(tlds),
    }
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)
    except (OSError, PermissionError, json.JSONDecodeError) as e:
        get_logger().warning(f"Cache file write error: {e}")


def _fetch_fresh_tlds() -> Set[str]:
    """
    Fetch fresh TLD data from IANA.

    Returns:
    - Set[str]: Set of valid TLD strings
    """

    response = requests.get(config.IANA_URL, timeout=config.DEFAULT_TIMEOUT)
    response.raise_for_status()

    return {
        line.strip().lower()
        for line in response.text.strip().split("\n")
        if line and not line.startswith("#")
    }