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

"""
Network utils
"""

# Config CONSTANTS
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_DAYS = 7
MAX_RETRIES = 3
IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


def fetch_content(url: str) -> str | None:
    """
    Fetch content from a URL with error handling, fragment stripping,

    Args:
    - url (str): URL to fetch content from

    Returns:
    - str: HTML content of the webpage
    """

    if not url.startswith(("http", "https")):
        raise Exception("URL must start with http or https")

    url, _ = urldefrag(url)

    # Avoid request rejection
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    }

    for attempt in range(MAX_RETRIES):
        try:
            get_logger().info(f"Fetching (attempt {attempt + 1}): {url}")

            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)

            if response.status_code in (403, 429):
                if attempt < MAX_RETRIES - 1:
                    wait = 2**attempt
                    get_logger().info(
                        f"Rate limited ({response.status_code}), waiting {wait}s..."
                    )
                    time.sleep(wait)
                    continue

            response.raise_for_status()

            content = response.text
            get_logger().info(f"Content length: {len(content)}")

            return content

        except requests.Timeout:
            get_logger().warning(f"Timeout on attempt {attempt + 1}")
            if attempt == MAX_RETRIES - 1:
                break

        except requests.ConnectionError:
            get_logger().warning(f"Connection error on attempt {attempt + 1}")
            if attempt == MAX_RETRIES - 1:
                break

        except requests.HTTPError as e:
            get_logger().warning(
                f"HTTP error {e.response.status_code} on attempt {attempt + 1}"
            )
            if attempt == MAX_RETRIES - 1:
                break

        if attempt < MAX_RETRIES - 1:
            time.sleep(1)

    get_logger().error("All requests failed, trying Selenium...")
    try:
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

    except Exception as e:
        get_logger().error(f"Selenium failed: {e}")
        raise Exception(f"All fetch methods failed for URL: {url}")


def get_valid_tlds(DEFAULT_CACHE_DAYS: int) -> Set[str]:
    """
    Get valid tlds

    Args:
    - DEFAULT_CACHE_DAYS (int): number of days to look for valid tlds

    Returns:
    - Set[str]: set of valid lowercase tlds strings (e.g., {'com', 'org', 'net'})
    """

    cache_file = Path("data/tld_cache.json")

    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                cache_time = datetime.fromisoformat(data["timestamp"])

                if datetime.now() - cache_time < timedelta(days=DEFAULT_CACHE_DAYS):
                    get_logger().info(
                        f"Using cached TLD data ({len(data['tlds'])} TLDs)"
                    )
                    return set(data["tlds"])
        except (json.JSONDecodeError, KeyError, ValueError):
            get_logger().error("Cache corrupted, fetching fresh TLD data...")

    get_logger().info("Fetching fresh TLD data from IANA...")
    try:
        url = IANA_URL
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        tlds = {
            line.strip().lower()
            for line in response.text.strip().split("\n")
            if line and not line.startswith("#")
        }

        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "tlds": sorted(list(tlds)),
            "source": "IANA",
            "count": len(tlds),
        }
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)

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
