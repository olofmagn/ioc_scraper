import re
from typing import List

from bs4 import BeautifulSoup

"""
Data utils
"""


def clean_ioc(ioc: str) -> str:
    """
    Clean and normalize an IOC by removing defanging patterns

    Args:
     - ioc (str): Raw IOC string potentially containing defanging

    Returns:
    - str: Cleaned IOC in lowercase
    """

    ioc = ioc.strip()

    defang_patterns = {
        r"hxxps": "https",
        r"hXXps": "https",
        r"hxxp": "http",
        r"hXXp": "http",
        r"\[\.\]": ".",
        r"\(\.\)": ".",
        r"\[dot\]": ".",
        r"\(dot\)": ".",
        r"\[:\]": ":",
        r"\(\@\)": "@",
        r"\[\@\]": "@",
        r"\[at\]": "@",
    }

    for pattern, replacement in defang_patterns.items():
        ioc = re.sub(pattern, replacement, ioc, flags=re.IGNORECASE)

    return ioc.lower()


def get_ioc_patterns() -> List[str]:
    """
    Get list of IOC header patterns to search for

    Returns:
    - List[str]: List of regex patterns for IOC section headers
    """

    return [
        r"Indicators?\s+of\s+Compromises?",
        r"Network-Based\s+IOCs?",
        r"Host-Based\s+IOCs?",
        r"IOCs?\b",
        r"Observables?",
        r"Technical\s+Indicators?",
    ]


def parse_html_to_lines(html_content: str) -> List[str]:
    """
    Parse html to lines

    Args:
    - html_content (str): HTML content to extract IOCs from

    Returns:
    - List[str]: text lines extracted from each IOC section
    """

    soup = BeautifulSoup(html_content, "html.parser")
    all_text = soup.get_text(separator="\n")
    return all_text.split("\n")
