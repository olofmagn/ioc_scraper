import re

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
