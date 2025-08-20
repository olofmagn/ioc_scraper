import json
import re

from datetime import datetime
from typing import Dict, Set
from pathlib import Path
from urllib.parse import urlparse

from .loggerutils import get_logger

"""
File utils
"""


def save_iocs(iocs: Dict[str, Set[str]], output_dir: str, source_url: str) -> None:
    """
    Args:
    - iocs (Dict[str, Set[str]]): dictionary mapping IOC types to sets of extracted IOCs
    - output_dir (str): output directory to save the IOC files
    - source_url (str): source URL that was processed for IOC extraction
    """

    if not iocs:
        get_logger().warning("No IOCs found")
        return

    if not source_url:
        get_logger().error("No source URL provided")
        raise ValueError("source_url cannot be None")

    try:
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
    except Exception as e:
        get_logger().error(f"Failed to save IOCs to output directory: {e}")
        raise

    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    domain = sanitize_domain(source_url)

    combined = {
        "ip_addresses": iocs.get("ips", set()),
        "domains": iocs.get("domains", set()),
        "urls": iocs.get("urls", set()),
        "emails": iocs.get("emails", set()),
        "filenames": iocs.get("filenames", set()),
        "hashes": iocs.get("hashes", set()),
        **{h: iocs[h] for h in ["md5", "sha1", "sha256"] if h in iocs},
    }

    sorted_items = [
        (ioc_type, items) for ioc_type, items in _sort_by_count(combined) if items
    ]

    for ioc_type, items in sorted_items:
        filepath = output_path / f"{domain}_{ioc_type}_{timestamp}.txt"

        try:
            with filepath.open("w", encoding="utf-8") as f:
                f.writelines(f"{item}\n" for item in sorted(items))

            get_logger().info(f"Saved {len(items)} {ioc_type} IOCs to {filepath}")

        except Exception as e:
            get_logger().error(f"Failed to save IOCs to {filepath}: {e}")
            raise

    _save_summary(combined, iocs, output_path, domain, timestamp, source_url, now)


def _sort_by_count(items_dict: Dict, reverse: bool = True):
    """
    Sort dictionary items by count of values

    Args:
    - items_dict (Dict): Dictionary where values are collections
    - reverse (bool): If True (default), sort in descending order (highest count first)

    Returns:
    - List[Tuple]: List of (key, value) tuples sorted by collection size

    """
    
    return sorted(items_dict.items(), key=lambda x: len(x[1]), reverse=reverse)

def sanitize_domain(url: str) -> str:
    """
    Sanitize domain for use in filename

    Args:
    - url (str): url to sanitize

    Returns:
    - str: sanitized url
    """

    try:
        netloc = urlparse(url).netloc
        if not netloc:
            return "unknown_domain"

        sanitized = re.sub(r'[<>:"|?*\s]', '_', netloc)
        return sanitized if sanitized else "unknown_domain"
    except Exception:
        return "unknown_domain"


def _save_summary(
        combined: Dict,
        iocs: Dict,
        output_path: Path,
        domain: str,
        timestamp: str,
        source_url: str,
        now: datetime,
) -> None:
    """
    Save summary JSON file

    Args:
    - combined (dict): combined dictionary mapping IOC categories to sets of IOCs
    - iocs (dict): raw dictionary mapping individual IOC types to sets of IOCs
    - output_path (path): directory path where the summary file will be saved
    - domain (str): cleaned domain name from source URL for filename
    - timestamp (str): formatted timestamp string for filename uniqueness
    - source_url (str): original URL processed for IOC extraction
    - now (datetime): current datetime object for ISO timestamp in summary
    """

    sorted_combined = {k: sorted(v) for k, v in _sort_by_count(combined) if v}

    sorted_ioc_counts = {k: len(v) for k, v in _sort_by_count(iocs)}

    summary_file = output_path / f"{domain}_summary_{timestamp}.json"

    try:
        with summary_file.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "source_url": source_url,
                    "timestamp": now.isoformat(),
                    "total_iocs": sum(len(v) for v in iocs.values()),
                    "ioc_counts": sorted_ioc_counts,
                    "combined_iocs": sorted_combined,
                },
                f,
                indent=2,
            )
    except Exception as e:
        get_logger().error(f"Failed to save summary to {summary_file}: {e}")
        raise

    get_logger().info(f"Saved summary to {summary_file}")
