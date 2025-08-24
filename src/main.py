import ipaddress
import re
import argparse
import json
import urllib.parse
import tldextract

from pathlib import Path
from typing import Dict, Set, Optional, List, Tuple

from utils.configutils import IOCConfig
from utils.datautils import clean_ioc, get_ioc_patterns, parse_html_to_lines
from utils.fileutils import save_iocs
from utils.loggerutils import get_logger
from utils.networkutils import get_valid_tlds, fetch_content


"""
IOC Extractor - Indicator of Compromise Extraction Tool

Author: olofmagn
Version: 1.0.0
"""


class IOCExtractor:
    """
    IOC (Indicator of Compromise) extraction engine
    """

    def __init__(self, false_positives_file: Optional[str] = None) -> None:
        """
        Initialize the IOC Extractor with optional configuration

        Args:
        - false_positives_file (Optional[str]): Path to JSON configuration file for false positive filtering
        """
        self.config = IOCConfig()

        if false_positives_file and not Path(false_positives_file).exists():
            raise FileNotFoundError(f"File {false_positives_file} does not exist")

        self.logger = get_logger("IOCExtractor")

        self.false_positives = {
            "ipv4": set(),
            "domain": set(),
        }

        self.false_positives_file = false_positives_file

        if self.false_positives_file:
            self._load_false_positives(self.false_positives_file)

        self.logger.info("Initializing TLD validator...")
        self.valid_tlds = get_valid_tlds(self.config.DEFAULT_CACHE_DAYS)

        # Patterns
        ipv4_octet = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        ipv4_sep = r"(?:\.|\[\.\])"
        ipv4_addr = rf"{ipv4_octet}{ipv4_sep}{ipv4_octet}{ipv4_sep}{ipv4_octet}{ipv4_sep}{ipv4_octet}"
        ipv4_subnet = rf"{ipv4_addr}(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?"

        ipv6_addr = r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?=.*::)(?:[0-9a-fA-F]{0,4}:)*::[0-9a-fA-F:]*"
        ipv6_subnet = rf"{ipv6_addr}(?:/(?:\d|[1-9]\d|1[0-1]\d|12[0-8]))?"

        url = r"(https?|hxxps?)"
        domain_part = r"[a-zA-Z0-9-]+"
        domain_sep = r"(?:\.|\[\.\]|\(\.\))"
        domain = rf"{domain_part}(?:{domain_sep}{domain_part})+"
        path = r"(?:/[^\s]*?)?"

        MALICIOUS_EXTENSIONS = [
            "exe",
            "dll",
            "sys",
            "bat",
            "cmd",
            "scr",
            "ps1",
            "vbs",
            "js",
            "php",
            "asp",
            "aspx",
            "jsp",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "pdf",
            "zip",
            "rar",
            "tmp",
            "log",
        ]

        self.patterns = {
            "ipv4": rf"\b{ipv4_subnet}\b",
            "ipv6": rf"\b{ipv6_subnet}\b",
            "url": rf"{url}://{domain}{path}",
            "domain": r"\b(?:\[\.\])?[a-zA-Z0-9-]+(?:(?:\.|\[\.\]|\(\.\))[a-zA-Z0-9-]+)+(?:\[\.\])?\b",
            "email": r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\]|\(@\))[a-zA-Z0-9._-]+(?:\.|\[\.\]|\(\.\))[a-zA-Z]{2,}\b",
            "filename": rf"(?:[A-Za-z]:[\\/]|[\\/])?(?:[\w\s\-\.]+[\\/])*[\w\s\-\.]+\.({
                '|'.join(MALICIOUS_EXTENSIONS)
            })$",
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
        }

        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }

    def _load_false_positives(self, filepath: str) -> None:
        """
        Load false positive filtering configuration from JSON file

        Args:
        - filepath (str): Path to the JSON configuration file
        """

        try:
            with open(filepath, "r", encoding="utf8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("False positives file must contain a JSON object")

            for key in ["ipv4", "domain"]:
                if key in data:
                    if not isinstance(data[key], list):
                        self.logger.warning(f"Invalid type for '{key}', expected list")
                        continue
                        # Validate and get clean instances
                    valid_entries = [
                        str(item).lower().strip()
                        for item in data[key]
                        if isinstance(item, (str, int, float)) and str(item).strip()
                    ]
                    self.false_positives[key].update(valid_entries)

            self.logger.info(f"Loaded false positives from {filepath}")
            self.logger.info(f"Company keywords: {len(self.false_positives['domain'])}")

        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"Error loading false positives: {e}")
            self.logger.error("Falling back to default configuration")

    def _validate_ip(self, ioc: str, base_type: str) -> bool:
        """
        Validate IP addresses with enhanced filtering for private/reserved ranges

        Args:
        - ioc (str): IP address or subnet to validate
        - base_type (str): Either 'ipv4' or 'ipv6'

        Returns:
        - bool: True if IP is valid and not in private/reserved ranges
        """

        try:
            match base_type:
                case "ipv4":
                    if ioc in self.false_positives["ipv4"]:
                        return False

                    if "/" in ioc:
                        network = ipaddress.IPv4Network(ioc, strict=False)
                        if (
                            network.is_private
                            or network.is_reserved
                            or network.is_loopback
                            or network.is_multicast
                        ):
                            return False
                    else:
                        addr = ipaddress.IPv4Address(ioc)
                        if (
                            addr.is_private
                            or addr.is_reserved
                            or addr.is_loopback
                            or addr.is_multicast
                        ):
                            return False

                case "ipv6":
                    if "/" in ioc:
                        network = ipaddress.IPv6Network(ioc, strict=False)
                        if (
                            network.is_private
                            or network.is_reserved
                            or network.is_loopback
                            or network.is_multicast
                        ):
                            return False
                    else:
                        addr = ipaddress.IPv6Address(ioc)
                        if (
                            addr.is_private
                            or addr.is_reserved
                            or addr.is_loopback
                            or addr.is_multicast
                        ):
                            return False

                case _:
                    return False

            return True

        except ValueError as e:
            self.logger.error(f"Error during IP address validation: {e}")
            return False

    def _validate_email(self, email: str) -> bool:
        """
        Validate email addresses

        Args:
        - email (str): Email address to validate

        Returns:
        - bool: True if an email address is validated
        """

        try:
            if not email or "@" not in email:
                return False

            parts = email.split("@")
            if len(parts) != 2:
                return False

            local_part, domain_part = parts
            if not local_part or not domain_part:
                return False

            return self._validate_tld_core(domain_part)

        except Exception as e:
            self.logger.error(f"Error during email address validation: {e}")
            return False

    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain names with comprehensive filtering

        Args:
        - domain (str): Domain name to validate

        Returns:
        - bool: True if domain appears to be a legitimate IOC
        """

        full_domain = domain.lower().strip()
        if (
            full_domain.startswith(".")
            or full_domain.endswith(".")
            or ".." in full_domain
        ):
            return False

        if not self._validate_tld_core(full_domain):
            return False

        if any(
            re.search(keyword, full_domain)
            for keyword in self.false_positives["domain"]
        ):
            return False

        return True

    def _validate_url(self, url: str) -> bool:
        """
        Validate URLs with basic filtering

        Args:
        - url (str): URL to validate

        Returns:
        - bool: True if the URL passes validation
        """

        try:
            self.logger.info(f"URL validation for: {url}")

            if not url or len(url) < 10:
                self.logger.error("Failed: URL too short or empty")
                return False

            parsed = urllib.parse.urlparse(url)
            self.logger.info(
                f"Parsed - scheme: '{parsed.scheme}', netloc: '{parsed.netloc}'"
            )

            if not parsed.scheme or not parsed.netloc:
                self.logger.error("Failed: Missing scheme or netloc")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Failed: Exception during URL validation: {e}")
            return False

    def _validate_tld_core(self, domain: str) -> bool:
        """
        Validate TLD core filtering

        Args:
        - domain (str): Domain name to validate

        Returns:
        - bool: True if domain has valid TLD structure
        """

        try:
            extracted = tldextract.extract(domain)

            # Check if domain is meaningful
            if len(extracted.domain) <= 1:
                return False

            if not extracted.suffix or extracted.suffix.lower() not in self.valid_tlds:
                return False

            return True

        except Exception as e:
            self.logger.error(f"Failed: Exception during TLD validation: {e}")
            return False

    def _validate_ioc(self, ioc: str, ioc_type: str) -> bool:
        """
        Determine if an extracted string is a valid IOC

        Args:
        - ioc (str): The potential IOC string
        - ioc_type (str): Type of IOC ('ipv4', 'ipv6', 'domain', 'md5', 'sha1', 'sha256', 'url', 'email')

        Returns:
        - bool: True if the IOC passes validation for its type
        """

        base_type = ioc_type
        match base_type:
            case "ipv4" | "ipv6":
                return self._validate_ip(ioc, base_type)
            case "domain":
                return self._validate_domain(ioc)
            case "url":
                return self._validate_url(ioc)
            case "email":
                return self._validate_email(ioc)
            case _:
                return True

    def _extract_iocs(self, content: str) -> Dict[str, Set[str]]:
        """
        Extract all IOC types from text content

        Args:
        - content (str): Text content to analyze for IOCs

        Returns:
        - Dict[str, Set[str]]: Dictionary mapping IOC types to sets of validated IOCs
        """

        if not content or not content.strip():
            return {}

        iocs = {}

        for ioc_type, pattern in self.compiled_patterns.items():
            matches = set()

            # Clean and normalize
            for match in pattern.finditer(content):
                raw_match = match.group()
                cleaned = clean_ioc(raw_match)
                self.logger.info(f"Checking {ioc_type}: {cleaned}")
                if self._validate_ioc(cleaned, ioc_type):
                    matches.add(cleaned)

            if matches:
                iocs[ioc_type] = matches

        return iocs

    def process_url(
        self, url: str, output_dir: str = "iocs_output"
    ) -> Dict[str, Set[str]]:
        """
        Complete IOC extraction workflow for a given URL

        Args:
        - url (str): URL to process
        - output_dir (str): Directory to write IOCs to

        Returns:
        - Dict[str, Set[str]]: Dictionary mapping IOC types to sets of extracted IOCs
        """

        self.logger.info(f"Fetching content from: {url}")
        content = fetch_content(url)

        ioc_section = self._extract_ioc_sections(content)

        if not ioc_section:
            self.logger.warning("No 'Indicators of Compromise' section found.")
            return {}

        self.logger.info("IOC section found, extracting IOCs")

        grouped_iocs = self._extract_iocs_iteratively(ioc_section)
        total = sum(len(v) for v in grouped_iocs.values())
        self.logger.info(f"Total IOCs found: {total}")

        if total > 0:
            save_iocs(grouped_iocs, output_dir, url)
        else:
            self.logger.warning("No IOCs found")

        return grouped_iocs

    def _extract_content_from_headers(
        self, lines: List[str], accepted_headers: List[Tuple[int, str, str]]
    ) -> str:
        """
        Extract content from headers

        Args:
        - lines (List[str]): List of text lines to extract content from
        - accepted_headers (List[Tuple[int, str, str]]): List of valid headers with (line_index, pattern, text)

        Returns:
        - str: Content from the headers
        """

        boundaries = self._calculate_section_boundaries(accepted_headers, len(lines))
        all_content = []

        for i, (start_idx, end_idx) in enumerate(boundaries):
            _, _, header_line = accepted_headers[i]
            section_content = self._extract_section_content(
                lines, start_idx, end_idx, header_line
            )
            all_content.extend(section_content)

        self.logger.info(f"Extracted content from {len(accepted_headers)} IOC sections")

        return "\n".join(all_content)

    def _find_valid_ioc_headers(self, lines: List[str]) -> List[Tuple[int, str, str]]:
        """
        Find valid IOC headers

        Args:
        - lines (List[str]): IOC section lines to search through

        Returns:
        - List[Tuple[int, str, str]]:
        List of tuples containing (line_index, matched_pattern, line_text) sorted by line index
        """

        pattern_matches = self._find_pattern_matches(lines)
        accepted_headers = []

        for line_idx, pattern, line_text in pattern_matches:
            if self._validate_header_length(line_text):
                accepted_headers.append((line_idx, pattern, line_text))

        accepted_headers.sort(key=lambda x: x[0])

        self.logger.info(f"Found {len(accepted_headers)} valid IOC section headers:")
        for idx, pattern, line in accepted_headers:
            self.logger.info(f"  Line {idx}: '{pattern}' -> '{line}'")

        return accepted_headers

    def _extract_ioc_sections(self, html_content: str) -> str:
        """
        Find all IOC section headers and extract content from each one

        Args:
        - html_content (str): HTML content to extract IOCs from

        Returns:
        - str: Content extracted from each IOC section
        """

        try:
            lines = parse_html_to_lines(html_content)
            accepted_headers = self._find_valid_ioc_headers(lines)

            if not accepted_headers:
                self.logger.warning(
                    "No IOC section found with any pattern in short lines"
                )
                return ""

            return self._extract_content_from_headers(lines, accepted_headers)

        except Exception as e:
            self.logger.error(f"Failed: Exception during HTML extraction: {e}")
            return ""

    def _find_pattern_matches(self, lines: List[str]) -> List[Tuple[int, str, str]]:
        """
        Find all lines that match IOC patterns.

        Args:
        - lines (List[str]): lines to search through

        Returns:
        - List of tuples: (line_index, matched_pattern, line_text)
        """

        patterns = get_ioc_patterns()
        matches = []

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.logger.info(f"Found pattern '{pattern}' in line: '{line}'")
                    self.logger.info(f"Line length: {len(line)} characters")
                    matches.append((i, pattern, line))
                    break

        return matches

    def _validate_header_length(self, line_text: str) -> bool:
        """
        Validate if a line is a valid header based on length

        Args:
        - line_text (str): The text line to validate

        Returns:
        - bool: True if line is short enough to be a header
        """

        if len(line_text) <= self.config.MAX_HEADER:
            self.logger.info(f"✓ Accepting as header (length: {len(line_text)})")
            return True
        else:
            self.logger.info(
                f"✗ Rejecting as narrative text (length: {len(line_text)})"
            )
            return False

    def _calculate_section_boundaries(
        self, accepted_headers: List[Tuple[int, str, str]], total_lines: int
    ) -> List[Tuple[int, int]]:
        """
        Calculate start and end boundaries for each section

        Args:
        - accepted_headers (List[tuple[int, str, str]]): List of valid headers with (line_index, pattern, text)
        - total_lines (int): Total number of lines in the document

        Returns:
        - List[tuple[int, int]]: List of tuples containing (start_index, end_index) for each section
        """

        boundaries = []

        for i, (start_idx, _, _) in enumerate(accepted_headers):
            if i + 1 < len(accepted_headers):
                end_idx = accepted_headers[i + 1][0]
            else:
                end_idx = min(start_idx + self.config.MAX_SECTION_LINES, total_lines)

            boundaries.append((start_idx, end_idx))

        return boundaries

    def _extract_section_content(
        self, lines: List[str], start_idx: int, end_idx: int, header_line: str
    ) -> List[str]:
        """
        Extract content from a single IOC section.

        Args:
        - lines (List[str]): All text lines
        - start_idx (int): Starting line index
        - end_idx (int): Ending line index
        - header_line (str): Header text for logging

        Returns:
        - List of lines for this section including header
        """

        self.logger.info(f"Extracting content from section: '{header_line}'")

        section_lines = lines[start_idx:end_idx]
        section_content = [f"=== {header_line} ==="]
        section_content.extend(section_lines)
        section_content.append("")  # Add spacing between sections

        return section_content

    def _extract_iocs_iteratively(self, text: str) -> Dict[str, Set[str]]:
        """
        Smart IOC extraction with line-by-line processing and stopping conditions.

        Args:
        - text (str): Text to extract IOCs from

        Returns:
        - Dict[str, Set[str]]: Dictionary mapping IOC types to sets of extracted IOCs
        """

        all_iocs = self.config.get_empty_ioc_dict()
        key_map = self.config.TYPE_MAPPING

        lines = text.split("\n")

        # Initialize
        lines_since_last_ioc = 0
        total_iocs_found = 0
        processed_lines = 0

        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            processed_lines += 1

            iocs = self._extract_iocs(line)
            new_found = False

            for ioc_type, values in iocs.items():
                mapped_type = key_map.get(ioc_type, ioc_type)
                if mapped_type not in all_iocs:
                    continue

                new_values = values - all_iocs[mapped_type]
                if new_values:
                    all_iocs[mapped_type].update(new_values)
                    new_found = True
                    total_iocs_found += len(new_values)

            if new_found:
                lines_since_last_ioc = 0
            else:
                lines_since_last_ioc += 1

            if lines_since_last_ioc >= self.config.MAX_LINES_WITHOUT_IOCS:
                if total_iocs_found > 0:
                    self.logger.info(
                        f"No new IOCs found in {lines_since_last_ioc} consecutive lines, stopping"
                    )
                else:
                    self.logger.info(f"Last processed line: {line}")
                    break

            # Safety check
            if processed_lines > self.config.MAX_PROCESSING_LINES:
                self.logger.info(
                    f"Processed {processed_lines} lines, stopping for safety"
                )
                break

        self.logger.info(
            f"Processed {processed_lines} lines, found {total_iocs_found} total IOCs"
        )
        return all_iocs


def main() -> None:
    """
    Command-line interface for the IOC Extractor
    """

    parser = argparse.ArgumentParser(
        description="Extract IOCs from cybersecurity reports with automatic TLD validation",
        epilog="""
Examples:
  python3 -m src.main -u https://example.com/threat-report
  python3 -m src.main -u https://example.com/report -f data/false_positives.json -o output/

For more information, visit: https://github.com/ioc-extractor
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-u", "--url", help="URL to extract IOCs from", required=True)
    parser.add_argument(
        "-o",
        "--output",
        default="iocs_output",
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "-f",
        "--false-positives",
        help="Path to false positives JSON configuration file",
    )
    parser.add_argument(
        "-v", "--version", action="version", version="IOC Extractor v1.0.0"
    )

    args = parser.parse_args()

    try:
        extractor = IOCExtractor(args.false_positives)
        extractor.process_url(args.url, args.output)

    except FileNotFoundError as e:
        get_logger().error(f"Error: {e}")
        get_logger().error("Please check that the specified configuration file exists.")
        exit(1)

    except Exception as e:
        get_logger().error(f"Error: {e}")
        get_logger().error("Please check the URL and your network connection.")
        exit(1)


if __name__ == "__main__":
    main()
