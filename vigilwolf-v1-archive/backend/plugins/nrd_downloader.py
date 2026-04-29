"""NRD (Newly Registered Domains) downloader with retry logic and safe extraction.

Replaces the bash script with a robust Python implementation.
"""
import os
import re
import zipfile
import base64
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_DAY_RANGE = 7
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_BASE_URL = "https://www.whoisds.com//whois-database/newly-registered-domains"


def _encode_date(date_str: str) -> str:
    """Encode date string to base64 URL-safe format matching whoisds.com pattern."""
    b64 = base64.b64encode(date_str.encode()).decode()
    return b64.rstrip("=")


def _get_dates(day_range: int) -> List[str]:
    """Generate list of dates in YYYY-MM-DD format for the last N days."""
    dates = []
    for i in range(day_range):
        date = datetime.now(timezone.utc) - timedelta(days=i)
        dates.append(date.strftime("%Y-%m-%d"))
    return dates


def _download_with_retries(url: str, dest: Path, retries: int = DEFAULT_RETRIES, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Download a file with retry logic.

    Returns True on success, False on failure after all retries.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    for attempt in range(retries):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    logger.warning(f"HTTP {response.status} for {url}")
                    continue
                data = response.read()
                if len(data) == 0:
                    logger.warning(f"Empty response for {url}")
                    continue
                dest.write_bytes(data)
                return True
        except HTTPError as e:
            logger.warning(f"HTTP error {e.code} for {url} (attempt {attempt + 1}/{retries})")
        except URLError as e:
            logger.warning(f"URL error for {url}: {e.reason} (attempt {attempt + 1}/{retries})")
        except Exception as e:
            logger.warning(f"Download error for {url}: {e} (attempt {attempt + 1}/{retries})")

    return False


def _extract_zip_safe(zip_path: Path, extract_dir: Path) -> bool:
    """Safely extract a zip file, guarding against path traversal.

    Returns True on success.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                member_path = extract_dir / member
                try:
                    member_path.resolve().relative_to(extract_dir.resolve())
                except ValueError:
                    logger.warning(f"Path traversal blocked in zip: {member}")
                    return False
            zf.extractall(extract_dir)
        return True
    except zipfile.BadZipFile:
        logger.warning(f"Corrupted zip file: {zip_path}")
        return False
    except Exception as e:
        logger.warning(f"Extraction error for {zip_path}: {e}")
        return False


def _find_domain_files(directory: Path) -> List[Path]:
    """Find all domain-names.txt files recursively in a directory."""
    return list(directory.rglob("domain-names.txt"))


def download_nrd_data(
    day_range: int = DEFAULT_DAY_RANGE,
    output_dir: Optional[Path] = None,
    temp_dir: Optional[Path] = None,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT
) -> dict:
    """Download and merge NRD data for the specified day range.

    Args:
        day_range: Number of days to download (default 7)
        output_dir: Directory for merged output files (default: ./nrd-file-dump)
        temp_dir: Directory for temporary downloads (default: ./nrdtemp)
        retries: Number of download retries per day
        timeout: HTTP timeout in seconds

    Returns:
        Dictionary with:
        - success: bool
        - merged_file: Path to static merged file
        - timestamped_file: Path to timestamped merged file
        - total_domains: int
        - days_downloaded: int
        - days_failed: int
        - errors: List[str]
    """
    root_dir = Path.cwd()
    output_dir = output_dir or (root_dir / "nrd-file-dump")
    temp_dir = temp_dir or (root_dir / "nrdtemp")

    output_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    dates = _get_dates(day_range)
    merged_file = root_dir / f"nrd-{day_range}days-free.txt"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    timestamped_file = output_dir / f"nrd-{timestamp}.txt"

    errors = []
    all_domains = []
    days_downloaded = 0
    days_failed = 0

    logger.info(f"Starting NRD download for {day_range} days")

    for date_str in dates:
        date_b64 = _encode_date(f"{date_str}.zip")
        url = f"{DEFAULT_BASE_URL}/{date_b64}/nrd"
        zip_file = temp_dir / f"{date_str}.zip"
        extract_dir = temp_dir / date_str

        logger.info(f"Downloading NRD for {date_str}")

        if not _download_with_retries(url, zip_file, retries, timeout):
            logger.warning(f"Failed to download NRD for {date_str} after {retries} retries")
            errors.append(f"Download failed for {date_str}")
            days_failed += 1
            continue

        extract_dir.mkdir(parents=True, exist_ok=True)

        if not _extract_zip_safe(zip_file, extract_dir):
            logger.warning(f"Failed to extract NRD for {date_str}")
            errors.append(f"Extraction failed for {date_str}")
            days_failed += 1
            continue

        domain_files = _find_domain_files(extract_dir)
        if not domain_files:
            logger.warning(f"No domain-names.txt found for {date_str}")
            errors.append(f"No domain data found for {date_str}")
            days_failed += 1
            continue

        day_domains = []
        for df in domain_files:
            try:
                content = df.read_text(encoding="utf-8", errors="ignore")
                domains = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                day_domains.extend(domains)
            except Exception as e:
                logger.warning(f"Failed to read domain file {df}: {e}")

        if day_domains:
            all_domains.extend(day_domains)
            days_downloaded += 1
            logger.info(f"Added {len(day_domains)} domains from {date_str}")

    # Write merged files
    total_domains = len(all_domains)

    if total_domains == 0:
        logger.error("No domains were successfully downloaded")
        return {
            "success": False,
            "merged_file": merged_file,
            "timestamped_file": None,
            "total_domains": 0,
            "days_downloaded": 0,
            "days_failed": days_failed,
            "errors": errors
        }

    # Static merged file (overwritten each run)
    merged_content = [f"# NRD list for the last {day_range} days", ""]
    merged_content.extend(all_domains)
    merged_file.write_text("\n".join(merged_content), encoding="utf-8")

    # Timestamped file (new each run)
    timestamped_content = [f"# Timestamped NRD merge: {timestamp}", ""]
    timestamped_content.extend(all_domains)
    timestamped_file.write_text("\n".join(timestamped_content), encoding="utf-8")

    logger.info(f"NRD download complete: {total_domains} domains from {days_downloaded} days")

    return {
        "success": True,
        "merged_file": merged_file,
        "timestamped_file": timestamped_file,
        "total_domains": total_domains,
        "days_downloaded": days_downloaded,
        "days_failed": days_failed,
        "errors": errors
    }


def cleanup_temp_files(temp_dir: Optional[Path] = None) -> None:
    """Clean up temporary NRD download files.

    Args:
        temp_dir: Directory to clean (default: ./nrdtemp)
    """
    temp_dir = temp_dir or (Path.cwd() / "nrdtemp")
    if temp_dir.exists():
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info(f"Cleaned up temp directory: {temp_dir}")
