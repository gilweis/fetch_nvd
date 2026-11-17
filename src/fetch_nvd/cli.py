"""Fetch delta CVE updates from the NVD API and export them as JSON files."""

import argparse
import datetime
import json
import logging
import os
import sys
import time

import requests

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMESTAMP_FILE = "last_run_timestamp.txt"
DEFAULT_OUTPUT_DIR = "delta_exports"
DEFAULT_API_KEY_FILE = "api_key.txt"
DEFAULT_LOG_FILE = "fetch_nvd.log"
PLACEHOLDER_API_KEY = "YOUR_NVD_API_KEY_HERE"
RESULTS_PER_PAGE = 2000  # Max allowed by NVD API v2.0 per page
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000"

logger = logging.getLogger("fetch_nvd")


def setup_logging(log_file):
    """Configures logging to both the console and the given log file (appended)."""
    close_logging()
    logger.setLevel(logging.INFO)
    logger.propagate = False

    parent = os.path.dirname(log_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console_handler)


def close_logging():
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def read_api_key(api_key_file):
    """Returns the API key from the given file, or None if missing/placeholder."""
    if not api_key_file or not os.path.exists(api_key_file):
        return None
    with open(api_key_file, "r", encoding="utf-8") as f:
        key = f.read().strip()
    if not key or key == PLACEHOLDER_API_KEY:
        return None
    return key


def get_last_timestamp(timestamp_file):
    """Reads the last execution timestamp. If not found, defaults to 24 hours ago."""
    if os.path.exists(timestamp_file):
        with open(timestamp_file, "r", encoding="utf-8") as f:
            value = f.read().strip()
        if value:
            return value
    default_time = utc_now() - datetime.timedelta(days=1)
    return default_time.strftime(TIME_FORMAT)


def save_current_timestamp(timestamp_file, timestamp_str):
    """Saves the current execution timestamp for the next run."""
    parent = os.path.dirname(timestamp_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(timestamp_file, "w", encoding="utf-8") as f:
        f.write(timestamp_str)


def fetch_nvd_delta(
    api_url=DEFAULT_NVD_API_URL,
    timestamp_file=DEFAULT_TIMESTAMP_FILE,
    output_dir=DEFAULT_OUTPUT_DIR,
    api_key=None,
    timeout=30,
):
    """Fetches CVEs modified since the last run and writes them to a JSON delta file.

    Returns True on success, False on failure.
    """
    start_time = get_last_timestamp(timestamp_file)
    end_time = utc_now().strftime(TIME_FORMAT)

    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    # NVD rate limits: 5 requests / 30s without a key, 50 / 30s with a key.
    page_delay = 0.6 if api_key else 6.0

    params = {
        "lastModStartDate": start_time,
        "lastModEndDate": end_time,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    logger.info("Fetching updates from %s to %s from %s", start_time, end_time, api_url)

    all_vulnerabilities = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        try:
            response = requests.get(api_url, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.error("Error fetching data from NVD API: %s", e)
            return False

        vulnerabilities = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulnerabilities)

        total_results = data.get("totalResults", 0)
        logger.info(
            "Retrieved %d vulnerabilities (Progress: %d/%d)",
            len(vulnerabilities), len(all_vulnerabilities), total_results,
        )

        if len(all_vulnerabilities) >= total_results or not vulnerabilities:
            break

        start_index += len(vulnerabilities)
        time.sleep(page_delay)

    if not all_vulnerabilities:
        logger.info("No new or updated CVEs found in this time window.")
        save_current_timestamp(timestamp_file, end_time)
        return True

    os.makedirs(output_dir, exist_ok=True)

    filename = f"cve_delta_{end_time.replace(':', '-')}.json"
    output_path = os.path.join(output_dir, filename)

    payload = {
        "export_metadata": {
            "start_time": start_time,
            "end_time": end_time,
            "total_records": len(all_vulnerabilities),
        },
        "vulnerabilities": all_vulnerabilities,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info("Successfully generated delta file: %s (%d records)", output_path, len(all_vulnerabilities))

    # Update timestamp checkpoint only after successful execution
    save_current_timestamp(timestamp_file, end_time)
    return True


def build_parser():
    parser = argparse.ArgumentParser(
        prog="fetch-nvd",
        description="Fetch CVEs modified since the last run from the NVD API and save them as JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--api-key-file",
        default=DEFAULT_API_KEY_FILE,
        help="File containing the NVD API key (optional; the NVD_API_KEY env var is used if the file is missing)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where delta JSON files are written",
    )
    parser.add_argument(
        "--timestamp-file",
        default=DEFAULT_TIMESTAMP_FILE,
        help="File storing the timestamp of the last successful run",
    )
    parser.add_argument(
        "--nvd-api-url",
        default=DEFAULT_NVD_API_URL,
        help="NVD CVE API endpoint URL",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="HTTP request timeout in seconds",
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_FILE,
        help="Log file name (appended on each run)",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    setup_logging(args.log)
    try:
        logger.info("Starting fetch-nvd run")
        api_key = read_api_key(args.api_key_file) or os.environ.get("NVD_API_KEY") or None
        if not api_key:
            logger.warning("No NVD API key provided; requests will be heavily rate limited.")
        ok = fetch_nvd_delta(
            api_url=args.nvd_api_url,
            timestamp_file=args.timestamp_file,
            output_dir=args.output_dir,
            api_key=api_key,
            timeout=args.timeout,
        )
    except Exception:
        logger.exception("Unexpected error")
        ok = False
    logger.info("Run finished: %s", "success" if ok else "FAILED")
    close_logging()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
