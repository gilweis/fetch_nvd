"""fetch_nvd - fetch delta CVE JSON exports from the NVD API."""

from .cli import fetch_nvd_delta, main

__all__ = ["fetch_nvd_delta", "main"]
__version__ = "0.1.0"
