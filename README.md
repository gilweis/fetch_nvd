# fetch-nvd

Fetch CVE updates (deltas) from the [NIST National Vulnerability Database (NVD) API v2.0](https://nvd.nist.gov/developers/vulnerabilities)
and save them as JSON files.

Each run fetches all CVEs modified since the previous successful run (or the last 24 hours on the first run),
writes them to `cve_delta_<end-time>.json` in the output directory, and records the end time in a timestamp file.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install .
```

Or just install the dependencies: `pip install -r requirements.txt`.

## API key

An NVD API key is optional but highly recommended to avoid severe rate limiting.
Request one at <https://nvd.nist.gov/developers/request-an-api-key>, then either:

- put it in `api_key.txt` (or another file passed with `--api-key-file`), or
- set the `NVD_API_KEY` environment variable.

`api_key.txt` is listed in `.gitignore` so it is not committed.

## Usage

```bash
fetch-nvd [options]
# or
python -m fetch_nvd [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `--api-key-file` | `api_key.txt` | File containing the NVD API key |
| `--output-dir` | `delta_exports` | Directory where delta JSON files are written |
| `--timestamp-file` | `last_run_timestamp.txt` | File storing the timestamp of the last successful run |
| `--nvd-api-url` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE API endpoint |
| `--timeout` | `30` | HTTP request timeout in seconds |
| `--log` | `fetch_nvd.log` | Log file name (appended on each run) |

Example:

```bash
fetch-nvd --api-key-file C:\secrets\nvd.txt --output-dir exports --timestamp-file state\last_run.txt
```

The exit code is `0` on success and `1` on failure (the timestamp is not updated on failure).

Progress and errors are printed to the console and appended, with timestamps, to the log file
(`fetch_nvd.log` by default; change it with `--log`).

> Note: the NVD API limits a single `lastModStartDate`/`lastModEndDate` range to 120 days.

## Output format

```json
{
  "export_metadata": {
    "start_time": "2026-11-15T13:00:00.000",
    "end_time": "2026-11-16T13:00:00.000",
    "total_records": 123
  },
  "vulnerabilities": [ ... ]
}
```

## Development

```bash
pip install -e .[dev]
pytest
```

## License

[MIT](LICENSE)
