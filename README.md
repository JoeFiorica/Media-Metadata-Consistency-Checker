# Media Metadata Consistency Checker

Read-only checks for media metadata, extensions, timestamps, frame rates and companion-file rules.

## Requirements

Python 3.11+ available as `python`. Keep the BAT and PY together; no Python packages are needed.
Trusted `ffprobe` on PATH enables metadata checks. Without it, discovery and companion
checks still run, but a scan returns 3. Dry runs need no FFmpeg tools.

## Usage

Open Command Prompt in the downloaded folder. In PowerShell, prefix BAT commands with `.\`.

```bat
media-metadata-checker.bat help
media-metadata-checker.bat scan "./media" --dry-run
media-metadata-checker.bat scan "./media" --path-mode redacted --output "../audit.jsonl"
media-metadata-checker.bat report "../audit.jsonl" --json "audit.json" --csv "audit.csv"
```

`python media_metadata_checker.py` accepts the same arguments. Quote paths containing spaces.

## Behavior

`rules` explains findings; `rules --defaults` prints a configuration template.
Use `help scan` for filters, configuration, timeouts and path options.
Findings need review and do not prove corruption or complete file integrity.
Optional `deep-decode` uses trusted `ffmpeg` and requires `--acknowledge-cost`;
it can use substantial CPU and disk activity. Start with `help deep-decode` and `--dry-run`.

## Outputs

Scans write JSONL to the console or a new `--output` file outside the source folder.
Totals go to stderr. `report` converts completed JSONL to JSON/CSV. Existing files are refused.
Exit codes: 0 success/dry run; 1 findings above the chosen threshold;
2 usage, configuration or output error; 3 incomplete checks (takes precedence over 1);
130 interrupted.

## Safety and privacy

Media is never renamed, repaired, transcoded or timestamp-edited. Reading may update access times.
Links are skipped by default; following them is limited to the scan root. Probes have time/output limits.
Raw scans default to absolute paths; use `--path-mode redacted` to hide paths and filenames.
Report exports default to redacted paths. Review files before sharing. No telemetry or uploads.

## Troubleshooting

`media-metadata-checker.bat help` should exit 0. An invalid command exits 2.
A dry run on an empty disposable folder should exit 0 without changing it.
If Python is missing, install it separately and enable PATH. If ffprobe is missing,
metadata checks remain incomplete; install a trusted copy separately when needed.

Report issues with the command, runtime version and expected/actual result.
Omit real media and identifying reports.
