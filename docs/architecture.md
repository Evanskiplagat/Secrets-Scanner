# Architecture

Secret Scanner uses a layered design:

- `scanner/core`: CLI, config, orchestration, domain models
- `scanner/detectors`: Pattern rules and entropy-based detection engine
- `scanner/reports`: Terminal, JSON, CSV, and HTML reporting
- `scanner/utils`: File discovery, safe reading, and masking helpers

## Detection Flow

1. Discover supported files recursively while applying built-in and user-supplied exclusions.
2. Read file content with UTF-8 fallback semantics.
3. Evaluate each line against documented regex signatures.
4. Apply hardcoded credential and high-entropy heuristics.
5. Filter by minimum requested severity.
6. Suppress findings already accepted in a baseline or ignore file.
7. Render masked output to terminal and optional reports.

## Performance Notes

- `ThreadPoolExecutor` parallelizes file scanning across repositories.
- File discovery filters extensions before content analysis.
- Progress rendering is transient, keeping terminal output concise for CI and local runs.
