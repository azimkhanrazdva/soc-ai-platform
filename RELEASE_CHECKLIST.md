# Release Checklist

- `scripts/release_check.sh` passes.
- `soc-ai doctor` passes locally.
- Splunk credentials are provided through environment variables or `.env`.
- `soc-ai splunk-preflight` has been reviewed before real export.
- No production SPL contains `head`, `tail`, `sample`, or bounded `sort`.
- Chunk size and partitions are reviewed for expected event volume.
- Checkpoint, manifest, analysis JSON, rule findings, model profile, evaluation, and report artifacts are retained.
- Generated reports have been reviewed for sensitive information.
- Real precision/recall/F1/ROC-AUC are reported only when labeled data exists.

