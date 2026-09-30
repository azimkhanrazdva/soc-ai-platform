# SOC AI Report Template

## Executive Summary

- Total events processed:
- Time range:
- Data source:
- Detection summary:
- Highest-priority findings:

## Data Scope

- Splunk indexes:
- Sourcetypes:
- Hosts/sources:
- Chunking mode:
- Checkpoint file:

## Data Integrity

- Planned chunks:
- Completed chunks:
- Failed chunks:
- Retried chunks:
- Rows exported:
- Rows analyzed:
- Rows skipped:

## Privacy And Redaction

- Redacted fields:
- Masked IPs:
- Masked users:
- Sensitive values discovered:
- Known residual risk:

## Performance

- Ingest elapsed time:
- Analysis elapsed time:
- Report generation time:
- Events per second:
- Peak memory:
- CPU/GPU notes:

## Model And Detection Comparison

| Method | Type | Labels Required | Metric | Value |
| --- | --- | --- | --- | --- |
| rules_keywords | baseline | false | anomaly_score | |
| frequency_outliers | statistical | false | rare_count | |

Precision, recall, F1 and ROC-AUC must only be filled when labeled validation data exists.

## Findings

| Priority | Finding | Evidence | Recommended Action |
| --- | --- | --- | --- |

## Limitations

- SPL performance depends on Splunk index design, indexed fields, time bounds, data model acceleration, and concurrent search load.
- Local GPU does not accelerate Splunk SPL directly.
- Large runs require enough disk for chunk outputs and reports.

## Next Steps

- Tune SPL filters and selected fields.
- Run benchmark against representative data.
- Add labeled datasets for model quality measurement.
- Configure retention for temporary chunk files.

