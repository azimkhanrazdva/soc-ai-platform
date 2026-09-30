# Security

## Secrets

- Put Splunk credentials in environment variables or `.env`.
- Do not commit `.env`, real tokens, raw credential dumps, or unredacted production logs.
- The CLI loads `.env`, but existing shell variables take precedence.

## Splunk Export Safety

- Production export commands reject lossy SPL commands such as `head`, `tail`, `sample`, and bounded `sort` by default.
- Use time windows and partitions instead of truncating result sets.
- Keep checkpoint files and chunk manifests with the report package.

## Data Handling

- Source logs in Splunk are never deleted.
- Local cleanup must be limited to project-owned temporary files.
- Reports should contain redacted evidence and aggregate metrics, not full sensitive payloads.

## Incident Response

If secrets are discovered in generated artifacts:

1. Stop sharing the artifact.
2. Rotate the exposed credential.
3. Remove the artifact from the report bundle.
4. Add or tighten a redaction rule.
5. Rerun `soc-ai pipeline-local` or the relevant Splunk pipeline.

