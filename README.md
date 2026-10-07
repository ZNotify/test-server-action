# test-server-action for Notify

Setup a test server listen on `0.0.0.0:14444`

```yaml
uses: ZNotify/test-server-action@master
```

The action first downloads the current workflow run's server artifact using the
GitHub Actions artifact v4 backend. If no artifact can be downloaded, it uses the
published test release by default, preserving standalone SDK test behavior.

When testing a candidate server build, require its current-run artifact so a
download failure cannot silently substitute the published release:

```yaml
- uses: ZNotify/test-server-action@master
  with:
    require-current-artifact: true
```

## License

This is free and unencumbered software released into the public domain.
