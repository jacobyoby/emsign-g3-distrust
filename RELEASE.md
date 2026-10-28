# Releases and PyPI

## Versioning

- Package version lives in [`pyproject.toml`](pyproject.toml) and [`src/emsign_g3/__init__.py`](src/emsign_g3/__init__.py).
- Tag releases as `v*` (for example `v0.2.0`) on `main` after merging release prep.

## GitHub Release (automated)

Pushing a tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Runs verify, committed-rule check, and pytest
2. Builds sdist/wheel
3. Uploads a GitHub Release with:
   - `dist/*`
   - `indicators.csv`, `indicators.json`, `indicators.ndjson`
   - `tools/emsign-g3-distrust.rules`
   - `sigma-rules.tar.gz`, `elastic-kql.tar.gz`
4. Publishes the wheel to PyPI (see below)

```bash
git tag v0.2.0
git push origin v0.2.0
```

## PyPI trusted publishing (one-time)

For step 4 to succeed, configure [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) for this repository:

1. Create the `emsign-g3-distrust` project on PyPI (or claim the name).
2. Add a trusted publisher: GitHub, owner `jacobyoby`, repository `emsign-g3-distrust`, workflow `release.yml`, environment optional.
3. Push a tag; the `pypa/gh-action-pypi-publish` step uses OIDC (`id-token: write`).

Until PyPI is configured, disable or skip the **Publish to PyPI** step in the workflow, or ignore that job failure; the GitHub Release assets still upload.

## Regenerating SIEM files before release

After editing `indicators.csv`:

```bash
tools/regenerate_detection_rules.sh
git add rules/sigma rules/elastic
```
