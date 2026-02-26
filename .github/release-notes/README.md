# Manual Release Notes Overrides

The release workflow auto-generates notes for each tag with these sections:

- Highlights
- Breaking Changes
- Migration Notes
- Full changelog

To manually curate a specific release body, add a file named:

- `.github/release-notes/<tag>.md`

Example:

- `.github/release-notes/v1.2.3.md`

When this file exists for the pushed tag, the workflow uses it verbatim as the GitHub Release notes body.
