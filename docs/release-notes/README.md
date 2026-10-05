# Release notes

Put notes for a tag at `docs/release-notes/<tag>.md` on the commit you tag.

Examples:

- `docs/release-notes/v2026.10.04.01.md`
- `docs/release-notes/v2026.10.05.01.md`

Versions are `YYYY.MM.DD.BB` in America/Chicago. Month, day, and build are zero-padded to at least two digits. `scripts/next-date-build-version` prints the next version (without the `v`). The GitHub Release title is `v<version>`.

If that file is absent from the tagged commit, the release workflow uses GitHub's generated notes. The workflow does not create the tag.
