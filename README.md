# OSINT Regex

This is a collection of REGEX in a single place. It is a work in progress and some formulas may not be optimal or complete for every variation.

Use for Good. Use with care.

## Release

1. Update `__version__` in `src/osint_regex/__init__.py`.
2. Add a new entry to `CHANGELOG.md` describing the changes.
3. Commit the changes.
4. Create and push a tag:

   ```sh
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

Tags trigger the GitHub Action workflow to build and publish the package to PyPI.
