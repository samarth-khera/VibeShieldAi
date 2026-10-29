# npm Job-portal fixture

- `original.package.json`, `original.package-lock.json`: `backend/package.json` and
  `backend/package-lock.json` of the public repository
  [samarth-khera/Job-portal](https://github.com/samarth-khera/Job-portal) at commit
  `7f90143a47c6280f6bcf9d55bb7c4767a48c1542` (multer 2.0.2 is installed).
- `npm-expected.*`: the same files after running npm 10.9.3 in an empty directory with no `.npmrc`:
  `npm install multer@2.5.0 --package-lock-only --ignore-scripts --no-audit --no-fund --registry https://registry.npmjs.org/`.
- `npm-update-proxy-addr.package-lock.json`: `npm update proxy-addr --package-lock-only --ignore-scripts`
  (same isolated setup); package.json is unchanged by npm.
- `registry-multer-2.5.0.json`, `registry-proxy-addr-2.0.8.json`: the fields VibeShield reads from
  https://registry.npmjs.org/<name>/<version> (fetched 2026-10-30).
- `registry-proxy-addr.versions.json`, `registry-brace-expansion.versions.json`: the release lists from
  npm's abbreviated metadata (`Accept: application/vnd.npm.install-v1+json`), trimmed to version
  numbers and deprecation flags (fetched 2026-10-30).

The files are deliberately not named `package.json`/`package-lock.json`, so dependency scanners
(Dependabot, OSV-Scanner) do not report this fixture's intentionally vulnerable multer 2.0.2 as
VibeShield's own dependency.
