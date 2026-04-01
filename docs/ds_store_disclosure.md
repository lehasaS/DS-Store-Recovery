# .DS_Store Disclosure: What It Is, Why It Works, and How to Prevent It

## What is `.DS_Store`?

`.DS_Store` (Desktop Services Store) is a macOS Finder metadata file created in directories that users browse. It can include metadata such as visible entry names and folder display preferences.

## Why disclosure is possible

Disclosure happens when `.DS_Store` is published to a web-accessible location (for example, static site roots, backup artifacts, misconfigured deployments, or synced archives). If an attacker can download it, they can parse names of files/directories that may not be linked in the public UI.

Common causes:

- Deployment pipelines copying hidden files.
- Web server rules that do not block dotfiles.
- Archive extraction workflows preserving hidden metadata files.
- Shared hosting misconfiguration.

## What can be exposed

- Directory names that are not directly listed by the web app.
- File names and inferred structure of private or admin paths.
- Additional candidate targets for direct path probing.

Important: `.DS_Store` usually does **not** include full contents of target files. It provides discovery data that can enable follow-on requests to real files.

## Typical attack flow

1. Attacker requests `/.DS_Store`.
2. Parses entry names from returned metadata.
3. Tries discovered paths directly (`/admin/`, `/backup.zip`, etc.).
4. Repeats recursively by probing discovered subdirectories for nested `/.DS_Store`.

## Impact

- Information disclosure and reduced attack effort.
- Exposure of sensitive filenames (backups, keys, admin endpoints, drafts).
- Increased success probability for targeted exploitation.

## Prevention and hardening

## 1) Block dotfiles at the web layer

Deny requests to hidden files, especially `.DS_Store`.

Nginx example:

```nginx
location ~ /\.(?!well-known).* {
    deny all;
    return 404;
}
```

Apache example (`.htaccess`):

```apache
<FilesMatch "^\.">
    Require all denied
</FilesMatch>
```

## 2) Exclude `.DS_Store` from artifacts and repos

- Add to `.gitignore` and deployment excludes.
- Clean build directories before packaging.
- In CI/CD, fail builds that contain hidden metadata files in publish roots.

## 3) Scan continuously

- Add a scheduled check for exposed `/.DS_Store` and nested variants.
- Validate staging and production domains after each release.

## 4) Minimize static exposure

- Avoid serving raw filesystem trees where possible.
- Use allowlists for publicly served files.

## 5) Incident response steps if exposed

1. Remove/deny `.DS_Store` access immediately.
2. Enumerate discovered paths and assess sensitivity.
3. Rotate any secrets referenced by exposed path names.
4. Review access logs for suspicious requests to discovered files.
5. Add preventive controls in deployment and server config.

## Why this project is useful

This project demonstrates and validates the practical risk of `.DS_Store` exposure by reconstructing likely structure from remote or local metadata, supporting both defensive testing and incident analysis.
