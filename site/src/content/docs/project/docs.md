---
title: Writing the docs
description: Where the documentation lives, how to preview it, the conventions it follows, and how versions are published.
sidebar:
  order: 2
---

The documentation is this site, an [Astro Starlight](https://starlight.astro.build) project in `site/`. Its pages are Markdown (and MDX) files in `site/src/content/docs/`; the README only has an overview and links here.

## Previewing

```bash
mise run docs          # dev server at http://localhost:4321, reloads on save
mise run docs:build    # build as CI does, and check every internal link and anchor
```

Both install the dependencies first. Node comes from `mise.toml`.

## Where things go

| Directory | Sidebar group | For |
| --- | --- | --- |
| `start/` | Getting started | introduction, quick start |
| `install/` | Install | packages, verifying downloads |
| `guides/` | Guides | rules, prompts |
| `reference/` | Reference | configuration, command line, rule files, protocol, changelog |
| `internals/` | How it works | deciding a connection, security |
| `project/` | Project | development, docs, releasing |

The sidebar is generated from the directories; order pages with `sidebar.order` in their frontmatter. A new page needs `title` and `description` frontmatter, and no H1.

The [protocol schema](/reference/protocol/#schema) is read from `proto/` when the site is built, and the [changelog](/reference/changelog/) from `CHANGELOG.md`: neither is copied by hand.

## When to update what

Every change to behaviour updates the docs in the same commit:

- A new or changed setting: `reference/configuration.md` and `dist/daemon.toml`.
- A new or changed rule condition, alias or precedence: `guides/rules.md` and `reference/rule-files.md`.
- A change to prompts or suggestions: `guides/prompts.md`.
- A new command or option: `reference/cli.md`.
- A change to the protocol: `reference/protocol.mdx` for anything the schema's comments don't say.
- A change to what the daemon trusts or checks: `internals/security.md`.

## Conventions

- Plain, precise sentences, engineer to engineer. Say what happens, not how good it is.
- Internal links are site-absolute, without the version: `[rules](/guides/rules/)`, with the trailing slash. A plugin adds the base of the version being built. The build fails on a link to a page or anchor that doesn't exist.
- Code blocks have a language, and a `title` when they are a file.
- Examples use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and example domains (`example.com`, `example.org`, `example.net`).
- Don't document behaviour the code doesn't have. Check the source, or the end-to-end scenario that covers it. Parts still in development are named as such, without promises of how they will work.

## Versions

The site is published on GitHub Pages from the `gh-pages` branch, at `https://nikarh.github.io/snitchhiker/`, one directory per version:

| Path | Built from | Updated |
| --- | --- | --- |
| `/snitchhiker/main/` | the tip of `main` | on every push to `main` |
| `/snitchhiker/vX.Y.Z/` | the release tag | once, when the release is published; kept for good |
| `/snitchhiker/` | | redirects to the newest release (to `main/` while there is none) |
| `/snitchhiker/versions.json` | | the list of versions, read by the version menu |

A path without a version goes to that page of the newest release, through `404.html`.

The **Docs** workflow (`.github/workflows/docs.yml`) builds the site with `DOCS_VERSION` set to the version, which sets the base path, and `scripts/docs-publish.sh` copies the build into the version's directory of `gh-pages`, rewrites `versions.json` and the root redirect, and pushes. Pull requests only build, so broken links fail them.

A release's docs are its tag's `site/`, frozen when the release is published. To rebuild a release's docs, run the workflow by hand with the tag (`gh workflow run docs.yml -f version=v0.2.0`); the fix has to be on the tag. Normally, fix `main` instead. Don't edit the `gh-pages` branch by hand.
