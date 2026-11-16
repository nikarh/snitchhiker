#!/usr/bin/env bash
# Publishes a built version of the docs to the gh-pages branch, which GitHub Pages serves as
# https://nikarh.github.io/snitchhiker/ (a project site). Each version has a directory of its own: main/ for the tip of main, vX.Y.Z/ for
# releases. The build replaces its version's directory, and the script rewrites what spans versions: versions.json
# (read by the version menu), the root index.html (a redirect to the newest release, or to main before the first
# release) and 404.html.
#
#   scripts/docs-publish.sh <version> <built site>      e.g. scripts/docs-publish.sh v0.2.0 site/dist
#   scripts/docs-publish.sh repo <package repositories>  the signed package repositories (scripts/package-repos.sh)
#
# The site has to be built with DOCS_VERSION=<version>. Pushes with the credentials of the checkout it runs in; another
# publish pushing in between is retried on top of it.
set -euo pipefail

version=${1:?usage: docs-publish.sh <version> <built site>}
built=$(realpath "${2:?usage: docs-publish.sh <version> <built site>}")
remote=${DOCS_REMOTE:-origin}
branch=gh-pages
# The project site's address, and the path GitHub Pages serves the branch under.
site=https://nikarh.github.io/snitchhiker
prefix=/snitchhiker/

if ! [[ $version == main || $version == repo || $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "docs-publish: version must be main, repo or vX.Y.Z, not $version" >&2
  exit 1
fi
[[ -f $built/index.html ]] || { echo "docs-publish: $built has no index.html" >&2; exit 1; }

repo=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
fetched=refs/docs-publish/$branch
orphan=docs-publish-$$
cleanup() {
  git -C "$repo" worktree remove --force "$work" 2>/dev/null || rm -rf "$work"
  git -C "$repo" branch -D "$orphan" >/dev/null 2>&1 || true
  git -C "$repo" update-ref -d "$fetched" 2>/dev/null || true
}
trap cleanup EXIT

render_root() {
  local dir=$1 latest
  # Newest first: main, then releases by version.
  mapfile -t releases < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -name 'v*' -printf '%f\n' | sort -rV)
  {
    [[ -d $dir/main ]] && echo main
    printf '%s\n' "${releases[@]}"
  } | jq -R . | jq -cs 'map(select(length > 0))' > "$dir/versions.json"
  latest=${releases[0]:-main}
  cat > "$dir/index.html" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>Snitchhiker</title>
<meta http-equiv="refresh" content="0; url=./$latest/">
<link rel="canonical" href="$site/$latest/">
<p>The documentation of the latest release is at <a href="./$latest/">$latest</a>.</p>
HTML
  # GitHub Pages serves this for any path that doesn't exist. A path without a version, such as
  # /reference/configuration/ (what the README and the example configuration link to), goes to that page of the
  # latest release; anything else gets a page pointing at the versions.
  cat > "$dir/404.html" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>Not found · Snitchhiker</title>
<script>
  (function () {
    var latest = "$latest";
    var versions = $(cat "$dir/versions.json");
    var prefix = "$prefix";
    if (location.pathname.indexOf(prefix) !== 0) return;
    var path = location.pathname.slice(prefix.length), first = path.split("/")[0];
    if (path && versions.indexOf(first) < 0) location.replace(prefix + latest + "/" + path + location.search + location.hash);
  })();
</script>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:36rem;margin:15vh auto;padding:0 1rem;color:#13161b}a{color:#0b6b64}@media (prefers-color-scheme:dark){body{background:#0f1216;color:#e9edf2}a{color:#31c6b9}}</style>
<h1>Page not found</h1>
<p>This page doesn't exist in this version of the Snitchhiker docs. It may have moved, or belong to another version.</p>
<p><a href="$prefix$latest/">Go to the documentation of $latest</a> or <a href="${prefix}main/">of main</a>.</p>
HTML
  touch "$dir/.nojekyll"
}

for attempt in 1 2 3 4 5; do
  git -C "$repo" worktree remove --force "$work" 2>/dev/null || rm -rf "$work"
  if git -C "$repo" fetch --quiet --depth 1 "$remote" "+refs/heads/$branch:$fetched" 2>/dev/null; then
    git -C "$repo" worktree add --quiet --detach "$work" "$fetched"
  else
    # The first publish: start the branch with no history.
    git -C "$repo" branch -D "$orphan" >/dev/null 2>&1 || true
    git -C "$repo" worktree add --quiet --detach "$work"
    git -C "$work" switch --quiet --orphan "$orphan"
  fi

  rm -rf "${work:?}/$version"
  cp -R "$built" "$work/$version"
  render_root "$work"

  git -C "$work" add -A
  if git -C "$work" diff --cached --quiet; then
    echo "docs-publish: $version is up to date"
    exit 0
  fi
  git -C "$work" -c user.name="${GIT_AUTHOR_NAME:-github-actions[bot]}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}" \
    commit --quiet -m "docs: publish $version ($(git -C "$repo" rev-parse --short HEAD))"
  if git -C "$work" push --quiet "$remote" "HEAD:refs/heads/$branch"; then
    echo "docs-publish: published $version, versions: $(cat "$work/versions.json")"
    exit 0
  fi
  echo "docs-publish: the push was rejected (attempt $attempt), trying again on top of the newer $branch" >&2
  sleep $((attempt * 2))
done
echo "docs-publish: giving up after 5 attempts" >&2
exit 1
