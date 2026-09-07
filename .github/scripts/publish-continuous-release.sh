#!/usr/bin/env bash
# Atomically replace the "continuous" release with the files given as
# arguments. Uploads everything to a run-unique staging release first, backs
# up the existing continuous release, and restores it if the short tag swap
# fails, so the project is never left without a verified continuous release.
# Requires: GH_TOKEN, GH_REPO/GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_RUN_ID,
# GITHUB_RUN_ATTEMPT, RUNNER_TEMP.
set -euo pipefail

files=("$@")
test "${#files[@]}" -gt 0
for path in "${files[@]}"; do
  test -s "$path"
done

staging_tag="continuous-staging-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
cleanup_staging() {
  status=$?
  trap - EXIT
  if [[ "$status" -ne 0 ]]; then
    set +e
    gh release delete "$staging_tag" --cleanup-tag --yes >/dev/null 2>&1
    gh api --method DELETE \
      "repos/$GITHUB_REPOSITORY/git/refs/tags/$staging_tag" \
      >/dev/null 2>&1
  fi
  exit "$status"
}
trap cleanup_staging EXIT

gh release create "$staging_tag" "${files[@]}" \
  --target "$GITHUB_SHA" \
  --title "Continuous build" \
  --notes "Automatically reproduced and verified from $GITHUB_SHA." \
  --draft

test "$(gh release view "$staging_tag" --json assets --jq '.assets | length')" -eq "${#files[@]}"
for path in "${files[@]}"; do
  name="$(basename "$path")"
  expected_size="$(stat -c %s "$path")"
  expected_digest="sha256:$(sha256sum "$path" | cut -d' ' -f1)"
  asset="$(gh release view "$staging_tag" --json assets \
    --jq ".assets[] | select(.name == \"$name\") | [.size, .digest] | @tsv")"
  IFS=$'\t' read -r actual_size actual_digest <<<"$asset"
  test "$actual_size" = "$expected_size"
  test "$actual_digest" = "$expected_digest"
done

# GitHub uploads all assets before exposing a release created this
# way. Back up the old release before the short tag swap so a failed
# API call cannot leave the project without a continuous release.
release_tags="$(gh api --paginate \
  "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
  --jq '.[].tag_name')"
had_continuous=false
rollback_root="$RUNNER_TEMP/continuous-rollback-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
rollback_assets="$rollback_root/assets"
rollback_release="$rollback_root/release.json"
rollback_notes="$rollback_root/notes.md"
mkdir -p "$rollback_assets"
if grep -Fxq continuous <<<"$release_tags"; then
  had_continuous=true
  gh release view continuous \
    --json name,body,targetCommitish,isPrerelease,assets \
    >"$rollback_release"
  jq -r '.body // ""' "$rollback_release" >"$rollback_notes"
  gh release download continuous --dir "$rollback_assets"
  while IFS=$'\t' read -r name size digest; do
    test "$(stat -c %s "$rollback_assets/$name")" = "$size"
    test "sha256:$(sha256sum "$rollback_assets/$name" | cut -d' ' -f1)" = "$digest"
  done < <(jq -r '.assets[] | [.name, .size, .digest] | @tsv' "$rollback_release")
fi

restore_needed=false
swap_started=false
restore_continuous() {
  status=$?
  trap - EXIT
  if [[ "$status" -ne 0 ]]; then
    set +e
    if [[ "$restore_needed" == true ]]; then
      echo "::warning::Continuous release swap failed; restoring the previous release"
      current_release="$rollback_root/current.json"
      release_projection='{name, body, targetCommitish, isPrerelease,
        assets: ([.assets[] | {name, size, digest}] | sort_by(.name))}'
      if gh release view continuous \
        --json name,body,targetCommitish,isPrerelease,assets \
        >"$current_release" && diff -q \
          <(jq -S "$release_projection" "$rollback_release") \
          <(jq -S "$release_projection" "$current_release") \
          >/dev/null; then
        echo "Previous continuous release is still intact"
      else
        gh release delete continuous --cleanup-tag --yes >/dev/null 2>&1
        gh release delete "$staging_tag" --cleanup-tag --yes >/dev/null 2>&1
        gh api --method DELETE \
          "repos/$GITHUB_REPOSITORY/git/refs/tags/continuous" \
          >/dev/null 2>&1

        mapfile -d '' -t rollback_files \
          < <(find "$rollback_assets" -maxdepth 1 -type f -print0 | sort -z)
        rollback_flags=(--latest=false)
        if [[ "$(jq -r '.isPrerelease' "$rollback_release")" == true ]]; then
          rollback_flags+=(--prerelease)
        fi
        if gh release create continuous "${rollback_files[@]}" \
          --target "$(jq -r '.targetCommitish' "$rollback_release")" \
          --title "$(jq -r '.name // "Continuous build"' "$rollback_release")" \
          --notes-file "$rollback_notes" \
          "${rollback_flags[@]}"; then
          if ! diff -u \
            <(jq -S '[.assets[] | {name, size, digest}] | sort_by(.name)' "$rollback_release") \
            <(gh release view continuous --json assets \
              --jq '[.assets[] | {name, size, digest}] | sort_by(.name)'); then
            echo "::error::Restored continuous release assets differ from the backup"
          fi
        else
          echo "::error::Could not restore the previous continuous release"
        fi
      fi
    elif [[ "$swap_started" == true && "$had_continuous" == false ]]; then
      gh release delete continuous --cleanup-tag --yes >/dev/null 2>&1
      gh api --method DELETE \
        "repos/$GITHUB_REPOSITORY/git/refs/tags/continuous" \
        >/dev/null 2>&1
    fi
    gh release delete "$staging_tag" --cleanup-tag --yes >/dev/null 2>&1
    gh api --method DELETE \
      "repos/$GITHUB_REPOSITORY/git/refs/tags/$staging_tag" \
      >/dev/null 2>&1
  fi
  exit "$status"
}
trap restore_continuous EXIT

swap_started=true
if [[ "$had_continuous" == true ]]; then
  restore_needed=true
  gh release delete continuous --cleanup-tag --yes
fi
continuous_refs="$(gh api \
  "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/continuous" \
  --jq '.[].ref')"
if grep -Fxq refs/tags/continuous <<<"$continuous_refs"; then
  gh api --method DELETE "repos/$GITHUB_REPOSITORY/git/refs/tags/continuous"
fi

gh release edit "$staging_tag" \
  --tag continuous \
  --target "$GITHUB_SHA" \
  --title "Continuous build" \
  --notes "Automatically reproduced and verified from $GITHUB_SHA." \
  --draft=false \
  --latest=false

test "$(gh release view continuous --json assets --jq '.assets | length')" -eq "${#files[@]}"
restore_needed=false
trap - EXIT
