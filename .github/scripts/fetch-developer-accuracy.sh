#!/usr/bin/env bash
# Download the developer-build accuracy reports (CMake-MSVC420-Accuracy-Report)
# from the Build workflow run of this commit into the directory given as the
# only argument. Informative only: waits up to WAIT_SECONDS (default 1200)
# for that run to complete and exits 0 without files when it is missing,
# still running, cancelled, or has no reports.
# Requires: GH_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA.
set -euo pipefail

destination="$1"
deadline=$((SECONDS + ${WAIT_SECONDS:-1200}))
run_id=""
while :; do
  run="$(gh api \
    "repos/$GITHUB_REPOSITORY/actions/workflows/build.yml/runs?head_sha=$GITHUB_SHA&event=push&per_page=10" \
    --jq '[.workflow_runs[]] | sort_by(.run_number) | last // empty | "\(.id) \(.status) \(.conclusion)"' \
    || true)"
  read -r run_id status conclusion <<<"${run:-}" || true
  if [[ -z "${run_id:-}" ]]; then
    echo "No Build workflow run for $GITHUB_SHA yet"
  elif [[ "$status" == "completed" ]]; then
    echo "Build run $run_id completed: $conclusion"
    break
  else
    echo "Build run $run_id is $status"
  fi
  if (( SECONDS >= deadline )); then
    echo "::warning::The Build workflow run for $GITHUB_SHA did not complete in time; publishing without the developer-build accuracy reports"
    exit 0
  fi
  sleep 30
done

if ! gh run download "$run_id" --name CMake-MSVC420-Accuracy-Report --dir "$destination"; then
  echo "::warning::Build run $run_id ($conclusion) published no developer-build accuracy reports"
  rm -rf "$destination"
  exit 0
fi
ls -la "$destination"
