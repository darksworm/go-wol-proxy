#!/usr/bin/env bash
#
# Set up or rotate RELEASE_PLEASE_TOKEN, the personal access token the release
# pipeline uses to open release pull requests and cut tags.
#
# GitHub has no API for creating a personal access token, so one paste is
# unavoidable. This script does the rest: opens the form, tells you exactly what
# to tick, then checks the token really works before installing it, so a wrong
# permission fails here rather than quietly three weeks later when a release is
# due.
#
set -euo pipefail

REPO="${REPO:-darksworm/doormouse}"
SECRET_NAME="RELEASE_PLEASE_TOKEN"
NEW_TOKEN_URL="https://github.com/settings/personal-access-tokens/new"

usage() {
	cat <<EOF
Rotate $SECRET_NAME on $REPO.

First mint a token at
  $NEW_TOKEN_URL

  Resource owner ....... the account owning $REPO
  Repository access .... Only select repositories -> $REPO
  Contents ............. Read and write   (commits, tags, releases)
  Pull requests ........ Read and write   (the release pull request)
  Issues ............... Read and write   (labels on the release pull request)

Then:
  scripts/rotate-release-token.sh              open the form, then prompt
  pass show gh/doormouse-release | scripts/rotate-release-token.sh
  scripts/rotate-release-token.sh --dry-run    validate it, install nothing
  scripts/rotate-release-token.sh --no-browser prompt without opening a browser

Set REPO in the environment to target a different repository.
EOF
}

dry_run=false
open_browser=true
for arg in "$@"; do
	case "$arg" in
	--dry-run) dry_run=true ;;
	--no-browser) open_browser=false ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $arg" >&2
		usage >&2
		exit 2
		;;
	esac
done

command -v gh >/dev/null || {
	echo "error: the GitHub CLI (gh) is required" >&2
	exit 1
}

# Hand the URL to whatever opens links here. Backgrounded because some browsers
# hold the terminal, and best-effort because plenty of machines have no opener at
# all — over SSH, in a container.
open_url() {
	if [ -n "${BROWSER:-}" ] && command -v "${BROWSER%% *}" >/dev/null 2>&1; then
		"$BROWSER" "$1" >/dev/null 2>&1 &
		return 0
	fi
	for opener in xdg-open open wslview; do
		if command -v "$opener" >/dev/null 2>&1; then
			"$opener" "$1" >/dev/null 2>&1 &
			return 0
		fi
	done
	return 1
}

# Read the token from a prompt when there is a terminal, otherwise from stdin so
# it can be piped out of a password manager. Never echoed, and never passed as an
# argument, so it stays out of the shell history and out of ps.
if [ -t 0 ]; then
	cat >&2 <<EOF
Mint a token for $REPO. GitHub has no API for this, so it is a form.

  Token name ........... doormouse-release-please
  Resource owner ....... ${REPO%%/*}
  Repository access .... Only select repositories -> $REPO

  Repository permissions, all three set to Read and write:
    Contents ........... commits the changelog, creates tags and releases
    Pull requests ...... opens and updates the release pull request
    Issues ............. the autorelease label on that pull request

  Metadata turns read-only by itself. Leave the rest alone; the summary
  should say "3 permissions" before you generate.

EOF
	if [ "$open_browser" = true ] && open_url "$NEW_TOKEN_URL"; then
		echo "Opening $NEW_TOKEN_URL" >&2
	else
		echo "Open $NEW_TOKEN_URL" >&2
	fi
	echo >&2
	printf 'Paste the token here (input hidden): ' >&2
	IFS= read -rs token
	printf '\n' >&2
else
	# An empty stdin makes read fail, which would otherwise end the script here
	# without explanation. Fall through to the "no token given" check instead.
	IFS= read -r token || true
fi

# Trim the whitespace a copy-paste tends to bring along.
token="${token#"${token%%[![:space:]]*}"}"
token="${token%"${token##*[![:space:]]}"}"

[ -n "$token" ] || {
	echo "error: no token given" >&2
	exit 1
}

# Authenticate as the new token rather than as whoever is running this. Both
# variable names are set because gh prefers GH_TOKEN but honours either.
as_new_token() {
	GH_TOKEN="$token" GITHUB_TOKEN="$token" gh "$@"
}

echo "==> Checking the token against $REPO"

# .permissions.push is true only when the token holds Contents: Read and write.
# Without it release-please cannot commit the changelog or create the tag.
if ! repo_info=$(as_new_token api "repos/$REPO" -q '[.full_name, .permissions.push] | @tsv' 2>&1); then
	# gh prints the API's JSON and then its own one-line summary, tacked onto the
	# JSON's closing brace without a newline. The summary is the useful half.
	reason=$(printf '%s\n' "$repo_info" | grep -o 'gh: .*' | head -1 || true)
	[ -n "$reason" ] || reason=$(printf '%s\n' "$repo_info" | tail -1)
	echo "error: the token cannot read $REPO" >&2
	echo "       ${reason#gh: }" >&2
	echo "       Check the resource owner, and that repository access covers $REPO." >&2
	exit 1
fi

full_name=${repo_info%%$'\t'*}
can_push=${repo_info##*$'\t'}

if [ "$can_push" != "true" ]; then
	echo "error: the token has read-only access to $full_name." >&2
	echo "       Set Contents to 'Read and write' and try again." >&2
	exit 1
fi
echo "    can write to $full_name"

# A token's expiry date comes back as a response header, so ask for the headers.
# A token with an expiry date carries one; one set never to expire does
# not, which is worth saying out loud rather than reporting as unknown.
#
# Captured into a variable and parsed in one command on purpose. Piping gh into
# awk and letting awk exit on the first match closes the pipe early, and under
# `set -eo pipefail` the resulting SIGPIPE takes the whole script down without a
# word — which it did, but only for tokens that actually carry the header.
headers=$(as_new_token api -i "repos/$REPO" 2>/dev/null || true)
expiry=$(awk -F': ' '
	tolower($1) == "github-authentication-token-expiration" {
		sub(/\r$/, "", $2)
		print $2
	}' <<<"$headers")

if [ -n "$expiry" ]; then
	echo "    expires $expiry"
else
	echo "    no expiry reported (a token set never to expire)"
fi

# GitHub's expiry dropdown defaults to 30 days, which is easy to accept by
# accident and means being back here in a month. Say so before storing, while
# going back to the form is still cheap. `|| true` because parsing the date
# needs GNU date, and a machine without it should not fail the rotation.
MIN_DAYS=${MIN_DAYS:-180}
if [ -n "$expiry" ]; then
	expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || true)
	if [ -n "$expiry_epoch" ]; then
		days_left=$(((expiry_epoch - $(date +%s)) / 86400))
		if [ "$days_left" -lt "$MIN_DAYS" ]; then
			echo
			echo "warning: this token lasts $days_left days, less than the $MIN_DAYS this script"
			echo "         expects. GitHub's Expiration dropdown defaults to 30 days; pick"
			echo "         Custom and set a date up to a year out instead."
			echo
			if [ "$dry_run" = false ] && [ -t 0 ]; then
				printf 'Store it anyway? [y/N] ' >&2
				IFS= read -r reply || true
				case "$reply" in
				y | Y | yes | YES) ;;
				*)
					echo "Nothing stored. Mint a longer-lived token and run this again." >&2
					exit 1
					;;
				esac
			fi
		fi
	fi
fi

if [ "$dry_run" = true ]; then
	echo "==> --dry-run: the secret was not changed"
	exit 0
fi

echo "==> Storing $SECRET_NAME on $REPO"
printf '%s' "$token" | gh secret set "$SECRET_NAME" --repo "$REPO"

# Read it back, so "stored" means the API agrees rather than that gh exited 0.
# `|| true` because a hiccup listing secrets must not report the store as failed.
stored=$(gh secret list --repo "$REPO" 2>/dev/null |
	awk -v n="$SECRET_NAME" '$1 == n { print }' || true)
if [ -n "$stored" ]; then
	echo "    $stored"
else
	echo "warning: the secret was set but does not show up in the list" >&2
fi

cat <<EOF

Done. The next release pull request will use the new token. To exercise it now
without waiting for a release:

    gh workflow run release-pipeline.yml --repo $REPO
EOF

if [ -n "$expiry" ]; then
	cat <<EOF

Set yourself a reminder before $expiry. An expired token does not
fail loudly: release-please just stops opening release pull requests.
EOF
fi
