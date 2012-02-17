#!/bin/bash
#
# Copyright (c) 2012 by Delphix.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

hooks=/delphix-gate/tools/git/hooks

function usage
{
	if [[ $# -ne 0 ]]; then
		echo "$(basename $0): $*" >&2
		echo
	fi

	cat <<EOF
Usage: $(basename $0) [-bBcCrR] [-d dir] <notification-address> ..."

	-b/B	enable/disable bug checks (enabled by default)
	-c/C	enable/disable comment checks (enabled by default)
	-r/R	enable/disable review checks (disabled by default)

	-d dir	specify the git hooks directory; default:
		$hooks

Execute this from the root of a git repository that you want to
configure as a project gate with emails sent to the given addresses.
EOF

	exit 2
}

function die
{
	echo "$(basename $0): $*" >&2
	exit 1
}

opt_b=true	# bug checks are enabled by default
opt_c=true	# comment checks are enabled by default
opt_r=false	# review checks are disabled by default

OPTIND=1; while getopts 'bBcCd:rRh' c; do
	case "$c" in
	b|c|r) eval opt_$c=true ;;
	B|C|R) eval "opt_$(echo $c | tr '[:upper:]' '[:lower:]')=false" ;;
	d) hooks="$OPTARG" ;;
	h) usage ;;
	*) usage ;;
	esac
done

let OPTIND="$OPTIND - 1"; shift $OPTIND

[[ $# -gt 0 ]] || usage

$opt_r && ($opt_b || usage "Review checks (-r) require bug checks (-b)")
$opt_b && ($opt_c || usage "Bug checks (-b) require comment checks (-c)")

base=$(git rev-parse --show-toplevel 2>/dev/null)
[[ $? -eq 0 ]] || die "Must be run from a git repository"
[[ $(pwd -P) = $base ]] || die "Must be run from the top-level directory"


git config --get gate.name >/dev/null 2>&1 && \
    die ".git/config is already configured as a gate"

cp -r $hooks .git/newhooks || die "failed to copy $hooks"
rm -rf .git/hooks || die "failed to remove old hooks"
mv .git/newhooks .git/hooks || die "failed to rename new hooks"

cat <<EOF >.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[receive]
	denyCurrentBranch = ignore
[gate]
	name = $(basename $base)
	notify = $*
	# user-check = skip
	$($opt_c && echo "# ")commit-check = skip
	$($opt_b && echo "# ")comment-check = skip
	$($opt_r && echo "# ")review-check = skip
EOF

echo "Your gate has been configured"

exit 0
