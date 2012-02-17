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

shopt -s xpg_echo

tmp_dir=$(mktemp -d /tmp/githooks.XXXXXX)
gate=$tmp_dir/gate
work=$tmp_dir/work

function die
{
	echo "$0: $*" >&2
	echo "  scratch space: $tmp_dir"
	exit 1
}

function reset
{
	cd $gate
	git reset --hard $head >/dev/null
	cd - >/dev/null
	cd $work
	git reset --hard $head >/dev/null
	cd - >/dev/null
}

function push
{
	local ret comment files file

	cd $gate
	comment=$(git config --get test.comment)
	[[ -z "$comment" ]] && comment="new file"
	files=$(git config --get test.files)
	[[ -z "$files" ]] && files=the_epa
	cd - >/dev/null

	cd $work
	for file in $files; do
		[[ -d $(dirname $file) ]] || mkdir -p $(dirname $file)
	done
	touch $files
	git add -f $files
	git log >>/tmp/foo
	git commit --quiet -m "$comment"
	git log >>/tmp/foo
	git push
	ret=$?
	cd - >/dev/null
	return $ret
}

base=$(git rev-parse --show-toplevel 2>/dev/null)
[[ $? -eq 0 ]] || die "not in a git repository"

config_dir=$(dirname $0)/configs

tests=$*
[[ -z $tests ]] && tests=$(cd $config_dir; ls *)


#
# Create our test gate and link in our hooks.
#
echo "Creating test gate ... \c"
mkdir $gate
cd $gate
git init --quiet --template=.././dev/null >/dev/null 2>&1 || \
    dir "failed to git init"
[[ -d "$base/tools/git/hooks" ]] || die "$base/tools/git/hooks doesn't exist"
ln -s "$base/tools/git/hooks" $gate/.git
touch dept_energy dept_transport um...
git add .
git commit --quiet -m "init"
head=$(git show-ref --hash)
cd - >/dev/null
echo "done."

#
# As yet, there are no pull hooks, so we can pull once.
#
echo "Creating a clone ... \c"
git clone --quiet $gate $work
echo "done."

echo
total=0
pass=0
fail=0

for test in $tests; do
	[[ $test =~ ^err.*.cfg$ ]] || continue
	reset
	echo "$test ... \c"

	cp $config_dir/$test $gate/.git/config || die "cp failed"
	push > >(grep remote: >$tmp_dir/$test.out) 2>&1
	err=$?

	if [[ $err -eq 0 ]]; then
		echo "failed: expected failure"
		fail=$(($fail + 1))
	elif [[ $err -ne 1 ]]; then
		echo "failed: unexpected code $err"
		fail=$(($fail + 1))
	elif diff $config_dir/$test.out $tmp_dir/$test.out >/dev/null 2>&1; then
		echo "passed."
		pass=$(($pass + 1))
	else
		echo "failed: mismatched output"
		diff $config_dir/$test.out $tmp_dir/$test.out
		fail=$(($fail + 1))
	fi
	total=$(($total + 1))
done

for test in $tests; do
	[[ $test =~ ^tst.*.cfg$ ]] || continue
	reset
	echo "$test ... \c"

	cp $config_dir/$test $gate/.git/config || die "cp failed"
	push > >(grep remote: >$tmp_dir/$test.out) 2>&1
	err=$?

	if [[ $err -ne 0 ]]; then
		echo "failed: error code $err"
		fail=$(($fail + 1))
		cat $tmp_dir/$test.out
	elif diff $config_dir/$test.out $tmp_dir/$test.out >/dev/null 2>&1; then
		echo "passed."
		pass=$(($pass + 1))
	else
		echo "failed: mismatched output"
		diff $config_dir/$test.out $tmp_dir/$test.out
		fail=$(($fail + 1))
	fi

	total=$(($total + 1))
done

echo
echo "passed: $pass"
echo "failed: $fail"
echo "total:  $total"

if [[ $fail -ne 0 ]]; then
	echo
	echo $tmp_dir
fi

exit 0
