#!/bin/sh -eu
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# seccomp.sh - Build seccomp profiles from "#syscalls[:PROFILE]" comments in code
#
# Copyright (c) 2021 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

TMP="$(mktemp)"
OUT="seccomp.h"

HEADER="/* This file was automatically generated by $(basename ${0}) */"

# Prefix for each profile: check that 'arch' in seccomp_data is matching
PRE='
struct sock_filter filter_@PROFILE@[] = {
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		 (offsetof(struct seccomp_data, arch))),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PASST_AUDIT_ARCH, 0, @KILL@),
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		 (offsetof(struct seccomp_data, nr))),

'

# Suffix for each profile: return actions
POST='	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
'

# Syscall, @NR@: number, @ALLOW@: offset to RET_ALLOW, @NAME@: syscall name
CALL='	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, @NR@, @ALLOW@, 0), /* @NAME@ */'

# Binary search tree node or leaf, @NR@: value, @R@: right jump, @L@: left jump
BST='	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, @NR@, @R@, @L@),'

# sub() - Substitute in-place file line with processed template line
# $1:	Line number
# $@:	Replacement for @KEY@ in the form KEY:value
sub() {
	IFS=
	__line_no="${1}"
	__template="$(eval printf '%s' "\${${2}}")"
	shift; shift

	sed -i "${__line_no}s#.*#${__template}#" "${TMP}"

	for __def in ${@}; do
		__key="@${__def%%:*}@"
		__value="${__def#*:}"
		sed -i "${__line_no}s/${__key}/${__value}/" "${TMP}"
	done
	unset IFS
}

# finish() - Finalise header file from temporary files with prefix and suffix
# $1:	Variable name of prefix
# $@:	Replacements for prefix variable
finish() {
	IFS=
	__out="$(eval printf '%s' "\${${1}}")"
	shift

	for __def in ${@}; do
		__key="@${__def%%:*}@"
		__value="${__def#*:}"
		__out="$(printf '%s' "${__out}" | sed "s#${__key}#${__value}#")"
	done

	printf '%s\n' "${__out}" >> "${OUT}"
	cat "${TMP}" >> "${OUT}"
	rm "${TMP}"
	printf '%s' "${POST}" >> "${OUT}"
	unset IFS
}

# log2() - Binary logarithm
# $1:	Operand
log2() {
	__x=-1
	__y=${1}
	while [ ${__y} -gt 0 ]; do : $((__y >>= 1)); __x=$((__x + 1)); done
	echo ${__x}
}

# gen_profile() - Build struct sock_filter for a single profile
# $1:	Profile name
# $@:	Names of allowed system calls, amount padded to next power of two
gen_profile() {
	__profile="${1}"
	shift

	__statements_calls=${#}
	__bst_levels=$(log2 $(( __statements_calls / 4 )) )
	__statements_bst=$(( __statements_calls / 4 - 1 ))
	__statements=$((__statements_calls + __statements_bst))

	for __i in $(seq 1 ${__statements_bst} ); do
		echo -1 >> "${TMP}"
	done
	for __i in $(seq 1 ${__statements_calls} ); do
		ausyscall $(eval echo \${${__i}}) --exact >> "${TMP}"
	done
	sort -go "${TMP}" "${TMP}"

	__distance=$(( __statements_calls / 2 ))
	__level_nodes=1
	__ll=0
	__line=1
	for __level in $(seq 1 $(( __bst_levels - 1 )) ); do
		# Nodes
		__cmp_pos=${__distance}

		for __node in $(seq 1 ${__level_nodes}); do
			__cmp_line=$(( __statements_bst + __cmp_pos ))
			__lr=$(( __ll + 1 ))
			__nr="$(sed -n ${__cmp_line}p "${TMP}")"

			sub ${__line} BST "NR:${__nr}" "L:${__ll}" "R:${__lr}"

			__ll=${__lr}
			__line=$(( __line + 1 ))
			__cmp_pos=$(( __cmp_pos + __distance * 2 ))
		done

		__distance=$(( __distance / 2 ))
		__level_nodes=$(( __level_nodes * 2 ))
	done

	# Leaves
	__ll=$(( __level_nodes - 1 ))
	__lr=$(( __ll + __distance - 1 ))
	__cmp_pos=${__distance}

	for __leaf in $(seq 1 ${__level_nodes}); do
		__cmp_line=$(( __statements_bst + __cmp_pos ))
		__nr="$(sed -n ${__cmp_line}p "${TMP}")"
		sub ${__line} BST "NR:${__nr}" "L:${__ll}" "R:${__lr}"

		__ll=$(( __lr + __distance - 1 ))
		__lr=$(( __ll + __distance))
		__line=$(( __line + 1 ))
		__cmp_pos=$(( __cmp_pos + __distance * 2 ))
	done

	# Calls
	for __i in $(seq $(( __statements_bst + 1 )) ${__statements}); do
		__nr="$(sed -n ${__i}p "${TMP}")"
		__name=$(ausyscall ${__nr})
		__allow=$(( __statements - __i + 1 ))
		sub ${__i} CALL "NR:${__nr}" "NAME:${__name}" "ALLOW:${__allow}"
	done

	finish PRE "PROFILE:${__profile}" "KILL:$(( __statements + 1))"
}

printf '%s\n' "${HEADER}" > "${OUT}"
__profiles="$(sed -n 's/[\t ]*\*[\t ]*#syscalls:\([^ ]*\).*/\1/p' *.[ch] | sort -u)"
for __p in ${__profiles}; do
	__calls="$(sed -n 's/[\t ]*\*[\t ]*#syscalls\(:'"${__p}"'\|\)[\t ]\{1,\}\(.*\)/\2/p' *.[ch] | tr ' ' '\n' | sort -u)"

	echo "seccomp profile ${__p} allows: ${__calls}" | tr '\n' ' ' | fmt -t

	# Pad here to keep gen_profile() "simple"
	__count=0
	for __c in ${__calls}; do __count=$(( __count + 1 )); done
	__padded=$(( 1 << (( $(log2 ${__count}) + 1 )) ))
	for __i in $( seq ${__count} $(( __padded - 1 )) ); do
		__calls="${__calls} tuxcall"
	done

	gen_profile "${__p}" ${__calls}
done