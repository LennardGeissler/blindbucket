# bash completion for blindbucket.
#
# Source it from ~/.bashrc, or copy it into a completion directory:
# /usr/share/bash-completion/completions/blindbucket on Linux, or
# $(brew --prefix)/etc/bash_completion.d/blindbucket on macOS. It needs bash
# 3.2 or later and nothing else; the bash-completion package is not required.
#
# Hand-written, so a new flag does not appear here by itself. The test in
# cmd/blindbucket/completions_test.go fails when the flags offered here and
# the ones `blindbucket <command> -h` lists differ.

_blindbucket_flags() {
	case "$1" in
	init)
		echo --bucket --credential-source --dir --encrypt-names --endpoint --keys-provider --kid \
			--kms-endpoint --kms-key-id --kms-region --non-interactive --passphrase-file \
			--path-style --region --vault-address --vault-key-name --vault-mount ;;
	doctor) echo --config --json --no-write --passphrase-file ;;
	serve) echo --config --passphrase-file -v ;;
	keygen)
		echo --activate --add --add-audit-key --add-freshness-key --add-name-key --config --kid \
			--out --passphrase-file ;;
	reseal) echo --config --dry-run --keyring --new-passphrase-file --passphrase-file --to-config ;;
	gc) echo --config --dry-run --json --min-age --passphrase-file -v ;;
	rotate) echo --allow-unconditional --concurrency --config --dry-run --json --passphrase-file --to-kid -v ;;
	migrate-names) echo --allow-unconditional --concurrency --config --dry-run --json --passphrase-file -v ;;
	encrypt-existing) echo --allow-unconditional --concurrency --config --dry-run --json --keep-versions --passphrase-file -v ;;
	probe) echo --config --json ;;
	scrub) echo --concurrency --config --json --passphrase-file -v ;;
	encrypt) echo --chunk-size-log2 -i --keyring -o --passphrase-file ;;
	decrypt) echo -i --keyring -o --passphrase-file ;;
	inspect) echo --json ;;
	"keys list") echo --config --json --keyring --passphrase-file ;;
	"keys remove") echo --config --force --keyring --passphrase-file ;;
	"audit verify") echo --config --expect --json --keyring --passphrase-file --print --public-key ;;
	"audit pubkey") echo --config --keyring --open --passphrase-file ;;
	esac
}

_blindbucket() {
	local cur prev cmd
	cur=${COMP_WORDS[COMP_CWORD]}
	prev=${COMP_WORDS[COMP_CWORD - 1]}
	COMPREPLY=()

	if [ "$COMP_CWORD" -eq 1 ]; then
		COMPREPLY=($(compgen -W "init doctor serve keygen keys reseal gc rotate migrate-names encrypt-existing
			probe scrub audit encrypt decrypt inspect version help" -- "$cur"))
		return
	fi

	cmd=${COMP_WORDS[1]}
	case $cmd in
	keys | audit)
		if [ "$COMP_CWORD" -eq 2 ]; then
			case $cmd in
			keys) COMPREPLY=($(compgen -W "list remove" -- "$cur")) ;;
			audit) COMPREPLY=($(compgen -W "verify pubkey" -- "$cur")) ;;
			esac
			return
		fi
		cmd="$cmd ${COMP_WORDS[2]}"
		;;
	esac

	# The value of the flag before the cursor. Go's flag package takes one dash
	# or two, so both spellings are recognised.
	local flag=${prev#-}
	flag=${flag#-}
	case $prev in
	-*)
		case $flag in
		config | to-config | keyring | out | passphrase-file | new-passphrase-file | public-key | i | o)
			COMPREPLY=($(compgen -f -- "$cur"))
			return
			;;
		dir)
			COMPREPLY=($(compgen -d -- "$cur"))
			return
			;;
		keys-provider)
			COMPREPLY=($(compgen -W "file vault awskms" -- "$cur"))
			return
			;;
		credential-source)
			COMPREPLY=($(compgen -W "env profile web_identity container imds chain" -- "$cur"))
			return
			;;
		bucket | endpoint | region | kid | to-kid | kms-endpoint | kms-key-id | kms-region | \
			vault-address | vault-key-name | vault-mount | concurrency | min-age | chunk-size-log2 | expect)
			return
			;;
		esac
		;;
	esac

	case $cur in
	-*) COMPREPLY=($(compgen -W "$(_blindbucket_flags "$cmd")" -- "$cur")) ;;
	*)
		# The files inspect and audit verify read. Everything else takes an
		# s3:// target, a key id or nothing, none of which can be listed here.
		case $cmd in
		inspect | "audit verify") COMPREPLY=($(compgen -f -- "$cur")) ;;
		esac
		;;
	esac
}

complete -o filenames -F _blindbucket blindbucket
