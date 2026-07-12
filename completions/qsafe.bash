# bash completion for qsafe
# Install: source this file, or copy to /etc/bash_completion.d/ (or
# $(brew --prefix)/etc/bash_completion.d/ on macOS).

_qsafe() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
    }

    local commands="keygen encrypt decrypt verify rekey inspect sign-keygen sign verify-sig \
keys split-key join-key vault secrets age-keygen age-encrypt age-decrypt help version"
    local vault_subcommands="init write read footprint create add ls extract rm passwd"
    local secrets_subcommands="set get list rm"
    local options="--key-file --pub-file --recipient -r --identity --identity-file -i \
--passphrase --passphrase-file --check --armor --sign-with --signer --pad \
--threshold --shares --scrypt-cost --keychain --verbose --force --help --version \
--size --offset --capacity --name --keep --keyfile --new-passphrase-file --argon2 --store"

    # Options that take a file/path argument.
    case "$prev" in
        --key-file|--pub-file|--recipient|-r|--passphrase-file|--sign-with|--signer|--identity-file|-i|--keep|--keyfile|--new-passphrase-file|--store)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --scrypt-cost)
            COMPREPLY=( $(compgen -W "14 15 16 17 18 19 20 21 22" -- "$cur") )
            return 0
            ;;
        --threshold)
            COMPREPLY=( $(compgen -W "2 3 4 5" -- "$cur") )
            return 0
            ;;
        --shares)
            COMPREPLY=( $(compgen -W "3 4 5 6 7" -- "$cur") )
            return 0
            ;;
        --identity)
            return 0
            ;;
    esac

    # First non-option word is the command.
    local i cmd=""
    for (( i=1; i < COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            -*) ;;
            *) cmd="${COMP_WORDS[i]}"; break ;;
        esac
    done

    if [[ -z "$cmd" && "$cur" != -* ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    # For `vault`/`secrets`, complete the subcommand as the first argument after it.
    if [[ ( "$cmd" == "vault" || "$cmd" == "secrets" ) && "$cur" != -* ]]; then
        local j sub=""
        for (( j=i+1; j < COMP_CWORD; j++ )); do
            case "${COMP_WORDS[j]}" in
                -*) ;;
                *) sub="${COMP_WORDS[j]}"; break ;;
            esac
        done
        if [[ -z "$sub" ]]; then
            if [[ "$cmd" == "vault" ]]; then
                COMPREPLY=( $(compgen -W "$vault_subcommands" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$secrets_subcommands" -- "$cur") )
            fi
            return 0
        fi
    fi

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$options" -- "$cur") )
        return 0
    fi

    # Otherwise complete file paths for inputs/outputs.
    COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -F _qsafe qsafe
