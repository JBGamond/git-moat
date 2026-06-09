# Bash completion for git-moat.
# Install to ~/.local/share/bash-completion/completions/git-moat
# or source this file from ~/.bashrc.

_git_moat_branches() {
  # Local branches
  git branch --format='%(refname:short)' 2>/dev/null
  # Remote branches with the remote name stripped (same as git checkout tab-complete)
  git branch -r --format='%(refname:short)' 2>/dev/null | sed 's|^[^/]*/||' | sort -u
}

_git_moat() {
  local cur prev
  _init_completion 2>/dev/null || {
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
  }

  # First word after git-moat: offer subcommands
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "clone checkout --help -h" -- "$cur"))
    return
  fi

  local subcommand="${COMP_WORDS[1]}"

  case "$subcommand" in
    checkout)
      # Second word: complete from branch list
      if [[ $COMP_CWORD -eq 2 ]]; then
        local branches
        branches=$(_git_moat_branches)
        COMPREPLY=($(compgen -W "$branches" -- "$cur"))
      fi
      ;;
    clone)
      # Let bash-git-prompt or default handle URLs/paths
      COMPREPLY=($(compgen -f -- "$cur"))
      ;;
  esac
}

complete -F _git_moat git-moat
