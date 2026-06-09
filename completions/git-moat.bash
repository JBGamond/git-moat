# Bash completion for git-moat.
# Install to ~/.local/share/bash-completion/completions/git-moat
# or source this file from ~/.bashrc.

_git_moat_branches() {
  # Local branches
  git branch --format='%(refname:short)' 2>/dev/null
  # Remote branches with the remote name stripped (same as git checkout tab-complete)
  git branch -r --format='%(refname:short)' 2>/dev/null | sed 's|^[^/]*/||' | sort -u
}

_git_moat_remotes() {
  git remote 2>/dev/null
}

_git_moat_fetch_flags() {
  echo "--all --prune --tags --depth --unshallow --dry-run --verbose --quiet"
}

_git_moat() {
  local cur prev
  _init_completion 2>/dev/null || {
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
  }

  # First word after git-moat: offer subcommands
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "clone checkout pull fetch --help -h" -- "$cur"))
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
    pull)
      # pull takes no additional arguments in git-moat
      ;;
    fetch)
      # Complete remotes first, then flags
      if [[ $COMP_CWORD -eq 2 ]]; then
        local remotes flags
        remotes=$(_git_moat_remotes)
        flags=$(_git_moat_fetch_flags)
        COMPREPLY=($(compgen -W "$remotes $flags" -- "$cur"))
      elif [[ $COMP_CWORD -eq 3 ]]; then
        # After remote: offer remote branches (refspecs)
        local remote="${COMP_WORDS[2]}"
        local refs
        refs=$(git ls-remote --heads "$remote" 2>/dev/null | awk '{print $2}' | sed 's|refs/heads/||')
        COMPREPLY=($(compgen -W "$refs" -- "$cur"))
      fi
      ;;
    clone)
      # Let bash-git-prompt or default handle URLs/paths
      COMPREPLY=($(compgen -f -- "$cur"))
      ;;
  esac
}

complete -F _git_moat git-moat
