package shellrules

import "testing"

// A here-document opened inside a command substitution has its body right
// below; the lines after the substitution are commands again.
func TestSignalImplicitTargetHeredocInsideSubstitution(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "heredoc.sh", `#!/bin/bash
x=$(cat <<EOF
hello
EOF
)
kill 0 # want
y="$(cat <<EOF
it's
EOF
)"
kill $PPID # want
z=`+"`"+`cat <<EOF
text
EOF
`+"`"+`
kill -9 0 # want
`)
}

// A # glued to the ) that closes a substitution is part of the word.
func TestSignalImplicitTargetHashAfterSubstitutionIsWord(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "word.sh", `#!/bin/bash
echo $(echo a)#; kill 0 # want
x=$(echo a)#tag; kill $PPID # want
`)
}

// ;# and &# inside ${…} are part of the expansion, not a comment.
func TestSignalImplicitTargetHashInsideParameterExpansion(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "expansion.sh", `#!/bin/bash
s=${s//&#39;/x}; kill 0 # want
echo ${x%%;#*}; kill 0 # want
`)
}

// Words of a command inside a quoted substitution are not arguments of kill.
func TestSignalImplicitTargetQuotedSubstitutionIsOneArgument(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "pid.sh", `#!/bin/bash
kill -TERM "$(head -1 pidfile)"
kill "$(tail -1 pidfile)"
kill -TERM "$(ls -1 pidfile)"
kill $(head -1 pidfile)
`)
}
