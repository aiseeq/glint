package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellPredictableTmpUsesExecutedShellCalls(t *testing.T) {
	script := `#!/bin/bash
grep 'sudo cat /tmp/grep.txt' input.txt
echo "sudo cat /tmp/echo.txt"
[[ $value == *"sudo cat /tmp/condition.txt"* ]]
sudo cat /tmp/direct.txt
ssh host "sudo cat /tmp/remote.txt"
bash -c "sudo cat /tmp/bash-c.txt"
sudo -E cat /tmp/preserved.txt
env sudo cat /tmp/env.txt
nohup sudo cat /tmp/nohup.txt
sudo -u nobody cat /tmp/user.txt
env sudo -u nobody cat /tmp/env-user.txt
nohup sudo -u nobody cat /tmp/nohup-user.txt
`
	assert.Equal(t, []int{5, 6, 7, 8, 9, 10}, textRuleLines(t, NewShellPredictableTmpRule(), "deploy/test.sh", script))
}
