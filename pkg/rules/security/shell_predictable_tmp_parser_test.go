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
sudo -n docker exec -u retro "$c" bash -c 'set -e
    rm -f /tmp/probe.ppm
    grim -t ppm /tmp/probe.ppm' 2>/dev/null
sudo docker exec box sh -c 'cat /tmp/x'
sudo su - bob -c 'cat /tmp/x'
sudo ssh host 'cat /tmp/x'
sudo runuser -u bob -- cat /tmp/runuser.txt
sudo kubectl exec pod -- cat /tmp/kube.txt
sudo sh -c 'exec cat /tmp/exec.txt'
sudo command cat /tmp/command.txt
sudo nice cat /tmp/nice.txt
sudo timeout 2 cat /tmp/timeout.txt
sudo sh -c 'cat /tmp/sh-c.txt'
sudo su - root -c 'cat /tmp/su-root.txt'
sudo runuser -u root -- cat /tmp/runuser-root.txt
ssh -t host "sudo mkdir -p /srv/backup && sudo mv /tmp/sync-a.conf /etc/nginx/a.conf"
`
	assert.Equal(t, []int{5, 6, 7, 8, 9, 10, 22, 23, 24, 25, 26, 27, 28, 29}, textRuleLines(t, NewShellPredictableTmpRule(), "deploy/test.sh", script))
}
