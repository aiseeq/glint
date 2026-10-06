package patterns

import "testing"

// A deploy starts the new release's container and then runs the migrations
// with docker exec inside it: the new code's startup jobs run on the old
// schema first. Reading the schema version from the running container is not
// a migration, and migrations run by a one-off container before the start
// are the fix.
func TestDeployStartsNewCodeBeforeMigrations(t *testing.T) {
	shellWanted(t, "deploy-starts-new-code-before-migrations", "deploy.sh", `#!/bin/bash
set -euo pipefail
start_slot() {
    ssh "$HOST" "
        cd /srv/app/$1
        sudo docker compose up -d
    "
    echo "app-$1"
}
run_migrations() {
    local container=$1
    ssh "$HOST" "sudo docker exec $container /app/bin/migrate -direction up -path /app/migrations" # want
}
schema_version() {
    ssh "$HOST" "sudo docker exec $1 /app/bin/migrate -direction version -path /app/migrations"
}
main() {
    container=$(start_slot "$target")
    run_migrations "$container"
    schema_version "$container"
}
main "$@"
`)
	shellWanted(t, "deploy-starts-new-code-before-migrations", "stage.sh", `#!/bin/bash
set -euo pipefail
cd "$STAGE_DIR"
$DOCKER_COMPOSE up -d --force-recreate
docker exec app-stage /app/bin/migrate -path /app/migrations -direction up # want
`)
	shellWanted(t, "deploy-starts-new-code-before-migrations", "fixed.sh", `#!/bin/bash
set -euo pipefail
run_migrations() {
    ssh "$HOST" "cd /srv/app/$1 && sudo docker compose run --rm --no-deps -T --entrypoint /app/bin/migrate app -direction up"
}
start_slot() {
    ssh "$HOST" "cd /srv/app/$1 && sudo docker compose up -d"
}
run_migrations "$target"
start_slot "$target"
docker exec app-stage /app/bin/migrate -direction version
`)
	shellWanted(t, "deploy-starts-new-code-before-migrations", "migrate-only.sh", `#!/bin/bash
set -euo pipefail
docker exec app /app/bin/migrate -path /app/migrations -direction "$DIRECTION"
`)
}
