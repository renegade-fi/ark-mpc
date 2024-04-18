# Use BuildKit
export DOCKER_BUILDKIT=1

# Build the image
compose_file=integration/docker-compose.yml
docker compose --file $compose_file down
docker compose --file $compose_file rm

# Stop any running compositions then re-run ours
docker-compose \
  --file $compose_file \
  up \
  --remove-orphans \
  --build \
  --force-recreate \
  --renew-anon-volumes \
  --abort-on-container-exit \
  --timeout 1