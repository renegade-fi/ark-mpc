# Use BuildKit
export DOCKER_BUILDKIT=1

# Build the image
docker compose down
docker compose rm

# Stop any running compositions then re-run ours
docker-compose up \
  --build \
  --force-recreate \
  --renew-anon-volumes \
