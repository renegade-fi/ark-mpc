# Use BuildKit
export DOCKER_BUILDKIT=1

# Build the image
docker compose down
docker build \
  --tag integration-test:latest \
  . 

# Stop any running compositions then re-run ours
docker-compose up \
  --force-recreate \
  --renew-anon-volumes \
  --abort-on-container-exit
