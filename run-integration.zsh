# Use BuildKit
export DOCKER_BUILDKIT=1

# Build the image
docker build \
  --tag integration-test:latest \
  . 

# Stop any running compositions then re-run ours
docker compose stop
docker compose rm -f
docker-compose up \
  --force-recreate \
  --renew-anon-volumes \
  --abort-on-container-exit
