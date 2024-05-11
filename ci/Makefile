CI := ghcr.io/staex-io/cijail-ci:latest

.PHONY: ci
ci:
	@cp build-dependencies.sh ../packages/
	docker build --tag $(CI) -f Dockerfile ../packages
	docker push $(CI)
