CI := ghcr.io/staex-io/cijail-ci:latest

.PHONY: ci
ci:
	docker build --tag $(CI) -f Dockerfile ../packages/cijail-glibc-2.31
	docker push $(CI)
