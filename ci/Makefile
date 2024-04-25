CI := ghcr.io/staex-io/cijail-ci:latest

.PHONY: ci
ci:
	docker build --tag $(CI) - < Dockerfile
	docker push $(CI)
