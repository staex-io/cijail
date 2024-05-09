CI := ghcr.io/staex-io/cijail-ci:latest
CI_TEST := ghcr.io/staex-io/cijail-ci-test:latest

.PHONY: ci
ci:
	docker build --tag $(CI) - < Dockerfile
	docker push $(CI)

.PHONY: ci-test
ci-test:
	docker build --tag $(CI) - < Dockerfile
	docker build --tag $(CI_TEST) -f Dockerfile-test ../packages/cijail-glibc-2.31
	docker push $(CI_TEST)
