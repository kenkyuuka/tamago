.PHONY: test
test:
	hatch run test

.PHONY: reinstall
reinstall:
	hatch env prune && hatch env create

.PHONY: help
help:                ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
