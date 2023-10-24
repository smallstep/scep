test:
	go test -cover ./...

# don't run race tests by default. see https://github.com/etcd-io/bbolt/issues/187
test-race:
	go test -cover -race ./...

.PHONY: test test-race
