module github.com/micromdm/scep/v2

go 1.16

require (
	github.com/boltdb/bolt v1.3.1
	github.com/go-kit/kit v0.4.0
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-stack/stack v1.6.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/groob/finalizer v0.0.0-20170707115354-4c2ed49aabda
	github.com/pkg/errors v0.8.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	golang.org/x/net v0.0.0-20170726083632-f5079bd7f6f7 // indirect
	golang.org/x/sys v0.0.0-20170728174421-0f826bdd13b5 // indirect
)

// use github.com/smallstep/pkcs7 fork with patches applied
replace go.mozilla.org/pkcs7 => github.com/smallstep/pkcs7 v0.0.0-20230302202335-4c094085c948
