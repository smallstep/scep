module github.com/smallstep/scep

go 1.16

require (
	github.com/go-kit/kit v0.4.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
)

require (
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-stack/stack v1.6.0 // indirect
)

// use github.com/smallstep/pkcs7 fork with patches applied
replace go.mozilla.org/pkcs7 => github.com/smallstep/pkcs7 v0.0.0-20230615175518-7ce6486b74eb
