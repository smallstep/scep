module github.com/smallstep/scep

go 1.16

require (
	github.com/go-kit/kit v0.12.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
)

// use github.com/smallstep/pkcs7 fork with patches applied
replace go.mozilla.org/pkcs7 => github.com/smallstep/pkcs7 v0.0.0-20230302202335-4c094085c948
