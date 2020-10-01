module github.com/phoreproject/bls

require (
	github.com/kilic/bls12-381 v0.0.0-20200820230200-6b2c19996391
	//github.com/mikelodder7/bls12-381 v0.0.0-20200708145258-ee2bda426526
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20200707235045-ab33eee955e0
)

replace (
	github.com/kilic/bls12-381 => /Users/dima/projects/securekey/_clones/BBS/go/bls12-381_mine
)


go 1.13
