module github.com/wealdtech/go-eth2-util

go 1.12

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.4.0
	github.com/wealdtech/go-bytesutil v1.1.1
	github.com/wealdtech/go-eth2-types/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20200414173820-0848c9571904
	golang.org/x/sys v0.0.0-20200413165638-669c56c373c4 // indirect
)

replace github.com/wealdtech/go-eth2-types/v2 => ../go-eth2-types
