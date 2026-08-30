package buffer

import (
	"sync"
)

var (
	TPool sync.Pool
	UPool sync.Pool
)

func Initialize(tPool, uPool int) {
	TPool = sync.Pool{
		New: func() any {
			b := make([]byte, tPool)
			return &b
		},
	}
	UPool = sync.Pool{
		New: func() any {
			b := make([]byte, uPool)
			return &b
		},
	}
}

// GetU gets a buffer pointer and slice from UPool guaranteed to be at full capacity.
func GetU() (*[]byte, []byte) {
	bp := UPool.Get().(*[]byte)
	buf := (*bp)[:cap(*bp)]
	return bp, buf
}

// PutU safely returns a buffer pointer to UPool.
func PutU(bp *[]byte) {
	if bp != nil {
		UPool.Put(bp)
	}
}

// GetT gets a buffer pointer and slice from TPool guaranteed to be at full capacity.
func GetT() (*[]byte, []byte) {
	bp := TPool.Get().(*[]byte)
	buf := (*bp)[:cap(*bp)]
	return bp, buf
}

// PutT safely returns a buffer pointer to TPool.
func PutT(bp *[]byte) {
	if bp != nil {
		TPool.Put(bp)
	}
}
