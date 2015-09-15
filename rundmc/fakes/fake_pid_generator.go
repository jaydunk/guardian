// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"github.com/cloudfoundry-incubator/guardian/rundmc"
)

type FakePidGenerator struct {
	GenerateStub        func() uint32
	generateMutex       sync.RWMutex
	generateArgsForCall []struct{}
	generateReturns     struct {
		result1 uint32
	}
}

func (fake *FakePidGenerator) Generate() uint32 {
	fake.generateMutex.Lock()
	fake.generateArgsForCall = append(fake.generateArgsForCall, struct{}{})
	fake.generateMutex.Unlock()
	if fake.GenerateStub != nil {
		return fake.GenerateStub()
	} else {
		return fake.generateReturns.result1
	}
}

func (fake *FakePidGenerator) GenerateCallCount() int {
	fake.generateMutex.RLock()
	defer fake.generateMutex.RUnlock()
	return len(fake.generateArgsForCall)
}

func (fake *FakePidGenerator) GenerateReturns(result1 uint32) {
	fake.GenerateStub = nil
	fake.generateReturns = struct {
		result1 uint32
	}{result1}
}

var _ rundmc.PidGenerator = new(FakePidGenerator)