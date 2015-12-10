package gardener

import (
	"io"
	"time"

	"github.com/cloudfoundry-incubator/garden"
	"github.com/pivotal-golang/lager"
)

type container struct {
	logger lager.Logger

	handle          string
	containerizer   Containerizer
	networker       Networker
	propertyManager PropertyManager
}

func NewContainer(logger lager.Logger, handle string, containerizer Containerizer, networker Networker, propertyManager PropertyManager) *container {
	return &container{
		logger:          logger,
		handle:          handle,
		containerizer:   containerizer,
		networker:       networker,
		propertyManager: propertyManager,
	}
}

func (c *container) Handle() string {
	return c.handle
}

func (c *container) Run(spec garden.ProcessSpec, io garden.ProcessIO) (garden.Process, error) {
	return c.containerizer.Run(c.logger, c.handle, spec, io)
}

func (c *container) Stop(kill bool) error {
	return nil
}

func (c *container) Info() (garden.ContainerInfo, error) {
	return garden.ContainerInfo{}, nil
}

func (c *container) StreamIn(garden.StreamInSpec) error {
	return nil
}

func (c *container) StreamOut(garden.StreamOutSpec) (io.ReadCloser, error) {
	return nil, nil
}

func (c *container) LimitBandwidth(limits garden.BandwidthLimits) error {
	return nil
}

func (c *container) CurrentBandwidthLimits() (garden.BandwidthLimits, error) {
	return garden.BandwidthLimits{}, nil
}

func (c *container) LimitCPU(limits garden.CPULimits) error {
	return nil
}

func (c *container) CurrentCPULimits() (garden.CPULimits, error) {
	return garden.CPULimits{}, nil
}

func (c *container) LimitDisk(limits garden.DiskLimits) error {
	return nil
}

func (c *container) CurrentDiskLimits() (garden.DiskLimits, error) {
	return garden.DiskLimits{}, nil
}

func (c *container) LimitMemory(limits garden.MemoryLimits) error {
	return nil
}

func (c *container) CurrentMemoryLimits() (garden.MemoryLimits, error) {
	return garden.MemoryLimits{}, nil
}

func (c *container) NetIn(hostPort, containerPort uint32) (uint32, uint32, error) {
	return c.networker.NetIn(c.handle, hostPort, containerPort)
}

func (c *container) NetOut(netOutRule garden.NetOutRule) error {
	return nil
}

func (c *container) Attach(processID string, io garden.ProcessIO) (garden.Process, error) {
	return nil, nil
}

func (c *container) Metrics() (garden.Metrics, error) {
	return garden.Metrics{}, nil
}

func (c *container) Properties() (garden.Properties, error) {
	return c.propertyManager.All(c.handle)
}

func (c *container) Property(name string) (string, error) {
	return c.propertyManager.Get(c.handle, name)
}

func (c *container) SetProperty(name string, value string) error {
	return c.propertyManager.Set(c.handle, name, value)
}

func (c *container) RemoveProperty(name string) error {
	return c.propertyManager.Remove(c.handle, name)
}

func (c *container) SetGraceTime(t time.Duration) error {
	return nil
}
