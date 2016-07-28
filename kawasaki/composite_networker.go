package kawasaki

import (
	"math"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager"
)

type CompositeNetworker struct {
	Networkers []Networker
}

func (c *CompositeNetworker) Capacity() (m uint64) {
	m = math.MaxUint64
	for _, networker := range c.Networkers {
		m = min(networker.Capacity(), m)
	}

	return m
}

func (c *CompositeNetworker) Destroy(log lager.Logger, handle string) error {
	for _, networker := range c.Networkers {
		if err := networker.Destroy(log, handle); err != nil {
			return err
		}
	}
	return nil
}

func (c *CompositeNetworker) NetIn(log lager.Logger, handle string, externalPort, containerPort uint32) (uint32, uint32, error) {
	var returnedHostPort, returnedContainerPort uint32
	for i, nw := range c.Networkers {
		hPort, cPort, err := nw.NetIn(log, handle, externalPort, containerPort)
		if err != nil {
			log.Error("net-in-error", err)
			panic(err)
		}
		if i == 0 {
			returnedHostPort = hPort
			returnedContainerPort = cPort
		}
	}
	log.Info("composite-networker-net-in", lager.Data{
		"host_port":      returnedHostPort,
		"container_port": returnedContainerPort,
	})
	return returnedHostPort, returnedContainerPort, nil
}

func (c *CompositeNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	for _, nw := range c.Networkers {
		err := nw.NetOut(log, handle, rule)
		if err != nil {
			log.Error("net-out-error", err)
			panic(err)
		}
	}
	return nil
}

func (c *CompositeNetworker) Restore(log lager.Logger, handle string) error {
	for _, networker := range c.Networkers {
		if err := networker.Restore(log, handle); err != nil {
			return err
		}
	}
	return nil
}

func (c *CompositeNetworker) Network(log lager.Logger, containerSpec garden.ContainerSpec, pid int) error {
	for _, networker := range c.Networkers {
		if err := networker.Network(log, containerSpec, pid); err != nil {
			return err
		}
	}
	return nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}
