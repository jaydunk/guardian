package kawasaki

import (
	"net"
	"strings"

	"github.com/cloudfoundry-incubator/guardian/kawasaki/subnets"
)

type SpecParserFunc func(spec string) (subnets.SubnetSelector, subnets.IPSelector, error)

func (fn SpecParserFunc) Parse(spec string) (subnets.SubnetSelector, subnets.IPSelector, error) {
	return fn(spec)
}

func ParseSpec(spec string) (subnets.SubnetSelector, subnets.IPSelector, error) {
	var ipSelector subnets.IPSelector = subnets.DynamicIPSelector
	var subnetSelector subnets.SubnetSelector = subnets.DynamicSubnetSelector

	if spec != "" {
		specifiedIP, ipn, err := net.ParseCIDR(suffixIfNeeded(spec))
		if err != nil {
			return nil, nil, err
		}

		subnetSelector = subnets.StaticSubnetSelector{ipn}

		if !specifiedIP.Equal(subnets.NetworkIP(ipn)) {
			ipSelector = subnets.StaticIPSelector{specifiedIP}
		}
	}

	return subnetSelector, ipSelector, nil
}

func suffixIfNeeded(spec string) string {
	if !strings.Contains(spec, "/") {
		spec = spec + "/30"
	}

	return spec
}