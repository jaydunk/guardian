package netplugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/guardian/kawasaki/dns"
	"code.cloudfoundry.org/guardian/kawasaki/netns"
	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry/gunk/command_runner"
	"github.com/vishvananda/netlink"
)

const NetworkPropertyPrefix = "network."

type ExternalBinaryNetworker struct {
	commandRunner command_runner.CommandRunner
	configStore   kawasaki.ConfigStore
	portPool      kawasaki.PortPool
	externalIP    net.IP
	dnsServers    []net.IP
	path          string
	extraArg      []string
}

func New(commandRunner command_runner.CommandRunner, configStore kawasaki.ConfigStore, portPool kawasaki.PortPool, externalIP net.IP, dnsServers []net.IP, path string, extraArg ...string) kawasaki.Networker {
	return &ExternalBinaryNetworker{
		commandRunner: commandRunner,
		configStore:   configStore,
		portPool:      portPool,
		externalIP:    externalIP,
		dnsServers:    dnsServers,
		path:          path,
		extraArg:      extraArg,
	}
}

func networkProperties(containerProperties garden.Properties) garden.Properties {
	properties := garden.Properties{}

	for k, value := range containerProperties {
		if strings.HasPrefix(k, NetworkPropertyPrefix) {
			key := strings.TrimPrefix(k, NetworkPropertyPrefix)
			properties[key] = value
		}
	}

	return properties
}

func (p *ExternalBinaryNetworker) Network(log lager.Logger, containerSpec garden.ContainerSpec, pid int) error {
	pathAndExtraArgs := append([]string{p.path}, p.extraArg...)
	propertiesJSON, err := json.Marshal(networkProperties(containerSpec.Properties))
	if err != nil {
		return fmt.Errorf("marshaling network properties: %s", err) // not tested
	}

	networkPluginFlags := []string{
		"--handle", containerSpec.Handle,
		"--network", containerSpec.Network,
		"--properties", string(propertiesJSON),
	}

	upArgs := append(pathAndExtraArgs, "--action", "up")
	upArgs = append(upArgs, networkPluginFlags...)

	cmd := exec.Command(p.path)
	cmd.Args = upArgs
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput

	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	_, err = io.WriteString(input, fmt.Sprintf("{\"PID\":%d}", pid))
	if err != nil {
		return err
	}
	input.Close()

	err = p.commandRunner.Run(cmd)
	if err != nil {
		return err
	}

	if len(cmdOutput.Bytes()) == 0 {
		return nil
	}

	var properties map[string]map[string]string

	if err := json.Unmarshal(cmdOutput.Bytes(), &properties); err != nil {
		return fmt.Errorf("network plugin returned invalid JSON: %s", err)
	}

	if _, ok := properties["properties"]; !ok {
		return fmt.Errorf("network plugin returned JSON without a properties key")
	}

	for k, v := range properties["properties"] {
		p.configStore.Set(containerSpec.Handle, k, v)
	}

	p.configStore.Set(containerSpec.Handle, gardener.ExternalIPKey, p.externalIP.String())

	log.Info("external-binary-write-dns-to-config", lager.Data{
		"dnsServers": p.dnsServers,
	})

	containerIP, ok := p.configStore.Get(containerSpec.Handle, "network.external-networker.container-ip")
	if !ok {
		panic("no container ip")
	}

	p.configStore.Set(containerSpec.Handle, gardener.ContainerIPKey, containerIP)
	p.configStore.Set(containerSpec.Handle, gardener.BridgeIPKey, containerIP)

	splitIP := strings.Split(containerIP, ".")
	splitIP[3] = "1"
	bridgeIP := strings.Join(splitIP, ".")

	netnsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		panic(err)
	}
	defer netnsFile.Close()

	netNsPath := netnsFile.Name()
	fd, err := os.Open(netNsPath)
	if err != nil {
		panic(err)
	}

	netNsExecer := &netns.Execer{}
	if err = netNsExecer.Exec(fd, func() error {
		link, err := netlink.LinkByName("eth0")
		if err != nil {
			panic(err)
		}
		route := &netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: link.Attrs().Index,
			Gw:        net.ParseIP(bridgeIP),
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			panic(err)
		}
		return nil
	}); err != nil {
		panic(err)
	}

	cfg := kawasaki.NetworkConfig{
		ContainerIP:     net.ParseIP(containerIP),
		BridgeIP:        net.ParseIP(containerIP),
		ContainerHandle: containerSpec.Handle,
		DNSServers:      p.dnsServers,
	}
	resolvConfigurer := &kawasaki.ResolvConfigurer{
		HostsFileCompiler:  &dns.HostsFileCompiler{},
		ResolvFileCompiler: &dns.ResolvFileCompiler{},
		FileWriter:         &dns.RootfsWriter{},
		IDMapReader:        &kawasaki.RootIdMapReader{},
	}

	err = resolvConfigurer.Configure(log, cfg, pid)
	if err != nil {
		panic(err)
	}

	setDefault(log, containerIP)

	return nil
}

func (p *ExternalBinaryNetworker) Destroy(log lager.Logger, handle string) error {
	cleanupTable(log, "filter", handle)
	cleanupTable(log, "nat", handle)

	pathAndExtraArgs := append([]string{p.path}, p.extraArg...)

	networkPluginFlags := []string{
		"--handle", handle,
	}

	downArgs := append(pathAndExtraArgs, "--action", "down")
	downArgs = append(downArgs, networkPluginFlags...)

	cmd := exec.Command(p.path)
	cmd.Args = downArgs
	return p.commandRunner.Run(cmd)
}

func cleanupTable(log lager.Logger, table string, handle string) {
	log.Info("external-binary-destroy", lager.Data{
		"table":  table,
		"handle": handle,
	})
	listCmd := exec.Command("/sbin/iptables", "-w", "-t", table, "-S")
	output, err := listCmd.CombinedOutput()
	if err != nil {
		log.Error("external-binary-run-iptables-list", err)
		panic(err)
	}
	ruleList := strings.Split(string(output), "\n")
	deleteRules := []string{}
	for _, r := range ruleList {
		if strings.Contains(r, handle) {
			deleteRules = append(deleteRules, strings.Replace(r, "-A", "-D", -1))
		}
	}

	for _, dr := range deleteRules {
		log.Info("external-binary-run-iptables-delete", lager.Data{
			"table":  table,
			"handle": handle,
			"rule":   dr,
		})
		delArgs := append([]string{"-w", "-t", table}, strings.Split(dr, " ")...)
		delCmd := exec.Command("/sbin/iptables", delArgs...)
		err := delCmd.Run()
		if err != nil {
			log.Error("external-binary-run-iptables-delete", err, lager.Data{
				"args": delArgs,
			})
			panic(err)
		}
	}

}

func (p *ExternalBinaryNetworker) Restore(log lager.Logger, handle string) error {
	return nil
}

func (p *ExternalBinaryNetworker) Capacity() (m uint64) {
	return math.MaxUint64
}

func (p *ExternalBinaryNetworker) NetIn(log lager.Logger, handle string, externalPort, containerPort uint32) (uint32, uint32, error) {
	var err error
	if externalPort == 0 {
		externalPort, err = p.portPool.Acquire()
		if err != nil {
			return 0, 0, err
		}
	}

	if err := addPortMapping(log, p.configStore, handle, garden.PortMapping{
		HostPort:      externalPort,
		ContainerPort: containerPort,
	}); err != nil {
		return 0, 0, err
	}
	return externalPort, containerPort, nil
}

type portMappingList []garden.PortMapping

func (l portMappingList) toJson() string {
	b, err := json.Marshal(l)
	if err != nil {
		panic(err) // impossible, since []PortMapping is always encodable
	}

	return string(b)
}

func portsFromJson(s string) (portMappingList, error) {
	var mappings portMappingList
	if err := json.Unmarshal([]byte(s), &mappings); err != nil {
		return nil, err
	}

	return mappings, nil
}

func addPortMapping(logger lager.Logger, configStore kawasaki.ConfigStore, handle string, newMapping garden.PortMapping) error {
	var currentMappings portMappingList
	if currentMappingsJson, ok := configStore.Get(handle, gardener.MappedPortsKey); ok {
		var err error
		currentMappings, err = portsFromJson(currentMappingsJson)
		if err != nil {
			return err
		}
	}

	updatedMappings := append(currentMappings, newMapping)
	configStore.Set(handle, gardener.MappedPortsKey, updatedMappings.toJson())
	return nil
}

func (p *ExternalBinaryNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	containerIP, ok := p.configStore.Get(handle, "network.external-networker.container-ip")
	if !ok {
		panic("key not set")
	}
	for _, nw := range rule.Networks {
		log.Info("external-binary-netout-rule", lager.Data{
			"rule": fmt.Sprintf("-w -A FORWARD -s %s -m iprange --dst-range %s-%s -j RETURN", containerIP, nw.Start.String(), nw.End.String()),
		})
		cmd := exec.Command("/sbin/iptables",
			"-w",
			"-A", "FORWARD",
			"-s", containerIP,
			"-m", "iprange",
			"--dst-range", fmt.Sprintf("%s-%s", nw.Start.String(), nw.End.String()),
			"-j", "RETURN",
			"-m", "comment", "--comment", handle,
		)
		err := cmd.Run()
		if err != nil {
			log.Error("external-binary-run-iptables-netout", err)
			panic(err)
		}
	}

	setDefault(log, containerIP)

	return nil
}

func parseSubnet(ip string) string {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		panic("invalid ip string")
	}
	return strings.Join(octets[:3], ".") + ".0/24"
}

func setDefault(log lager.Logger, containerIP string) {
	subnet := parseSubnet(containerIP)

	listCmd := exec.Command("/sbin/iptables", "-w", "-S")
	output, err := listCmd.CombinedOutput()
	if err != nil {
		log.Error("external-binary-run-iptables-list-netout", err)
		panic(err)
	}
	ruleList := strings.Split(string(output), "\n")
	for _, r := range ruleList {
		if strings.Contains(r, fmt.Sprintf("-A FORWARD ! -d %s -j REJECT", subnet)) {
			log.Info("external-binary-netout-rule-delete-old-default", lager.Data{
				"rule": fmt.Sprintf("-w -D FORWARD ! -d %s -j REJECT", subnet),
			})
			cmd := exec.Command("/sbin/iptables",
				"-w",
				"-D", "FORWARD",
				"!", "-d", subnet,
				"-j", "REJECT",
			)
			err := cmd.Run()
			if err != nil {
				log.Error("external-binary-netout-rule-delete-old-default", err)
				panic(err)
			}
		}
	}

	log.Info("external-binary-netout-rule-readd-default", lager.Data{
		"rule": fmt.Sprintf("-w -A FORWARD ! -d %s -j REJECT", subnet),
	})
	cmd := exec.Command("/sbin/iptables",
		"-w",
		"-A", "FORWARD",
		"!", "-d", subnet,
		"-j", "REJECT",
	)
	err = cmd.Run()
	if err != nil {
		log.Error("external-binary-netout-rule-readd-default", err)
		panic(err)
	}
}
