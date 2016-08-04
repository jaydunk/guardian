package netplugin_test

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os/exec"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/guardian/netplugin"
	"code.cloudfoundry.org/guardian/properties"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/cloudfoundry/gunk/command_runner/fake_command_runner"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ExternalBinaryNetworker", func() {
	var (
		containerSpec     garden.ContainerSpec
		configStore       kawasaki.ConfigStore
		fakeCommandRunner *fake_command_runner.FakeCommandRunner
	)

	BeforeEach(func() {
		fakeCommandRunner = fake_command_runner.New()
		configStore = properties.NewManager()
		containerSpec = garden.ContainerSpec{
			Handle:  "some-handle",
			Network: "potato",
			Properties: garden.Properties{
				"some-key":               "some-value",
				"some-other-key":         "some-other-value",
				"network.some-key":       "some-network-value",
				"network.some-other-key": "some-other-network-value",
			},
		}
	})

	Describe("Network", func() {
		var pluginOutput string
		var pluginErr error

		BeforeEach(func() {
			pluginErr = nil
			fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
				Path: "some/path",
			}, func(cmd *exec.Cmd) error {
				cmd.Stdout.Write([]byte(pluginOutput))
				return pluginErr
			})
		})

		It("passes the pid of the container to the external plugin's stdin", func() {
			plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
			err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			input, err := ioutil.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(input)).To(ContainSubstring("42"))
		})

		It("executes the external plugin with the correct args", func() {
			plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
			err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args[:7]).To(Equal([]string{
				"some/path",
				"--action", "up",
				"--handle", "some-handle",
				"--network", "potato",
			}))

			Expect(cmd.Args[7]).To(Equal("--properties"))
			Expect(cmd.Args[8]).To(MatchJSON(`{
					"some-key":       "some-network-value",
					"some-other-key": "some-other-network-value"
			}`))
		})

		Context("when there are extra args", func() {
			It("prepends the extra args before the standard hook parameters", func() {
				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path", "arg1", "arg2", "arg3")
				err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				cmd := fakeCommandRunner.ExecutedCommands()[0]

				Expect(cmd.Args[:6]).To(Equal([]string{
					"some/path",
					"arg1",
					"arg2",
					"arg3",
					"--action", "up",
				}))
			})
		})

		Context("when the external plugin errors", func() {
			It("returns the error", func() {
				pluginErr = errors.New("external-plugin-error")

				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
				Expect(plugin.Network(nil, containerSpec, 42)).To(MatchError("external-plugin-error"))
			})
		})

		Context("when the external plugin returns valid properties JSON", func() {
			It("persists the returned properties to the container's properties", func() {
				pluginOutput = `{"properties":{"foo":"bar","ping":"pong"}}`

				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
				err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				persistedPropertyValue, _ := configStore.Get("some-handle", "foo")
				Expect(persistedPropertyValue).To(Equal("bar"))
			})
		})

		Context("when the external plugin returns invalid JSON", func() {
			It("returns a useful error message", func() {
				pluginOutput = "invalid-json"

				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
				err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
				Expect(err).To(MatchError(ContainSubstring("network plugin returned invalid JSON")))
			})
		})

		Context("when the external plugin returns JSON without a properties key", func() {
			It("returns a useful error message", func() {
				pluginOutput = `{"not-properties-key":{"foo":"bar"}}`

				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
				err := plugin.Network(lagertest.NewTestLogger("test"), containerSpec, 42)
				Expect(err).To(MatchError(ContainSubstring("network plugin returned JSON without a properties key")))
			})
		})
	})

	Describe("Destroy", func() {
		It("executes the external plugin with the correct args", func() {
			plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
			Expect(plugin.Destroy(lagertest.NewTestLogger("test"), "my-handle")).To(Succeed())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args[:5]).To(Equal([]string{
				"some/path",
				"--action", "down",
				"--handle", "my-handle",
			}))
		})

		Context("when there are extra args", func() {
			It("prepends the extra args before the standard hook parameters", func() {
				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path", "arg1", "arg2", "arg3")
				err := plugin.Destroy(lagertest.NewTestLogger("test"), "my-handle")
				Expect(err).NotTo(HaveOccurred())

				cmd := fakeCommandRunner.ExecutedCommands()[0]

				Expect(cmd.Args[:8]).To(Equal([]string{
					"some/path",
					"arg1",
					"arg2",
					"arg3",
					"--action", "down",
					"--handle", "my-handle",
				}))
			})
		})

		Context("when the external plugin errors", func() {
			It("returns the error", func() {
				fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
					Path: "some/path",
				}, func(cmd *exec.Cmd) error {
					return errors.New("boom")
				})

				plugin := netplugin.New(fakeCommandRunner, configStore, "some/path")
				Expect(plugin.Network(nil, containerSpec, 42)).To(MatchError("boom"))
			})
		})
	})

	Describe("NetOut", func() {
		handle := "my-handle"
		var plugin kawasaki.Networker

		BeforeEach(func() {
			plugin = netplugin.New(fakeCommandRunner, configStore, "some/path")
		})

		It("writes to the config store", func() {
			netOutRules := []garden.NetOutRule{{
				Protocol: garden.ProtocolTCP,
				Networks: []garden.IPRange{{
					Start: net.IPv4(10, 10, 10, 2),
					End:   net.IPv4(10, 10, 10, 2),
				}},
			}}

			expectedJSON, err := json.Marshal(netOutRules)
			Expect(err).NotTo(HaveOccurred())
			Expect(plugin.NetOut(lagertest.NewTestLogger("test"), handle, netOutRules[0])).To(Succeed())
			v, ok := configStore.Get(handle, netplugin.NetOutKey)
			Expect(ok).To(BeTrue())
			Expect(v).To(MatchJSON(expectedJSON))
		})

		Context("when config store has existing net-out rule", func() {
			var oldNetOutRule garden.NetOutRule

			BeforeEach(func() {
				oldNetOutRule = garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 2),
						End:   net.IPv4(10, 10, 10, 2),
					}},
				}

				netOutRules := []garden.NetOutRule{oldNetOutRule}
				r, _ := json.Marshal(netOutRules)
				configStore.Set(handle, netplugin.NetOutKey, string(r))
			})

			It("adds another net-out rule", func() {

				newNetOutRule := garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 3),
						End:   net.IPv4(10, 10, 10, 3),
					}},
				}
				Expect(plugin.NetOut(lagertest.NewTestLogger("test"), handle, newNetOutRule)).To(Succeed())

				expectedJSON, err := json.Marshal([]garden.NetOutRule{oldNetOutRule, newNetOutRule})
				Expect(err).NotTo(HaveOccurred())
				v, ok := configStore.Get(handle, netplugin.NetOutKey)
				Expect(ok).To(BeTrue())
				Expect(v).To(MatchJSON(expectedJSON))
			})
		})

		Context("when config store has bad net-out rule data", func() {
			BeforeEach(func() {
				configStore.Set(handle, netplugin.NetOutKey, "bad-data")
			})

			It("returns an error", func() {
				newNetOutRule := garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 3),
						End:   net.IPv4(10, 10, 10, 3),
					}},
				}
				err := plugin.NetOut(lagertest.NewTestLogger("test"), handle, newNetOutRule)
				Expect(err).To(MatchError(ContainSubstring("store net-out invalid JSON")))
			})
		})
	})
})
