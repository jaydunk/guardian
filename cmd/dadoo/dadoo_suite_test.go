package main_test

import (
	"encoding/json"
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var dadooBinPath string

func TestReap(t *testing.T) {
	RegisterFailHandler(Fail)

	skip := os.Getenv("GARDEN_TEST_ROOTFS") == ""

	SynchronizedBeforeSuite(func() []byte {
		var err error
		bins := make(map[string]string)

		if skip {
			return nil
		}

		bins["dadoo_bin_path"], err = gexec.Build("github.com/cloudfoundry-incubator/guardian/cmd/dadoo")
		Expect(err).NotTo(HaveOccurred())

		data, err := json.Marshal(bins)
		Expect(err).NotTo(HaveOccurred())

		return data
	}, func(data []byte) {
		if skip {
			return
		}

		bins := make(map[string]string)
		Expect(json.Unmarshal(data, &bins)).To(Succeed())

		dadooBinPath = bins["dadoo_bin_path"]
	})

	BeforeEach(func() {
		if skip {
			Skip("dadoo requires linux")
		}
	})

	RunSpecs(t, "Reap Suite")
}