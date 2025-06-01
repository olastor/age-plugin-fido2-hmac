package plugin

import (
	"fmt"

	"github.com/savely-krasovsky/go-ctaphid/pkg/device"
	"github.com/savely-krasovsky/go-ctaphid/pkg/sugar"

	"reflect"
	"testing"
)

func TestEnforcePin(t *testing.T) {
	locs, err := sugar.EnumerateFIDODevices()
	if err != nil {
		t.Error(err)
	}

	var dev *device.Device
	if len(locs) != 1 {
		fmt.Printf("Testing with virtual test device not possible\n")
		return
	}

	dev, _ = device.New(locs[0].Path)
	info := dev.GetInfo()
	aaguid := fmt.Sprintf("%s", info.AAGUID)
	if aaguid != "AAGUID0123456789" {
		fmt.Printf("Testing with virtual test device not possible.\n")
		return
	}

	// these were generated with the simulated device and the ifs=e2e/test_device.bin
	// recStr := "age14wj87kklx0nm6ek9sze0n4un2xrctweh37gw2hqxyl0h5asf633qtpymdv"
	idStr := "AGE-PLUGIN-FIDO2-HMAC-1QQPQRUMQXAUCGHS3STVLMHH5NGF0G026RXKQTY7EG7ZH4N2PM7UEX9875VQ9S7MU804DNHMK3L9CRUSKN3WRCNH4NHG90DZST8CZU5JVZJAPS83PVADFHLWDSATKX06H57EP2QZ2PGFJ8MU4VF2E0LDZYV0478T4SX4W7G7Y52JD3KPUY0AMYN66G52CX0XXE3GHZJU5WJ8F4WK5X9JD68FU3TA9FDZ900K7L3ADSRJWA284XADJ3CP4YGEE8N970J5SZNX9LHC8MZVSK8ANXDUJ8UP9PWPE8P4A45AWV4F0JLEZMDH9VRGRDDKRL"

	i, err := ParseFido2HmacIdentity(idStr)
	if err != nil {
		t.Error(err)
	}

	secretPin, err := getHmacSecret(dev, i.CredId, i.Salt, "1234")
	if err != nil {
		t.Error(err)
	}

	secretNoPin, err := getHmacSecret(dev, i.CredId, i.Salt, "")
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(secretNoPin, secretPin) {
		t.Error("Secrets with or without PIN must not be the same")
	}
}
