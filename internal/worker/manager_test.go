package worker

import "testing"

func TestStartRejectsBadInput(t *testing.T) {
	for _, rawURL := range []string{"", "http://vm.example/", "wss://vm.example:8443/"} {
		if _, err := (HyperV{}).Start("sbx-0badc0de", rawURL, "t"); err == nil {
			t.Fatalf("accepted %q", rawURL)
		}
	}
}

func TestWebsocketHost(t *testing.T) {
	host, err := websocketHost("wss://cad0.lambda-microvm.us-east-1.on.aws/wireguard")
	if err != nil || host != "cad0.lambda-microvm.us-east-1.on.aws" {
		t.Fatalf("host %q %v", host, err)
	}
	if _, err := websocketHost("wss://vm.example:8443/"); err == nil {
		t.Fatal("non-443 port was accepted")
	}
}
