package worker

import (
	"net"
	"testing"
)

func TestRoutableQueueIP(t *testing.T) {
	if routableQueueIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("10.0.0.1 is the Hyper-V default switch sinkhole, not a queue address")
	}
	if routableQueueIP(net.ParseIP("192.168.50.1")) || routableQueueIP(net.ParseIP("172.29.248.1")) || routableQueueIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("private and loopback addresses are not queue addresses")
	}
	if !routableQueueIP(net.ParseIP("54.39.107.163")) {
		t.Fatal("public address was rejected")
	}
}
