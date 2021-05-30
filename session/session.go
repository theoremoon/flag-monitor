package session

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/xerrors"
)

type Key [2]uint64

func (k *Key) String() string {
	return fmt.Sprintf("%d:%d", k[0], k[1])
}

type Session struct {
	Key        Key
	LastActive time.Time
	Packets    []gopacket.Packet
	Closed     bool
}

func getKey(packet gopacket.Packet) (Key, error) {
	net := packet.NetworkLayer()
	if net == nil {
		return Key{}, xerrors.Errorf(": %w", xerrors.New("packet is not on the Network Layer"))
	}
	tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !isTCP {
		return Key{}, xerrors.Errorf(": %w", xerrors.New("packet is not a TCP"))
	}

	netflow := net.NetworkFlow()
	tcpflow := tcp.TransportFlow()

	return Key{
		netflow.FastHash(),
		tcpflow.FastHash(),
	}, nil
}
