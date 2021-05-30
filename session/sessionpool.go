/// TCPのセッションを複数個持つための構造
/// 基本的に https://github.com/google/gopacket/blob/master/tcpassembly/assembly.go
package session

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/xerrors"
)

type SessionPool interface {
	AddTCP(gopacket.Packet, time.Time) error
	Flush(time.Time, func(sess *Session)) error
}

type sessionPool struct {
	sync.RWMutex
	Sessions map[Key]*Session
}

func NewPool() SessionPool {
	return &sessionPool{
		Sessions: make(map[Key]*Session, 128),
	}
}

/// パケットを適切なセッションに放り込む
func (pool *sessionPool) AddTCP(packet gopacket.Packet, now time.Time) error {
	tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !isTCP {
		return xerrors.Errorf(": %w", xerrors.New("packet is not a TCP"))
	}

	key, err := getKey(packet)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	pool.Lock()
	if sess, exist := pool.Sessions[key]; exist {
		sess.Packets = append(sess.Packets, packet)
		sess.LastActive = now
	} else {
		// session がなければ作っていれる
		pool.Sessions[key] = &Session{
			Key:        key,
			Packets:    make([]gopacket.Packet, 1, 128),
			LastActive: now,
			Closed:     false,
		}
		pool.Sessions[key].Packets[0] = packet
	}

	// RSTまたはFINが立っている時Sessionのcloseフラグをたてる
	if tcp.RST || tcp.FIN {
		pool.Sessions[key].Closed = true
	}
	pool.Unlock()

	return nil
}

/// closedになっているsession, 打ち切られてしまったsessionを探して消す
func (pool *sessionPool) Flush(olderThan time.Time, callback func(sess *Session)) error {
	pool.RLock()
	deleteList := make([]Key, 0, len(pool.Sessions)/4)
	for k, sess := range pool.Sessions {
		if sess.Closed || sess.LastActive.Before(olderThan) {
			callback(sess)
			deleteList = append(deleteList, k)
		}
	}
	pool.RUnlock()

	pool.Lock()
	for _, k := range deleteList {
		delete(pool.Sessions, k)
	}
	pool.Unlock()
	return nil
}
