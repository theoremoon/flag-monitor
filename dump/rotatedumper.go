/// パケットをpcapにダンプする
package dump

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/xerrors"
)

/// RotateDumperはパケットをダンプするが、一定時間ごとにファイルをローテートする
/// ファイル名にはstrftimeと同じ指定子が使える

type rotateDumper struct {
	CreatedAt      time.Time
	RotateDuration time.Duration
	Format         string
	dumper         *dumper
}

func NewRotateDumper(filename string, snaplen uint32, linktype layers.LinkType, dur time.Duration) (Dumper, error) {
	d, err := NewDumper(filename, snaplen, linktype)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &rotateDumper{
		dumper:         d.(*dumper),
		CreatedAt:      time.Now(),
		Format:         filename,
		RotateDuration: dur,
	}, nil
}

func (d *rotateDumper) Write(ci gopacket.CaptureInfo, data []byte) error {
	// rotateするかも
	now := time.Now()
	if now.Sub(d.CreatedAt) > d.RotateDuration {
		d.Close()
		newDumper, err := NewDumper(d.Format, d.dumper.SnapLen, d.dumper.LinkType)
		newDumper.SetCloseCallback(d.dumper.CloseCallback)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		d.dumper = newDumper.(*dumper)
	}

	// 書き込む
	if err := d.dumper.Write(ci, data); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (d *rotateDumper) Flush() error {
	if err := d.dumper.Flush(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (d *rotateDumper) Close() error {
	if err := d.dumper.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (d *rotateDumper) SetCloseCallback(f func(string)) {
	d.SetCloseCallback(f)
}
