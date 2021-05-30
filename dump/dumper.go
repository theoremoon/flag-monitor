package dump

import (
	"bufio"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/lestrrat-go/strftime"
	"golang.org/x/xerrors"
)

type Dumper interface {
	Write(ci gopacket.CaptureInfo, data []byte) error
	Flush() error
	Close() error
	SetCloseCallback(func(string))
}

type dumper struct {
	File      *os.File
	BufWriter *bufio.Writer
	Writer    *pcapgo.Writer

	SnapLen       uint32
	LinkType      layers.LinkType
	CloseCallback func(string)
}

func NewDumper(filename string, snaplen uint32, linktype layers.LinkType) (Dumper, error) {
	// formatをチェックしておく
	formatter, err := strftime.New(filename)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	dumper := dumper{
		SnapLen:  snaplen,
		LinkType: linktype,
	}
	dumper.initiateWriter(formatter.FormatString(time.Now()))
	return &dumper, nil
}

func (d *dumper) Write(ci gopacket.CaptureInfo, data []byte) error {
	// 書き込む
	if err := d.Writer.WritePacket(ci, data); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (d *dumper) Flush() error {
	if err := d.BufWriter.Flush(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (d *dumper) Close() error {
	d.Flush()
	filename := d.File.Name()
	if err := d.File.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if d.CloseCallback != nil {
		d.CloseCallback(filename)
	}
	return nil
}

func (d *dumper) SetCloseCallback(f func(string)) {
	d.CloseCallback = f
}

/// ファイル作ってWriterの初期化をする
func (d *dumper) initiateWriter(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	d.BufWriter = bufio.NewWriter(f)

	d.Writer = pcapgo.NewWriter(d.BufWriter)
	if err := d.Writer.WriteFileHeader(d.SnapLen, d.LinkType); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}
