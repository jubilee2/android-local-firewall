package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.getoutline.org/sdk/network"
	"golang.getoutline.org/sdk/network/lwip2transport"
	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/sys/unix"
)

// pinnedOutlineCommit is injected at build time from OUTLINE_SDK_COMMIT via -ldflags.
var pinnedOutlineCommit = "unverified-dev-build"

const (
	defaultMaxTCPStreams       = 256
	defaultMaxUDPAssociations  = 256
	defaultMaxUDPDatagramBytes = 65507
	defaultMaxUDPQueuePackets  = 64
	defaultUDPIdleTimeout      = 60 * time.Second
	defaultTCPDialTimeout      = 10 * time.Second
	defaultFlowDecisionTTL     = 30 * time.Second
	defaultMaxCachedFlows      = 2048
	defaultDestinationGrantTTL = 30 * time.Second
	defaultShutdownTimeout     = 5 * time.Second
	tunReadBufferBytes         = 65536
)

var (
	errForwarderAlreadyActive = errors.New("outline forwarder: previous instance is still active or pending cleanup")
	errForwarderClosed        = errors.New("outline forwarder: closed")
	errSocketProtectionFailed = errors.New("outline forwarder: VpnService.protect failed")
	errDestinationNotAdmitted = errors.New("outline forwarder: destination has no admission grant")
	errConcurrencyLimit       = errors.New("outline forwarder: flow limit reached")
	errDatagramTooLarge       = errors.New("outline forwarder: UDP datagram exceeds limit")
)

// Callbacks connects the userspace forwarder to synchronous policy admission and VpnService.protect.
type Callbacks interface {
	AdmitPacket(hdr ParsedPacketHeader) bool
	ProtectSocket(fd int) bool
	OnFatalError(reason string)
}

// Config bounds forwarder concurrency, queue sizes, idle expiry, and shutdown timeouts.
type Config struct {
	MaxTCPStreams       int
	MaxUDPAssociations  int
	MaxUDPDatagramBytes int
	MaxUDPQueuePackets  int
	UDPIdleTimeout      time.Duration
	TCPDialTimeout      time.Duration
	FlowDecisionTTL     time.Duration
	MaxCachedFlows      int
	ShutdownTimeout     time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxTCPStreams <= 0 {
		c.MaxTCPStreams = defaultMaxTCPStreams
	}
	if c.MaxUDPAssociations <= 0 {
		c.MaxUDPAssociations = defaultMaxUDPAssociations
	}
	if c.MaxUDPDatagramBytes <= 0 {
		c.MaxUDPDatagramBytes = defaultMaxUDPDatagramBytes
	}
	if c.MaxUDPQueuePackets <= 0 {
		c.MaxUDPQueuePackets = defaultMaxUDPQueuePackets
	}
	if c.UDPIdleTimeout <= 0 {
		c.UDPIdleTimeout = defaultUDPIdleTimeout
	}
	if c.TCPDialTimeout <= 0 {
		c.TCPDialTimeout = defaultTCPDialTimeout
	}
	if c.FlowDecisionTTL <= 0 {
		c.FlowDecisionTTL = defaultFlowDecisionTTL
	}
	if c.MaxCachedFlows <= 0 {
		c.MaxCachedFlows = defaultMaxCachedFlows
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = defaultShutdownTimeout
	}
	return c
}

// BridgeMetadata reports build-pinned and Go BuildInfo-verified dependency metadata.
type BridgeMetadata struct {
	PinnedOutlineCommit string `json:"pinnedOutlineCommit"`
	OutlineModulePath   string `json:"outlineModulePath"`
	OutlineVersion      string `json:"outlineVersion"`
	OutlineSum          string `json:"outlineSum"`
	LwipModulePath      string `json:"lwipModulePath"`
	LwipVersion         string `json:"lwipVersion"`
	LwipSum             string `json:"lwipSum"`
	GoVersion           string `json:"goVersion"`
}

// ReadBridgeMetadata inspects compiled module metadata from Go's embedded BuildInfo.
func ReadBridgeMetadata() BridgeMetadata {
	meta := BridgeMetadata{
		PinnedOutlineCommit: pinnedOutlineCommit,
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		meta.GoVersion = info.GoVersion
		for _, dep := range info.Deps {
			switch dep.Path {
			case "golang.getoutline.org/sdk":
				meta.OutlineModulePath = dep.Path
				meta.OutlineVersion = dep.Version
				meta.OutlineSum = dep.Sum
			case "github.com/eycorsican/go-tun2socks":
				meta.LwipModulePath = dep.Path
				meta.LwipVersion = dep.Version
				meta.LwipSum = dep.Sum
			}
		}
	}
	return meta
}

// BridgeMetadataJSON serializes ReadBridgeMetadata for JNI callers.
func BridgeMetadataJSON() string {
	encoded, err := json.Marshal(ReadBridgeMetadata())
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

var (
	activeForwarderMu sync.Mutex
	activeForwarder   *Forwarder
)

type fiveTuple struct {
	proto int
	src   netip.AddrPort
	dst   netip.AddrPort
}

type destKey struct {
	proto int
	dst   netip.AddrPort
}

// Forwarder owns one TUN duplicate FD, a wakeup pipe, the singleton lwip2transport stack, and all outbound sockets.
type Forwarder struct {
	cfg         Config
	callbacks   Callbacks
	tunFd       int
	wakeReadFd  int
	wakeWriteFd int
	ipDevice    network.IPDevice

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stopping atomic.Bool
	stopOnce sync.Once
	stopErr  error

	tcpSem chan struct{}
	udpSem chan struct{}

	stateMu         sync.Mutex
	admittedFlows   map[fiveTuple]time.Time
	destGrants      map[destKey]time.Time
	activeTCPConns  map[*trackedTCPConn]struct{}
	activeUDPAssocs map[*directUDPAssociation]struct{}
	onCloseRelease  func()
}

// StartForwarder duplicates tunFd, configures lwip2transport, and starts bidirectional packet workers.
func StartForwarder(tunFd int, callbacks Callbacks, cfg Config) (*Forwarder, error) {
	if tunFd < 0 {
		return nil, errors.New("outline forwarder: tunFd must be non-negative")
	}
	if callbacks == nil {
		return nil, errors.New("outline forwarder: callbacks must not be nil")
	}

	activeForwarderMu.Lock()
	if activeForwarder != nil {
		activeForwarderMu.Unlock()
		return nil, errForwarderAlreadyActive
	}

	dupFd, err := unix.Dup(tunFd)
	if err != nil {
		activeForwarderMu.Unlock()
		return nil, fmt.Errorf("outline forwarder: dup tunFd: %w", err)
	}
	unix.CloseOnExec(dupFd)
	if err := unix.SetNonblock(dupFd, true); err != nil {
		_ = unix.Close(dupFd)
		activeForwarderMu.Unlock()
		return nil, fmt.Errorf("outline forwarder: setnonblock tunFd: %w", err)
	}

	var wakePipe [2]int
	if err := unix.Pipe2(wakePipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(dupFd)
		activeForwarderMu.Unlock()
		return nil, fmt.Errorf("outline forwarder: pipe2 wakeup: %w", err)
	}

	resolvedCfg := cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())

	fwd := &Forwarder{
		cfg:             resolvedCfg,
		callbacks:       callbacks,
		tunFd:           dupFd,
		wakeReadFd:      wakePipe[0],
		wakeWriteFd:     wakePipe[1],
		ctx:             ctx,
		cancel:          cancel,
		tcpSem:          make(chan struct{}, resolvedCfg.MaxTCPStreams),
		udpSem:          make(chan struct{}, resolvedCfg.MaxUDPAssociations),
		admittedFlows:   make(map[fiveTuple]time.Time),
		destGrants:      make(map[destKey]time.Time),
		activeTCPConns:  make(map[*trackedTCPConn]struct{}),
		activeUDPAssocs: make(map[*directUDPAssociation]struct{}),
	}

	ipDevice, err := lwip2transport.ConfigureDeviceWithRelay(
		&directStreamDialer{fwd: fwd},
		&directPacketRelay{fwd: fwd},
	)
	if err != nil {
		cancel()
		_ = unix.Close(wakePipe[0])
		_ = unix.Close(wakePipe[1])
		_ = unix.Close(dupFd)
		activeForwarderMu.Unlock()
		return nil, fmt.Errorf("outline forwarder: configure lwip2transport: %w", err)
	}
	fwd.ipDevice = ipDevice
	activeForwarder = fwd
	activeForwarderMu.Unlock()

	fwd.wg.Add(2)
	go fwd.readTunToStack()
	go fwd.readStackToTun()
	return fwd, nil
}

// Stop tears down workers, closes all outbound sockets and stack handles, and releases singleton ownership.
func (f *Forwarder) Stop() error {
	f.stopOnce.Do(func() {
		f.stopping.Store(true)
		f.cancel()

		var errs []error
		// Closing wakeWriteFd immediately unblocks unix.Poll in TUN workers with POLLHUP.
		if f.wakeWriteFd >= 0 {
			if err := unix.Close(f.wakeWriteFd); err != nil && !errors.Is(err, unix.EBADF) {
				errs = append(errs, fmt.Errorf("close wake pipe write end: %w", err))
			}
		}
		if f.ipDevice != nil {
			if err := f.ipDevice.Close(); err != nil && !errors.Is(err, network.ErrClosed) {
				errs = append(errs, fmt.Errorf("close lwip2transport: %w", err))
			}
		}

		f.stateMu.Lock()
		tcpConns := make([]*trackedTCPConn, 0, len(f.activeTCPConns))
		for c := range f.activeTCPConns {
			tcpConns = append(tcpConns, c)
		}
		udpAssocs := make([]*directUDPAssociation, 0, len(f.activeUDPAssocs))
		for a := range f.activeUDPAssocs {
			udpAssocs = append(udpAssocs, a)
		}
		clear(f.admittedFlows)
		clear(f.destGrants)
		releaseFn := f.onCloseRelease
		f.onCloseRelease = nil
		f.stateMu.Unlock()

		for _, c := range tcpConns {
			_ = c.Close()
		}
		for _, a := range udpAssocs {
			_ = a.Close()
		}

		done := make(chan struct{})
		go func() {
			f.wg.Wait()
			close(done)
		}()

		joined := false
		select {
		case <-done:
			joined = true
		case <-time.After(f.cfg.ShutdownTimeout):
			errs = append(errs, errors.New("outline forwarder: worker join timed out"))
		}

		if joined {
			if err := unix.Close(f.tunFd); err != nil && !errors.Is(err, unix.EBADF) {
				errs = append(errs, fmt.Errorf("close tun dup: %w", err))
			}
			if err := unix.Close(f.wakeReadFd); err != nil && !errors.Is(err, unix.EBADF) {
				errs = append(errs, fmt.Errorf("close wake pipe read end: %w", err))
			}
		}

		if releaseFn != nil {
			releaseFn()
		}

		if len(errs) > 0 {
			f.stopErr = errors.Join(errs...)
		} else {
			activeForwarderMu.Lock()
			if activeForwarder == f {
				activeForwarder = nil
			}
			activeForwarderMu.Unlock()
		}
	})
	return f.stopErr
}

func (f *Forwarder) readTunToStack() {
	defer f.wg.Done()
	buf := make([]byte, tunReadBufferBytes)
	pollFds := []unix.PollFd{
		{Fd: int32(f.tunFd), Events: unix.POLLIN},
		{Fd: int32(f.wakeReadFd), Events: unix.POLLIN},
	}

	for !f.stopping.Load() {
		pollFds[0].Revents = 0
		pollFds[1].Revents = 0
		_, err := unix.Poll(pollFds, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !f.stopping.Load() {
				f.callbacks.OnFatalError(fmt.Sprintf("tun poll failed: %v", err))
			}
			return
		}
		if f.stopping.Load() || pollFds[1].Revents != 0 {
			return
		}
		if pollFds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 && pollFds[0].Revents&unix.POLLIN == 0 {
			if !f.stopping.Load() {
				f.callbacks.OnFatalError("tun descriptor closed or errored")
			}
			return
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		for !f.stopping.Load() {
			n, readErr := unix.Read(f.tunFd, buf)
			if readErr != nil {
				if errors.Is(readErr, unix.EINTR) {
					continue
				}
				if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) {
					break
				}
				if !f.stopping.Load() {
					f.callbacks.OnFatalError(fmt.Sprintf("tun read failed: %v", readErr))
				}
				return
			}
			if n == 0 {
				if !f.stopping.Load() {
					f.callbacks.OnFatalError("tun EOF")
				}
				return
			}
			pkt := buf[:n]
			if !f.admitIngressPacket(pkt) {
				continue
			}
			if _, writeErr := f.ipDevice.Write(pkt); writeErr != nil {
				if f.stopping.Load() || errors.Is(writeErr, network.ErrClosed) {
					return
				}
				f.callbacks.OnFatalError(fmt.Sprintf("lwip write failed: %v", writeErr))
				return
			}
		}
	}
}

func (f *Forwarder) readStackToTun() {
	defer f.wg.Done()
	writer := &tunPacketWriter{
		fwd: f,
		pollFds: []unix.PollFd{
			{Fd: int32(f.tunFd), Events: unix.POLLOUT},
			{Fd: int32(f.wakeReadFd), Events: unix.POLLIN},
		},
	}
	// Use io.Copy so lwIPDevice.WriteTo is invoked instead of lwIPDevice.Read:
	// WriteTo selects on <-d.done when sending on d.rdN, avoiding a close race
	// with forwardOutgoingIPPacket and avoiding intermediate packet copies.
	_, err := io.Copy(writer, f.ipDevice)
	if err != nil && !f.stopping.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, network.ErrClosed) && !errors.Is(err, errForwarderClosed) {
		f.callbacks.OnFatalError(fmt.Sprintf("lwip to tun copy failed: %v", err))
	}
}

type tunPacketWriter struct {
	fwd     *Forwarder
	pollFds []unix.PollFd
}

func (w *tunPacketWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	f := w.fwd
	for !f.stopping.Load() {
		_, writeErr := unix.Write(f.tunFd, p)
		if writeErr == nil {
			return len(p), nil
		}
		if errors.Is(writeErr, unix.EINTR) {
			continue
		}
		if errors.Is(writeErr, unix.EAGAIN) || errors.Is(writeErr, unix.EWOULDBLOCK) {
			w.pollFds[0].Revents = 0
			w.pollFds[1].Revents = 0
			if _, pollErr := unix.Poll(w.pollFds, -1); pollErr != nil {
				if errors.Is(pollErr, unix.EINTR) {
					continue
				}
				return 0, fmt.Errorf("tun write poll failed: %w", pollErr)
			}
			if f.stopping.Load() || w.pollFds[1].Revents != 0 {
				return 0, errForwarderClosed
			}
			continue
		}
		return 0, fmt.Errorf("tun write failed: %w", writeErr)
	}
	return 0, errForwarderClosed
}

func (f *Forwarder) admitIngressPacket(pkt []byte) bool {
	if f.stopping.Load() {
		return false
	}
	hdr, ok := parsePacketHeader(pkt)
	if !ok {
		return false
	}

	now := time.Now()

	// Fragmented packets always consult Callbacks so FragmentDecisionEngine correlates fragments.
	if hdr.FragmentOffset != 0 || hdr.MoreFragments {
		if !f.callbacks.AdmitPacket(hdr) {
			return false
		}
		if hdr.FragmentOffset == 0 && hdr.DestinationPort >= 0 {
			dst := netip.AddrPortFrom(hdr.DestinationIP.Unmap(), uint16(hdr.DestinationPort))
			f.recordDestinationGrant(hdr.Protocol, dst, now)
		}
		return true
	}

	src := netip.AddrPortFrom(hdr.SourceIP.Unmap(), uint16(hdr.SourcePort))
	dst := netip.AddrPortFrom(hdr.DestinationIP.Unmap(), uint16(hdr.DestinationPort))
	flow := fiveTuple{proto: hdr.Protocol, src: src, dst: dst}

	f.stateMu.Lock()
	if expiry, exists := f.admittedFlows[flow]; exists && now.Before(expiry) {
		f.admittedFlows[flow] = now.Add(f.cfg.FlowDecisionTTL)
		f.destGrants[destKey{proto: hdr.Protocol, dst: dst}] = now.Add(defaultDestinationGrantTTL)
		f.stateMu.Unlock()
		return true
	}
	f.stateMu.Unlock()

	if !f.callbacks.AdmitPacket(hdr) {
		return false
	}

	f.stateMu.Lock()
	if len(f.admittedFlows) >= f.cfg.MaxCachedFlows {
		f.evictExpiredOrOldestFlowLocked(now)
	}
	f.admittedFlows[flow] = now.Add(f.cfg.FlowDecisionTTL)
	f.destGrants[destKey{proto: hdr.Protocol, dst: dst}] = now.Add(defaultDestinationGrantTTL)
	f.stateMu.Unlock()
	return true
}

func (f *Forwarder) recordDestinationGrant(proto int, dst netip.AddrPort, now time.Time) {
	f.stateMu.Lock()
	f.destGrants[destKey{proto: proto, dst: dst}] = now.Add(defaultDestinationGrantTTL)
	f.stateMu.Unlock()
}

func (f *Forwarder) hasDestinationGrant(proto int, dst netip.AddrPort) bool {
	normalized := netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	now := time.Now()
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	expiry, ok := f.destGrants[destKey{proto: proto, dst: normalized}]
	if !ok {
		return false
	}
	if !now.Before(expiry) {
		delete(f.destGrants, destKey{proto: proto, dst: normalized})
		return false
	}
	return true
}

func (f *Forwarder) evictExpiredOrOldestFlowLocked(now time.Time) {
	var oldestKey fiveTuple
	var oldestExpiry time.Time
	hasOldest := false
	for k, exp := range f.admittedFlows {
		if !now.Before(exp) {
			delete(f.admittedFlows, k)
			return
		}
		if !hasOldest || exp.Before(oldestExpiry) {
			oldestKey = k
			oldestExpiry = exp
			hasOldest = true
		}
	}
	if hasOldest {
		delete(f.admittedFlows, oldestKey)
	}
}

func (f *Forwarder) protectRawConn(_ string, _ string, rawConn syscall.RawConn) error {
	if f.stopping.Load() {
		return errForwarderClosed
	}
	var protected bool
	if err := rawConn.Control(func(fd uintptr) {
		protected = f.callbacks.ProtectSocket(int(fd))
	}); err != nil {
		return err
	}
	if !protected {
		return errSocketProtectionFailed
	}
	return nil
}

type directStreamDialer struct {
	fwd *Forwarder
}

var _ transport.StreamDialer = (*directStreamDialer)(nil)

func (d *directStreamDialer) DialStream(ctx context.Context, raddr string) (transport.StreamConn, error) {
	f := d.fwd
	if f.stopping.Load() || f.ctx.Err() != nil {
		return nil, errForwarderClosed
	}

	addrPort, err := netip.ParseAddrPort(raddr)
	if err != nil {
		return nil, fmt.Errorf("outline forwarder: invalid TCP destination %q: %w", raddr, err)
	}
	if !f.hasDestinationGrant(protoTCP, addrPort) {
		return nil, errDestinationNotAdmitted
	}

	select {
	case f.tcpSem <- struct{}{}:
	default:
		return nil, errConcurrencyLimit
	}

	networkFamily := "tcp6"
	if addrPort.Addr().Unmap().Is4() {
		networkFamily = "tcp4"
	}

	dialCtx, cancel := context.WithTimeout(f.ctx, f.cfg.TCPDialTimeout)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-dialCtx.Done():
		}
	}()

	dialer := net.Dialer{
		Control: f.protectRawConn,
	}
	rawConn, err := dialer.DialContext(dialCtx, networkFamily, netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()).String())
	if err != nil {
		<-f.tcpSem
		return nil, err
	}

	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		_ = rawConn.Close()
		<-f.tcpSem
		return nil, errors.New("outline forwarder: unexpected non-TCPConn")
	}

	tracked := &trackedTCPConn{
		TCPConn: tcpConn,
		fwd:     f,
	}
	f.stateMu.Lock()
	if f.stopping.Load() {
		f.stateMu.Unlock()
		_ = tracked.Close()
		return nil, errForwarderClosed
	}
	f.activeTCPConns[tracked] = struct{}{}
	f.stateMu.Unlock()
	return tracked, nil
}

type trackedTCPConn struct {
	*net.TCPConn
	fwd       *Forwarder
	closeOnce sync.Once
}

func (c *trackedTCPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.fwd.stateMu.Lock()
		delete(c.fwd.activeTCPConns, c)
		c.fwd.stateMu.Unlock()
		err = c.TCPConn.Close()
		<-c.fwd.tcpSem
	})
	return err
}

func (c *trackedTCPConn) CloseRead() error {
	return c.TCPConn.CloseRead()
}

func (c *trackedTCPConn) CloseWrite() error {
	return c.TCPConn.CloseWrite()
}

type directPacketRelay struct {
	fwd *Forwarder
}

var _ packetrelay.PacketRelay = (*directPacketRelay)(nil)

func (r *directPacketRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	f := r.fwd
	if f.stopping.Load() || f.ctx.Err() != nil {
		return nil, nil, errForwarderClosed
	}

	select {
	case f.udpSem <- struct{}{}:
	default:
		return nil, nil, errConcurrencyLimit
	}

	assoc := &directUDPAssociation{
		fwd:          f,
		allowedPeers: make(map[netip.AddrPort]struct{}),
		inboundQueue: make(chan inboundUDPPacket, f.cfg.MaxUDPQueuePackets),
		connReady:    make(chan struct{}),
		done:         make(chan struct{}),
	}
	assoc.lastActivityUnixNano.Store(time.Now().UnixNano())

	f.stateMu.Lock()
	if f.stopping.Load() {
		f.stateMu.Unlock()
		<-f.udpSem
		return nil, nil, errForwarderClosed
	}
	f.activeUDPAssocs[assoc] = struct{}{}
	f.stateMu.Unlock()

	return assoc, assoc, nil
}

type inboundUDPPacket struct {
	payload []byte
	source  netip.AddrPort
}

type directUDPAssociation struct {
	fwd *Forwarder

	mu           sync.Mutex
	conn         *net.UDPConn
	isIPv4Socket bool
	allowedPeers map[netip.AddrPort]struct{}
	closed       bool

	connReadyOnce        sync.Once
	connReady            chan struct{}
	inboundQueue         chan inboundUDPPacket
	done                 chan struct{}
	closeOnce            sync.Once
	lastActivityUnixNano atomic.Int64
}

func (a *directUDPAssociation) SendPacket(p []byte, destination netip.AddrPort) error {
	f := a.fwd
	if f.stopping.Load() {
		return network.ErrClosed
	}
	if len(p) > f.cfg.MaxUDPDatagramBytes {
		return errDatagramTooLarge
	}

	target := netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if !f.hasDestinationGrant(protoUDP, target) {
		return errDestinationNotAdmitted
	}

	conn, err := a.ensureProtectedSocket(target.Addr().Is4())
	if err != nil {
		return err
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return network.ErrClosed
	}
	if len(a.allowedPeers) < 128 {
		a.allowedPeers[target] = struct{}{}
	}
	a.mu.Unlock()

	a.lastActivityUnixNano.Store(time.Now().UnixNano())
	_, err = conn.WriteToUDPAddrPort(p, target)
	return err
}

func (a *directUDPAssociation) ensureProtectedSocket(wantIPv4 bool) (*net.UDPConn, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, network.ErrClosed
	}
	if a.conn != nil {
		if a.isIPv4Socket != wantIPv4 {
			a.mu.Unlock()
			return nil, errors.New("outline forwarder: mixed address family on UDP association")
		}
		conn := a.conn
		a.mu.Unlock()
		return conn, nil
	}
	a.mu.Unlock()

	networkFamily := "udp6"
	if wantIPv4 {
		networkFamily = "udp4"
	}
	listenCfg := net.ListenConfig{
		Control: a.fwd.protectRawConn,
	}
	pktConn, err := listenCfg.ListenPacket(a.fwd.ctx, networkFamily, "")
	if err != nil {
		return nil, err
	}
	udpConn, ok := pktConn.(*net.UDPConn)
	if !ok {
		_ = pktConn.Close()
		return nil, errors.New("outline forwarder: unexpected non-UDPConn")
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = udpConn.Close()
		return nil, network.ErrClosed
	}
	if a.conn != nil {
		existing := a.conn
		a.mu.Unlock()
		_ = udpConn.Close()
		return existing, nil
	}
	a.conn = udpConn
	a.isIPv4Socket = wantIPv4
	a.mu.Unlock()

	a.connReadyOnce.Do(func() {
		close(a.connReady)
		go a.readSocketIntoQueue(udpConn)
	})
	return udpConn, nil
}

func (a *directUDPAssociation) readSocketIntoQueue(conn *net.UDPConn) {
	buf := make([]byte, a.fwd.cfg.MaxUDPDatagramBytes)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			_ = a.Close()
			return
		}
		normalizedSrc := netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		a.mu.Lock()
		_, allowed := a.allowedPeers[normalizedSrc]
		closed := a.closed
		a.mu.Unlock()
		if closed {
			return
		}
		if !allowed {
			continue
		}
		a.lastActivityUnixNano.Store(time.Now().UnixNano())
		payloadCopy := make([]byte, n)
		copy(payloadCopy, buf[:n])
		select {
		case a.inboundQueue <- inboundUDPPacket{payload: payloadCopy, source: normalizedSrc}:
		case <-a.done:
			return
		default:
			// Bounded queue drops excess burst datagrams rather than growing unbounded memory.
		}
	}
}

func (a *directUDPAssociation) ReceivePackets(handler packetrelay.PacketHandler) error {
	idleCheckInterval := a.fwd.cfg.UDPIdleTimeout / 2
	if idleCheckInterval < 10*time.Millisecond {
		idleCheckInterval = 10 * time.Millisecond
	}
	if idleCheckInterval > time.Second {
		idleCheckInterval = time.Second
	}
	ticker := time.NewTicker(idleCheckInterval)
	defer ticker.Stop()

	select {
	case <-a.connReady:
	case <-a.done:
		return nil
	}

	for {
		select {
		case pkt := <-a.inboundQueue:
			if err := handler.HandlePacket(pkt.payload, pkt.source); err != nil {
				_ = a.Close()
				return err
			}
		case <-ticker.C:
			lastActive := time.Unix(0, a.lastActivityUnixNano.Load())
			if time.Since(lastActive) >= a.fwd.cfg.UDPIdleTimeout {
				_ = a.Close()
				return nil
			}
		case <-a.done:
			return nil
		}
	}
}

func (a *directUDPAssociation) Close() error {
	var closeErr error
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		conn := a.conn
		a.conn = nil
		clear(a.allowedPeers)
		a.mu.Unlock()

		close(a.done)
		if conn != nil {
			closeErr = conn.Close()
		}

		a.fwd.stateMu.Lock()
		delete(a.fwd.activeUDPAssocs, a)
		a.fwd.stateMu.Unlock()
		<-a.fwd.udpSem
	})
	return closeErr
}
