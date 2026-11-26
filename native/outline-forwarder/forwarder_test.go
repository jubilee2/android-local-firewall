package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type recordingCallbacks struct {
	mu           sync.Mutex
	events       []string
	admitFn      func(ParsedPacketHeader) bool
	protectFn    func(fd int) bool
	protectedFDs []int
	fatalErrors  []string
}

func (r *recordingCallbacks) AdmitPacket(hdr ParsedPacketHeader) bool {
	decision := true
	if r.admitFn != nil {
		decision = r.admitFn(hdr)
	}
	r.mu.Lock()
	r.events = append(r.events, "admit")
	r.mu.Unlock()
	return decision
}

func (r *recordingCallbacks) ProtectSocket(fd int) bool {
	// Verify fd is a valid open socket descriptor at the moment ProtectSocket is invoked,
	// and has not yet connected to a remote peer (getpeername returns ENOTCONN before connect()).
	_, peerErr := syscall.Getpeername(fd)
	beforeConnect := peerErr == syscall.ENOTCONN

	ok := true
	if r.protectFn != nil {
		ok = r.protectFn(fd)
	}
	r.mu.Lock()
	if beforeConnect {
		r.events = append(r.events, "protect-before-io")
	} else {
		r.events = append(r.events, "protect-after-connect-violation")
	}
	r.protectedFDs = append(r.protectedFDs, fd)
	r.mu.Unlock()
	return ok
}

func (r *recordingCallbacks) OnFatalError(reason string) {
	r.mu.Lock()
	r.fatalErrors = append(r.fatalErrors, reason)
	r.mu.Unlock()
}

func (r *recordingCallbacks) snapshotEvents() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

func createUnixDatagramPair(t *testing.T) (appEnd *os.File, tunEndFd int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatalf("SetNonblock failed: %v", err)
	}
	appFile := os.NewFile(uintptr(fds[0]), "app-tun-peer")
	t.Cleanup(func() {
		_ = appFile.Close()
		_ = syscall.Close(fds[1])
	})
	return appFile, fds[1]
}

func TestDirectUDPForwardingAdmissionAndProtectOrder(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()

	serverReceived := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		serverReceived <- cp
		_, _ = serverConn.WriteToUDP(append([]byte("pong:"), cp...), clientAddr)
	}()

	cb := &recordingCallbacks{}
	appTun, tunFd := createUnixDatagramPair(t)
	fwd, err := StartForwarder(tunFd, cb, Config{
		UDPIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartForwarder: %v", err)
	}
	defer func() {
		if err := fwd.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()

	reqPayload := []byte("hello-direct-udp")
	rawPkt := buildIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.2"),
		53000,
		serverAddr.Addr(),
		serverAddr.Port(),
		reqPayload,
	)
	if _, err := appTun.Write(rawPkt); err != nil {
		t.Fatalf("write tun packet: %v", err)
	}

	select {
	case got := <-serverReceived:
		if !bytes.Equal(got, reqPayload) {
			t.Fatalf("server got %q, want %q", got, reqPayload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for direct UDP server to receive datagram")
	}

	_ = appTun.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 4096)
	n, err := appTun.Read(respBuf)
	if err != nil {
		t.Fatalf("read tun response: %v", err)
	}
	respHdr, ok := parsePacketHeader(respBuf[:n])
	if !ok || respHdr.Protocol != protoUDP || respHdr.DestinationPort != 53000 {
		t.Fatalf("unexpected UDP response header: ok=%v hdr=%+v", ok, respHdr)
	}
	udpPayload := respBuf[28:n]
	if !bytes.Equal(udpPayload, []byte("pong:hello-direct-udp")) {
		t.Fatalf("unexpected UDP response payload: %q", udpPayload)
	}

	events := cb.snapshotEvents()
	if len(events) < 2 || events[0] != "admit" || events[1] != "protect-before-io" {
		t.Fatalf("expected [admit, protect-before-io], got %v", events)
	}
}

func TestDirectTCPForwardingHandshakeAndPayloadRelay(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	serverAddr := listener.Addr().(*net.TCPAddr).AddrPort()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		_, _ = conn.Write(append([]byte("ack:"), buf[:n]...))
	}()

	cb := &recordingCallbacks{}
	appTun, tunFd := createUnixDatagramPair(t)
	fwd, err := StartForwarder(tunFd, cb, Config{})
	if err != nil {
		t.Fatalf("StartForwarder: %v", err)
	}
	defer func() {
		if err := fwd.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()

	srcIP := netip.MustParseAddr("10.0.0.2")
	srcPort := uint16(54123)
	clientSeq := uint32(1000)

	// 1. Send TCP SYN.
	synPkt := buildIPv4TCPPacket(srcIP, srcPort, serverAddr.Addr(), serverAddr.Port(), clientSeq, 0, 0x02, nil)
	if _, err := appTun.Write(synPkt); err != nil {
		t.Fatalf("write SYN: %v", err)
	}

	// 2. Read SYN-ACK from lwIP.
	_ = appTun.SetReadDeadline(time.Now().Add(3 * time.Second))
	pktBuf := make([]byte, 4096)
	n, err := appTun.Read(pktBuf)
	if err != nil {
		t.Fatalf("read SYN-ACK: %v", err)
	}
	serverSeq, flags := parseIPv4TCPSeqAndFlags(t, pktBuf[:n])
	if flags&0x12 != 0x12 {
		t.Fatalf("expected SYN|ACK (0x12), got 0x%02x", flags)
	}

	// 3. Complete handshake with ACK and send PSH|ACK payload.
	clientSeq++
	ackNum := serverSeq + 1
	ackPkt := buildIPv4TCPPacket(srcIP, srcPort, serverAddr.Addr(), serverAddr.Port(), clientSeq, ackNum, 0x10, nil)
	if _, err := appTun.Write(ackPkt); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	payload := []byte("ping-tcp")
	pshPkt := buildIPv4TCPPacket(srcIP, srcPort, serverAddr.Addr(), serverAddr.Port(), clientSeq, ackNum, 0x18, payload)
	if _, err := appTun.Write(pshPkt); err != nil {
		t.Fatalf("write PSH: %v", err)
	}

	// 4. Read response packets until we receive payload "ack:ping-tcp".
	var receivedPayload []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = appTun.SetReadDeadline(deadline)
		rn, err := appTun.Read(pktBuf)
		if err != nil {
			t.Fatalf("waiting for TCP response payload: %v", err)
		}
		tcpData := extractIPv4TCPPayload(pktBuf[:rn])
		if len(tcpData) > 0 {
			receivedPayload = append(receivedPayload, tcpData...)
			if bytes.Equal(receivedPayload, []byte("ack:ping-tcp")) {
				break
			}
		}
	}
	if !bytes.Equal(receivedPayload, []byte("ack:ping-tcp")) {
		t.Fatalf("got TCP payload %q, want %q", receivedPayload, "ack:ping-tcp")
	}

	events := cb.snapshotEvents()
	if len(events) < 2 || events[0] != "admit" || events[1] != "protect-before-io" {
		t.Fatalf("expected [admit, protect-before-io], got %v", events)
	}
}

func TestBlockedAndUnknownUIDFlowsOpenZeroSockets(t *testing.T) {
	var accepted atomic.Int32
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	serverAddr := listener.Addr().(*net.TCPAddr).AddrPort()

	cb := &recordingCallbacks{
		admitFn: func(_ ParsedPacketHeader) bool {
			// Simulates BLOCK rule or unknown-UID fail-closed rejection.
			return false
		},
	}
	appTun, tunFd := createUnixDatagramPair(t)
	fwd, err := StartForwarder(tunFd, cb, Config{})
	if err != nil {
		t.Fatalf("StartForwarder: %v", err)
	}
	defer fwd.Stop()

	synPkt := buildIPv4TCPPacket(netip.MustParseAddr("10.0.0.2"), 55000, serverAddr.Addr(), serverAddr.Port(), 1, 0, 0x02, nil)
	if _, err := appTun.Write(synPkt); err != nil {
		t.Fatalf("write SYN: %v", err)
	}
	udpPkt := buildIPv4UDPPacket(netip.MustParseAddr("10.0.0.2"), 55001, serverAddr.Addr(), serverAddr.Port(), []byte("blocked"))
	if _, err := appTun.Write(udpPkt); err != nil {
		t.Fatalf("write UDP: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	cb.mu.Lock()
	protectCalls := len(cb.protectedFDs)
	cb.mu.Unlock()
	if protectCalls != 0 {
		t.Fatalf("expected 0 socket creations / protect calls for blocked flows, got %d", protectCalls)
	}
	if accepted.Load() != 0 {
		t.Fatalf("expected 0 accepted TCP connections for blocked flow, got %d", accepted.Load())
	}
}

func TestFailedProtectClosesSocketAndFailsFlowClosed(t *testing.T) {
	var accepted atomic.Int32
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	tcpServerAddr := listener.Addr().(*net.TCPAddr).AddrPort()

	udpServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udpServer.Close()
	var udpReceived atomic.Int32
	go func() {
		buf := make([]byte, 256)
		if _, _, err := udpServer.ReadFromUDP(buf); err == nil {
			udpReceived.Add(1)
		}
	}()
	udpServerAddr := udpServer.LocalAddr().(*net.UDPAddr).AddrPort()

	protectCalled := make(chan int, 4)
	cb := &recordingCallbacks{
		protectFn: func(fd int) bool {
			protectCalled <- fd
			return false
		},
	}
	appTun, tunFd := createUnixDatagramPair(t)
	fwd, err := StartForwarder(tunFd, cb, Config{})
	if err != nil {
		t.Fatalf("StartForwarder: %v", err)
	}
	defer fwd.Stop()

	// 1. TCP: complete app <-> lwIP 3-way handshake so lwIP invokes DialStream -> ProtectSocket.
	srcIP := netip.MustParseAddr("10.0.0.2")
	srcPort := uint16(56000)
	synPkt := buildIPv4TCPPacket(srcIP, srcPort, tcpServerAddr.Addr(), tcpServerAddr.Port(), 10, 0, 0x02, nil)
	if _, err := appTun.Write(synPkt); err != nil {
		t.Fatalf("write SYN: %v", err)
	}
	_ = appTun.SetReadDeadline(time.Now().Add(3 * time.Second))
	pktBuf := make([]byte, 4096)
	n, err := appTun.Read(pktBuf)
	if err != nil {
		t.Fatalf("read SYN-ACK: %v", err)
	}
	serverSeq, _ := parseIPv4TCPSeqAndFlags(t, pktBuf[:n])
	ackPkt := buildIPv4TCPPacket(srcIP, srcPort, tcpServerAddr.Addr(), tcpServerAddr.Port(), 11, serverSeq+1, 0x10, nil)
	if _, err := appTun.Write(ackPkt); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	select {
	case <-protectCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TCP ProtectSocket callback")
	}

	// 2. UDP: send datagram to trigger ListenPacket -> ProtectSocket.
	udpPkt := buildIPv4UDPPacket(srcIP, 56001, udpServerAddr.Addr(), udpServerAddr.Port(), []byte("must-drop"))
	if _, err := appTun.Write(udpPkt); err != nil {
		t.Fatalf("write UDP: %v", err)
	}

	select {
	case <-protectCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for UDP ProtectSocket callback")
	}

	time.Sleep(100 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatalf("unprotected TCP socket must never complete connect(); accepted=%d", accepted.Load())
	}
	if udpReceived.Load() != 0 {
		t.Fatalf("unprotected UDP socket must never send datagrams; udpReceived=%d", udpReceived.Load())
	}
}

func TestBuildInfoIncludesPinnedOutlineAndLwipModules(t *testing.T) {
	meta := ReadBridgeMetadata()
	if meta.OutlineModulePath != "golang.getoutline.org/sdk" {
		t.Fatalf("expected OutlineModulePath golang.getoutline.org/sdk, got %+v", meta)
	}
	if meta.LwipModulePath != "github.com/eycorsican/go-tun2socks" {
		t.Fatalf("expected LwipModulePath github.com/eycorsican/go-tun2socks, got %+v", meta)
	}
}

func TestSingletonLifecycleAndBoundedIdleUDPExpiry(t *testing.T) {
	cb := &recordingCallbacks{}
	_, tunFd1 := createUnixDatagramPair(t)
	fwd1, err := StartForwarder(tunFd1, cb, Config{
		MaxTCPStreams:      2,
		MaxUDPAssociations: 1,
		UDPIdleTimeout:     80 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartForwarder #1: %v", err)
	}

	// Second concurrent forwarder must be rejected while fwd1 owns lwip2transport.
	_, tunFd2 := createUnixDatagramPair(t)
	if _, err := StartForwarder(tunFd2, cb, Config{}); !errors.Is(err, errForwarderAlreadyActive) {
		t.Fatalf("expected errForwarderAlreadyActive, got %v", err)
	}

	// Repeated Stop() must be idempotent and bounded, after which a fresh forwarder may start.
	if err := fwd1.Stop(); err != nil {
		t.Fatalf("fwd1.Stop #1: %v", err)
	}
	if err := fwd1.Stop(); err != nil {
		t.Fatalf("fwd1.Stop #2: %v", err)
	}

	fwd2, err := StartForwarder(tunFd2, cb, Config{})
	if err != nil {
		t.Fatalf("StartForwarder #2 after clean Stop: %v", err)
	}
	if err := fwd2.Stop(); err != nil {
		t.Fatalf("fwd2.Stop: %v", err)
	}
}

func buildIPv4UDPPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[6] = 0x40 // DF
	pkt[8] = 64   // TTL
	pkt[9] = protoUDP
	s4 := srcIP.As4()
	d4 := dstIP.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[26:28], transportIPv4Checksum(s4, d4, protoUDP, pkt[20:]))
	return pkt
}

func buildIPv4TCPPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, seq uint32, ack uint32, flags byte, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	totalLen := 20 + tcpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = protoTCP
	s4 := srcIP.As4()
	d4 := dstIP.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], transportIPv4Checksum(s4, d4, protoTCP, tcp))
	return pkt
}

func parseIPv4TCPSeqAndFlags(t *testing.T, pkt []byte) (uint32, byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 || pkt[9] != protoTCP {
		t.Fatalf("not a valid IPv4 TCP packet (len=%d)", len(pkt))
	}
	seq := binary.BigEndian.Uint32(pkt[ihl+4 : ihl+8])
	flags := pkt[ihl+13]
	return seq, flags
}

func extractIPv4TCPPayload(pkt []byte) []byte {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != protoTCP {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) || ihl+20 > totalLen {
		return nil
	}
	dataOffset := int(pkt[ihl+12]>>4) * 4
	if ihl+dataOffset > totalLen {
		return nil
	}
	return pkt[ihl+dataOffset : totalLen]
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func transportIPv4Checksum(src [4]byte, dst [4]byte, proto byte, segment []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(proto)
	sum += uint32(len(segment))
	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 == 1 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if proto == protoUDP && csum == 0 {
		return 0xffff
	}
	return csum
}
