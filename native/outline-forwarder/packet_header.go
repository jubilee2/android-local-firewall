package main

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoTCP = 6
	protoUDP = 17

	ipv4MinHeaderLen    = 20
	ipv6FixedHeaderLen  = 40
	ipv6FragmentHdrLen  = 8
	maxIPv6ExtensionHdr = 8

	nextHdrHopByHop  = 0
	nextHdrRouting   = 43
	nextHdrFragment  = 44
	nextHdrDestOpts  = 60
)

// ParsedPacketHeader holds validated network and transport header metadata without payload bytes.
type ParsedPacketHeader struct {
	IPVersion       int
	Protocol        int
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      int
	DestinationPort int
	Identification  int
	FragmentOffset  int
	MoreFragments   bool
}

func parsePacketHeader(pkt []byte) (ParsedPacketHeader, bool) {
	if len(pkt) == 0 {
		return ParsedPacketHeader{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4PacketHeader(pkt)
	case 6:
		return parseIPv6PacketHeader(pkt)
	default:
		return ParsedPacketHeader{}, false
	}
}

func parseIPv4PacketHeader(pkt []byte) (ParsedPacketHeader, bool) {
	if len(pkt) < ipv4MinHeaderLen {
		return ParsedPacketHeader{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4MinHeaderLen || ihl > len(pkt) {
		return ParsedPacketHeader{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return ParsedPacketHeader{}, false
	}
	proto := int(pkt[9])
	if proto != protoTCP && proto != protoUDP {
		return ParsedPacketHeader{}, false
	}

	frag := binary.BigEndian.Uint16(pkt[6:8])
	fragOffset := int(frag & 0x1fff)
	moreFrags := (frag & 0x2000) != 0
	id := int(binary.BigEndian.Uint16(pkt[4:6]))

	var srcBytes, dstBytes [4]byte
	copy(srcBytes[:], pkt[12:16])
	copy(dstBytes[:], pkt[16:20])

	srcPort, dstPort := -1, -1
	if fragOffset == 0 {
		var ok bool
		srcPort, dstPort, ok = parseTransportPorts(pkt[:totalLen], ihl, proto, moreFrags)
		if !ok {
			return ParsedPacketHeader{}, false
		}
	}

	return ParsedPacketHeader{
		IPVersion:       4,
		Protocol:        proto,
		SourceIP:        netip.AddrFrom4(srcBytes),
		DestinationIP:   netip.AddrFrom4(dstBytes),
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		Identification:  id,
		FragmentOffset:  fragOffset,
		MoreFragments:   moreFrags,
	}, true
}

func parseIPv6PacketHeader(pkt []byte) (ParsedPacketHeader, bool) {
	if len(pkt) < ipv6FixedHeaderLen {
		return ParsedPacketHeader{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	totalLen := ipv6FixedHeaderLen + payloadLen
	if totalLen > len(pkt) {
		return ParsedPacketHeader{}, false
	}

	var srcBytes, dstBytes [16]byte
	copy(srcBytes[:], pkt[8:24])
	copy(dstBytes[:], pkt[24:40])

	nextHdr := int(pkt[6])
	offset := ipv6FixedHeaderLen
	fragOffset := 0
	moreFrags := false
	id := 0
	seenFrag := false

	for extIdx := 0; isIPv6Extension(nextHdr); extIdx++ {
		if extIdx >= maxIPv6ExtensionHdr {
			return ParsedPacketHeader{}, false
		}
		if nextHdr == nextHdrFragment {
			if seenFrag || offset+ipv6FragmentHdrLen > totalLen {
				return ParsedPacketHeader{}, false
			}
			seenFrag = true
			nextHdr = int(pkt[offset])
			fragField := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			fragOffset = int(fragField >> 3)
			moreFrags = (fragField & 0x0001) != 0
			id = int(int32(binary.BigEndian.Uint32(pkt[offset+4 : offset+8])))
			offset += ipv6FragmentHdrLen
			if fragOffset != 0 {
				break
			}
		} else {
			if offset+2 > totalLen {
				return ParsedPacketHeader{}, false
			}
			following := int(pkt[offset])
			extLen := (int(pkt[offset+1]) + 1) * 8
			if offset+extLen > totalLen {
				return ParsedPacketHeader{}, false
			}
			nextHdr = following
			offset += extLen
		}
	}

	if nextHdr != protoTCP && nextHdr != protoUDP {
		return ParsedPacketHeader{}, false
	}

	srcPort, dstPort := -1, -1
	if fragOffset == 0 {
		var ok bool
		srcPort, dstPort, ok = parseTransportPorts(pkt[:totalLen], offset, nextHdr, moreFrags)
		if !ok {
			return ParsedPacketHeader{}, false
		}
	}

	return ParsedPacketHeader{
		IPVersion:       6,
		Protocol:        nextHdr,
		SourceIP:        netip.AddrFrom16(srcBytes),
		DestinationIP:   netip.AddrFrom16(dstBytes),
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		Identification:  id,
		FragmentOffset:  fragOffset,
		MoreFragments:   moreFrags,
	}, true
}

func isIPv6Extension(hdr int) bool {
	return hdr == nextHdrHopByHop ||
		hdr == nextHdrRouting ||
		hdr == nextHdrFragment ||
		hdr == nextHdrDestOpts
}

func parseTransportPorts(pkt []byte, offset int, proto int, moreFrags bool) (int, int, bool) {
	switch proto {
	case protoTCP:
		if offset+20 > len(pkt) {
			return 0, 0, false
		}
		dataOffset := int(pkt[offset+12]>>4) * 4
		if dataOffset < 20 || offset+dataOffset > len(pkt) {
			return 0, 0, false
		}
		src := int(binary.BigEndian.Uint16(pkt[offset : offset+2]))
		dst := int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
		return src, dst, true
	case protoUDP:
		if offset+8 > len(pkt) {
			return 0, 0, false
		}
		udpLen := int(binary.BigEndian.Uint16(pkt[offset+4 : offset+6]))
		if udpLen < 8 {
			return 0, 0, false
		}
		if !moreFrags && offset+udpLen > len(pkt) {
			return 0, 0, false
		}
		src := int(binary.BigEndian.Uint16(pkt[offset : offset+2]))
		dst := int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
		return src, dst, true
	default:
		return 0, 0, false
	}
}
