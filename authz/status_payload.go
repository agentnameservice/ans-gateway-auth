package authz

import (
	"encoding/binary"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// statusPayloadNames reads agent_id (key 1) and ans_name (key 5) from a
// status token's CBOR payload, preferring the integer key over the string
// one and the last of duplicates, as the SDK does. It is used only on a
// token the SDK has already verified and then refused as terminal, which it
// does without returning the payload; it does not check the signature
// itself. It reads definite-length CBOR (RFC 8949) only, which is what the
// TL emits; anything else reports false, and the caller keeps the SDK's
// refusal. A hand reader keeps fxamacker/cbor an indirect dependency.
func statusPayloadNames(raw []byte) (*scitt.StatusTokenPayload, bool) {
	cose, err := scitt.ParseCoseSign1(raw)
	if err != nil {
		return nil, false
	}
	r := &cborReader{b: cose.Payload}
	n, ok := r.head(cborMajorMap)
	if !ok {
		return nil, false
	}
	var byInt, byName [2]string // indexed by slotAgentID, slotAnsName
	for range n {
		slot, isInt, ok := r.payloadKey()
		if !ok {
			return nil, false
		}
		if slot == slotOther {
			if !r.skip(0) {
				return nil, false
			}
			continue
		}
		v, ok := r.text()
		if !ok {
			return nil, false
		}
		if isInt {
			byInt[slot] = v
		} else {
			byName[slot] = v
		}
	}
	if r.off != len(r.b) {
		return nil, false
	}
	pick := func(i int) string {
		if byInt[i] != "" {
			return byInt[i]
		}
		return byName[i]
	}
	p := &scitt.StatusTokenPayload{AgentID: pick(slotAgentID), AnsName: pick(slotAnsName)}
	return p, p.AgentID != "" && p.AnsName != ""
}

const (
	cborMajorUint   = 0
	cborMajorNegInt = 1
	cborMajorBytes  = 2
	cborMajorText   = 3
	cborMajorMap    = 5
	cborMajorTag    = 6
	cborMajorSimple = 7
	// cborMajorShift and cborInfoMask split an initial byte (RFC 8949
	// section 3).
	cborMajorShift = 5
	cborInfoMask   = 0x1f
	// cborInfoUint8 is the first additional-information value that is
	// followed by an argument (1, 2, 4 or 8 bytes for 24 to 27).
	cborInfoUint8  = 24
	cborInfoUint64 = 27
	cborArgMaxLen  = 8
	// cborMaxDepth matches the SDK's MaxNestedLevels.
	cborMaxDepth = 16
	// cborMaxItems bounds a declared map length before it is doubled.
	cborMaxItems = 1 << 20
	// cborMapItemsPerPair: a map of n pairs holds 2n items.
	cborMapItemsPerPair = 2
)

// Status token payload keys (the SDK's CBOR keys for these fields).
const (
	payloadKeyAgentID = 1
	payloadKeyAnsName = 5
)

// Slots statusPayloadNames fills; slotOther is any other key.
const (
	slotAgentID = 0
	slotAnsName = 1
	slotOther   = -1
)

// cborItemHead is one item's head: its major type and argument.
type cborItemHead struct {
	major byte
	arg   uint64
}

// cborReader walks definite-length CBOR.
type cborReader struct {
	b   []byte
	off int
}

// remaining is how many bytes are left.
func (r *cborReader) remaining() uint64 { return uint64(len(r.b) - r.off) } //nolint:gosec // off <= len(b)

// take consumes n bytes, or reports false when fewer remain.
func (r *cborReader) take(n uint64) ([]byte, bool) {
	if n > r.remaining() {
		return nil, false
	}
	start := r.off
	r.off += int(n) //nolint:gosec // n <= remaining, so it fits in an int
	return r.b[start:r.off], true
}

// next reads one item head.
func (r *cborReader) next() (cborItemHead, bool) {
	ib, ok := r.take(1)
	if !ok {
		return cborItemHead{}, false
	}
	h := cborItemHead{major: ib[0] >> cborMajorShift}
	info := ib[0] & cborInfoMask
	if info < cborInfoUint8 {
		h.arg = uint64(info)
		return h, true
	}
	if info > cborInfoUint64 { // 28-30 reserved, 31 indefinite length
		return cborItemHead{}, false
	}
	argBytes, ok := r.take(1 << (info - cborInfoUint8))
	if !ok {
		return cborItemHead{}, false
	}
	buf := make([]byte, cborArgMaxLen)
	copy(buf[cborArgMaxLen-len(argBytes):], argBytes)
	h.arg = binary.BigEndian.Uint64(buf)
	return h, true
}

// head reads an item head of the wanted major type.
func (r *cborReader) head(want byte) (uint64, bool) {
	h, ok := r.next()
	return h.arg, ok && h.major == want
}

// payloadKey reads a map key and returns its slot (slotOther for any other
// key, already consumed), whether it was an integer key, and whether it read.
func (r *cborReader) payloadKey() (int, bool, bool) {
	start := r.off
	h, ok := r.next()
	if !ok {
		return 0, false, false
	}
	switch {
	case h.major == cborMajorUint && h.arg == payloadKeyAgentID:
		return slotAgentID, true, true
	case h.major == cborMajorUint && h.arg == payloadKeyAnsName:
		return slotAnsName, true, true
	case h.major == cborMajorText:
		r.off = start
		s, ok := r.text()
		switch {
		case !ok:
			return 0, false, false
		case s == "agent_id":
			return slotAgentID, false, true
		case s == "ans_name":
			return slotAnsName, false, true
		}
		return slotOther, false, true
	}
	r.off = start
	return slotOther, false, r.skip(0)
}

// text reads a text string. A value of another type reads as "", as the SDK
// decodes it, and is consumed.
func (r *cborReader) text() (string, bool) {
	start := r.off
	h, ok := r.next()
	if !ok {
		return "", false
	}
	if h.major != cborMajorText {
		r.off = start
		return "", r.skip(0)
	}
	b, ok := r.take(h.arg)
	return string(b), ok
}

// skip consumes one complete item of any type.
func (r *cborReader) skip(depth int) bool {
	if depth > cborMaxDepth {
		return false
	}
	h, ok := r.next()
	if !ok {
		return false
	}
	switch h.major {
	case cborMajorUint, cborMajorNegInt, cborMajorSimple:
		return true
	case cborMajorBytes, cborMajorText:
		_, ok := r.take(h.arg)
		return ok
	case cborMajorTag:
		return r.skip(depth + 1)
	}
	items := h.arg
	if h.major == cborMajorMap {
		if h.arg > cborMaxItems {
			return false
		}
		items = cborMapItemsPerPair * h.arg
	}
	// Each item takes at least one byte, so a longer declared length is
	// refused before the loop runs.
	if items > r.remaining() {
		return false
	}
	for range items {
		if !r.skip(depth + 1) {
			return false
		}
	}
	return true
}
