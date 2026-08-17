package fastparser

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

// FBEncoder builds a FlatBuffers frame from a parsed request/response pair + Meta.
// It reuses one flatbuffers.Builder + offset scratch across calls, so the steady
// state is allocation-free (Builder.Reset keeps the backing buffer).
//
// NOT safe for concurrent use — one FBEncoder per goroutine (same rule as Builder).
// The returned bytes are a view into the Builder's buffer, valid only until the
// next Encode call on this FBEncoder.
type FBEncoder struct {
	b       *flatbuffers.Builder
	reqHdr  []flatbuffers.UOffsetT
	respHdr []flatbuffers.UOffsetT
}

func NewFBEncoder() *FBEncoder {
	return &FBEncoder{
		b:       flatbuffers.NewBuilder(64 * 1024),
		reqHdr:  make([]flatbuffers.UOffsetT, 0, maxHeaders),
		respHdr: make([]flatbuffers.UOffsetT, 0, maxHeaders),
	}
}

func (e *FBEncoder) buildHeaders(hs []Header, dst []flatbuffers.UOffsetT) []flatbuffers.UOffsetT {
	dst = dst[:0]
	for i := range hs {
		nv := e.b.CreateByteVector(hs[i].Name)
		vv := e.b.CreateByteVector(hs[i].Value)
		FbHeaderStart(e.b)
		FbHeaderAddName(e.b, nv)
		FbHeaderAddValue(e.b, vv)
		dst = append(dst, FbHeaderEnd(e.b))
	}
	return dst
}

func (e *FBEncoder) makeVec(off []flatbuffers.UOffsetT) flatbuffers.UOffsetT {
	e.b.StartVector(4, len(off), 4)
	for i := len(off) - 1; i >= 0; i-- {
		e.b.PrependUOffsetT(off[i])
	}
	return e.b.EndVector(len(off))
}

// Encode builds the FlatBuffers frame and returns the finished bytes.
func (e *FBEncoder) Encode(req *Request, resp *Response, m *Meta) []byte {
	b := e.b
	b.Reset()

	// All leaf offsets must exist before the table is started.
	e.reqHdr = e.buildHeaders(req.Headers, e.reqHdr)
	reqHdrVec := e.makeVec(e.reqHdr)
	e.respHdr = e.buildHeaders(resp.Headers, e.respHdr)
	respHdrVec := e.makeVec(e.respHdr)

	method := b.CreateByteVector(req.Method)
	path := b.CreateByteVector(req.Path)
	version := b.CreateByteVector(req.Version)
	reason := b.CreateByteVector(resp.Reason)
	reqBody := b.CreateByteVector(req.Body)
	respBody := b.CreateByteVector(resp.Body)

	sip := b.CreateString(m.SourceIP)
	dip := b.CreateString(m.DestIP)
	acct := b.CreateString(m.AktoAccountID)
	src := b.CreateString(m.Source)
	ds := b.CreateString(m.DaemonsetID)
	pn := b.CreateString(m.ProcessName)
	tag := b.CreateString(m.Tag)

	FbHttpPairStart(b)
	FbHttpPairAddMethod(b, method)
	FbHttpPairAddPath(b, path)
	FbHttpPairAddVersion(b, version)
	FbHttpPairAddStatusCode(b, int32(resp.StatusCode))
	FbHttpPairAddReason(b, reason)
	FbHttpPairAddReqHeaders(b, reqHdrVec)
	FbHttpPairAddRespHeaders(b, respHdrVec)
	FbHttpPairAddReqBody(b, reqBody)
	FbHttpPairAddRespBody(b, respBody)
	FbHttpPairAddSourceIp(b, sip)
	FbHttpPairAddDestIp(b, dip)
	FbHttpPairAddAktoAccountId(b, acct)
	FbHttpPairAddSource(b, src)
	FbHttpPairAddDaemonsetId(b, ds)
	FbHttpPairAddProcessName(b, pn)
	FbHttpPairAddTag(b, tag)
	FbHttpPairAddTimeUnix(b, m.TimeUnix)
	FbHttpPairAddVxlanId(b, int32(m.VxlanID))
	FbHttpPairAddDirection(b, int32(m.Direction))
	FbHttpPairAddProcessId(b, m.ProcessID)
	FbHttpPairAddSocketId(b, m.SocketID)
	FbHttpPairAddIsPending(b, m.IsPending)
	FbHttpPairAddEnableGraph(b, m.EnableGraph)
	off := FbHttpPairEnd(b)
	b.Finish(off)
	return b.FinishedBytes()
}
