// JSONEncoder encodes parsed HTTP (from httpparser) into the Akto Kafka JSON
// payload — hand-rolled, zero-allocation, single pass. Output is always valid
// JSON: invalid UTF-8 in bodies is replaced with U+FFFD and control chars are
// escaped.
//
// Integration is parse-then-encode (parser and encoder are independent — one of
// each per goroutine):
//
//	p := fastparser.NewFastParser()       // NOT concurrency-safe
//	e := fastparser.NewJSONEncoder()      // NOT concurrency-safe
//	req,  _ := p.ParseRequest(reqBuf)
//	resp, _ := p.ParseResponse(respBuf)
//	out := e.Encode(req, resp, meta)      // Kafka JSON
//	method, path, host := req.Method, req.Path, req.Host()  // already parsed — free
//
// The returned bytes alias the encoder's internal buffer; copy (e.g. string(out))
// before the next Encode on the same encoder.
package fastparser

// JSONEncoder reuses an output buffer across Encode calls. NOT safe for
// concurrent use — one per goroutine.
type JSONEncoder struct {
	scratch []byte
	hdr     []byte // reusable buffer for the inner headers object (see Encode)
}

func NewJSONEncoder() *JSONEncoder {
	return &JSONEncoder{scratch: make([]byte, 0, 8192), hdr: make([]byte, 0, 2048)}
}

// Encode writes the Kafka JSON from already-parsed structs into the encoder's
// reused buffer. Returned bytes are valid until the next Encode on this encoder.
func (e *JSONEncoder) Encode(req *Request, resp *Response, m *Meta) []byte {
	buf := e.scratch[:0]
	buf = append(buf, `{"method":`...)
	buf = appendJSONString(buf, req.Method)
	buf = kv(buf, "path", req.Path)
	buf = kv(buf, "type", req.Version)
	buf = kvStatusCode(buf, resp.StatusCode)
	buf = append(buf, `,"status":`...)
	buf = appendStatus(buf, resp.StatusCode, resp.Reason)
	// requestHeaders/responseHeaders are emitted as a JSON-ENCODED STRING (the
	// headers object serialized, then escaped again), matching the legacy
	// json.Marshal(map[string]string) shape the downstream consumer expects
	// (it does `(String) json.get("requestHeaders")`). The request's Host key is
	// lowercased to "host" to match legacy, which re-adds it as such.
	e.hdr = buildHeadersObject(e.hdr[:0], req.Headers, true)
	buf = append(buf, `,"requestHeaders":`...)
	buf = appendJSONString(buf, e.hdr)
	e.hdr = buildHeadersObject(e.hdr[:0], resp.Headers, false)
	buf = append(buf, `,"responseHeaders":`...)
	buf = appendJSONString(buf, e.hdr)
	buf = kv(buf, "requestPayload", req.Body)
	buf = kv(buf, "responsePayload", resp.Body)
	buf = kvStr(buf, "ip", m.SourceIP)
	buf = kvStr(buf, "destIp", m.DestIP)
	buf = kvInt(buf, "time", m.TimeUnix)
	buf = kvStr(buf, "akto_account_id", m.AktoAccountID)
	buf = kvInt(buf, "akto_vxlan_id", int64(m.VxlanID))
	buf = kvBool(buf, "is_pending", m.IsPending)
	buf = kvStr(buf, "source", m.Source)
	buf = kvInt(buf, "direction", int64(m.Direction))
	buf = kvInt(buf, "process_id", int64(m.ProcessID))
	buf = kvInt(buf, "socket_id", int64(m.SocketID))
	buf = kvStr(buf, "daemonset_id", m.DaemonsetID)
	buf = kvStr(buf, "process_name", m.ProcessName)
	buf = kvBool(buf, "enable_graph", m.EnableGraph)
	if m.Tag != "" {
		buf = kvStr(buf, "tag", m.Tag)
	}
	buf = append(buf, '}')
	e.scratch = buf
	return buf
}
