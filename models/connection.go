package models

import (
	"encoding/json"
	"time"
)

const (
	nanosPerSecond = 1e9 // Nanoseconds per second
)

// Connection represents a Zeek connection log entry.
type Connection struct {
	Timestamp   float64 `json:"ts"`
	UID         string  `json:"uid"`
	OrigHost    string  `json:"id.orig_h"` //nolint:tagliatelle // Zeek log format
	OrigPort    int     `json:"id.orig_p"` //nolint:tagliatelle // Zeek log format
	RespHost    string  `json:"id.resp_h"` //nolint:tagliatelle // Zeek log format
	RespPort    int     `json:"id.resp_p"` //nolint:tagliatelle // Zeek log format
	Protocol    string  `json:"proto"`
	Service     string  `json:"service,omitempty"`
	Duration    float64 `json:"duration,omitempty"`
	OrigBytes   int     `json:"orig_bytes,omitempty"`   //nolint:tagliatelle // Zeek log format
	RespBytes   int     `json:"resp_bytes,omitempty"`   //nolint:tagliatelle // Zeek log format
	ConnState   string  `json:"conn_state"`             //nolint:tagliatelle // Zeek log format
	LocalOrig   bool    `json:"local_orig,omitempty"`   //nolint:tagliatelle // Zeek log format
	LocalResp   bool    `json:"local_resp,omitempty"`   //nolint:tagliatelle // Zeek log format
	MissedBytes int     `json:"missed_bytes,omitempty"` //nolint:tagliatelle // Zeek log format
	History     string  `json:"history,omitempty"`
	OrigPackets int     `json:"orig_pkts,omitempty"`     //nolint:tagliatelle // Zeek log format
	OrigIPBytes int     `json:"orig_ip_bytes,omitempty"` //nolint:tagliatelle // Zeek log format
	RespPackets int     `json:"resp_pkts,omitempty"`     //nolint:tagliatelle // Zeek log format
	RespIPBytes int     `json:"resp_ip_bytes,omitempty"` //nolint:tagliatelle // Zeek log format
	IPProtocol  int     `json:"ip_proto,omitempty"`      //nolint:tagliatelle // Zeek log format
}

// GetTime returns the timestamp as a time.Time.
func (c *Connection) GetTime() time.Time {
	return time.Unix(int64(c.Timestamp), int64((c.Timestamp-float64(int64(c.Timestamp)))*nanosPerSecond))
}

// TotalBytes returns the sum of orig_bytes and resp_bytes.
func (c *Connection) TotalBytes() int {
	return c.OrigBytes + c.RespBytes
}

// Node represents a network node (IP address) in the graph.
type Node struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Connections int     `json:"connections"`
	TotalBytes  int     `json:"total_bytes"` //nolint:tagliatelle // API consistency
	IsLocal     bool    `json:"is_local"`    //nolint:tagliatelle // API consistency
	X           float64 `json:"x,omitempty"`
	Y           float64 `json:"y,omitempty"`
}

// Edge represents a connection between two nodes.
type Edge struct {
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	Protocol   string  `json:"protocol"`
	Service    string  `json:"service"`
	Count      int     `json:"count"`
	TotalBytes int     `json:"total_bytes"` //nolint:tagliatelle // API consistency
	Weight     float64 `json:"weight"`
}

// TimelinePoint represents a point in the timeline.
type TimelinePoint struct {
	Timestamp   int64        `json:"timestamp"`
	Count       int          `json:"count"`
	Bytes       int          `json:"bytes"`
	Protocol    string       `json:"protocol,omitempty"`
	Connections []Connection `json:"connections,omitempty"`
}

// NetworkGraph represents the complete network visualization data.
type NetworkGraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// TimelineData represents timeline visualization data.
type TimelineData struct {
	Points []TimelinePoint `json:"points"`
	Start  int64           `json:"start"`
	End    int64           `json:"end"`
}

// UnmarshalConnection parses a JSON line into a Connection.
func UnmarshalConnection(data []byte) (*Connection, error) {
	var raw map[string]any
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}

	conn := &Connection{}

	parseStringFields(raw, conn)
	parseIntegerFields(raw, conn)
	parseFloatFields(raw, conn)
	parseBooleanFields(raw, conn)

	return conn, nil
}

// parseStringFields extracts string fields from raw JSON data.
func parseStringFields(raw map[string]any, conn *Connection) {
	if uid, ok := raw["uid"].(string); ok {
		conn.UID = uid
	}
	if origH, ok := raw["id.orig_h"].(string); ok {
		conn.OrigHost = origH
	}
	if respH, ok := raw["id.resp_h"].(string); ok {
		conn.RespHost = respH
	}
	if proto, ok := raw["proto"].(string); ok {
		conn.Protocol = proto
	}
	if service, ok := raw["service"].(string); ok {
		conn.Service = service
	}
	if state, ok := raw["conn_state"].(string); ok {
		conn.ConnState = state
	}
	if history, ok := raw["history"].(string); ok {
		conn.History = history
	}
}

// parseIntegerFields extracts integer and timestamp fields from raw JSON data.
func parseIntegerFields(raw map[string]any, conn *Connection) {
	parseTimestampAndPorts(raw, conn)
	parseByteFields(raw, conn)
	parsePacketFields(raw, conn)
}

// parseTimestampAndPorts extracts timestamp and port fields.
func parseTimestampAndPorts(raw map[string]any, conn *Connection) {
	if ts, ok := raw["ts"].(float64); ok {
		conn.Timestamp = ts
	}
	if origP, ok := raw["id.orig_p"].(float64); ok {
		conn.OrigPort = int(origP)
	}
	if respP, ok := raw["id.resp_p"].(float64); ok {
		conn.RespPort = int(respP)
	}
	if ipProto, ok := raw["ip_proto"].(float64); ok {
		conn.IPProtocol = int(ipProto)
	}
}

// parseByteFields extracts byte-related fields.
func parseByteFields(raw map[string]any, conn *Connection) {
	if origBytes, ok := raw["orig_bytes"].(float64); ok {
		conn.OrigBytes = int(origBytes)
	}
	if respBytes, ok := raw["resp_bytes"].(float64); ok {
		conn.RespBytes = int(respBytes)
	}
	if missedBytes, ok := raw["missed_bytes"].(float64); ok {
		conn.MissedBytes = int(missedBytes)
	}
	if origIPBytes, ok := raw["orig_ip_bytes"].(float64); ok {
		conn.OrigIPBytes = int(origIPBytes)
	}
	if respIPBytes, ok := raw["resp_ip_bytes"].(float64); ok {
		conn.RespIPBytes = int(respIPBytes)
	}
}

// parsePacketFields extracts packet-related fields.
func parsePacketFields(raw map[string]any, conn *Connection) {
	if origPkts, ok := raw["orig_pkts"].(float64); ok {
		conn.OrigPackets = int(origPkts)
	}
	if respPkts, ok := raw["resp_pkts"].(float64); ok {
		conn.RespPackets = int(respPkts)
	}
}

// parseFloatFields extracts float fields from raw JSON data.
func parseFloatFields(raw map[string]any, conn *Connection) {
	if duration, ok := raw["duration"].(float64); ok {
		conn.Duration = duration
	}
}

// parseBooleanFields extracts boolean fields from raw JSON data.
func parseBooleanFields(raw map[string]any, conn *Connection) {
	if localOrig, ok := raw["local_orig"].(bool); ok {
		conn.LocalOrig = localOrig
	}
	if localResp, ok := raw["local_resp"].(bool); ok {
		conn.LocalResp = localResp
	}
}

// IsLocalIP checks if an IP address is in local ranges.
func IsLocalIP(ip string) bool {
	if ip == "" {
		return false
	}

	// Common local IP patterns
	localPrefixes := []string{
		"192.168.",
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"127.",
		"fe80::",
		"::1",
	}

	for _, prefix := range localPrefixes {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}
