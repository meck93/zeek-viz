package handlers

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"zeek-viz/models"
)

const (
	maxUploadSize     = 50 << 20 // 50MB
	timelineBucketSec = 10       // 10 seconds
	bytesScaleFactor  = 1000.0   // Scale factor for visualization
	fileIDLength      = 16       // File ID hash length
	allProtocol       = "all"    // String constant for "all" protocol filter
)

var (
	errFailedToOpenLogFile = errors.New("failed to open log file")
	errErrorReadingData    = errors.New("error reading data")
)

// FileData represents an uploaded file with its connections.
type FileData struct {
	Filename    string              `json:"filename"`
	UploadTime  int64               `json:"upload_time"` //nolint:tagliatelle // API compatibility
	Size        int64               `json:"size"`
	Connections []models.Connection `json:"-"` // Don't include in JSON responses
}

// API handles all API endpoints.
type API struct {
	files         map[string]*FileData // Map of file ID to file data
	currentFileID string               // Currently selected file ID
	logPath       string               // For backward compatibility
}

// NewAPI creates a new API handler.
func NewAPI(logPath string) *API {
	return &API{
		files:   make(map[string]*FileData),
		logPath: logPath,
	}
}

// LoadConnections reads and parses the connection log file.
func (a *API) LoadConnections() error {
	file, err := os.Open(a.logPath)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedToOpenLogFile, err)
	}
	defer file.Close()

	connections, err := a.LoadConnectionsFromReader(file)
	if err != nil {
		return err
	}

	// For backward compatibility, store as a single file
	uploadTime := time.Now().Unix()
	fileID := a.generateFileID(a.logPath, uploadTime)

	fileData := &FileData{
		Filename:    a.logPath,
		UploadTime:  uploadTime,
		Size:        0, // File size not available in this case
		Connections: connections,
	}

	a.files[fileID] = fileData
	a.currentFileID = fileID

	return nil
}

// LoadConnectionsFromReader reads and parses connections from an io.Reader.
func (a *API) LoadConnectionsFromReader(reader io.Reader) ([]models.Connection, error) {
	var connections []models.Connection
	var err error
	var conn *models.Connection
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		conn, err = models.UnmarshalConnection([]byte(line))
		if err != nil {
			log.Printf("Failed to parse connection: %v", err)

			continue
		}

		connections = append(connections, *conn)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errErrorReadingData, err)
	}

	log.Printf("Parsed %d connections", len(connections))

	return connections, nil
}

// UploadFile handles file upload and parses the connection log.
func (a *API) UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	// Parse multipart form data
	err := r.ParseMultipartForm(maxUploadSize)
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)

		return
	}

	// Get the file from form data
	file, header, err := r.FormFile("logfile")
	if err != nil {
		http.Error(w, "Failed to get file from request", http.StatusBadRequest)

		return
	}
	defer file.Close()

	log.Printf("Received file upload: %s (size: %d bytes)", header.Filename, header.Size)

	// Parse connections from uploaded file
	connections, err := a.LoadConnectionsFromReader(file)
	if err != nil {
		log.Printf("Failed to load connections from uploaded file: %v", err)
		http.Error(w, "Failed to parse connection log file", http.StatusBadRequest)

		return
	}

	// Create file data record
	uploadTime := time.Now().Unix()
	fileID := a.generateFileID(header.Filename, uploadTime)

	fileData := &FileData{
		Filename:    header.Filename,
		UploadTime:  uploadTime,
		Size:        header.Size,
		Connections: connections,
	}

	// Store the file data
	a.files[fileID] = fileData
	a.currentFileID = fileID // Make this the current file

	log.Printf("Stored file %s as ID %s with %d connections", header.Filename, fileID, len(connections))

	// Return success response with stats
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"success":           true,
		"message":           fmt.Sprintf("Successfully loaded %d connections from %s", len(connections), header.Filename),
		"connections_count": len(connections),
		"filename":          header.Filename,
		"file_id":           fileID,
		"total_files":       len(a.files),
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetConnections returns all connections with optional filtering.
func (a *API) GetConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters for filtering
	query := r.URL.Query()
	startTime := query.Get("start")
	endTime := query.Get("end")
	protocol := query.Get("protocol")
	connState := query.Get("conn_state")

	filteredConnections := a.getCurrentConnections()
	filteredConnections = applyTimeFilter(filteredConnections, startTime, endTime)
	filteredConnections = applyProtocolFilter(filteredConnections, protocol)
	filteredConnections = applyConnStateFilter(filteredConnections, connState)

	err := json.NewEncoder(w).Encode(filteredConnections)
	if err != nil {
		log.Printf("Failed to encode connections: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetNodes returns network nodes for graph visualization.
func (a *API) GetNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters for filtering (same as GetConnections)
	query := r.URL.Query()
	startTime := query.Get("start")
	endTime := query.Get("end")
	protocol := query.Get("protocol")
	connState := query.Get("conn_state")

	connections := a.getCurrentConnections()
	connections = applyTimeFilter(connections, startTime, endTime)
	connections = applyProtocolFilter(connections, protocol)
	connections = applyConnStateFilter(connections, connState)

	nodes, edges := buildNodesAndEdges(connections)

	graph := models.NetworkGraph{
		Nodes: nodes,
		Edges: edges,
	}

	err := json.NewEncoder(w).Encode(graph)
	if err != nil {
		log.Printf("Failed to encode graph: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetTimeline returns timeline data for temporal visualization.
func (a *API) GetTimeline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	connections := a.getCurrentConnections()
	if len(connections) == 0 {
		err := json.NewEncoder(w).Encode(models.TimelineData{Points: []models.TimelinePoint{}})
		if err != nil {
			log.Printf("Failed to encode timeline data: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		return
	}

	// Sort connections by timestamp
	sortedConns := make([]models.Connection, len(connections))
	copy(sortedConns, connections)
	sort.Slice(sortedConns, func(i, j int) bool {
		return sortedConns[i].Timestamp < sortedConns[j].Timestamp
	})

	startTime := int64(sortedConns[0].Timestamp)
	endTime := int64(sortedConns[len(sortedConns)-1].Timestamp)

	// Create time buckets (better granularity)
	bucketSize := int64(timelineBucketSec) // Time bucket size in seconds
	timelineMap := make(map[int64]*models.TimelinePoint)

	// Populate buckets with connection data directly
	for _, conn := range sortedConns {
		bucket := (int64(conn.Timestamp) / bucketSize) * bucketSize
		if point, exists := timelineMap[bucket]; exists {
			point.Count++
			point.Bytes += conn.TotalBytes()
		} else {
			timelineMap[bucket] = &models.TimelinePoint{
				Timestamp: bucket,
				Count:     1,
				Bytes:     conn.TotalBytes(),
			}
		}
	}

	// Convert map to sorted slice
	points := make([]models.TimelinePoint, 0, len(timelineMap))
	for _, point := range timelineMap {
		points = append(points, *point)
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp < points[j].Timestamp
	})

	timeline := models.TimelineData{
		Points: points,
		Start:  startTime,
		End:    endTime,
	}

	err := json.NewEncoder(w).Encode(timeline)
	if err != nil {
		log.Printf("Failed to encode timeline: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getConnStateDescription returns a human-readable description for connection states.
func getConnStateDescription(state string) string {
	descriptions := map[string]string{
		"SF":     "Normal Established - Successful connection that was properly closed",
		"S0":     "Connection Attempt Rejected - Initial SYN was not acknowledged",
		"S1":     "Connection Established, Not Terminated - Connection established but not cleanly closed",
		"S2":     "Connection Established, Originator Aborted - Connection established but originator aborted",
		"S3":     "Connection Established, Responder Aborted - Connection established but responder aborted",
		"REJ":    "Connection Rejected - Connection attempt was explicitly rejected",
		"RSTO":   "Connection Reset by Originator - Originator sent RST",
		"RSTR":   "Connection Reset by Responder - Responder sent RST",
		"RSTOS0": "Originator Sent SYN+RST - Connection attempt with immediate reset",
		"RSTRH":  "Responder Sent RST after Handshake - Reset after successful handshake",
		"SH":     "Originator Sent SYN+FIN - Unusual SYN+FIN combination",
		"SHR":    "Responder Sent SYN+FIN after SYN - Response with SYN+FIN",
		"OTH":    "Other/No Further Info - No additional information available",
	}

	if desc, exists := descriptions[state]; exists {
		return desc
	}

	return state + " - Unknown connection state"
}

// GetStats returns summary statistics.
func (a *API) GetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	connections := a.getCurrentConnections()
	protocols, services, connStates, uniqueIPs, totalBytes, startTime, endTime := processConnectionStats(connections)

	stats := map[string]any{
		"total_connections": len(connections),
		"protocols":         protocols,
		"services":          services,
		"conn_states":       connStates,
		"total_bytes":       totalBytes,
		"unique_ip_count":   len(uniqueIPs),
		"time_range": map[string]any{
			"start":    startTime,
			"end":      endTime,
			"duration": endTime - startTime,
		},
	}

	stats["available_conn_states"] = buildConnStateDescriptions(connStates)

	// Add file information to stats
	if a.currentFileID != "" && a.files[a.currentFileID] != nil {
		currentFile := a.files[a.currentFileID]
		stats["current_file"] = map[string]any{
			"id":          a.currentFileID,
			"filename":    currentFile.Filename,
			"upload_time": currentFile.UploadTime,
			"size":        currentFile.Size,
		}
	}
	stats["total_files"] = len(a.files)

	err := json.NewEncoder(w).Encode(stats)
	if err != nil {
		log.Printf("Failed to encode stats: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetFiles returns list of all uploaded files.
func (a *API) GetFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type FileInfo struct {
		ID              string `json:"id"`
		Filename        string `json:"filename"`
		UploadTime      int64  `json:"upload_time"` //nolint:tagliatelle // API compatibility
		Size            int64  `json:"size"`
		ConnectionCount int    `json:"connection_count"` //nolint:tagliatelle // API compatibility
		IsCurrent       bool   `json:"is_current"`       //nolint:tagliatelle // API compatibility
	}

	files := make([]FileInfo, 0, len(a.files))
	for fileID, fileData := range a.files {
		files = append(files, FileInfo{
			ID:              fileID,
			Filename:        fileData.Filename,
			UploadTime:      fileData.UploadTime,
			Size:            fileData.Size,
			ConnectionCount: len(fileData.Connections),
			IsCurrent:       fileID == a.currentFileID,
		})
	}

	// Sort by upload time (most recent first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadTime > files[j].UploadTime
	})

	response := map[string]any{
		"files":        files,
		"current_file": a.currentFileID,
		"total_files":  len(files),
	}

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SwitchFile changes the currently active file.
func (a *API) SwitchFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Parse JSON body
	var request struct {
		FileID string `json:"file_id"` //nolint:tagliatelle // API compatibility
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)

		return
	}

	// Validate file ID exists
	if request.FileID == "" {
		http.Error(w, "File ID is required", http.StatusBadRequest)

		return
	}

	if a.files[request.FileID] == nil {
		http.Error(w, "File not found", http.StatusNotFound)

		return
	}

	// Switch to the requested file
	a.currentFileID = request.FileID
	currentFile := a.files[request.FileID]

	log.Printf("Switched to file: %s (ID: %s, %d connections)",
		currentFile.Filename, request.FileID, len(currentFile.Connections))

	response := map[string]any{
		"success":           true,
		"message":           "Switched to " + currentFile.Filename,
		"current_file":      request.FileID,
		"filename":          currentFile.Filename,
		"connections_count": len(currentFile.Connections),
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// DeleteFile removes a file from memory.
func (a *API) DeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Parse JSON body
	var request struct {
		FileID string `json:"file_id"` //nolint:tagliatelle // API compatibility
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)

		return
	}

	// Validate file ID exists
	if request.FileID == "" {
		http.Error(w, "File ID is required", http.StatusBadRequest)

		return
	}

	if a.files[request.FileID] == nil {
		http.Error(w, "File not found", http.StatusNotFound)

		return
	}

	// Don't allow deleting the only file
	if len(a.files) <= 1 {
		http.Error(w, "Cannot delete the only remaining file", http.StatusBadRequest)

		return
	}

	// Get filename before deletion
	filename := a.files[request.FileID].Filename

	// Delete the file
	delete(a.files, request.FileID)

	// If this was the current file, switch to another one
	if a.currentFileID == request.FileID {
		// Find another file to switch to
		for fileID := range a.files {
			a.currentFileID = fileID

			break
		}
	}

	log.Printf("Deleted file: %s (ID: %s)", filename, request.FileID)

	response := map[string]any{
		"success":      true,
		"message":      "Deleted " + filename,
		"current_file": a.currentFileID,
		"total_files":  len(a.files),
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// processNode updates or creates a node in the nodeMap.
func processNode(nodeMap map[string]*models.Node, host string, totalBytes int) {
	if _, exists := nodeMap[host]; !exists {
		nodeMap[host] = &models.Node{
			ID:      host,
			Label:   host,
			IsLocal: models.IsLocalIP(host),
		}
	}
	nodeMap[host].Connections++
	nodeMap[host].TotalBytes += totalBytes
}

// processEdge updates or creates an edge in the edgeMap.
func processEdge(edgeMap map[string]*models.Edge, conn models.Connection) {
	edgeKey := fmt.Sprintf("%s-%s-%s", conn.OrigHost, conn.RespHost, conn.Protocol)

	if _, exists := edgeMap[edgeKey]; !exists {
		edgeMap[edgeKey] = &models.Edge{
			Source:   conn.OrigHost,
			Target:   conn.RespHost,
			Protocol: conn.Protocol,
			Service:  conn.Service,
		}
	}
	edgeMap[edgeKey].Count++
	edgeMap[edgeKey].TotalBytes += conn.TotalBytes()
	edgeMap[edgeKey].Weight = float64(edgeMap[edgeKey].TotalBytes) / bytesScaleFactor
}

// buildNodesAndEdges processes connections to build the network graph data.
func buildNodesAndEdges(connections []models.Connection) ([]models.Node, []models.Edge) {
	nodeMap := make(map[string]*models.Node)
	edgeMap := make(map[string]*models.Edge)

	for _, conn := range connections {
		totalBytes := conn.TotalBytes()
		processNode(nodeMap, conn.OrigHost, totalBytes)
		processNode(nodeMap, conn.RespHost, totalBytes)
		processEdge(edgeMap, conn)
	}

	// Convert maps to slices
	nodes := make([]models.Node, 0, len(nodeMap))
	for _, node := range nodeMap {
		nodes = append(nodes, *node)
	}

	edges := make([]models.Edge, 0, len(edgeMap))
	for _, edge := range edgeMap {
		edges = append(edges, *edge)
	}

	return nodes, edges
}

// processConnectionStats processes connections and calculates statistics.
func processConnectionStats(connections []models.Connection) (
	map[string]int, map[string]int, map[string]int, map[string]bool, int, float64, float64,
) {
	protocols := make(map[string]int)
	services := make(map[string]int)
	connStates := make(map[string]int)
	uniqueIPs := make(map[string]bool)

	var totalBytes int
	var startTime, endTime float64 = -1, -1

	for _, conn := range connections {
		// Protocol distribution
		protocols[conn.Protocol]++

		// Service distribution
		if conn.Service != "" {
			services[conn.Service]++
		}

		// Connection state distribution
		connStates[conn.ConnState]++

		// Unique IPs
		uniqueIPs[conn.OrigHost] = true
		uniqueIPs[conn.RespHost] = true

		// Total bytes
		totalBytes += conn.TotalBytes()

		// Time range
		if startTime == -1 || conn.Timestamp < startTime {
			startTime = conn.Timestamp
		}
		if endTime == -1 || conn.Timestamp > endTime {
			endTime = conn.Timestamp
		}
	}

	return protocols, services, connStates, uniqueIPs, totalBytes, startTime, endTime
}

// buildConnStateDescriptions builds the available connection states with descriptions.
func buildConnStateDescriptions(connStates map[string]int) []map[string]any {
	availableStates := make([]map[string]any, 0)
	for state, count := range connStates {
		availableStates = append(availableStates, map[string]any{
			"code":        state,
			"description": getConnStateDescription(state),
			"count":       count,
		})
	}

	// Sort by count (descending)
	sort.Slice(availableStates, func(i, j int) bool {
		countI, okI := availableStates[i]["count"].(int)
		countJ, okJ := availableStates[j]["count"].(int)
		if !okI || !okJ {
			return false
		}

		return countI > countJ
	})

	return availableStates
}

// generateFileID creates a unique ID for a file based on name and upload time.
func (a *API) generateFileID(filename string, uploadTime int64) string {
	data := fmt.Sprintf("%s_%d", filename, uploadTime)
	hash := sha256.Sum256([]byte(data))

	return hex.EncodeToString(hash[:])[:fileIDLength] // Use first 16 characters
}

// getCurrentConnections returns connections from the currently selected file.
func (a *API) getCurrentConnections() []models.Connection {
	if a.currentFileID == "" || a.files[a.currentFileID] == nil {
		return []models.Connection{}
	}

	return a.files[a.currentFileID].Connections
}

// applyTimeFilter applies time-based filtering to connections.
func applyTimeFilter(connections []models.Connection, startTime, endTime string) []models.Connection {
	if startTime == "" || endTime == "" {
		return connections
	}

	start, err1 := strconv.ParseInt(startTime, 10, 64)
	end, err2 := strconv.ParseInt(endTime, 10, 64)

	if err1 != nil || err2 != nil {
		return connections
	}

	var filtered []models.Connection
	for _, conn := range connections {
		ts := int64(conn.Timestamp)
		if ts >= start && ts <= end {
			filtered = append(filtered, conn)
		}
	}

	return filtered
}

// applyProtocolFilter applies protocol-based filtering to connections.
func applyProtocolFilter(connections []models.Connection, protocol string) []models.Connection {
	if protocol == "" || protocol == allProtocol {
		return connections
	}

	var filtered []models.Connection
	for _, conn := range connections {
		if conn.Protocol == protocol {
			filtered = append(filtered, conn)
		}
	}

	return filtered
}

// applyConnStateFilter applies connection state filtering to connections.
func applyConnStateFilter(connections []models.Connection, connState string) []models.Connection {
	if connState == "" || connState == allProtocol {
		return connections
	}

	var filtered []models.Connection
	for _, conn := range connections {
		if conn.ConnState == connState {
			filtered = append(filtered, conn)
		}
	}

	return filtered
}
