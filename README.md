# Zeek Connection Log Visualizer

A Go-based web application for visualizing Zeek connection log data with interactive network topology and temporal analysis.

## Features

- **Network Graph Visualization**: Interactive force-directed graph showing IP address relationships
- **Timeline Analysis**: Temporal view of connections with brushing for time range selection
- **Protocol Filtering**: Filter connections by protocol (TCP, UDP, ICMP)
- **Node Details**: Click on nodes to see detailed connection information
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Data**: Loads and visualizes actual Zeek conn.log data

## Architecture

- **Backend**: Go web server with REST API
- **Frontend**: HTML + D3.js for interactive visualizations
- **Data Format**: Parses Zeek JSON log format
- **Development**: Uses mise for Go toolchain management

## Quick Start

### Prerequisites

- Go 1.25+ (managed via mise)

### Development Setup

1. Install mise and activate the environment:

```bash
mise trust
mise install
```

2. Build and run the application:

```bash
go mod tidy
task dev
```

3. Open your browser to `http://localhost:8080`

4. Upload your Zeek connection log file through the web interface

### Example Usage

```bash
# Dev server
task dev

# Production build
task build
./zeek-viz
```

### File Upload

The application now accepts Zeek connection log files through a web-based upload interface:

- **Drag and Drop**: Drag your conn.log file directly onto the upload area
- **Browse**: Click the browse button to select a file
- **File Size**: Maximum file size is 50MB
- **Format**: Supports JSON format Zeek connection logs (.log, .json, .txt files)

Once uploaded, the application will automatically parse the data and display the interactive visualizations.

**Browser Reload Support**: If you reload the browser during a session, the application will show any previously uploaded files from the current session, allowing you to continue without re-uploading.

### Multiple Files Support

The application now supports uploading and managing multiple Zeek connection log files:

- **Upload Multiple Files**: Upload additional files using the "Upload Another" button
- **File Switching**: Use the dropdown selector to switch between uploaded files instantly
- **File Management**: Delete files you no longer need (except the last remaining file)
- **Memory Storage**: All files are kept in memory during the session for fast switching
- **Session Persistence**: Files remain available until the application is restarted
- **Reload Recovery**: Browser reload shows existing files with option to continue or upload new ones

#### Reload Behavior

When you reload the browser page:

1. **Existing Files**: Shows a list of previously uploaded files from the current session
2. **File Selection**: Click "Select" to make any file the active one for visualization
3. **Continue Button**: Click "Continue with Files" to proceed to visualization with current file
4. **Upload More**: Option to upload additional files without losing existing ones

This allows you to compare different log files, time periods, or network captures without losing your previous uploads.

## API Endpoints

- `GET /` - Main visualization interface
- `POST /api/upload` - Upload Zeek connection log file
- `GET /api/files` - List all uploaded files with metadata
- `POST /api/switch` - Switch to a different uploaded file
- `POST /api/delete` - Delete an uploaded file
- `GET /api/stats` - Connection statistics summary (for current file)
- `GET /api/nodes` - Network graph nodes and edges (for current file)
- `GET /api/timeline` - Timeline data points (for current file)
- `GET /api/connections` - All connection records (for current file, with optional filtering)
- `GET /health` - Health check endpoint

### API Parameters

#### `/api/connections` and `/api/nodes`

- `start` - Start timestamp (Unix epoch)
- `end` - End timestamp (Unix epoch)
- `protocol` - Protocol filter (tcp, udp, icmp)
- `conn_state` - Connection state filter (SF, S0, S1, S2, S3, REJ, RSTO, RSTR, RSTOS0, RSTRH, SH, SHR, OTH)

Examples:

- `/api/connections?protocol=tcp&start=1755880000&end=1755890000`
- `/api/nodes?conn_state=SF&protocol=tcp`
- `/api/connections?conn_state=S0` (show only failed connection attempts)

## Data Format

The application expects Zeek connection logs in JSON format with fields like:

```json
{
  "ts": 1755880078.180765,
  "uid": "C2lkdh2kp8mgJoF5Th",
  "id.orig_h": "192.168.0.235",
  "id.orig_p": 63936,
  "id.resp_h": "192.168.0.1",
  "id.resp_p": 53,
  "proto": "udp",
  "service": "dns",
  "duration": 0.048789,
  "orig_bytes": 31,
  "resp_bytes": 86,
  "conn_state": "SF"
}
```

## Visualization Features

### Network Graph

- **Nodes**: IP addresses sized by connection count
- **Edges**: Connections colored by protocol, thickness by data volume
- **Colors**: Blue for local IPs, red for external IPs
- **Interactions**: Click to see details, drag to reposition, zoom/pan

### Timeline

- **Bars**: Connection count per time bucket (1-minute intervals)
- **Brush Selection**: Drag to select time range and filter network graph
- **Hover**: Show connection details for time period

### Controls

- **Active File**: Select which uploaded file to visualize
- **Protocol Filter**: Show only TCP, UDP, ICMP, or all protocols
- **Connection State Filter**: Dynamically populated dropdown showing only connection states present in the current log file:
  - Shows descriptive labels for each state (e.g., "SF - Normal Established")
  - Displays connection count for each state (e.g., "SF - Normal Established (156)")
  - Automatically updates when switching between uploaded files
  - Sorted by frequency (most common states appear first)
  - Common states include:
    - **SF**: Normal Established - Successful connection properly closed
    - **S0**: Connection Attempt Rejected - Initial SYN not acknowledged
    - **S1**: Connection Established, Not Terminated - Established but not cleanly closed
    - **OTH**: Other/No Further Info - No additional information available
- **Layout**: Switch between force-directed and circular layouts
- **Reset View**: Clear all filters and selections
- **Refresh Data**: Reload data from current file

## Development

### File Structure

```
/
├── main.go              # Web server entry point
├── mise.toml           # Go toolchain configuration
├── go.mod              # Go module definition
├── handlers/           # HTTP request handlers
│   ├── api.go          # API endpoint handlers
│   └── static.go       # Static file serving
├── models/             # Data structures
│   └── connection.go   # Connection log parsing
├── static/             # Frontend assets
│   ├── index.html      # Main HTML page
│   ├── style.css       # Styling
│   └── main.js         # D3.js visualization logic
└── README.md           # This file
```

### Performance Notes

- Efficiently streams and parses large log files
- In-memory data processing for fast API responses
- D3.js handles interactive visualizations smoothly
- Optimized for datasets with hundreds to thousands of connections

## License

MIT
