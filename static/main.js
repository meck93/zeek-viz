// Zeek Visualization Application
class ZeekVisualizer {
  constructor() {
    this.data = {
      connections: [],
      graph: { nodes: [], edges: [] },
      timeline: { points: [], start: 0, end: 0 },
      stats: {},
    };

    this.filters = {
      protocol: "all",
      connState: "all",
      timeRange: null,
    };

    this.svg = {
      network: null,
      timeline: null,
    };

    this.simulation = null;
    this.brush = null;

    this.init();
  }

  async init() {
    this.setupUI();
    this.setupFileUpload();

    // Check for existing files from current session
    await this.checkExistingFiles();

    this.showVisualizationSections(false);
    this.showLoading(false);
  }

  async loadData() {
    try {
      // Load all data in parallel
      const [statsResponse, graphResponse, timelineResponse] = await Promise.all([
        fetch("/api/stats"),
        fetch("/api/nodes"),
        fetch("/api/timeline"),
      ]);

      this.data.stats = await statsResponse.json();
      this.data.graph = await graphResponse.json();
      this.data.timeline = await timelineResponse.json();

      console.log("Data loaded:", {
        stats: this.data.stats,
        nodes: this.data.graph.nodes.length,
        edges: this.data.graph.edges.length,
        timelinePoints: this.data.timeline.points.length,
      });
    } catch (error) {
      throw new Error("Failed to load data from API: " + error.message);
    }
  }

  setupUI() {
    // File selector
    const fileSelector = document.getElementById("file-selector");
    fileSelector.addEventListener("change", (e) => {
      if (e.target.value) {
        this.switchFile(e.target.value);
      }
    });

    // Upload another file button
    document.getElementById("upload-another").addEventListener("click", () => {
      this.showUploadSection(true);
      this.showVisualizationSections(false);
    });

    // Delete file button
    document.getElementById("delete-file").addEventListener("click", () => {
      this.deleteCurrentFile();
    });

    // Continue with files button
    document.getElementById("continue-with-files").addEventListener("click", () => {
      this.continueWithExistingFiles();
    });

    // Protocol filter
    const protocolFilter = document.getElementById("protocol-filter");
    protocolFilter.addEventListener("change", (e) => {
      this.filters.protocol = e.target.value;
      this.updateVisualizations();
    });

    // Connection state filter
    const connStateFilter = document.getElementById("conn-state-filter");
    connStateFilter.addEventListener("change", (e) => {
      this.filters.connState = e.target.value;
      this.updateVisualizations();
    });

    // Layout selector
    const layoutSelect = document.getElementById("layout-select");
    layoutSelect.addEventListener("change", (e) => {
      this.updateNetworkLayout(e.target.value);
    });

    // Control buttons
    document.getElementById("reset-view").addEventListener("click", () => {
      this.resetView();
    });

    document.getElementById("refresh-data").addEventListener("click", () => {
      this.refresh();
    });

    // Details panel
    document.getElementById("close-details").addEventListener("click", () => {
      this.hideDetails();
    });
  }

  setupFileUpload() {
    const uploadArea = document.getElementById("upload-area");
    const fileInput = document.getElementById("file-input");
    const browseButton = document.getElementById("browse-button");

    // Browse button click
    browseButton.addEventListener("click", () => {
      fileInput.click();
    });

    // Upload area click
    uploadArea.addEventListener("click", (e) => {
      if (e.target !== browseButton) {
        fileInput.click();
      }
    });

    // File input change
    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) {
        this.handleFileUpload(e.target.files[0]);
      }
    });

    // Drag and drop
    uploadArea.addEventListener("dragover", (e) => {
      e.preventDefault();
      uploadArea.classList.add("dragover");
    });

    uploadArea.addEventListener("dragleave", (e) => {
      e.preventDefault();
      uploadArea.classList.remove("dragover");
    });

    uploadArea.addEventListener("drop", (e) => {
      e.preventDefault();
      uploadArea.classList.remove("dragover");

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        this.handleFileUpload(files[0]);
      }
    });
  }

  async handleFileUpload(file) {
    // Validate file size (50MB limit)
    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      alert("File size too large. Maximum size is 50MB.");
      return;
    }

    // Show progress
    this.showUploadProgress(true);
    this.updateUploadProgress(0, "Preparing upload...");

    try {
      const formData = new FormData();
      formData.append("logfile", file);

      // Upload with progress tracking
      const response = await this.uploadWithProgress("/api/upload", formData);

      if (response.success) {
        this.updateUploadProgress(100, `Successfully loaded ${response.connections_count} connections`);

        // Update file list and hide upload section
        setTimeout(() => {
          this.showUploadSection(false);
          this.showVisualizationSections(true);
          this.updateFileSelector();
          this.loadDataAndVisualize();
        }, 1500);
      } else {
        throw new Error(response.message || "Upload failed");
      }
    } catch (error) {
      console.error("Upload failed:", error);
      this.updateUploadProgress(0, "Upload failed: " + error.message);
      this.showUploadProgress(false);
    }
  }

  async uploadWithProgress(url, formData) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) {
          const progress = Math.round((e.loaded / e.total) * 90); // Leave 10% for processing
          this.updateUploadProgress(progress, "Uploading...");
        }
      });

      xhr.addEventListener("load", () => {
        if (xhr.status === 200) {
          try {
            const response = JSON.parse(xhr.responseText);
            resolve(response);
          } catch (e) {
            reject(new Error("Invalid response format"));
          }
        } else {
          reject(new Error(`Upload failed with status ${xhr.status}`));
        }
      });

      xhr.addEventListener("error", () => {
        reject(new Error("Network error during upload"));
      });

      this.updateUploadProgress(5, "Starting upload...");
      xhr.open("POST", url);
      xhr.send(formData);
    });
  }

  async loadDataAndVisualize() {
    this.showLoading(true);

    try {
      await this.loadData();
      await this.createNetworkVisualization();
      this.createTimelineVisualization();
      this.updateStats();
    } catch (error) {
      console.error("Failed to load data:", error);
      alert("Failed to load visualization data. Please try uploading the file again.");
    } finally {
      this.showLoading(false);
    }
  }

  async createNetworkVisualization() {
    const container = document.getElementById("network-graph");
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Clear existing
    d3.select(container).select("svg").remove();

    // Create SVG
    this.svg.network = d3
      .select(container)
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .call(
        d3.zoom().on("zoom", (event) => {
          this.svg.network.select(".graph-container").attr("transform", event.transform);
        })
      );

    const g = this.svg.network.append("g").attr("class", "graph-container");

    // Create force simulation
    this.simulation = d3
      .forceSimulation()
      .force(
        "link",
        d3
          .forceLink()
          .id((d) => d.id)
          .distance(100)
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(20));

    await this.updateNetworkVisualization(g);
  }

  async updateNetworkVisualization(g) {
    if (!g) g = this.svg.network.select(".graph-container");

    const { nodes, edges } = await this.getFilteredGraphData();

    // Update links
    const link = g.selectAll(".link").data(edges, (d) => `${d.source}-${d.target}-${d.protocol}`);

    link.exit().remove();

    const linkEnter = link
      .enter()
      .append("line")
      .attr("class", (d) => `link ${d.protocol}`)
      .attr("stroke-width", (d) => Math.max(1, Math.min(5, d.weight / 100)));

    link.merge(linkEnter);

    // Update nodes
    const node = g.selectAll(".node").data(nodes, (d) => d.id);

    node.exit().remove();

    const nodeEnter = node
      .enter()
      .append("circle")
      .attr("class", (d) => `node ${d.is_local ? "local" : "external"}`)
      .attr("r", (d) => Math.max(8, Math.min(25, Math.sqrt(d.connections) * 3)))
      .call(this.dragHandler())
      .on("click", (event, d) => this.showNodeDetails(d))
      .on("mouseover", (event, d) => this.showTooltip(event, d))
      .on("mouseout", () => this.hideTooltip());

    node.merge(nodeEnter);

    // Add labels
    const label = g.selectAll(".node-label").data(nodes, (d) => d.id);

    label.exit().remove();

    const labelEnter = label
      .enter()
      .append("text")
      .attr("class", "node-label")
      .text((d) => this.formatNodeLabel(d.label));

    label.merge(labelEnter);

    // Update simulation
    this.simulation.nodes(nodes);
    this.simulation.force("link").links(edges);

    this.simulation.on("tick", () => {
      g.selectAll(".link")
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      g.selectAll(".node")
        .attr("cx", (d) => d.x)
        .attr("cy", (d) => d.y);

      g.selectAll(".node-label")
        .attr("x", (d) => d.x)
        .attr("y", (d) => d.y + 4);
    });

    this.simulation.alpha(1).restart();
  }

  createTimelineVisualization() {
    const container = document.getElementById("timeline");
    const margin = { top: 20, right: 30, bottom: 40, left: 50 };
    const width = container.clientWidth - margin.left - margin.right;
    const height = container.clientHeight - margin.top - margin.bottom;

    // Clear existing
    d3.select(container).select("svg").remove();

    // Create SVG
    this.svg.timeline = d3
      .select(container)
      .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom);

    const g = this.svg.timeline.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    this.updateTimelineVisualization(g, width, height);
  }

  updateTimelineVisualization(g, width, height) {
    const points = this.data.timeline.points;

    if (points.length === 0) return;

    // Scales
    const xScale = d3
      .scaleTime()
      .domain(d3.extent(points, (d) => new Date(d.timestamp * 1000)))
      .range([0, width]);

    const yScale = d3
      .scaleLinear()
      .domain([0, d3.max(points, (d) => d.count)])
      .range([height, 0]);

    // Clear existing
    g.selectAll("*").remove();

    // Bars
    g.selectAll(".timeline-bar")
      .data(points)
      .enter()
      .append("rect")
      .attr("class", "timeline-bar")
      .attr("x", (d) => xScale(new Date(d.timestamp * 1000)))
      .attr("y", (d) => yScale(d.count))
      .attr("width", (width / points.length) * 0.8)
      .attr("height", (d) => height - yScale(d.count))
      .on("mouseover", (event, d) => this.showTimelineTooltip(event, d))
      .on("mouseout", () => this.hideTooltip());

    // Axes
    g.append("g")
      .attr("class", "axis")
      .attr("transform", `translate(0,${height})`)
      .call(d3.axisBottom(xScale).tickFormat(d3.timeFormat("%H:%M")));

    g.append("g").attr("class", "axis").call(d3.axisLeft(yScale));

    // Brush for time range selection
    this.brush = d3
      .brushX()
      .extent([
        [0, 0],
        [width, height],
      ])
      .on("brush end", (event) => this.onBrushChange(event, xScale));

    g.append("g").attr("class", "brush").call(this.brush);
  }

  async getFilteredGraphData() {
    // If we have active filters, we need to fetch filtered data from the API
    if (this.filters.protocol !== "all" || this.filters.connState !== "all" || this.filters.timeRange) {
      try {
        const params = new URLSearchParams();
        if (this.filters.protocol !== "all") {
          params.set("protocol", this.filters.protocol);
        }
        if (this.filters.connState !== "all") {
          params.set("conn_state", this.filters.connState);
        }
        if (this.filters.timeRange) {
          params.set("start", Math.floor(this.filters.timeRange[0].getTime() / 1000));
          params.set("end", Math.floor(this.filters.timeRange[1].getTime() / 1000));
        }

        const response = await fetch(`/api/nodes?${params}`);
        const filteredGraph = await response.json();
        return filteredGraph;
      } catch (error) {
        console.error("Failed to get filtered data:", error);
        // Fall back to unfiltered data
        return this.data.graph;
      }
    }

    return this.data.graph;
  }

  async updateNetworkLayout(layout) {
    if (!this.simulation) return;

    const { nodes } = await this.getFilteredGraphData();
    const width = document.getElementById("network-graph").clientWidth;
    const height = document.getElementById("network-graph").clientHeight;

    if (layout === "circular") {
      const radius = Math.min(width, height) / 3;
      const angleStep = (2 * Math.PI) / nodes.length;

      nodes.forEach((node, i) => {
        node.fx = width / 2 + radius * Math.cos(i * angleStep);
        node.fy = height / 2 + radius * Math.sin(i * angleStep);
      });
    } else {
      // Remove fixed positions for force-directed layout
      nodes.forEach((node) => {
        node.fx = null;
        node.fy = null;
      });
    }

    this.simulation.alpha(1).restart();
  }

  onBrushChange(event, xScale) {
    if (!event.selection) {
      this.filters.timeRange = null;
      document.getElementById("timeline-selection").textContent = "Select a time range to filter connections";
    } else {
      const [x0, x1] = event.selection;
      const timeRange = [xScale.invert(x0), xScale.invert(x1)];
      this.filters.timeRange = timeRange;

      document.getElementById("timeline-selection").textContent = `Selected: ${d3.timeFormat("%H:%M:%S")(
        timeRange[0]
      )} - ${d3.timeFormat("%H:%M:%S")(timeRange[1])}`;
    }

    // Update network visualization with time filter
    this.updateNetworkVisualization();
  }

  dragHandler() {
    return d3
      .drag()
      .on("start", (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0);
        // Keep node fixed after dragging
        // d.fx = null;
        // d.fy = null;
      });
  }

  showNodeDetails(node) {
    const panel = document.getElementById("details-panel");
    const content = document.getElementById("details-content");

    // Find connections for this node
    const nodeConnections = this.data.connections.filter(
      (conn) => conn.orig_host === node.id || conn.resp_host === node.id
    );

    content.innerHTML = `
            <div class="detail-group">
                <h4>Node Information</h4>
                <div class="detail-item">
                    <span class="detail-label">IP Address:</span>
                    <span class="detail-value">${node.label}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value">${node.is_local ? "Local" : "External"}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Total Connections:</span>
                    <span class="detail-value">${node.connections}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Total Bytes:</span>
                    <span class="detail-value">${this.formatBytes(node.total_bytes)}</span>
                </div>
            </div>
            
            <div class="detail-group">
                <h4>Connection Summary</h4>
                <div class="detail-item">
                    <span class="detail-label">As Source:</span>
                    <span class="detail-value">${nodeConnections.filter((c) => c.orig_host === node.id).length}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">As Destination:</span>
                    <span class="detail-value">${nodeConnections.filter((c) => c.resp_host === node.id).length}</span>
                </div>
            </div>
        `;

    panel.classList.remove("hidden");
  }

  hideDetails() {
    document.getElementById("details-panel").classList.add("hidden");
  }

  showTooltip(event, data) {
    // Simple tooltip implementation
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "tooltip")
      .style("position", "absolute")
      .style("background", "rgba(0,0,0,0.8)")
      .style("color", "white")
      .style("padding", "8px")
      .style("border-radius", "4px")
      .style("font-size", "12px")
      .style("pointer-events", "none")
      .style("z-index", "1000");

    tooltip
      .html(
        `
            <strong>${data.label}</strong><br/>
            Connections: ${data.connections}<br/>
            Bytes: ${this.formatBytes(data.total_bytes)}
        `
      )
      .style("left", event.pageX + 10 + "px")
      .style("top", event.pageY - 10 + "px");
  }

  showTimelineTooltip(event, data) {
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "tooltip")
      .style("position", "absolute")
      .style("background", "rgba(0,0,0,0.8)")
      .style("color", "white")
      .style("padding", "8px")
      .style("border-radius", "4px")
      .style("font-size", "12px")
      .style("pointer-events", "none")
      .style("z-index", "1000");

    const time = new Date(data.timestamp * 1000);
    tooltip
      .html(
        `
            <strong>${d3.timeFormat("%H:%M:%S")(time)}</strong><br/>
            Connections: ${data.count}<br/>
            Bytes: ${this.formatBytes(data.bytes)}
        `
      )
      .style("left", event.pageX + 10 + "px")
      .style("top", event.pageY - 10 + "px");
  }

  hideTooltip() {
    d3.selectAll(".tooltip").remove();
  }

  updateStats() {
    const stats = this.data.stats;
    const summary = document.getElementById("stats-summary");

    summary.innerHTML = `
            ${stats.total_connections} connections • 
            ${stats.unique_ip_count} unique IPs • 
            ${this.formatBytes(stats.total_bytes)} total data • 
            ${Object.keys(stats.protocols).join(", ")} protocols
        `;

    // Update connection state dropdown with available states
    this.updateConnectionStateDropdown(stats.available_conn_states || []);
  }

  updateConnectionStateDropdown(availableStates) {
    const dropdown = document.getElementById("conn-state-filter");
    const currentValue = dropdown.value;

    // Clear existing options except "All States"
    dropdown.innerHTML = '<option value="all">All States</option>';

    // Add options for available states
    availableStates.forEach((state) => {
      const option = document.createElement("option");
      option.value = state.code;
      option.textContent = `${state.code} - ${state.description} (${state.count})`;
      dropdown.appendChild(option);
    });

    // Restore previous selection if it still exists
    if (currentValue !== "all") {
      const optionExists = availableStates.some((state) => state.code === currentValue);
      if (optionExists) {
        dropdown.value = currentValue;
      } else {
        // Reset filter if previously selected state no longer exists
        this.filters.connState = "all";
        dropdown.value = "all";
      }
    }
  }

  async updateVisualizations() {
    if (this.svg.network) {
      await this.updateNetworkVisualization();
    }
  }

  resetView() {
    // Reset filters
    this.filters.protocol = "all";
    this.filters.connState = "all";
    this.filters.timeRange = null;

    // Reset UI
    document.getElementById("protocol-filter").value = "all";
    document.getElementById("conn-state-filter").value = "all";
    document.getElementById("timeline-selection").textContent = "Select a time range to filter connections";

    // Clear brush
    if (this.brush) {
      this.svg.timeline.select(".brush").call(this.brush.clear);
    }

    // Update visualizations
    this.updateVisualizations();
  }

  async refresh() {
    this.showLoading(true);
    try {
      await this.loadData();
      this.updateVisualizations();
      this.updateStats();
    } catch (error) {
      console.error("Failed to refresh:", error);
      alert("Failed to refresh data");
    } finally {
      this.showLoading(false);
    }
  }

  showLoading(show) {
    document.getElementById("loading").classList.toggle("hidden", !show);
  }

  showUploadSection(show) {
    document.getElementById("upload-section").classList.toggle("hidden", !show);
  }

  showVisualizationSections(show) {
    document.querySelector(".controls").classList.toggle("hidden", !show);
    document.querySelector(".visualization-container").classList.toggle("hidden", !show);
  }

  showUploadProgress(show) {
    document.getElementById("upload-progress").style.display = show ? "block" : "none";
  }

  updateUploadProgress(progress, status) {
    document.getElementById("progress-fill").style.width = progress + "%";
    document.getElementById("upload-status").textContent = status;
  }

  async updateFileSelector() {
    try {
      const response = await fetch("/api/files");
      const data = await response.json();

      const selector = document.getElementById("file-selector");
      const deleteButton = document.getElementById("delete-file");

      // Clear existing options
      selector.innerHTML = "";

      if (data.files && data.files.length > 0) {
        data.files.forEach((file) => {
          const option = document.createElement("option");
          option.value = file.id;
          option.textContent = `${file.filename} (${this.formatBytes(file.size)}, ${
            file.connection_count
          } connections)`;
          if (file.is_current) {
            option.selected = true;
          }
          selector.appendChild(option);
        });

        // Enable delete button only if there are multiple files
        deleteButton.disabled = data.files.length <= 1;
      } else {
        selector.innerHTML = '<option value="">No files loaded</option>';
        deleteButton.disabled = true;
      }
    } catch (error) {
      console.error("Failed to update file selector:", error);
    }
  }

  async switchFile(fileId) {
    this.showLoading(true);

    try {
      const response = await fetch("/api/switch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ file_id: fileId }),
      });

      const result = await response.json();

      if (result.success) {
        console.log("Switched to file:", result.filename);
        await this.loadDataAndVisualize();
        this.resetView(); // Reset any filters when switching files
      } else {
        throw new Error(result.message || "Failed to switch file");
      }
    } catch (error) {
      console.error("Failed to switch file:", error);
      alert("Failed to switch file: " + error.message);
    } finally {
      this.showLoading(false);
    }
  }

  async deleteCurrentFile() {
    const selector = document.getElementById("file-selector");
    const currentFileId = selector.value;

    if (!currentFileId) {
      alert("No file selected to delete");
      return;
    }

    const currentFileName = selector.options[selector.selectedIndex].textContent;

    if (!confirm(`Are you sure you want to delete "${currentFileName}"?`)) {
      return;
    }

    this.showLoading(true);

    try {
      const response = await fetch("/api/delete", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ file_id: currentFileId }),
      });

      const result = await response.json();

      if (result.success) {
        console.log("Deleted file:", result.message);
        await this.updateFileSelector();

        // If there are remaining files, load the new current file
        if (result.current_file) {
          await this.loadDataAndVisualize();
        } else {
          // No files left, show upload section
          this.showVisualizationSections(false);
          this.showUploadSection(true);
        }
      } else {
        throw new Error(result.message || "Failed to delete file");
      }
    } catch (error) {
      console.error("Failed to delete file:", error);
      alert("Failed to delete file: " + error.message);
    } finally {
      this.showLoading(false);
    }
  }

  async checkExistingFiles() {
    try {
      const response = await fetch("/api/files");
      const data = await response.json();

      if (data.files && data.files.length > 0) {
        // There are existing files, show them in the upload section
        this.populateExistingFilesList(data.files, data.current_file);
        document.getElementById("existing-files").style.display = "block";

        // Update the upload title to indicate additional files can be uploaded
        document.getElementById("upload-title").textContent = "Upload Additional File";

        // If there's a current file, we could automatically continue
        // but let the user choose to be explicit about the action
      }
    } catch (error) {
      console.error("Failed to check existing files:", error);
      // Continue with normal upload flow if can't check existing files
    }
  }

  populateExistingFilesList(files, currentFileId) {
    const filesList = document.getElementById("files-list");
    filesList.innerHTML = "";

    files.forEach((file) => {
      const fileItem = document.createElement("div");
      fileItem.className = "file-item";

      const uploadDate = new Date(file.upload_time * 1000).toLocaleString();

      fileItem.innerHTML = `
                <div class="file-info">
                    <div class="file-name">${file.filename}</div>
                    <div class="file-details">
                        ${this.formatBytes(file.size)} • ${file.connection_count} connections • 
                        Uploaded: ${uploadDate}
                        ${file.is_current ? " (Currently Active)" : ""}
                    </div>
                </div>
                <div class="file-actions">
                    <button class="file-select-btn ${file.is_current ? "current" : ""}" 
                            data-file-id="${file.id}">
                        ${file.is_current ? "Current" : "Select"}
                    </button>
                </div>
            `;

      // Add click handler for file selection
      const selectBtn = fileItem.querySelector(".file-select-btn");
      selectBtn.addEventListener("click", () => {
        if (!file.is_current) {
          this.selectExistingFile(file.id, file.filename);
        }
      });

      filesList.appendChild(fileItem);
    });
  }

  async selectExistingFile(fileId, filename) {
    this.showLoading(true);

    try {
      const response = await fetch("/api/switch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ file_id: fileId }),
      });

      const result = await response.json();

      if (result.success) {
        console.log("Selected existing file:", filename);

        // Update the files list to reflect new current file
        await this.checkExistingFiles();

        // Update header message
        document.querySelector(
          "#stats-summary"
        ).textContent = `Selected: ${filename} (${result.connections_count} connections)`;
      } else {
        throw new Error(result.message || "Failed to select file");
      }
    } catch (error) {
      console.error("Failed to select existing file:", error);
      alert("Failed to select file: " + error.message);
    } finally {
      this.showLoading(false);
    }
  }

  async continueWithExistingFiles() {
    // Find the current file and proceed to visualization
    try {
      const response = await fetch("/api/files");
      const data = await response.json();

      if (data.current_file && data.files.length > 0) {
        // Hide upload section and show visualization
        this.showUploadSection(false);
        this.showVisualizationSections(true);

        // Load and visualize data
        await this.updateFileSelector();
        await this.loadDataAndVisualize();
      } else {
        alert("No current file selected. Please select a file first.");
      }
    } catch (error) {
      console.error("Failed to continue with existing files:", error);
      alert("Failed to load existing files");
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  formatNodeLabel(label) {
    // Truncate long IPs for display
    return label.length > 15 ? label.substring(0, 12) + "..." : label;
  }
}

// Initialize application when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  window.zeekViz = new ZeekVisualizer();
});

// Handle window resize
window.addEventListener("resize", () => {
  if (window.zeekViz) {
    // Recreate visualizations on resize
    setTimeout(async () => {
      await window.zeekViz.createNetworkVisualization();
      window.zeekViz.createTimelineVisualization();
    }, 100);
  }
});
