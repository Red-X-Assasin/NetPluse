const interfaceSelect = document.getElementById('interfaceSelect');
const filterInput = document.getElementById('filterInput');
const startButton = document.getElementById('startButton');
const stopButton = document.getElementById('stopButton');
const refreshButton = document.getElementById('refreshButton');
const exportJsonButton = document.getElementById('exportJsonButton');
const exportCsvButton = document.getElementById('exportCsvButton');
const exportPcapButton = document.getElementById('exportPcapButton');
const packetFeed = document.getElementById('packetFeed');
const statusBadge = document.getElementById('statusBadge');
const statsPanel = document.getElementById('statsPanel');
const detailPanel = document.getElementById('detailPanel');

let selectedPacket = null;
let packets = [];

async function loadInterfaces() {
  const response = await fetch('/api/interfaces');
  const data = await response.json();
  interfaceSelect.innerHTML = '';
  data.interfaces.forEach((item) => {
    const option = document.createElement('option');
    option.value = item.value;
    option.textContent = item.name;
    interfaceSelect.appendChild(option);
  });
}

async function refreshPackets() {
  const params = new URLSearchParams();
  const filterValue = filterInput.value.trim();
  if (filterValue) params.set('search', filterValue);
  params.set('limit', '200');

  const response = await fetch(`/api/packets?${params.toString()}`);
  const data = await response.json();
  packets = data.packets;
  renderPackets();
}

async function refreshStats() {
  const response = await fetch('/api/stats');
  const data = await response.json();
  statsPanel.innerHTML = `
    <div class="stat-line"><span>Packets</span><strong>${data.packet_count}</strong></div>
    <div class="stat-list">
      ${data.protocol_breakdown.slice(0, 6).map((item) => `<div class="stat-line"><span>${item.name}</span><strong>${item.count}</strong></div>`).join('')}
    </div>
    <div class="stat-list">
      ${data.top_talkers.map((item) => `<div class="stat-line"><span>${item.ip}</span><strong>${item.count}</strong></div>`).join('')}
    </div>
  `;
}

function renderPackets() {
  if (!packets.length) {
    packetFeed.innerHTML = '<div class="empty-state">No packets captured yet.</div>';
    return;
  }

  packetFeed.innerHTML = packets
    .map((packet) => `
      <button class="packet-row ${selectedPacket?.id === packet.id ? 'selected' : ''}" data-id="${packet.id}">
        <div class="packet-meta">
          <span class="protocol-tag">${packet.protocol}</span>
          <span>${packet.timestamp}</span>
        </div>
        <div class="packet-summary">
          <strong>${packet.source_ip || '—'}:${packet.source_port || '—'} → ${packet.destination_ip || '—'}:${packet.destination_port || '—'}</strong>
          <span>${packet.payload_preview || 'No payload preview'}</span>
        </div>
      </button>
    `)
    .join('');

  packetFeed.querySelectorAll('.packet-row').forEach((row) => {
    row.addEventListener('click', () => {
      const rowId = row.getAttribute('data-id');
      selectedPacket = packets.find((packet) => packet.id === rowId) || null;
      renderPackets();
      renderDetail();
    });
  });
}

async function renderDetail() {
  if (!selectedPacket) {
    detailPanel.innerHTML = '<p class="empty-state">Select a packet to inspect its layers and payload.</p>';
    return;
  }

  const layers = selectedPacket.details?.layers || [];
  detailPanel.innerHTML = `
    <div class="detail-block">
      <h4>${selectedPacket.protocol}</h4>
      <p><strong>Timestamp:</strong> ${selectedPacket.timestamp}</p>
      <p><strong>Size:</strong> ${selectedPacket.packet_size} bytes</p>
      <p><strong>Payload preview:</strong> ${selectedPacket.payload_preview || 'None'}</p>
    </div>
    ${layers.map((layer) => `
      <div class="detail-block">
        <h4>${layer.name}</h4>
        ${Object.entries(layer.fields).map(([key, value]) => `<p><strong>${key}</strong>: ${value}</p>`).join('')}
      </div>
    `).join('')}
    <div class="detail-block">
      <h4>Hex payload</h4>
      <pre>${selectedPacket.payload_hex || 'None'}</pre>
    </div>
  `;
}

async function startCapture() {
  const payload = {
    interface: interfaceSelect.value,
    filter: filterInput.value.trim(),
  };
  const response = await fetch('/api/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  statusBadge.textContent = data.status === 'started' ? 'Capturing' : 'Running';
  statusBadge.className = data.status === 'started' ? 'status-on' : 'status-idle';
  refreshPackets();
}

async function stopCapture() {
  const response = await fetch('/api/stop', { method: 'POST' });
  const data = await response.json();
  statusBadge.textContent = 'Idle';
  statusBadge.className = 'status-idle';
  refreshPackets();
}

function downloadFile(url) {
  window.location.href = url;
}

startButton.addEventListener('click', startCapture);
stopButton.addEventListener('click', stopCapture);
refreshButton.addEventListener('click', async () => {
  await refreshPackets();
  await refreshStats();
});
exportJsonButton.addEventListener('click', () => downloadFile('/api/export/json'));
exportCsvButton.addEventListener('click', () => downloadFile('/api/export/csv'));
exportPcapButton.addEventListener('click', () => downloadFile('/api/export/pcap'));

loadInterfaces();
refreshPackets();
refreshStats();
setInterval(() => {
  refreshPackets();
  refreshStats();
}, 2500);
