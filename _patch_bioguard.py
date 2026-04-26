from pathlib import Path

html = Path("bioguard_platform.html").read_text(encoding="utf-8")

# Inject live data loader before </script> close
live_js = """
// ══════════ LIVE SERVER CONNECTION ══════════════════════════════════════
const SERVER = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? `ws://${window.location.host}/ws`
  : null;

async function loadLiveStats() {
  try {
    const res  = await fetch('/api/bioguard');
    const data = await res.json();
    // Update stat strip
    const vals = document.querySelectorAll('.stat-value');
    if (vals[0]) vals[0].textContent = data.tco2_fraud.toLocaleString();
    if (vals[1]) vals[1].textContent = data.confirmed_violations;
    if (vals[2]) vals[2].textContent = data.flagged_actors;
    if (vals[3]) vals[3].textContent = data.blocks_on_chain;
    if (vals[4]) vals[4].textContent = data.aerial_zones;
    // Update threat counter
    const counter = document.querySelector('.threat-counter');
    if (counter && data.flagged_actors) {
      counter.innerHTML = `<span class="blink">●</span> ${data.flagged_actors + data.confirmed_violations} ACTIVE THREATS`;
    }
    console.log('[BIOGUARD] Live stats loaded:', data.blocks_on_chain, 'blocks');
  } catch(e) {
    console.log('[BIOGUARD] Server offline — using static data');
  }
}

function connectWebSocket() {
  if (!SERVER) return;
  const ws = new WebSocket(SERVER);
  ws.onopen = () => {
    console.log('[BIOGUARD] WebSocket connected');
    document.querySelector('.threat-counter').style.borderColor = '#27ae60';
  };
  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'scan_complete' || msg.type === 'new_block') {
        loadLiveStats();
        showToast('NEW BLOCK CERTIFIED — CHAIN UPDATED');
      }
    } catch(e) {}
  };
  ws.onclose = () => setTimeout(connectWebSocket, 5000);
}

// Boot live connection
window.addEventListener('load', () => {
  loadLiveStats();
  connectWebSocket();
  setInterval(loadLiveStats, 30000); // refresh every 30s
});
"""

# Inject before closing </script>
html = html.replace("</script>\n</body>", live_js + "\n</script>\n</body>")
Path("bioguard_platform.html").write_text(html, encoding="utf-8")
print("Patched:", Path("bioguard_platform.html").stat().st_size, "bytes")
