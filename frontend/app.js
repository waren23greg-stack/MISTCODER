const CHAIN_ROWS = [
  [108,'000982...','EDEN-AC-0002','eco',7.6],
  [107,'000594...','EDEN-AC-0001','eco',6.5],
  [106,'000e3e...','EDEN-NV-0036','eco',5.5],
  [105,'000337...','EDEN-NV-0033','eco',9.2],
  [104,'00027a...','EDEN-NV-0031','eco',8.7],
  [103,'00063c...','EDEN-NV-0025','eco',9.2],
  [102,'0000bc...','EDEN-NV-0016','eco',9.2],
  [101,'000872...','EDEN-NV-0012','eco',9.2],
  [100,'0008e9...','EDEN-NV-0003','eco',6.8],
  [99,'0008e9...','EDEN-NV-0001','eco',8.7],
  [77,'000be9...','UNIFIED-PY-0014','code',8.1],
  [63,'000XXX...','UNIFIED-JA-0003','code',8.4],
  [57,'00004b...','LANG-JS-0001','code',9.0],
  [1,'000f77...','GENESIS','code',0],
];

const TOKENS_STATIC = [
  {id:'EDEN-NV-0025',region:'Rift Valley',event:'Deforestation event',bio:9.2,carbon:64638,area:195,block:95,sev:'critical'},
  {id:'EDEN-NV-0033',region:'Rift Valley',event:'Deforestation event',bio:9.2,carbon:57402,area:174,block:102,sev:'critical'},
  {id:'EDEN-NV-0031',region:'Rift Valley',event:'Illegal clearing',bio:8.7,carbon:27750,area:178,block:100,sev:'critical'},
  {id:'EDEN-NV-0002',region:'Mau Forest',event:'Illegal clearing',bio:8.7,carbon:27376,area:175,block:78,sev:'critical'},
  {id:'EDEN-NV-0032',region:'Rift Valley',event:'Illegal clearing',bio:8.7,carbon:24379,area:156,block:101,sev:'critical'},
  {id:'EDEN-NV-0016',region:'Nairobi Eastlands',event:'Deforestation event',bio:9.2,carbon:13391,area:41,block:90,sev:'critical'},
  {id:'EDEN-NV-0012',region:'Mau Forest',event:'Deforestation event',bio:9.2,carbon:16239,area:49,block:86,sev:'critical'},
  {id:'EDEN-NV-0010',region:'Mau Forest',event:'Habitat fragmentation',bio:7.5,carbon:9363,area:77,block:84,sev:'high'},
  {id:'EDEN-NV-0026',region:'Rift Valley',event:'Vegetation stress',bio:6.8,carbon:3030,area:47,block:96,sev:'high'},
  {id:'EDEN-AC-0002',region:'Rift Valley',event:'Chainsaw + heavy vehicle',bio:7.6,carbon:1028,area:0,block:107,sev:'high'},
  {id:'EDEN-AC-0001',region:'Mau Forest',event:'Human activity + fire',bio:6.5,carbon:857,area:0,block:106,sev:'high'},
  {id:'EDEN-NV-0003',region:'Mau Forest',event:'Vegetation stress',bio:6.8,carbon:1089,area:17,block:79,sev:'high'},
];

function buildChainFeed() {
  const feed = document.getElementById('chain-feed');
  if (!feed) return;
  CHAIN_ROWS.forEach(([idx, hash, fid, type, score]) => {
    const row = document.createElement('div');
    row.className = 'chain-row';
    const dot = type === 'eco'
      ? '<span class="block-type-eco"></span>'
      : '<span class="block-type-code"></span>';
    const scoreClass = score >= 9 ? 'block-score-high' : score >= 7 ? 'block-score-mid' : 'block-score-normal';
    const scoreStr = score > 0 ? score.toFixed(1) : '—';
    row.innerHTML = `
      <span class="block-num">#${idx}</span>
      ${dot}
      <span class="block-hash">${hash}</span>
      <span class="block-id">${fid}</span>
      <span class="${scoreClass}">${scoreStr}</span>
    `;
    feed.appendChild(row);
  });
}

function buildTokenCards() {
  const container = document.getElementById('token-cards');
  if (!container) return;

  const tokens = TOKENS_STATIC;
  tokens.slice(0, 8).forEach(t => {
    const card = document.createElement('div');
    card.className = `token-card ${t.sev}`;
    const carbon = t.carbon ? t.carbon.toLocaleString() + ' tCO₂' : '—';
    const area   = t.area > 0 ? t.area.toFixed(0) + ' ha' : 'acoustic';
    card.innerHTML = `
      <div class="token-header">
        <div class="token-id-label">${t.id}</div>
        <div class="token-block-ref">blk #${t.block}</div>
      </div>
      <div class="token-region-name">${t.region}</div>
      <div class="token-event-type">${t.event}</div>
      <div class="token-metrics">
        <div class="token-metric">
          <div class="token-metric-val ${t.sev === 'critical' ? 'val-fire' : 'val-amber'}">${t.bio.toFixed(1)}</div>
          <div class="token-metric-key">bio score</div>
        </div>
        <div class="token-metric">
          <div class="token-metric-val val-moss">${carbon}</div>
          <div class="token-metric-key">carbon</div>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

async function tryLoadFromFile() {
  try {
    const r = await fetch('../reports/bio_tokens.json');
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

window.addEventListener('DOMContentLoaded', async () => {
  buildChainFeed();
  buildTokenCards();

  const live = await tryLoadFromFile();
  if (live && live.length) {
    console.log(`Loaded ${live.length} live BioTokens from reports/bio_tokens.json`);
  }
});
