/* ════════════════════════════════════════════════════════════
   SQLiShield — Frontend Logic
   Features: Detection, Voice Input, History, Patterns, Stats
   ════════════════════════════════════════════════════════════ */

'use strict';

// ── Pattern metadata (mirrors backend, for Pattern Library tab) ──────────────
const PATTERN_LIBRARY = [
  // Classic
  { name: "Classic Auth Bypass (OR/AND tautology)", severity: "CRITICAL", category: "Auth Bypass" },
  { name: "Admin comment bypass",                    severity: "CRITICAL", category: "Auth Bypass" },
  { name: "String tautology bypass",                 severity: "CRITICAL", category: "Auth Bypass" },
  { name: "Tautology (OR 1=1)",                      severity: "CRITICAL", category: "Auth Bypass" },
  { name: "Tautology (AND 1=1)",                     severity: "HIGH",     category: "Auth Bypass" },
  // UNION
  { name: "UNION SELECT injection",                  severity: "CRITICAL", category: "UNION-Based" },
  { name: "UNION SELECT NULL enumeration",           severity: "CRITICAL", category: "UNION-Based" },
  // Stacked
  { name: "DROP TABLE/DATABASE",                     severity: "CRITICAL", category: "Stacked Queries" },
  { name: "Stacked INSERT query",                    severity: "CRITICAL", category: "Stacked Queries" },
  { name: "Stacked UPDATE query",                    severity: "CRITICAL", category: "Stacked Queries" },
  { name: "Stacked DELETE query",                    severity: "CRITICAL", category: "Stacked Queries" },
  { name: "xp_cmdshell execution",                   severity: "CRITICAL", category: "Stacked Queries" },
  // Comments
  { name: "SQL comment (--)",                        severity: "HIGH",     category: "Comment Injection" },
  { name: "MySQL comment (#)",                       severity: "HIGH",     category: "Comment Injection" },
  { name: "Block comment (/* */)",                   severity: "MEDIUM",   category: "Comment Injection" },
  // Time-Based
  { name: "Time-based blind (SLEEP)",                severity: "CRITICAL", category: "Time-Based Blind" },
  { name: "Time-based blind (BENCHMARK)",            severity: "CRITICAL", category: "Time-Based Blind" },
  { name: "Time-based blind (WAITFOR DELAY)",        severity: "CRITICAL", category: "Time-Based Blind" },
  { name: "Time-based blind (pg_sleep)",             severity: "CRITICAL", category: "Time-Based Blind" },
  // Error-Based
  { name: "Error-based (ExtractValue)",              severity: "CRITICAL", category: "Error-Based" },
  { name: "Error-based (UpdateXML)",                 severity: "CRITICAL", category: "Error-Based" },
  { name: "Error-based (EXP overflow)",              severity: "HIGH",     category: "Error-Based" },
  { name: "Error-based (FLOOR+RAND)",                severity: "HIGH",     category: "Error-Based" },
  // Boolean-Based
  { name: "Boolean-based blind subquery",            severity: "HIGH",     category: "Boolean Blind" },
  { name: "CASE WHEN blind",                         severity: "HIGH",     category: "Boolean Blind" },
  { name: "IF() blind injection",                    severity: "HIGH",     category: "Boolean Blind" },
  // Out-of-Band / Advanced
  { name: "File read (LOAD_FILE)",                   severity: "CRITICAL", category: "Out-of-Band" },
  { name: "File write (INTO OUTFILE)",               severity: "CRITICAL", category: "Out-of-Band" },
  { name: "Schema enumeration",                      severity: "HIGH",     category: "Enumeration" },
  { name: "System table enumeration",                severity: "HIGH",     category: "Enumeration" },
  { name: "CHAR() encoding obfuscation",             severity: "MEDIUM",   category: "Obfuscation" },
  { name: "Hex encoding obfuscation",                severity: "MEDIUM",   category: "Obfuscation" },
  { name: "CONCAT() function",                       severity: "MEDIUM",   category: "Obfuscation" },
  { name: "GROUP_CONCAT enumeration",                severity: "HIGH",     category: "Enumeration" },
  { name: "HAVING clause injection",                 severity: "HIGH",     category: "Advanced" },
  { name: "ORDER BY column enumeration",             severity: "HIGH",     category: "Advanced" },
];

const SEV_COLOR = { CRITICAL: "red", HIGH: "orange", MEDIUM: "yellow", LOW: "green" };

// ── DOM Refs ─────────────────────────────────────────────────────────────────
const payloadInput   = document.getElementById('payload-input');
const scanBtn        = document.getElementById('scan-btn');
const clearBtn       = document.getElementById('clear-btn');
const voiceBtn       = document.getElementById('voice-btn');
// (voice-status / voice-text replaced by voice-strip + vm-* modal elements)
const resultCard     = document.getElementById('result-card');
const resultVerdict  = document.getElementById('result-verdict');
const resultScore    = document.getElementById('result-score');
const gaugeArc       = document.getElementById('gauge-arc');
const hitsSection    = document.getElementById('hits-section');
const payloadHL      = document.getElementById('payload-highlight');
const historyTbody   = document.getElementById('history-tbody');
const clearHistoryBtn= document.getElementById('clear-history');
const patternsGrid   = document.getElementById('patterns-grid');

// ── Stats ─────────────────────────────────────────────────────────────────────
const sTotal     = document.getElementById('s-total');
const sDanger    = document.getElementById('s-danger');
const sSuspicious= document.getElementById('s-suspicious');
const sSafe      = document.getElementById('s-safe');

// ── Scan ─────────────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', runScan);
payloadInput.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') runScan();
});

async function runScan() {
  const payload = payloadInput.value.trim();
  if (!payload) {
    flashInput();
    return;
  }
  scanBtn.classList.add('loading');
  scanBtn.querySelector('span:last-child').textContent = 'SCANNING…';

  try {
    const res  = await fetch('/api/detect', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ payload }),
    });
    const data = await res.json();
    renderResult(data);
    fetchStats();
    fetchHistory();
  } catch (err) {
    console.error('Scan error:', err);
    alert('Connection error — is the Flask server running?');
  } finally {
    scanBtn.classList.remove('loading');
    scanBtn.querySelector('span:last-child').textContent = 'ANALYSE PAYLOAD';
  }
}

// ── Render Result ─────────────────────────────────────────────────────────────
function renderResult(d) {
  resultCard.classList.remove('hidden', 'danger', 'orange', 'yellow', 'safe-c');

  const colorMap = { red: 'danger', orange: 'orange', yellow: 'yellow', green: 'safe-c' };
  resultCard.classList.add(colorMap[d.color] || 'safe-c');

  // Verdict
  const icons = { DANGEROUS: '⛔', SUSPICIOUS: '⚠️', WARNING: '🔶', SAFE: '✅' };
  resultVerdict.textContent = `${icons[d.verdict] || ''} ${d.verdict}`;

  // Score
  resultScore.textContent = d.risk_score.toFixed(2);

  // Gauge arc: full arc = ~157 (semicircle)
  const offset = 157 - (d.risk_score * 157);
  gaugeArc.setAttribute('stroke-dashoffset', offset.toFixed(1));
  const gaugeColors = { red: '#ff2d55', orange: '#ff8c00', yellow: '#ffd200', green: '#00ff88' };
  gaugeArc.setAttribute('stroke', gaugeColors[d.color] || '#00ff88');

  // Rule hits
  hitsSection.innerHTML = '';
  if (d.hits && d.hits.length > 0) {
    const heading = document.createElement('div');
    heading.style.cssText = 'font-family:var(--font-mono);font-size:.7rem;color:var(--text-dim);letter-spacing:1.5px;margin-bottom:6px';
    heading.textContent = `DETECTED PATTERNS (${d.hits.length})`;
    hitsSection.appendChild(heading);

    d.hits.forEach((h, i) => {
      const el = document.createElement('div');
      el.className = `hit-item hit-${h.severity}`;
      el.style.animationDelay = `${i * 60}ms`;
      el.innerHTML = `
        <span class="hit-badge badge-${h.severity}">${h.severity}</span>
        <div>
          <div class="hit-name">${esc(h.rule)}</div>
          <div class="hit-matched">Matched: <code>${esc(h.matched)}</code></div>
        </div>`;
      hitsSection.appendChild(el);
    });
  } else {
    hitsSection.innerHTML = `
      <div style="font-family:var(--font-mono);font-size:.8rem;color:var(--green);padding:6px 0">
        ✓ No malicious patterns detected
      </div>`;
  }

  // Highlighted payload
  let highlighted = esc(d.payload);
  if (d.hits && d.hits.length > 0) {
    d.hits.forEach(h => {
      const safe = esc(h.matched);
      highlighted = highlighted.replace(safe, `<span class="hl-match">${safe}</span>`);
    });
  }
  payloadHL.innerHTML = highlighted;

  // Scroll to result
  setTimeout(() => resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
}

// ── Clear ─────────────────────────────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  payloadInput.value = '';
  resultCard.classList.add('hidden');
  payloadInput.focus();
});

function flashInput() {
  payloadInput.style.borderColor = 'var(--red)';
  payloadInput.style.boxShadow   = '0 0 0 3px var(--red-glow)';
  payloadInput.focus();
  setTimeout(() => {
    payloadInput.style.borderColor = '';
    payloadInput.style.boxShadow   = '';
  }, 800);
}

// ── Quick Examples ────────────────────────────────────────────────────────────
document.querySelectorAll('.ex-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    payloadInput.value = btn.dataset.v;
    payloadInput.focus();
    runScan();
  });
});

// ══════════════════════════════════════════════════════════════════
//  VOICE COMMAND ENGINE  —  Web Speech API (Chrome / Edge)
//  Features:
//    • Full-screen modal with live waveform visualiser
//    • Interim (grey) + final (green) transcript display
//    • Spoken-phrase → SQL translation (e.g. "dash dash" → "--")
//    • Auto-countdown then scan after final result
//    • Inline strip under textarea while listening
//    • Graceful fallback for unsupported browsers
// ══════════════════════════════════════════════════════════════════

/* ── DOM refs ─────────────────────────────────────────────────── */
const voiceModal      = document.getElementById('voice-modal');
const vmClose         = document.getElementById('vm-close');
const vmStart         = document.getElementById('vm-start');
const vmStop          = document.getElementById('vm-stop');
const vmScanNow       = document.getElementById('vm-scan-now');
const vmClearBtn      = document.getElementById('vm-clear-transcript');
const vmDot           = document.getElementById('vm-dot');
const vmStatusText    = document.getElementById('vm-status-text');
const vmCountdown     = document.getElementById('vm-countdown');
const vmTranscript    = document.getElementById('vm-transcript');
const vmIdleHint      = document.getElementById('vm-idle-hint');
const vmBrowserNote   = document.getElementById('vm-browser-note');
const vmCanvas        = document.getElementById('vm-canvas');
const voiceStrip      = document.getElementById('voice-strip');
const vsLabel         = document.getElementById('vs-label');
const vsInterim       = document.getElementById('vs-interim');
const vsStop          = document.getElementById('vs-stop');

/* ── Spoken-phrase → SQL translation map ─────────────────────── */
const SPEECH_MAP = [
  // punctuation
  [/\bdash dash\b/gi,           '--'],
  [/\bdouble dash\b/gi,         '--'],
  [/\bsemicolon\b/gi,           ';'],
  [/\bsingle quote\b/gi,        "'"],
  [/\bapostrophe\b/gi,          "'"],
  [/\bdouble quote\b/gi,        '"'],
  [/\bopen paren(thesis)?\b/gi, '('],
  [/\bclose paren(thesis)?\b/gi,')'],
  [/\bcomma\b/gi,               ','],
  [/\basterisk\b/gi,            '*'],
  [/\bstar\b/gi,                '*'],
  [/\bpercent\b/gi,             '%'],
  [/\bunderscore\b/gi,          '_'],
  [/\bequals\b/gi,              '='],
  [/\bequal\b/gi,               '='],
  [/\bgreater than\b/gi,        '>'],
  [/\bless than\b/gi,           '<'],
  [/\bat\b/gi,                  '@'],
  [/\bdot\b/gi,                 '.'],
  [/\bhash\b/gi,                '#'],
  [/\bpound\b/gi,               '#'],
  [/\bslash\b/gi,               '/'],
  [/\bbackslash\b/gi,           '\\'],
  [/\btilde\b/gi,               '~'],
  // numbers written out
  [/\bone\b/gi,   '1'],
  [/\btwo\b/gi,   '2'],
  [/\bthree\b/gi, '3'],
  [/\bfour\b/gi,  '4'],
  [/\bfive\b/gi,  '5'],
  [/\bsix\b/gi,   '6'],
  [/\bseven\b/gi, '7'],
  [/\beight\b/gi, '8'],
  [/\bnine\b/gi,  '9'],
  [/\bzero\b/gi,  '0'],
  // common SQL keyword corrections
  [/\bunion select\b/gi,   'UNION SELECT'],
  [/\bdrop table\b/gi,     'DROP TABLE'],
  [/\binsert into\b/gi,    'INSERT INTO'],
  [/\bselect star\b/gi,    'SELECT *'],
  [/\bfrom users\b/gi,     'FROM users'],
  [/\band sleep\b/gi,      'AND SLEEP'],
  [/\bor sleep\b/gi,       'OR SLEEP'],
];

function translateSpeech(raw) {
  let out = raw;
  SPEECH_MAP.forEach(([re, rep]) => { out = out.replace(re, rep); });
  return out.trim();
}

/* ── Browser support detection ───────────────────────────────── */
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
const isChrome = /Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor);
const isEdge   = /Edg\//.test(navigator.userAgent);

function showBrowserNote() {
  if (!SR) {
    vmBrowserNote.className = 'vm-browser-note error';
    vmBrowserNote.innerHTML =
      '⚠️ <strong>Web Speech API not supported</strong> in this browser.<br>' +
      'Please open this page in <strong>Google Chrome</strong> or <strong>Microsoft Edge</strong>.';
    vmStart.disabled = true;
    vmStart.style.opacity = '.4';
    vmStart.style.cursor  = 'not-allowed';
  } else if (!isChrome && !isEdge) {
    vmBrowserNote.className = 'vm-browser-note warn';
    vmBrowserNote.textContent =
      '⚠️ Voice recognition works best in Chrome or Edge. Results may vary in your browser.';
  } else {
    vmBrowserNote.className = 'vm-browser-note';
    vmBrowserNote.textContent =
      '✓ Chrome detected — voice recognition fully supported. Microphone permission required.';
  }
}

/* ── Waveform visualiser (AudioContext + AnalyserNode) ───────── */
let audioCtx = null, analyser = null, micStream = null, waveRAF = null;

async function startWaveform() {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    micStream = stream;
    analyser  = audioCtx.createAnalyser();
    analyser.fftSize = 256;
    audioCtx.createMediaStreamSource(stream).connect(analyser);
    drawWave();
  } catch (e) {
    // Microphone denied or unavailable — waveform just stays blank
    console.warn('Waveform mic access:', e.message);
  }
}

function stopWaveform() {
  if (waveRAF) { cancelAnimationFrame(waveRAF); waveRAF = null; }
  if (micStream) { micStream.getTracks().forEach(t => t.stop()); micStream = null; }
  // Clear canvas
  const ctx = vmCanvas.getContext('2d');
  ctx.clearRect(0, 0, vmCanvas.width, vmCanvas.height);
}

function drawWave() {
  const ctx  = vmCanvas.getContext('2d');
  const W    = vmCanvas.width;
  const H    = vmCanvas.height;
  const buf  = new Uint8Array(analyser ? analyser.frequencyBinCount : 128);

  function frame() {
    waveRAF = requestAnimationFrame(frame);
    ctx.clearRect(0, 0, W, H);

    if (analyser) {
      analyser.getByteTimeDomainData(buf);
    } else {
      // Idle flat line
      buf.fill(128);
    }

    ctx.lineWidth   = 2;
    ctx.strokeStyle = '#00ff88';
    ctx.shadowColor = '#00ff88';
    ctx.shadowBlur  = 8;
    ctx.beginPath();

    const slice = W / buf.length;
    let x = 0;
    for (let i = 0; i < buf.length; i++) {
      const v = buf[i] / 128;
      const y = (v * H) / 2;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      x += slice;
    }
    ctx.stroke();
  }
  frame();
}

/* ── SpeechRecognition instance ─────────────────────────────── */
let recognition   = null;
let isListening   = false;
let finalText     = '';
let countdownTimer = null;

function buildRecognition() {
  if (!SR) return;
  recognition = new SR();
  recognition.continuous     = true;   // keep listening until manually stopped
  recognition.interimResults = true;
  recognition.lang           = 'en-US';
  recognition.maxAlternatives = 1;

  recognition.onstart = () => {
    isListening = true;
    finalText   = '';
    setVmState('listening');
    vmIdleHint.classList.add('hidden');
    startWaveform();
    // Inline strip
    voiceStrip.classList.remove('hidden');
    vsLabel.textContent = 'Listening…';
  };

  recognition.onresult = (e) => {
    let interim = '';
    let newFinal = '';

    for (let i = e.resultIndex; i < e.results.length; i++) {
      const t = e.results[i][0].transcript;
      if (e.results[i].isFinal) {
        newFinal += t + ' ';
      } else {
        interim += t;
      }
    }

    if (newFinal) {
      finalText += newFinal;
      clearAutoScan();
      scheduleAutoScan();
    }

    // Render transcript: final (bright) + interim (dim)
    const translated = translateSpeech(finalText + interim);
    renderTranscript(finalText, interim);

    // Update inline strip
    vsInterim.textContent = translateSpeech(interim || finalText).slice(-60);

    // Push to textarea live
    payloadInput.value = translated;
  };

  recognition.onerror = (e) => {
    const msgs = {
      'not-allowed':  'Microphone permission denied. Allow mic access and try again.',
      'no-speech':    'No speech detected. Please speak clearly.',
      'network':      'Network error. Check your internet connection.',
      'aborted':      'Recognition stopped.',
      'audio-capture':'No microphone found.',
    };
    const msg = msgs[e.error] || `Error: ${e.error}`;
    setVmState('error', msg);
    stopVoiceSession(false);
  };

  recognition.onend = () => {
    // onend fires when browser auto-stops (silence timeout, etc.)
    if (isListening) {
      // Try to restart for continuous feel
      try { recognition.start(); }
      catch (e) { stopVoiceSession(false); }
    }
  };
}

function renderTranscript(final, interim) {
  vmTranscript.innerHTML = '';
  if (final) {
    const fSpan = document.createElement('span');
    fSpan.className = 'vm-final';
    fSpan.textContent = translateSpeech(final);
    vmTranscript.appendChild(fSpan);
  }
  if (interim) {
    const iSpan = document.createElement('span');
    iSpan.className = 'vm-interim';
    iSpan.textContent = ' ' + translateSpeech(interim);
    vmTranscript.appendChild(iSpan);
  }
  if (!final && !interim) {
    vmTranscript.innerHTML = '<span class="vm-transcript-placeholder">Your spoken words will appear here in real-time...</span>';
  }
  vmTranscript.scrollTop = vmTranscript.scrollHeight;
}

/* ── State management ────────────────────────────────────────── */
function setVmState(state, msg) {
  const states = {
    ready:     { dot: '',          text: 'Ready — click START LISTENING',    transcriptCls: '' },
    listening: { dot: 'listening', text: 'Listening… speak your SQL payload', transcriptCls: 'active' },
    done:      { dot: 'done',      text: 'Recognition complete',              transcriptCls: 'final' },
    error:     { dot: 'error',     text: msg || 'An error occurred',          transcriptCls: '' },
  };
  const s = states[state] || states.ready;
  vmDot.className        = 'vm-status-dot ' + s.dot;
  vmStatusText.textContent = s.text;
  vmTranscript.className = 'vm-transcript ' + s.transcriptCls;

  const listening = state === 'listening';
  vmStart.classList.toggle('hidden', listening);
  vmStop.classList.toggle('hidden', !listening);
  vmScanNow.classList.toggle('hidden', !finalText && state !== 'done');
  voiceBtn.classList.toggle('active', listening);
}

/* ── Auto-scan countdown ─────────────────────────────────────── */
function scheduleAutoScan() {
  let secs = 3;
  vmCountdown.classList.remove('hidden');
  vmCountdown.textContent = secs;
  countdownTimer = setInterval(() => {
    secs--;
    vmCountdown.textContent = secs;
    if (secs <= 0) {
      clearAutoScan();
      stopVoiceSession(true);  // stop then scan
    }
  }, 1000);
}
function clearAutoScan() {
  if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  vmCountdown.classList.add('hidden');
  vmCountdown.textContent = '';
}

/* ── Start / Stop session ────────────────────────────────────── */
function startVoiceSession() {
  if (!SR) return;
  buildRecognition();
  finalText = '';
  renderTranscript('', '');
  vmScanNow.classList.add('hidden');
  clearAutoScan();
  try {
    recognition.start();
  } catch (e) {
    setVmState('error', 'Could not start recognition. Reload and try again.');
  }
}

function stopVoiceSession(thenScan) {
  isListening = false;
  clearAutoScan();
  if (recognition) {
    try { recognition.stop(); } catch (_) {}
  }
  stopWaveform();
  voiceStrip.classList.add('hidden');
  voiceBtn.classList.remove('active');
  setVmState('done');

  if (finalText.trim()) {
    const result = translateSpeech(finalText.trim());
    payloadInput.value = result;
    vmScanNow.classList.remove('hidden');
    renderTranscript(finalText, '');
  }

  if (thenScan && finalText.trim()) {
    setTimeout(() => {
      closeVoiceModal();
      runScan();
    }, 400);
  }
}

/* ── Open / Close modal ──────────────────────────────────────── */
function openVoiceModal() {
  voiceModal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  showBrowserNote();
  setVmState('ready');
}

function closeVoiceModal() {
  if (isListening) stopVoiceSession(false);
  voiceModal.classList.add('hidden');
  document.body.style.overflow = '';
}

/* ── Event listeners ─────────────────────────────────────────── */
voiceBtn.addEventListener('click', openVoiceModal);

vmClose.addEventListener('click', closeVoiceModal);
voiceModal.addEventListener('click', e => {
  if (e.target === voiceModal) closeVoiceModal();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !voiceModal.classList.contains('hidden')) closeVoiceModal();
});

vmStart.addEventListener('click', startVoiceSession);

vmStop.addEventListener('click', () => stopVoiceSession(false));

vmScanNow.addEventListener('click', () => {
  closeVoiceModal();
  runScan();
});

vmClearBtn.addEventListener('click', () => {
  finalText = '';
  renderTranscript('', '');
  payloadInput.value = '';
  vmScanNow.classList.add('hidden');
  clearAutoScan();
  if (isListening) setVmState('listening');
  else setVmState('ready');
});

vsStop.addEventListener('click', () => stopVoiceSession(false));

// ── History ───────────────────────────────────────────────────────────────────
async function fetchHistory() {
  try {
    const res  = await fetch('/api/history');
    const rows = await res.json();
    renderHistory(rows);
  } catch (e) { /* silent */ }
}

function renderHistory(rows) {
  if (!rows.length) {
    historyTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No scans yet — run a scan above</td></tr>';
    return;
  }
  historyTbody.innerHTML = rows.map(r => `
    <tr>
      <td style="color:var(--text-dim)">${r.timestamp}</td>
      <td style="color:var(--green)">${esc(r.payload)}</td>
      <td><span class="verdict-pill v-${r.verdict}">${r.verdict}</span></td>
      <td style="color:var(--text-bright);font-weight:700">${r.score.toFixed(2)}</td>
      <td style="color:${r.hits > 0 ? 'var(--red)' : 'var(--green)'}">${r.hits}</td>
    </tr>`).join('');
}

clearHistoryBtn.addEventListener('click', () => {
  historyTbody.innerHTML = '<tr class="empty-row"><td colspan="5">History cleared</td></tr>';
  fetch('/api/history'); // just refresh
});

// ── Stats ─────────────────────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    animCount(sTotal,      data.total);
    animCount(sDanger,     data.dangerous);
    animCount(sSuspicious, data.suspicious + data.warning);
    animCount(sSafe,       data.safe);
  } catch (e) { /* silent */ }
}

function animCount(el, target) {
  const start    = parseInt(el.textContent) || 0;
  const duration = 600;
  const step     = (timestamp) => {
    if (!start_t) start_t = timestamp;
    const progress = Math.min((timestamp - start_t) / duration, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(progress));
    if (progress < 1) requestAnimationFrame(step);
  };
  let start_t = null;
  requestAnimationFrame(step);
}
const easeOut = t => 1 - Math.pow(1 - t, 3);

// ── Patterns Library ──────────────────────────────────────────────────────────
function renderPatterns() {
  patternsGrid.innerHTML = PATTERN_LIBRARY.map(p => {
    const col = SEV_COLOR[p.severity] || 'green';
    return `
      <div class="pat-card">
        <span class="pat-badge badge-${p.severity}">${p.severity}</span>
        <div style="font-size:.6rem;color:var(--text-dim);letter-spacing:1px;margin-bottom:4px">${p.category}</div>
        <div class="pat-name">${esc(p.name)}</div>
      </div>`;
  }).join('');
}

// ── Nav smooth highlight ──────────────────────────────────────────────────────
const navLinks = document.querySelectorAll('.nav-link[href^="#"]');
const sections = ['scanner','history','patterns'].map(id => document.getElementById(id));

window.addEventListener('scroll', () => {
  const scrollY = window.scrollY + 100;
  sections.forEach((sec, i) => {
    if (sec && scrollY >= sec.offsetTop) {
      navLinks.forEach(l => l.classList.remove('active'));
      navLinks[i]?.classList.add('active');
    }
  });
}, { passive: true });

// ── Utility ───────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
(function init() {
  renderPatterns();
  fetchHistory();
  fetchStats();
  payloadInput.focus();

  // Periodic stats refresh
  setInterval(fetchStats, 10000);
})();


const recognition = new webkitSpeechRecognition();

recognition.lang = 'en-US';
recognition.start();

recognition.onresult = function(event) {
    let spokenText = event.results[0][0].transcript;
    document.getElementById('inputBox').value = spokenText;
};