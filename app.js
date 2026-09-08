/**
 * ScamShield AI — Core Application Controller
 *
 * Wires the two live-simulator lanes (QR + Voice) to the FastAPI backend,
 * with an on-device heuristic fallback whenever the backend can't be
 * reached, and keeps a running "threat signal log" of everything that's
 * been checked in this session.
 */

(function () {
  "use strict";

  const LOG_STORAGE_KEY = "scamshield_log_v1";
  const MAX_LOG_ENTRIES = 25;
  const LOCAL_API_CANDIDATES = ["/api", "http://localhost:8000/api"];

  let apiBase = null;
  let apiChecked = false;

  const $ = (sel) => document.querySelector(sel);

  const el = {
    statusPill: $("#topStatusPill"),
    statusLabel: $("#topStatusLabel"),

    // QR lane
    qrVideo: $("#qrVideo"),
    qrReticle: $("#qrReticle"),
    qrPlaceholder: $("#qrPlaceholder"),
    qrStartBtn: $("#qrStartBtn"),
    qrStopBtn: $("#qrStopBtn"),
    qrUploadInput: $("#qrUploadInput"),
    qrManualInput: $("#qrManualInput"),
    qrManualBtn: $("#qrManualBtn"),
    qrVerdict: $("#qrVerdict"),
    qrScore: $("#qrScore"),
    qrFindings: $("#qrFindings"),

    // Voice lane
    voiceStartBtn: $("#voiceStartBtn"),
    voiceStopBtn: $("#voiceStopBtn"),
    waveformCanvas: $("#waveformCanvas"),
    transcriptBox: $("#transcriptBox"),
    voiceManualInput: $("#voiceManualInput"),
    voiceManualBtn: $("#voiceManualBtn"),
    voiceVerdict: $("#voiceVerdict"),
    voiceScore: $("#voiceScore"),
    voiceFindings: $("#voiceFindings"),

    // Log + footer
    logList: $("#logList"),
    logEmpty: $("#logEmpty"),
    clearLogBtn: $("#clearLogBtn"),
    apiDot: $("#apiDot"),
    apiLabel: $("#apiLabel"),
  };

  // -------------------------------------------------------------------
  // API base resolution + health polling
  // -------------------------------------------------------------------

  async function pingHealth(base, timeoutMs) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${base}/health`, { signal: controller.signal });
      clearTimeout(t);
      return res.ok;
    } catch (_) {
      clearTimeout(t);
      return false;
    }
  }

  async function resolveApiBase() {
    for (const candidate of LOCAL_API_CANDIDATES) {
      // eslint-disable-next-line no-await-in-loop
      if (await pingHealth(candidate, 1500)) {
        return candidate;
      }
    }
    return null;
  }

  async function refreshApiStatus() {
    apiBase = await resolveApiBase();
    apiChecked = true;
    if (apiBase) {
      el.apiDot.dataset.state = "online";
      el.apiLabel.textContent = "Backend connected — live scoring";
      el.statusLabel.textContent = "Scanning";
    } else {
      el.apiDot.dataset.state = "offline";
      el.apiLabel.textContent = "Backend offline — using on-device heuristics";
      el.statusLabel.textContent = "On-device mode";
    }
  }

  // -------------------------------------------------------------------
  // Local JS fallback for QR/link heuristics (mirrors backend/app/services/qr_service.py)
  // -------------------------------------------------------------------

  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"];
  const SUSPICIOUS_TLDS = [".zip", ".mov", ".top", ".xyz", ".club", ".gq", ".tk", ".work", ".loan", ".men", ".click", ".country", ".stream", ".gdn"];
  const BRANDS = {
    paypal: ["paypal.com"], amazon: ["amazon.com"], apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"], netflix: ["netflix.com"],
    usps: ["usps.com"], irs: ["irs.gov"], bankofamerica: ["bankofamerica.com"],
    wellsfargo: ["wellsfargo.com"], chase: ["chase.com"], fedex: ["fedex.com"],
    ups: ["ups.com"], google: ["google.com", "gmail.com"], docusign: ["docusign.com", "docusign.net"],
  };
  const URGENCY_WORDS = ["verify", "confirm", "suspend", "locked", "urgent", "immediately", "reactivate", "limited", "expire", "restricted"];

  const URL_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
  // Bare domain with an optional path, e.g. "bit.ly/3xYzAbC" — kept in
  // sync with DOMAIN_LIKE_RE in backend/app/services/qr_service.py.
  const DOMAIN_LIKE_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:[/?#]\S*)?$/;

  function localAnalyzeQr(raw) {
    const text = raw.trim();
    const findings = [];
    const looksLikeUrl = URL_SCHEME_RE.test(text) || DOMAIN_LIKE_RE.test(text);

    if (!looksLikeUrl) {
      if (URGENCY_WORDS.some((w) => text.toLowerCase().includes(w))) {
        findings.push({ label: "Contains urgent/scare language typical of scam QR payloads", weight: 20 });
      }
      return finalizeQr(text, findings, null);
    }

    const normalized = text.includes("://") ? text : `http://${text}`;
    let host = "";
    let parsed;
    try {
      parsed = new URL(normalized);
      host = parsed.hostname.toLowerCase();
    } catch (_) {
      findings.push({ label: "Malformed link that browsers may parse unpredictably", weight: 25 });
      return finalizeQr(text, findings, null);
    }

    if (parsed.protocol === "http:") findings.push({ label: "Link does not use a secure HTTPS connection", weight: 15 });
    if (normalized.split("://")[1].split("/")[0].includes("@")) {
      findings.push({ label: "Contains an '@' before the domain — a classic trick to disguise the real destination", weight: 30 });
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      findings.push({ label: "Points directly to a raw IP address instead of a named domain", weight: 35 });
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      findings.push({ label: "Uses Punycode encoding, often used to mimic a trusted brand with look-alike characters", weight: 35 });
    }
    if (SHORTENERS.includes(host)) {
      findings.push({ label: "Uses a link shortener, which hides the real destination until after you click", weight: 15 });
    }
    if (SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) {
      findings.push({ label: "Uses a domain ending disproportionately common in scam campaigns", weight: 15 });
    }
    if ((host.match(/\./g) || []).length >= 4) {
      findings.push({ label: "Unusually long chain of subdomains, often used to bury a fake brand name", weight: 20 });
    }
    if (text.length > 120) findings.push({ label: "Unusually long link, which can hide redirect parameters", weight: 10 });

    for (const [brand, domains] of Object.entries(BRANDS)) {
      const bare = host.replace(/-/g, "").replace(/\./g, "");
      if (bare.includes(brand) && !domains.some((d) => host === d || host.endsWith(`.${d}`))) {
        findings.push({ label: `Domain references '${brand}' but is not an official ${brand} domain`, weight: 40 });
        break;
      }
    }

    const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
    if (URGENCY_WORDS.some((w) => pathAndQuery.includes(w) || host.includes(w))) {
      findings.push({ label: "URL contains pressure language (e.g. 'verify', 'suspended') typical of phishing links", weight: 20 });
    }

    return finalizeQr(text, findings, host);
  }

  function finalizeQr(content, findings, host) {
    const risk_score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
    const verdict = risk_score >= 60 ? "danger" : risk_score >= 25 ? "caution" : "safe";
    return { content, risk_score, verdict, findings, resolved_host: host };
  }

  // -------------------------------------------------------------------
  // QR lane
  // -------------------------------------------------------------------

  let qrActive = false;

  function setQrScanningUI(active) {
    qrActive = active;
    el.qrStartBtn.disabled = active;
    el.qrStopBtn.disabled = !active;
    el.qrPlaceholder.style.display = active ? "none" : "block";
    el.qrReticle.classList.toggle("active", active);
  }

  el.qrStartBtn.addEventListener("click", () => {
    setQrScanningUI(true);
    ScamShieldQR.startCamera(
      el.qrVideo,
      (data) => handleQrResult(data),
      (err) => {
        setQrScanningUI(false);
        renderQrError(err.message);
      }
    );
  });

  el.qrStopBtn.addEventListener("click", () => {
    ScamShieldQR.stopCamera();
    setQrScanningUI(false);
  });

  el.qrUploadInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    ScamShieldQR.decodeFromFile(
      file,
      (data) => handleQrResult(data),
      (err) => renderQrError(err.message)
    );
    e.target.value = "";
  });

  el.qrManualBtn.addEventListener("click", () => {
    const val = el.qrManualInput.value.trim();
    if (val) handleQrResult(val);
  });

  async function handleQrResult(content) {
    let result;
    if (apiBase) {
      try {
        const res = await fetch(`${apiBase}/analyze/qr`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        });
        if (!res.ok) throw new Error("bad response");
        result = await res.json();
      } catch (_) {
        result = localAnalyzeQr(content);
      }
    } else {
      result = localAnalyzeQr(content);
    }
    renderQrResult(result);
    pushLogEntry({ source: "qr", detail: content, verdict: result.verdict, score: result.risk_score });
  }

  function renderQrResult(result) {
    el.qrVerdict.dataset.level = result.verdict;
    el.qrVerdict.querySelector(".verdict-label").textContent = labelFor(result.verdict);
    el.qrScore.innerHTML = `${result.risk_score}<small> / 100</small>`;
    const findings = result.findings || [];
    el.qrFindings.classList.toggle("is-empty", findings.length === 0);
    el.qrFindings.innerHTML = findings.length
      ? findings.map((f) => `<li>${escapeHtml(f.label)}</li>`).join("")
      : `<li>No red flags found in this link.</li>`;
  }

  function renderQrError(message) {
    el.qrVerdict.dataset.level = "idle";
    el.qrVerdict.querySelector(".verdict-label").textContent = "Idle";
    el.qrFindings.classList.remove("is-empty");
    el.qrFindings.innerHTML = `<li>${escapeHtml(message)}</li>`;
  }

  // -------------------------------------------------------------------
  // Voice lane
  // -------------------------------------------------------------------

  let voiceActive = false;
  let pendingFinalText = "";
  let analyzeDebounce = null;

  function setVoiceListeningUI(active) {
    voiceActive = active;
    el.voiceStartBtn.disabled = active;
    el.voiceStopBtn.disabled = !active;
  }

  el.voiceStartBtn.addEventListener("click", () => {
    setVoiceListeningUI(true);
    pendingFinalText = "";
    ScamShieldAudio.startListening(el.waveformCanvas, {
      onTranscript: ({ finalText, interimText }) => {
        if (finalText) pendingFinalText = `${pendingFinalText} ${finalText}`.trim();
        el.transcriptBox.textContent = `${pendingFinalText} ${interimText}`.trim() || "Listening…";
        scheduleVoiceAnalysis();
      },
      onError: (err) => {
        el.transcriptBox.textContent = err.message;
      },
    });
  });

  el.voiceStopBtn.addEventListener("click", () => {
    ScamShieldAudio.stopListening();
    setVoiceListeningUI(false);
  });

  el.voiceManualBtn.addEventListener("click", () => {
    const val = el.voiceManualInput.value.trim();
    if (val) analyzeVoiceTranscript(val);
  });

  function scheduleVoiceAnalysis() {
    clearTimeout(analyzeDebounce);
    analyzeDebounce = setTimeout(() => {
      if (pendingFinalText.length > 8) analyzeVoiceTranscript(pendingFinalText);
    }, 900);
  }

  async function analyzeVoiceTranscript(transcript) {
    let result;
    if (apiBase) {
      try {
        const res = await fetch(`${apiBase}/analyze/voice`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transcript }),
        });
        if (!res.ok) throw new Error("bad response");
        result = await res.json();
      } catch (_) {
        result = ScamShieldAudio.analyzeTranscriptLocally(transcript);
      }
    } else {
      result = ScamShieldAudio.analyzeTranscriptLocally(transcript);
    }
    renderVoiceResult(result);
    pushLogEntry({
      source: "voice",
      detail: transcript.slice(0, 90),
      verdict: result.verdict,
      score: result.risk_score,
    });
  }

  function renderVoiceResult(result) {
    el.voiceVerdict.dataset.level = result.verdict;
    el.voiceVerdict.querySelector(".verdict-label").textContent = labelFor(result.verdict);
    el.voiceScore.innerHTML = `${result.risk_score}<small> / 100</small>`;
    const categories = result.categories || [];
    el.voiceFindings.classList.toggle("is-empty", categories.length === 0);
    el.voiceFindings.innerHTML = categories.length
      ? categories.map((c) => `<li>${escapeHtml(c.label)}</li>`).join("")
      : `<li>No scam-script patterns detected so far.</li>`;
  }

  // -------------------------------------------------------------------
  // Threat signal log
  // -------------------------------------------------------------------

  function loadLog() {
    try {
      return JSON.parse(localStorage.getItem(LOG_STORAGE_KEY) || "[]");
    } catch (_) {
      return [];
    }
  }

  function saveLog(entries) {
    try {
      localStorage.setItem(LOG_STORAGE_KEY, JSON.stringify(entries));
    } catch (_) {
      /* storage unavailable — log just won't persist across reloads */
    }
  }

  function pushLogEntry(entry) {
    const entries = loadLog();
    entries.unshift({ ...entry, time: new Date().toISOString(), id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) });
    const trimmed = entries.slice(0, MAX_LOG_ENTRIES);
    saveLog(trimmed);
    renderLog(trimmed);
  }

  function renderLog(entries) {
    el.logEmpty.style.display = entries.length ? "none" : "block";
    el.logList.innerHTML = entries
      .map((e) => {
        const icon = e.source === "qr" ? "▦" : "◐";
        const time = new Date(e.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        return `
          <li class="log-row">
            <span class="log-source" title="${e.source === "qr" ? "QR / link" : "Voice / call"}">${icon}</span>
            <span class="log-detail">${escapeHtml(e.detail || "")}</span>
            <span class="verdict" data-level="${e.verdict}"><span class="verdict-dot"></span><span class="verdict-label">${labelFor(e.verdict)}</span></span>
            <span class="log-time">${time}</span>
          </li>`;
      })
      .join("");
  }

  el.clearLogBtn.addEventListener("click", () => {
    saveLog([]);
    renderLog([]);
  });

  // -------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------

  function labelFor(level) {
    return { safe: "Looks safe", caution: "Use caution", danger: "High risk", idle: "Idle" }[level] || "Idle";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // -------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------

  function init() {
    renderLog(loadLog());
    refreshApiStatus();
    setInterval(refreshApiStatus, 30000);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
