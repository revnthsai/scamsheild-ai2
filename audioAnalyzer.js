/**
 * ScamShield AI — WebAudio Visualizer & Regional Scam Keyword Engine
 *
 * Two independent jobs live in this file:
 *   1. Draw a live waveform from the microphone onto a <canvas> so the
 *      voice lane feels alive while listening.
 *   2. Run a lightweight, on-device keyword/pattern classifier over
 *      whatever transcript text it's given, as an offline fallback for
 *      when the FastAPI backend isn't reachable. The category list is
 *      intentionally kept in sync with backend/app/services/voice_service.py
 *      so the on-device and server verdicts never contradict each other.
 */

(function (global) {
  "use strict";

  let audioCtx = null;
  let analyser = null;
  let micStream = null;
  let rafId = null;
  let recognizer = null;

  // Kept 1:1 with the backend CATEGORIES table.
  const CATEGORIES = [
    {
      code: "authority_impersonation",
      label: "Impersonating a government agency, bank, or well-known company",
      weight: 25,
      cap: 50,
      phrases: [
        "irs", "social security administration", "medicare", "arrest warrant",
        "federal agent", "the sheriff", "fraud department", "amazon security",
        "microsoft support", "apple support", "your bank's fraud team",
        "court order", "final legal notice",
      ],
    },
    {
      code: "urgency_pressure",
      label: "Manufactured urgency meant to stop you from thinking it through",
      weight: 15,
      cap: 30,
      phrases: [
        "act now", "immediately", "right away", "within the hour",
        "before it's too late", "final notice", "last warning",
        "your account will be closed", "you will be arrested",
        "time-sensitive", "act today",
      ],
    },
    {
      code: "untraceable_payment",
      label: "Requests payment through untraceable or hard-to-reverse methods",
      weight: 30,
      cap: 60,
      phrases: [
        "gift card", "itunes card", "google play card", "wire transfer",
        "western union", "moneygram", "bitcoin", "cryptocurrency",
        "crypto atm", "prepaid card", "cash app", "zelle transfer",
      ],
    },
    {
      code: "secrecy_isolation",
      label: "Asking you to keep the call secret or avoid verifying with others",
      weight: 25,
      cap: 50,
      phrases: [
        "don't tell anyone", "keep this confidential", "don't hang up",
        "stay on the line", "don't tell your family", "this is confidential",
        "do not call anyone else",
      ],
    },
    {
      code: "credential_harvesting",
      label: "Directly requesting sensitive personal or account information",
      weight: 20,
      cap: 40,
      phrases: [
        "verify your social security number", "confirm your password",
        "your pin number", "one-time passcode", "verification code",
        "your card number", "your account number", "your date of birth",
        "security question",
      ],
    },
  ];

  function analyzeTranscriptLocally(transcript) {
    const lower = (transcript || "").toLowerCase();
    const categories = [];

    CATEGORIES.forEach((cfg) => {
      const matched = cfg.phrases.filter((p) => lower.includes(p));
      if (matched.length) {
        categories.push({
          category: cfg.code,
          label: cfg.label,
          matched_phrases: matched,
          weight: Math.min(cfg.cap, cfg.weight * matched.length),
        });
      }
    });

    const risk_score = Math.min(100, categories.reduce((s, c) => s + c.weight, 0));
    const verdict = risk_score >= 55 ? "danger" : risk_score >= 20 ? "caution" : "safe";
    return { risk_score, verdict, categories };
  }

  // ---------------------------------------------------------------------
  // Microphone + waveform
  // ---------------------------------------------------------------------

  async function startListening(canvasEl, { onTranscript, onError, onLevel } = {}) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      onError && onError(new Error("Microphone access isn't supported in this browser."));
      return;
    }
    try {
      micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const AudioContextCls = window.AudioContext || window.webkitAudioContext;
      audioCtx = new AudioContextCls();
      const source = audioCtx.createMediaStreamSource(micStream);
      analyser = audioCtx.createAnalyser();
      analyser.fftSize = 1024;
      source.connect(analyser);
      drawWaveform(canvasEl, onLevel);
    } catch (err) {
      onError && onError(err);
      return;
    }
    startSpeechRecognition(onTranscript, onError);
  }

  function drawWaveform(canvasEl, onLevel) {
    const ctx = canvasEl.getContext("2d");
    const bufferLength = analyser.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);

    function render() {
      rafId = requestAnimationFrame(render);
      analyser.getByteTimeDomainData(dataArray);

      const dpr = window.devicePixelRatio || 1;
      const width = canvasEl.clientWidth;
      const height = canvasEl.clientHeight;
      if (canvasEl.width !== width * dpr) {
        canvasEl.width = width * dpr;
        canvasEl.height = height * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      ctx.lineWidth = 2;
      ctx.strokeStyle = "#e8a94c";
      ctx.beginPath();

      const sliceWidth = width / bufferLength;
      let x = 0;
      let peak = 0;
      for (let i = 0; i < bufferLength; i++) {
        const v = dataArray[i] / 128.0;
        peak = Math.max(peak, Math.abs(v - 1));
        const y = (v * height) / 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
        x += sliceWidth;
      }
      ctx.lineTo(width, height / 2);
      ctx.stroke();

      onLevel && onLevel(peak);
    }
    render();
  }

  function startSpeechRecognition(onTranscript, onError) {
    const SpeechRecognitionCls = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognitionCls) {
      onError &&
        onError(
          new Error(
            "Live transcription isn't supported in this browser — try Chrome, or paste a transcript manually."
          )
        );
      return;
    }
    recognizer = new SpeechRecognitionCls();
    recognizer.continuous = true;
    recognizer.interimResults = true;
    recognizer.lang = "en-US";

    recognizer.onresult = (event) => {
      let finalText = "";
      let interimText = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const chunk = event.results[i][0].transcript;
        if (event.results[i].isFinal) finalText += chunk + " ";
        else interimText += chunk;
      }
      onTranscript && onTranscript({ finalText: finalText.trim(), interimText: interimText.trim() });
    };
    recognizer.onerror = (e) => {
      if (e.error !== "no-speech") onError && onError(new Error("Speech recognition error: " + e.error));
    };
    recognizer.onend = () => {
      // Auto-restart while the lane is still active, browsers stop after
      // periods of silence.
      if (micStream) {
        try { recognizer.start(); } catch (_) { /* already starting */ }
      }
    };
    try { recognizer.start(); } catch (_) { /* ignore double-start */ }
  }

  function stopListening() {
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
    if (recognizer) {
      recognizer.onend = null;
      recognizer.stop();
      recognizer = null;
    }
    if (micStream) {
      micStream.getTracks().forEach((t) => t.stop());
      micStream = null;
    }
    if (audioCtx) {
      audioCtx.close();
      audioCtx = null;
    }
  }

  global.ScamShieldAudio = { startListening, stopListening, analyzeTranscriptLocally };
})(window);
