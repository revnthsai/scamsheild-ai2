/**
 * ScamShield AI — QR Overlay & Decode Engine
 *
 * Wraps jsQR (loaded from CDN in index.html) to turn a live camera feed
 * or an uploaded image into decoded text, entirely on-device. Nothing
 * here ever uploads the raw image anywhere — only the decoded text (a
 * URL, usually) is later sent to the risk-analysis endpoint.
 */

(function (global) {
  "use strict";

  let stream = null;
  let rafId = null;
  let scratchCanvas = null;
  let scratchCtx = null;
  let lastEmitted = null;
  let lastEmitTime = 0;

  function ensureScratchCanvas() {
    if (!scratchCanvas) {
      scratchCanvas = document.createElement("canvas");
      scratchCtx = scratchCanvas.getContext("2d", { willReadFrequently: true });
    }
    return { canvas: scratchCanvas, ctx: scratchCtx };
  }

  async function startCamera(videoEl, onDecode, onError) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      onError && onError(new Error("Camera access isn't supported in this browser."));
      return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      videoEl.srcObject = stream;
      await videoEl.play();
      loop(videoEl, onDecode);
    } catch (err) {
      onError && onError(err);
    }
  }

  function loop(videoEl, onDecode) {
    const { canvas, ctx } = ensureScratchCanvas();

    function tick() {
      if (!stream) return;
      if (videoEl.readyState === videoEl.HAVE_ENOUGH_DATA) {
        canvas.width = videoEl.videoWidth;
        canvas.height = videoEl.videoHeight;
        ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
        try {
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = global.jsQR
            ? global.jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "dontInvert",
              })
            : null;
          if (code && code.data) {
            emitDecode(code.data, onDecode);
          }
        } catch (_) {
          /* frame not ready yet — ignore and try the next one */
        }
      }
      rafId = requestAnimationFrame(tick);
    }
    rafId = requestAnimationFrame(tick);
  }

  function emitDecode(data, onDecode) {
    const now = Date.now();
    // Debounce identical reads so a held-up QR code doesn't flood the app
    // with duplicate detections every animation frame.
    if (data === lastEmitted && now - lastEmitTime < 4000) return;
    lastEmitted = data;
    lastEmitTime = now;
    onDecode(data);
  }

  function stopCamera() {
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
    if (stream) {
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
    }
    lastEmitted = null;
  }

  function decodeFromFile(file, onDecode, onError) {
    if (!global.jsQR) {
      onError && onError(new Error("QR decoder failed to load."));
      return;
    }
    const img = new Image();
    const reader = new FileReader();
    reader.onload = (e) => {
      img.onload = () => {
        const { canvas, ctx } = ensureScratchCanvas();
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = global.jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
          emitDecode(code.data, onDecode);
        } else {
          onError && onError(new Error("No QR code found in that image."));
        }
      };
      img.onerror = () => onError && onError(new Error("Couldn't read that image file."));
      img.src = e.target.result;
    };
    reader.onerror = () => onError && onError(new Error("Couldn't read that file."));
    reader.readAsDataURL(file);
  }

  global.ScamShieldQR = { startCamera, stopCamera, decodeFromFile };
})(window);
