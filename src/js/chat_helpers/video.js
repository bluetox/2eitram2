const { invoke } = window.__TAURI__.core;

let shouldContinue = false;
let sending = Promise.resolve();
const video          = document.getElementById('videoElement');

const offscreenCanvas = document.createElement('canvas');
const ctx             = offscreenCanvas.getContext('2d');
const receivedCanvas = document.getElementById('receivedCanvas');
export const receivedCtx    = receivedCanvas.getContext('2d');

let mediaStream = null;
let rafId       = null;


export async function startWebcam(chatId) {
  try {
    const constraints = {
      video: {
        width:  { ideal: 1280 },
        height: { ideal: 720 },
        facingMode: "user"
      }
    };
    const stream = await navigator.mediaDevices.getUserMedia(constraints);
    mediaStream = stream;
    video.srcObject = stream;

    const [track] = stream.getVideoTracks();
    applyTrackSettings(track);

    track.addEventListener('ended', stopWebcam);
    track.addEventListener('mute', stopWebcam);

    shouldContinue = true;

    function loop() {
      if (shouldContinue === false) return;
      captureAndSendFrame(chatId);
      rafId = requestAnimationFrame(loop);
    }

    rafId = requestAnimationFrame(loop);
  } catch (err) {
    console.error("Webcam access failed:", err);
  }
}

export function stopWebcam() {
  shouldContinue = false;
  if (rafId !== null) {
    cancelAnimationFrame(rafId);
    rafId = null;
  }

  if (mediaStream) {
    mediaStream.getTracks().forEach(t => t.stop());
    mediaStream = null;
  }

  video.pause();
  video.srcObject = null;

}

function applyTrackSettings(track) {
  const settings = track.getSettings();
  offscreenCanvas.width  = settings.width  || video.videoWidth;
  offscreenCanvas.height = settings.height || video.videoHeight;
}

async function captureAndSendFrame(chatId) {
  if (shouldContinue === false) return;
  const w = offscreenCanvas.width, h = offscreenCanvas.height;
  ctx.drawImage(video, 0, 0, w, h);

  let compressionQuality = 0.6;
  sending = sending.then(() => new Promise(resolve => {
    if (shouldContinue === false) return resolve();
    offscreenCanvas.toBlob(async blob => {
      if (!blob) return resolve();
      const arrayBuffer = await blob.arrayBuffer();
      const img = new Uint8Array(arrayBuffer);

      const header = new Uint32Array([w, h]);
      const payload = new Uint8Array(8 + img.length);
      payload.set(new Uint8Array(header.buffer), 0);
      payload.set(img, 8);

      await invoke("handle_frame_rgba", {
        frame: { data: Array.from(payload), width: w, height: h, format: "jpeg" },
        chatId
      });
      
      resolve();
    }, "image/jpeg", compressionQuality);
  }));
}

