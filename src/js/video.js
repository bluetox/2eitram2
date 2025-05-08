function waitForTauri() {
    return new Promise((resolve) => {
      if (window.__TAURI__.core) {
        resolve(window.__TAURI__.core);
      } else {
        const interval = setInterval(() => {
          if (window.__TAURI__.core) {
            clearInterval(interval);
            resolve(window.__TAURI__.core);
          }
        }, 100); // Check every 100ms
      }
    });
  }
  
waitForTauri();// 1000ms = 1 second

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const video = document.getElementById('webcam');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');
const receivedCanvas = document.getElementById('receivedCanvas');
const receivedCtx = receivedCanvas.getContext('2d');

let userId = null;

document.getElementById("start").addEventListener('click', startWebcam);
async function startWebcam() {
  try {
    userId = document.getElementById("dst-user-id").value;
    if (userId === "") {
        alert("enter a user_id");
        return;
    }
    const stream = await navigator.mediaDevices.getUserMedia({
      video: true
    });
    video.srcObject = stream;
    const trackSettings = stream.getVideoTracks()[0].getSettings();
    canvas.width = trackSettings.width;
    canvas.height = trackSettings.height;
    requestAnimationFrame(startFrameLoop);
  } catch (err) {
    console.error("Webcam access failed:", err);
  }
}

async function captureAndSendFrame() {
  const width = canvas.width;
  const height = canvas.height;

  ctx.drawImage(video, 0, 0, width, height);

  canvas.toBlob(async (blob) => {
    if (!blob) return;

    const arrayBuffer = await blob.arrayBuffer();
    const imageBytes = new Uint8Array(arrayBuffer);

    // Allocate new array: 8 bytes for dimensions + image data
    const fullArray = new Uint8Array(8 + imageBytes.length);

    // Insert width and height as 4-byte unsigned integers
    const view = new DataView(fullArray.buffer);
    view.setUint32(0, width);
    view.setUint32(4, height);

    // Copy image bytes after dimensions
    fullArray.set(imageBytes, 8);

    // Convert to JS array for Tauri
    const bytes = Array.from(fullArray);

    await invoke("handle_frame_rgba", {
      frame: { data: bytes, width, height, format: "jpeg" },
      userId: userId
    });
  }, "image/jpeg", 1);
}
function startFrameLoop() {
  captureAndSendFrame();
  requestAnimationFrame(startFrameLoop);
}


listen("received-video", async (event) => {
  const compressedBytes = event.payload;
  const uint8Array = new Uint8Array(compressedBytes);

  // Read dimensions from first 8 bytes
  const view = new DataView(uint8Array.buffer);
  const width = view.getUint32(0);
  const height = view.getUint32(4);

  // Resize receivedCanvas dynamically
  receivedCanvas.width = width;
  receivedCanvas.height = height;

  // Slice image bytes after the 8-byte header
  const imageBytes = uint8Array.slice(8);
  console.log("received w×h:", width, height, "bytes length:", imageBytes.length);
  const blob = new Blob([imageBytes], { type: "image/jpeg" });
  const bitmap = await createImageBitmap(blob);
  receivedCtx.drawImage(bitmap, 0, 0, width, height);
});