const { listen } = window.__TAURI__.event;

import {loadExistingChats, currentChatId} from '../chat.js';
import {decodeHTMLEntities} from './sanitize.js';
import {receivedCtx} from './video.js';

export async function start_listeners() {

    listenForMessages();
    listen("received-video", async (event) => {
      console.log("received");
      const compressedBytes = event.payload;
      const uint8Array = new Uint8Array(compressedBytes);
      const view = new DataView(uint8Array.buffer);
    
      const w = view.getUint32(0, true);
      const h = view.getUint32(4, true);
    
      if (receivedCanvas.width  !== w ||
        receivedCanvas.height !== h) {
        receivedCanvas.width  = w;
        receivedCanvas.height = h;
      }
    
      const imageBytes = uint8Array.slice(8);
      const blob = new Blob([imageBytes], { type: "image/jpeg" });
    
      if (blob.size === 0) {
        console.error("No image data at all!");
        return;
      }
    
      const bitmap = await createImageBitmap(blob);
      receivedCtx.drawImage(bitmap, 0, 0, w, h);
    });
}

async function listenForMessages() {
    listen("received-message", async (event) => {
      const data = JSON.parse(event.payload);
      const message = data.message;
      const userId = data.source;
      if (!userId) {
        console.error("Error: userId is missing for received message.");
        return;
      }
      if (currentChatId === data.chatId) {
        try {
        
          const chatMessages = document.getElementById("chatMessages");
          const newMessage = document.createElement("div");
          newMessage.classList.add("message", "message-received");
          newMessage.innerHTML = decodeHTMLEntities(message);
          chatMessages.appendChild(newMessage);
          chatMessages.scrollTop = chatMessages.scrollHeight;
          loadExistingChats();
        } catch (error) {
          console.error("Failed to fetch chat name or save received message:", error);
        }  
      }
    });
  
  }

