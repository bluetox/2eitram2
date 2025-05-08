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
const { isPermissionGranted, requestPermission, sendNotification, } = window.__TAURI__.notification;

const video          = document.getElementById('videoElement');
const receivedCanvas = document.getElementById('receivedCanvas');
const receivedCtx    = receivedCanvas.getContext('2d');

const offscreenCanvas = document.createElement('canvas');
const ctx             = offscreenCanvas.getContext('2d');

let mediaStream = null;
let rafId       = null;

const strictConfig = {
    ALLOWED_TAGS: [
      'h1','h2','h3','h4','h5','h6',
      'p','div','span','pre','code','blockquote',
      'ul','ol','li','dl','dt','dd',
      'img','a','table','thead','tbody','tfoot','tr','th','td',
      'br','hr','strong','em','u','s','sub','sup',
      'small','big','figure','figcaption'
    ],
  
    ALLOWED_ATTR: [
      'href','title','alt','src','srcset','width','height',
      'colspan','rowspan','align','valign',
      'class','style','name'
    ],

    FORBID_ATTR: [/^on/i, 'id'],
  
    ALLOWED_CSS_PROPERTIES: [
      'color','background-color','font-size','font-weight','font-style',
      'text-decoration','text-align','margin','padding','border',
      'width','height','max-width','max-height'
    ],
  
    ALLOWED_URI_REGEXP: /^(?:[#\/][^"\s]*)|(?:data:image\/[a-zA-Z0-9+\/=;,%\-_.]+)$/,

    WHOLE_DOCUMENT: false,
    SAFE_FOR_TEMPLATES: true
  };
  
let permissionGranted = await isPermissionGranted();

if (!permissionGranted) {
  const permission = await requestPermission();
  permissionGranted = permission === 'granted';
}

if (permissionGranted) {
  sendNotification({ title: 'Tauri', body: 'Tauri is awesome!' });
}

async function loadExistingChats() {
  const chatItemsContainer = document.getElementById("chatItems");
  chatItemsContainer.innerHTML = "";
  const chatList = await invoke("get_chats");

  chatList.forEach((chat) => {
    const chatName = chat.chat_name;
    const chatId = chat.chat_id;
    const chatType = chat.chat_type;

    const newChat = document.createElement("div");
    newChat.classList.add("chat-item");
    newChat.id = chatId;

    const chatAvatar = document.createElement("div");
    chatAvatar.classList.add("chat-avatar");
    chatAvatar.textContent = chatName.charAt(0).toUpperCase();

    const chatContent = document.createElement("div");
    chatContent.classList.add("chat-content");

    const chatNameDiv = document.createElement("div");
    chatNameDiv.classList.add("chat-name");
    chatNameDiv.textContent = chatName;

    const chatMessageDiv = document.createElement("div");
    chatMessageDiv.classList.add("chat-message");

    chatMessageDiv.textContent = `user id placeholder`;

    chatContent.appendChild(chatNameDiv);
    chatContent.appendChild(chatMessageDiv);

    newChat.appendChild(chatAvatar);
    newChat.appendChild(chatContent);
    let timer;

    newChat.addEventListener("mousedown", async () => {
        timer = setTimeout(async () => {
          await invoke("delete_chat", {chatId: chatId})
          newChat.remove();
        }, 800);
    });
    newChat.addEventListener("mouseup", () => {
        clearTimeout(timer);
    });
    if (chatType === "private") {
      newChat.onclick = async () => { 
        if (await invoke("has_shared_secret", {chatId: chatId}) == true) {
          openChat(chatName, chatId, chatType);
        }
        else {
          await invoke("establish_ss", {chatId: chatId}).then(console.log("did it")); 
  
        }
      };
    } else if (chatType === "group") {
        newChat.onclick = () => {
          openChat(chatName, chatId, chatType);
        };
    }
    chatItemsContainer.appendChild(newChat);
  });
}

async function load_tauri() {
  if (window.__TAURI__) {
    await invoke("terminate_any_client");
    loadExistingChats();
    await listenForMessages();
    document.getElementById("submit-password").addEventListener("click", checkPassword);
    document.getElementById("add-chat").addEventListener("click", openAddChatChoice);
    document.getElementById("back-to-chats").addEventListener("click", closeChat);
    document.getElementById("submit-new-chat").addEventListener("click", submitNewChat);
    const toggleBtn = document.getElementById('open-sidebar');
    const disconnect = document.getElementById('disconnect');
    const params_button = document.getElementById('settings-button');
    const parameterExit = document.getElementById('parameter-exit');
    const addConvExit = document.getElementById('add-conv-exit');
    addConvExit.addEventListener('click', () => {
      document.getElementById('create-conv-container').style.display = 'none';
    });
    parameterExit.addEventListener('click', () => {
      document.getElementById('parameter-view').style.display = 'none';
    });
    params_button.addEventListener('click', () => {
      console.log('did settings');
      document.getElementById('parameter-view').style.display = 'flex';
    });
    
    disconnect.addEventListener('click', () => {
      window.location = "index.html";
    })
    const sidebar = document.getElementById('sidebar');
    
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('active');
        const filter = document.getElementById("dark-sidebar-filter")
        filter.style.display = "flex";
        filter.addEventListener('click', () => {
          sidebar.classList.remove('active');
          filter.style.display = "none";
        })
      });
    
  }
}
load_tauri();

async function checkPassword() {
  let password = document.getElementById("passwordInput").value;
  document.getElementById("passwordInput").value = null;
  const userId = await invoke("generate_dilithium_keys", {password: password});
  document.getElementById("user-id").textContent = userId;
  document.getElementById("copy-perso-id").addEventListener('click', async () => {
    await navigator.clipboard.writeText(userId);
  })
  document.getElementById('group-chat').addEventListener('click', async () => {
    await invoke("create_groupe", {members: ["e29a09f0613616e0eb73d1f22ab561eebe1dc24f979d11fdf95f0f3a3f9bc5ed", "e6935a27bc6ba7780124a6c54da097b78e3585c9fb20ead106b2a5ebd1b60452"], groupName: "other group"})
  })
  if (password) {
    document.getElementById("passwordOverlay").style.display = "none";
    document.getElementById("container").style.display = "flex";
    password = null;
  } else {
    alert("Wrong password!");
  }
}

async function openChat(chatName, chatId, chatType) {
  document.getElementById("chatTitle").innerText = chatName;
  const chatMessages = document.getElementById("chatMessages");
  chatMessages.innerHTML = "";

  console.log("Opening chat:", chatId);

  try {
    const messages = await invoke("get_messages", { chatId });

    messages.forEach((message) => {
      const newMessage = document.createElement("div");
      newMessage.classList.add("message", message.message_type === "sent" ? "message-sent" : "message-received");

      if (isHTML(message.content)) {
        newMessage.innerHTML = decodeHTMLEntities(message.content);
      } else {
        newMessage.innerText = message.content;
      }

      chatMessages.appendChild(newMessage);
      chatMessages.scrollTop = chatMessages.scrollHeight;
    });

    console.log(`Loaded ${messages.length} messages for chat: ${chatName}`);
  } catch (error) {
    console.error(`Failed to load messages for ${chatName}:`, error);
  }

  document.getElementById("video-call-button").addEventListener('click', async () => {
    document.getElementById("video-call-container").style.display = "flex";
    await startWebcam(chatId);
  });
  
  document.getElementById("exit-chat").addEventListener('click', () => {
    document.getElementById("video-call-container").style.display = "none";
    stopWebcam();
  });
  if (chatType === "private") {
    document.getElementById("send-message-button").onclick = async () => {
      const input = document.getElementById("chatInput");
      const message = input.value.trim();
        await invoke("send_message", {
          chatId: chatId,
          messageString: message
        });
      
      loadExistingChats();

      input.value = "";

      const newMessage = document.createElement("div");
      newMessage.classList.add("message", "message-sent");
      newMessage.innerText = message;
      chatMessages.appendChild(newMessage);

      chatMessages.scrollTop = chatMessages.scrollHeight;
    };
  } else if (chatType === "group") {
    document.getElementById("send-message-button").onclick = async () => {
      const input = document.getElementById("chatInput");
      const message = input.value.trim();
        await invoke("send_group_message", {
          chatId: chatId,
          message: message
        });
        

      
      loadExistingChats();

      input.value = "";

      const newMessage = document.createElement("div");
      newMessage.classList.add("message", "message-sent");
      newMessage.addEventListener('click', async () => {
        const newMember = prompt("Enter new member id:");
        await invoke("add_group_member", {chatId: chatId, userId: newMember, groupName: chatName})
      });
      newMessage.innerText = message;
      chatMessages.appendChild(newMessage);

      chatMessages.scrollTop = chatMessages.scrollHeight;
    };
  }
  document.getElementById("container").style.transform = "translateX(-100vw)";
  document.getElementById("bottom-bar").style.transform = "translateX(-100vw)";
}

function isHTML(str) {
  const doc = new DOMParser().parseFromString(str, "text/html");
  return Array.from(doc.body.childNodes).some((node) => node.nodeType === 1);
}

async function listenForInvites() {
  listen("new-chat"), async () => {
    loadExistingChats();
  }
}
listenForInvites();
async function listenForMessages() {
  listen("received-message", async (event) => {
    const data = JSON.parse(event.payload);
    const message = data.message;
    const userId = data.source;
    if (!userId) {
      console.error("Error: userId is missing for received message.");
      return;
    }

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

  });

}

function decodeHTMLEntities(html) {
  const txt = document.createElement("textarea");
  txt.innerHTML = DOMPurify.sanitize(html, strictConfig);
  return txt.value;
}

function closeChat() {
  document.getElementById("container").style.transform = "translateX(0)";
}

function openAddChatChoice() {
  document.getElementById("create-conv-container").style.display = "flex";
  document.getElementById("create-group-chat").addEventListener('click', async () => {
    alert("this feature is currently under developement");
    //await invoke("create_group_chat", {chatName: "chatTest", members: ["f79dfc952f269c10569948092cdfaba3e1c88d38b7c32074bce983f69947fdf8", "ad254ceed942460c3a1bceb3a3ec7655cb71db3fff5eec4128edf3cd095044f4", "a8ef6e1e0aeafca616cc543af19231125992afa3f870f6e6be6d1bf46d5edcfb", "2c5a582f1f876a3c445e3fb732fae513b5c8b5e3ab316db7dd82a858b61ae1fe"]});
  });
  document.getElementById("create-private-chat").addEventListener('click', async () => {
    document.getElementById("create-conv-container").style.display = "none";
    openAddChatForm();
  });
}

function openAddChatForm() {
  document.getElementById("addChatForm").style.display = "flex";
}

function closeAddChatForm() {
  document.getElementById("addChatForm").style.display = "none";
}
function isValid32ByteHex(hex) {
  return /^[0-9a-fA-F]{64}$/.test(hex);
}
async function submitNewChat() {
  const chatName = document.getElementById("newChatName").value;
  const userId = document.getElementById("newUserId").value;
  const message = "Chat started";

  if (chatName && userId) {
    if (!isValid32ByteHex(userId)) {
      return
    }
    const chatId = await invoke("create_private_chat", {name: chatName, dstUserId: userId});
    loadExistingChats();
    console.log(`Inserted new chat with user ${userId}: ${message}`);
    closeAddChatForm();
  } else {
    alert("Please fill out both fields.");
  }
}

function openSettings() {
  alert("Settings menu (to be implemented)");
}

async function startWebcam(userId) {
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

    track.addEventListener('ended', () => cancelAnimationFrame(rafId));
    track.addEventListener('mute',  () => cancelAnimationFrame(rafId));

    rafId = requestAnimationFrame(function loop() {
      captureAndSendFrame(userId);
      rafId = requestAnimationFrame(loop);
    });
  } catch (err) {
    console.error("Webcam access failed:", err);
  }
}
function stopWebcam() {
  // 1) Cancel the animation‑frame loop
  if (rafId !== null) {
    cancelAnimationFrame(rafId);
    rafId = null;
  }

  // 2) Stop all tracks on the MediaStream
  if (mediaStream) {
    mediaStream.getTracks().forEach(track => track.stop());
    mediaStream = null;
  }

  // 3) Un‑bind the video element
  video.srcObject = null;

  console.log("Webcam stopped.");
}
let sending = Promise.resolve();
function applyTrackSettings(track) {
  const settings = track.getSettings();
  offscreenCanvas.width  = settings.width  || video.videoWidth;
  offscreenCanvas.height = settings.height || video.videoHeight;
}

async function captureAndSendFrame(userId) {
  const w = offscreenCanvas.width, h = offscreenCanvas.height;
  ctx.drawImage(video, 0, 0, w, h);

  let compressionQuality = 0.8;
  sending = sending.then(() => new Promise(resolve => {
    offscreenCanvas.toBlob(async blob => {
      if (!blob) return resolve();
      const arrayBuffer = await blob.arrayBuffer();
      const img = new Uint8Array(arrayBuffer);

      // include a counter if you like
      const header = new Uint32Array([w, h]);
      const payload = new Uint8Array(8 + img.length);
      payload.set(new Uint8Array(header.buffer), 0);
      payload.set(img, 8);

      await invoke("handle_frame_rgba", {
        frame: { data: Array.from(payload), width: w, height: h, format: "jpeg" },
        userId
      });
      resolve();
    }, "image/jpeg", compressionQuality);
  }));
}

listen("received-video", async (event) => {

  const compressedBytes = event.payload;
  const uint8Array = new Uint8Array(compressedBytes);
  const view = new DataView(uint8Array.buffer);

  // ← read little‑endian so we get the right numbers back
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
