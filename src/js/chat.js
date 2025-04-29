const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { isPermissionGranted, requestPermission, sendNotification, } = window.__TAURI__.notification;

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
  console.log(chatList);

  chatList.forEach((chat) => {
    const chatName = chat.chat_name;
    const userId = chat.dst_user_id;
    const chatId = chat.chat_id;

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
    const firstFive = userId.slice(0, 5);
    const lastFive = userId.slice(-5);
    chatMessageDiv.textContent = `${firstFive}...${lastFive}`;

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
    newChat.onclick = async () => { 
      if (await invoke("has_shared_secret", {chatId: chatId}) == true) {
        openChat(chatName, userId, chatId)
      }
      else {
        await invoke("establish_ss", {dstUserId: userId, chatId: chatId}).then(console.log("did it")); 

      }
    };
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
  if (password) {
    document.getElementById("passwordOverlay").style.display = "none";
    document.getElementById("container").style.display = "flex";
    password = null;
  } else {
    alert("Wrong password!");
  }
}

async function openChat(chatName, userId, chatId) {
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

        try {
          const button = newMessage.querySelector("button");
          if (button) {
            button.addEventListener("click", async () => {
              await invoke("send_message", {
                dstIdHexs: userId,
                messageString: "text"
              });
              console.log("Auto-response sent.");
            });
          }
        } catch (err) {
          console.warn("Button listener error:", err);
        }
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

  document.getElementById("send-message-button").onclick = async () => {
    const input = document.getElementById("chatInput");
    const message = input.value.trim();
    if (!message) return;

    await invoke("send_message", {
      chatId: chatId,
      dstIdHexs: userId,
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
  txt.innerHTML = html;
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
