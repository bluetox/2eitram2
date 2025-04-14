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
        invoke("establish_ss", {dstUserId: userId}).then(console.log("did it")); 

      }
    };
    chatItemsContainer.appendChild(newChat);
  });
}

async function load_tauri() {
  if (window.__TAURI__) {
    loadExistingChats();
    await listenForMessages();

    document.getElementById("submit-password").addEventListener("click", checkPassword);
    document.getElementById("add-chat").addEventListener("click", openAddChatForm);
    document.getElementById("back-to-chats").addEventListener("click", closeChat);
    document.getElementById("submit-new-chat").addEventListener("click", submitNewChat);
  }
}
load_tauri();

async function checkPassword() {
  let password = document.getElementById("passwordInput").value;
  document.getElementById("passwordInput").value = null;
  const accountCred = await invoke("generate_dilithium_keys", {password: password});

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
  document.getElementById("chatMessages").innerHTML = "";
  console.log(chatId);
  try {
    const messages = await invoke("get_messages", {chatId: chatId});
    console.log(messages);

    messages.forEach((message) => {
      const chatMessages = document.getElementById("chatMessages");
      const newMessage = document.createElement("div");
      if (message.message_type === "sent") {
        newMessage.classList.add("message", "message-sent");
      } else {
        newMessage.classList.add("message", "message-received");
      }
      newMessage.innerText = message.content;
      chatMessages.appendChild(newMessage);
      chatMessages.scrollTop = chatMessages.scrollHeight;
    });

    console.log(`Loaded messages for chat: ${chatName}`);
  } catch (error) {
    console.error(`Failed to load messages for ${chatName}:`, error);
  }

  document.getElementById("send-message-button").onclick = async () => {
    const message = document.getElementById("chatInput").value;

    await invoke("send_message", {
      dstIdHexs: userId,
      messageString: message
    });
    console.log("sent one message");

    document.getElementById("chatInput").value = "";

    const chatMessages = document.getElementById("chatMessages");
    const newMessage = document.createElement("div");
    newMessage.classList.add("message", "message-sent");
    newMessage.innerText = message;
    chatMessages.appendChild(newMessage);
    await invoke("save_message", {chatId: chatId,senderId: userId, message: message});
    chatMessages.scrollTop = chatMessages.scrollHeight;
  };

  document.getElementById("container").style.transform = "translateX(-100vw)";
  document.getElementById("bottom-bar").style.transform = "translateX(-100vw)";
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

    try {
      
      const chatMessages = document.getElementById("chatMessages");
      const newMessage = document.createElement("div");
      newMessage.classList.add("message", "message-received");
      newMessage.innerText = message;
      chatMessages.appendChild(newMessage);
      chatMessages.scrollTop = chatMessages.scrollHeight;
    } catch (error) {
      console.error("Failed to fetch chat name or save received message:", error);
    }

  });

}

function closeChat() {
  document.getElementById("container").style.transform = "translateX(0)";
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
    const newChat = document.createElement("div");
    newChat.classList.add("chat-item");
    const chatId = await invoke("add_chat", {name: chatName, dstUserId: userId});

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
    chatMessageDiv.textContent = userId;

    chatContent.appendChild(chatNameDiv);
    chatContent.appendChild(chatMessageDiv);

    newChat.appendChild(chatAvatar);
    newChat.appendChild(chatContent);

    newChat.onclick = async () => { 
      if (await invoke("has_shared_secret", {chatId: chatId}) == true) {
        openChat(chatName, userId, chatId)
      }
      else {
        await invoke("establish_ss", {dstUserId: userId})
      }
    };
    const chatItemsContainer = document.getElementById("chatItems");
    chatItemsContainer.appendChild(newChat);


    console.log(`Inserted new chat with user ${userId}: ${message}`);
    closeAddChatForm();
  } else {
    alert("Please fill out both fields.");
  }
}

function openSettings() {
  alert("Settings menu (to be implemented)");
}
