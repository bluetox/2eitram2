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
      }, 100);
    }
  });
}

waitForTauri();

import { startWebcam, stopWebcam } from './chat_helpers/video.js';
import { start_listeners } from './chat_helpers/events.js';
import { isHTML, decodeHTMLEntities } from './chat_helpers/sanitize.js';
import { loadListeners } from './chat_helpers/listener.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

export let currentChatId = null;

export async function loadExistingChats() {
  const chatItemsContainer = document.getElementById("chatItems");
  const chatList = await invoke("get_chats");
  console.log(chatList);

  const fragment = document.createDocumentFragment();

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
        await invoke("delete_chat", { chatId: chatId });
        newChat.remove();
      }, 800);
    });

    newChat.addEventListener("mouseup", () => {
      clearTimeout(timer);
    });

    if (chatType === "private") {
      newChat.onclick = async () => { 
        if (await invoke("has_shared_secret", { chatId: chatId }) == true) {
          openChat(chatName, chatId, chatType);
        } else {
          await invoke("establish_ss", { chatId: chatId }).then(console.log("did it"));
        }
      };
    } else if (chatType === "group") {
      newChat.onclick = () => {
        openChat(chatName, chatId, chatType);
      };
    }

    fragment.appendChild(newChat);
  });
  chatItemsContainer.innerHTML = "";
  chatItemsContainer.appendChild(fragment);
}

async function load_tauri() {
    await invoke("terminate_any_client");

    loadExistingChats();

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

async function checkPassword() {
  let password = document.getElementById("passwordInput").value;
  document.getElementById("passwordInput").value = null;
  const userId = await invoke("generate_dilithium_keys", {password: password});
  document.getElementById("user-id").textContent = userId;
  document.getElementById("copy-perso-id").addEventListener('click', async () => {
    await navigator.clipboard.writeText(userId);
  })
  document.getElementById('group-chat').addEventListener('click', async () => {
    await invoke("create_groupe", {members: ["ea587497159413fc8ca0da3b2071b2ac02c08535a2054d136b1677f2b923aa92", "5787b3af9a3bd9fcf342d679cd2038f421cf8b39b2a2846a83d0ffbbcc340b26", "a949a57316ce51bc5aefb4802d0ba120d850f161bdeab7b20685330152330745", "ffe46ad3736ee8a03eeb672bd73468efaa6584f88e76b20da1900b15fdc93960"], groupName: "other group"})
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
  let params = await invoke("get_params", {chatId: chatId});
  console.log(params);
  document.getElementById("chatTitle").innerText = params.nickname;

  const chatMessages = document.getElementById("chatMessages");
  chatMessages.innerHTML = "";

  document.getElementById("header-data").addEventListener('click', () => {
    document.getElementById("chat-parameter-page").style.display = 'flex';
  });

  currentChatId = chatId;

  try {
    const messages = await invoke("get_messages", { chatId });

    messages.forEach((message) => {
      const newMessage = document.createElement("div");
      newMessage.classList.add("message", message.message_type === "sent" ? "message-sent" : "message-received");
      if (message.message_type === "sent") {
        newMessage.style.backgroundColor = params.bubble_color;
      }
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
      newMessage.style.backgroundColor = params.bubble_color;
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
      newMessage.style.backgroundColor = params.bubble_color;
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

function closeChat() {
  document.getElementById("container").style.transform = "translateX(0)";
  currentChatId = null;
}

function openAddChatChoice() {
  document.getElementById("create-conv-container").style.display = "flex";
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
    const _ = await invoke("create_private_chat", {name: chatName, dstUserId: userId});
    loadExistingChats();
    console.log(`Inserted new chat with user ${userId}: ${message}`);
    closeAddChatForm();
  } else {
    alert("Please fill out both fields.");
  }
}

load_tauri();
start_listeners();

listen("received-invite"), async (event) => {
  console.log(event);
    loadExistingChats();
    console.log("received invite");
}

loadListeners()