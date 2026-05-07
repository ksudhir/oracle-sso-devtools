const form = document.getElementById("chatForm");
const promptInput = document.getElementById("promptInput");
const messagesContainer = document.getElementById("messages");
const sendButton = document.getElementById("sendButton");
const clearButton = document.getElementById("clearButton");
const statusText = document.getElementById("statusText");
const endpointInput = document.getElementById("endpointInput");
const modelInput = document.getElementById("modelInput");
const wireApiSelect = document.getElementById("wireApiSelect");
const settingsSource = document.getElementById("settingsSource");
const settingsNote = document.getElementById("settingsNote");
const providerBadge = document.getElementById("providerBadge");
const modelBadge = document.getElementById("modelBadge");
const apiBadge = document.getElementById("apiBadge");
const conversationCount = document.getElementById("conversationCount");

const conversation = [];
let defaultProviderLabel = "Custom";

loadDefaults();
updateConversationCount();

promptInput.addEventListener("input", autoResize);
promptInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});

clearButton.addEventListener("click", () => {
  conversation.length = 0;
  messagesContainer.innerHTML = `
    <article class="message assistant intro-message">
      <div class="message-meta">
        <span>Assistant</span>
        <span>Reset</span>
      </div>
      <p>Conversation cleared. Ask a new question whenever you're ready.</p>
    </article>
  `;
  updateConversationCount();
  setStatus("Chat cleared.");
  promptInput.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const content = promptInput.value.trim();
  if (!content) {
    return;
  }

  const userMessage = { role: "user", content };
  conversation.push(userMessage);
  appendMessage("user", content, "You");
  updateConversationCount();
  promptInput.value = "";
  autoResize();
  setBusy(true);
  setStatus("Waiting for the model response...");

  const loadingCard = appendMessage("assistant", "Thinking...", "Assistant");
  loadingCard.classList.add("loading");

  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        messages: conversation,
        config: {
          baseUrl: endpointInput.value.trim(),
          model: modelInput.value.trim(),
          wireApi: wireApiSelect.value
        }
      })
    });

    const payload = await response.json();
    loadingCard.remove();

    if (!response.ok) {
      appendMessage("error", payload.error || "Request failed.", "System");
      setStatus("The request failed. Check your endpoint settings.");
      return;
    }

    conversation.push({ role: "assistant", content: payload.message });
    appendMessage("assistant", payload.message, "Assistant");
    updateConversationCount();
    setStatus("Response received.");
  } catch (error) {
    loadingCard.remove();
    appendMessage(
      "error",
      "Unable to reach the backend. Make sure the local server is running.",
      "System"
    );
    setStatus("Backend connection failed.");
  } finally {
    setBusy(false);
    promptInput.focus();
  }
});

async function loadDefaults() {
  try {
    const response = await fetch("/api/config");
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Failed to load defaults.");
    }

    endpointInput.value = payload.defaults.baseUrl || "";
    modelInput.value = payload.defaults.model || "";
    wireApiSelect.value = payload.defaults.wireApi || "chat_completions";
    defaultProviderLabel = payload.defaults.providerName || "Custom";
    settingsSource.textContent = payload.source.codexConfigLoaded ? "Codex" : "Env";
    providerBadge.textContent = defaultProviderLabel;
    modelBadge.textContent = payload.defaults.model || "Unset";
    apiBadge.textContent = formatWireApiLabel(payload.defaults.wireApi);
    settingsNote.textContent = payload.source.hasApiKey
      ? `Using ${payload.defaults.providerName} defaults on the server. The API key stays backend-only.`
      : "Defaults loaded, but no API key was detected on the server yet.";
  } catch (error) {
    defaultProviderLabel = "Manual";
    settingsSource.textContent = "Manual";
    providerBadge.textContent = defaultProviderLabel;
    modelBadge.textContent = "Unset";
    apiBadge.textContent = formatWireApiLabel(wireApiSelect.value);
    settingsNote.textContent =
      "Could not load backend defaults, so you can enter the endpoint and model manually.";
  }
}

endpointInput.addEventListener("input", () => {
  providerBadge.textContent = endpointInput.value.trim()
    ? "Override"
    : defaultProviderLabel;
});

modelInput.addEventListener("input", () => {
  modelBadge.textContent = modelInput.value.trim() || "Unset";
});

wireApiSelect.addEventListener("change", () => {
  apiBadge.textContent = formatWireApiLabel(wireApiSelect.value);
});

function appendMessage(role, content, author) {
  const card = document.createElement("article");
  card.className = `message ${role}`;
  card.innerHTML = `
    <div class="message-meta">
      <span>${escapeHtml(author)}</span>
      <span>${new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
      })}</span>
    </div>
    <p>${escapeHtml(content)}</p>
  `;
  messagesContainer.appendChild(card);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
  return card;
}

function setBusy(isBusy) {
  sendButton.disabled = isBusy;
  clearButton.disabled = isBusy;
  promptInput.disabled = isBusy;
  endpointInput.disabled = isBusy;
  modelInput.disabled = isBusy;
  wireApiSelect.disabled = isBusy;
}

function setStatus(message) {
  statusText.textContent = message;
}

function updateConversationCount() {
  conversationCount.textContent = String(conversation.length);
}

function autoResize() {
  promptInput.style.height = "auto";
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 180)}px`;
}

function formatWireApiLabel(value) {
  if (value === "responses") {
    return "Responses";
  }

  return "Chat API";
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
