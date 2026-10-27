// Stores the per-client API key in chrome.storage.local, which only this
// extension can read. The key is never shown again after saving.
const input = document.getElementById("api-key");
const statusEl = document.getElementById("status");

chrome.storage.local.get("etisApiKey").then(({ etisApiKey }) => {
  statusEl.textContent = etisApiKey ? "A key is saved." : "No key saved.";
});

document.getElementById("save").addEventListener("click", async () => {
  const key = input.value.trim();
  if (!key.startsWith("etis_")) {
    statusEl.textContent = "That does not look like an ETIS key (it starts with etis_).";
    return;
  }
  await chrome.storage.local.set({ etisApiKey: key });
  input.value = "";
  statusEl.textContent = "Saved.";
});

document.getElementById("clear").addEventListener("click", async () => {
  await chrome.storage.local.remove("etisApiKey");
  statusEl.textContent = "Key removed.";
});
