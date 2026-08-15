const signedOut = document.getElementById("signed-out");
const signedIn = document.getElementById("signed-in");

async function invokeCli(args) {
  // Tauri command bridge; falls back to demo state in browser preview
  if (window.__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("run_wsl", { args });
  }
  return { demo: true, output: "demo mode" };
}

document.getElementById("sign-in").addEventListener("click", async () => {
  await invokeCli(["login", "--email", "alice@example.com"]);
  signedOut.classList.add("hidden");
  signedIn.classList.remove("hidden");
  document.getElementById("email").textContent = "alice@example.com";
  document.getElementById("device").textContent = "This Mac";
  document.getElementById("networks").innerHTML = `
    <li><span>Development</span><span>Connected</span></li>
    <li><span>DTAP</span><span>Connected</span></li>
    <li><span>Registry</span><span>Connected</span></li>
  `;
});

document.getElementById("disconnect").addEventListener("click", async () => {
  await invokeCli(["disconnect"]);
  document.getElementById("networks").innerHTML = `<li><span>No active networks</span></li>`;
});
