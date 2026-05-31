"use strict";

const API_URL = "https://s-advanced-attendance-system.onrender.com";
// ===== Token Store ==========================================================
const Auth = {
  get token()   { return sessionStorage.getItem("att_token"); },
  get company() { return sessionStorage.getItem("att_company"); },
  set(token, company) {
    sessionStorage.setItem("att_token",   token);
    sessionStorage.setItem("att_company", company);
  },
  clear() {
    sessionStorage.removeItem("att_token");
    sessionStorage.removeItem("att_company");
  },
  isLoggedIn() { return !!this.token; }
};


// ===== Toast ================================================================
let toastTimer = null;
function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
}


// ===== API Fetch =============================================================
async function apiFetch(path, options = {}, requireAuth = true) {
  const headers = { "Content-Type": "application/json" };
  if (requireAuth) {
    if (!Auth.isLoggedIn()) { showAuthShell(); return; }
    headers["Authorization"] = `Bearer ${Auth.token}`;
  }
  const res  = await fetch(`${API_URL}${path}`, { headers, ...options });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    Auth.clear();
    showAuthShell();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}


// ===== Screen Switching =====================================================
function showAuthShell() {
  document.getElementById("auth-shell").classList.remove("hidden");
  document.getElementById("app-shell").classList.add("hidden");
}

function showAppShell() {
  document.getElementById("auth-shell").classList.add("hidden");
  document.getElementById("app-shell").classList.remove("hidden");
  document.getElementById("company-name-display").textContent = Auth.company || "Your Company";
  refreshDisplay();
}


// ===== Tab Switching =========================================================
function switchTab(tab) {
  document.getElementById("form-login").classList.toggle("hidden",    tab !== "login");
  document.getElementById("form-register").classList.toggle("hidden", tab !== "register");
  document.getElementById("tab-login").classList.toggle("active",    tab === "login");
  document.getElementById("tab-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-message").classList.add("hidden");
}

function showAuthMessage(msg, type = "error") {
  const el = document.getElementById("auth-message");
  el.textContent = msg;
  el.className   = `auth-message ${type}`;
}

function toggleEye(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (inp.type === "password") { inp.type = "text";     btn.textContent = "🙈"; }
  else                         { inp.type = "password"; btn.textContent = "👁"; }
}


// ===== Password Strength ====================================================
document.getElementById("reg-password")?.addEventListener("input", function () {
  const pw = this.value;
  const el = document.getElementById("pw-strength");
  if (!pw) { el.textContent = ""; el.className = "pw-strength"; return; }
  let score = 0;
  if (pw.length >= 8)  score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["", "Weak", "Fair", "Good", "Strong"];
  const classes = ["", "pw-weak", "pw-fair", "pw-good", "pw-strong"];
  el.textContent = labels[score] || "Weak";
  el.className   = `pw-strength ${classes[score] || "pw-weak"}`;
});


// ===== Register =============================================================
async function handleRegister() {
  const company  = document.getElementById("reg-company").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const phone    = document.getElementById("reg-phone").value.trim();
  const password = document.getElementById("reg-password").value;
  const password2= document.getElementById("reg-password2").value;
  const pin      = document.getElementById("reg-pin").value.trim();

  if (!company)             { showAuthMessage("Please enter your company/organisation name."); return; }
  if (!email)               { showAuthMessage("Please enter your email address."); return; }
  if (password.length < 8)  { showAuthMessage("Password must be at least 8 characters."); return; }
  if (password !== password2){ showAuthMessage("Passwords do not match."); return; }
  if (!/^\d{4,8}$/.test(pin)){ showAuthMessage("PIN must be 4–8 digits."); return; }

  const btn     = document.getElementById("btn-register");
  const spinner = document.getElementById("register-spinner");
  btn.disabled  = true;
  spinner.classList.remove("hidden");

  try {
    const res = await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ company, email, phone, password, pin })
    }, false);
    Auth.set(res.token, res.company);
    showAppShell();
    showToast(`Welcome to S Advanced Attendance, ${res.company}!`, "success");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}


// ===== Login ================================================================
async function handleLogin() {
  const email    = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;

  if (!email || !password) { showAuthMessage("Please enter your email and password."); return; }

  const btn     = document.getElementById("btn-login");
  const spinner = document.getElementById("login-spinner");
  btn.disabled  = true;
  spinner.classList.remove("hidden");

  try {
    const res = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    }, false);
    Auth.set(res.token, res.company);
    showAppShell();
    showToast(`Welcome back, ${res.company}!`, "success");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}


// ===== Logout ===============================================================
function handleLogout() {
  Auth.clear();
  showAuthShell();
  switchTab("login");
  showToast("Signed out successfully.", "success");
}


// ===== PIN Modal ============================================================
let pinResolve = null;
let pinReject  = null;

function requestPin() {
  return new Promise((resolve, reject) => {
    pinResolve = resolve;
    pinReject  = reject;
    // Clear boxes
    document.querySelectorAll(".pin-box").forEach(b => b.value = "");
    document.getElementById("pin-error").classList.add("hidden");
    openModal("pin-modal");
    document.querySelector(".pin-box").focus();
  });
}

// PIN box navigation
document.getElementById("pin-inputs").addEventListener("input", e => {
  if (!e.target.classList.contains("pin-box")) return;
  const boxes = [...document.querySelectorAll(".pin-box")];
  const idx   = boxes.indexOf(e.target);
  if (e.target.value && idx < boxes.length - 1) boxes[idx + 1].focus();
});

document.getElementById("pin-inputs").addEventListener("keydown", e => {
  if (!e.target.classList.contains("pin-box")) return;
  const boxes = [...document.querySelectorAll(".pin-box")];
  const idx   = boxes.indexOf(e.target);
  if (e.key === "Backspace" && !e.target.value && idx > 0) boxes[idx - 1].focus();
  if (e.key === "Enter") confirmPin();
});

async function confirmPin() {
  const pin = [...document.querySelectorAll(".pin-box")].map(b => b.value).join("");
  if (pin.length < 4) {
    document.getElementById("pin-error").textContent = "Please enter your full PIN.";
    document.getElementById("pin-error").classList.remove("hidden");
    return;
  }
  const btn = document.getElementById("btn-confirm-pin");
  btn.disabled = true;
  try {
    await apiFetch("/auth/verify-pin", { method: "POST", body: JSON.stringify({ pin }) });
    closeModal();
    if (pinResolve) pinResolve(true);
  } catch (err) {
    document.getElementById("pin-error").textContent = "Incorrect PIN. Try again.";
    document.getElementById("pin-error").classList.remove("hidden");
    document.querySelectorAll(".pin-box").forEach(b => b.value = "");
    document.querySelector(".pin-box").focus();
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("btn-confirm-pin").addEventListener("click", confirmPin);
document.getElementById("btn-close-pin").addEventListener("click",  () => {
  closeModal();
  if (pinReject) pinReject(new Error("PIN cancelled"));
});
document.getElementById("btn-close-pin2").addEventListener("click", () => {
  closeModal();
  if (pinReject) pinReject(new Error("PIN cancelled"));
});

// Helper: run an action only after PIN confirmed
async function withPin(action) {
  try {
    await requestPin();
    await action();
  } catch (err) {
    if (err.message !== "PIN cancelled") showToast(err.message, "error");
  }
}


// ===== Staff ID =============================================================
function generateStaffId() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `S-${ts}-${rand}`;
}

function sanitize(str, maxLen = 120) {
  if (!str) return "";
  return String(str).replace(/<[^>]*>/g, "").trim().substring(0, maxLen);
}


// ===== Staff CRUD ===========================================================
async function addStaff(name, email, phone) {
  const id = generateStaffId();
  await apiFetch("/staff", {
    method: "POST",
    body: JSON.stringify({ id, name, email, phone })
  });
  showToast(`Staff '${name}' added (${id})`, "success");
  refreshDisplay();
}

async function updateStaff(id, name, email, phone) {
  await apiFetch(`/staff/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ name, email, phone })
  });
  showToast(`Staff '${id}' updated`, "success");
  refreshDisplay();
}

async function removeStaff(id) {
  if (!confirm(`Remove staff '${id}'? Their attendance records will also be deleted.`)) return;
  await apiFetch(`/staff/${encodeURIComponent(id)}`, { method: "DELETE" });
  showToast(`Staff '${id}' removed`, "success");
  refreshDisplay();
}


// ===== Attendance ===========================================================
async function recordAttendance(type, staffId) {
  await apiFetch("/attendance", {
    method: "POST",
    body: JSON.stringify({ staff_id: staffId, action: type })
  });
  const label = type === "check_in" ? "checked in" : "checked out";
  showToast(`${staffId} ${label}`, "success");
  refreshDisplay();
}


// ===== Fetch Helpers ========================================================
async function listStaff()      { return apiFetch("/staff"); }
async function listAttendance() { return apiFetch("/attendance"); }


// ===== Rendering ============================================================
async function renderStaffOptions() {
  const select  = document.getElementById("attendance-staff");
  const current = select.value;
  select.innerHTML = '<option value="">-- select staff --</option>';
  const staff = await listStaff();
  staff.forEach(person => {
    const opt = document.createElement("option");
    opt.value       = person.id;
    opt.textContent = `${person.id} • ${sanitize(person.name)}`;
    select.appendChild(opt);
  });
  if (current) select.value = current;
}

async function renderStaffTable() {
  const tbody = document.querySelector("#staff-table tbody");
  tbody.innerHTML = "";
  const staff = await listStaff();
  staff.forEach(person => {
    const row = document.createElement("tr");
    [person.id, person.name, person.email || "—", person.phone || "—"].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("staff-count").textContent = `${staff.length} staff`;
}

async function renderAttendanceTable() {
  const tbody = document.querySelector("#attendance-table tbody");
  tbody.innerHTML = "";
  const records = await listAttendance();
  records.forEach(record => {
    const date = new Date(record.timestamp + "Z");
    const row  = document.createElement("tr");
    [
      date.toLocaleDateString(),
      record.name ? `${record.staff_id} • ${record.name}` : record.staff_id,
      record.action === "check_in" ? "✅ Check In" : "🚪 Check Out",
      date.toLocaleTimeString()
    ].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("attendance-count").textContent = `${records.length} entries`;
}

async function refreshDisplay() {
  try {
    await Promise.all([
      renderStaffOptions(),
      renderStaffTable(),
      renderAttendanceTable()
    ]);
  } catch (err) {
    showToast(`Failed to load data: ${err.message}`, "error");
  }
}


// ===== Update Mode ==========================================================
let updateMode     = false;
let updateTargetId = null;

function enterUpdateMode(staffId, name, email, phone) {
  updateMode     = true;
  updateTargetId = staffId;
  document.getElementById("staff-name").value  = name  || "";
  document.getElementById("staff-email").value = email || "";
  document.getElementById("staff-phone").value = phone || "";
  document.getElementById("staff-id").value    = staffId;
  document.getElementById("update-banner-id").textContent = staffId;
  document.getElementById("update-banner").classList.remove("hidden");
  document.getElementById("btn-submit-staff").textContent = "Save Changes";
  document.getElementById("staff-name").focus();
}

function exitUpdateMode() {
  updateMode     = false;
  updateTargetId = null;
  ["staff-name","staff-email","staff-phone","staff-id"].forEach(id =>
    document.getElementById(id).value = ""
  );
  document.getElementById("update-banner").classList.add("hidden");
  document.getElementById("btn-submit-staff").textContent = "Add Staff";
}


// ===== Staff Form Submit ====================================================
document.getElementById("btn-submit-staff").addEventListener("click", async () => {
  const name  = sanitize(document.getElementById("staff-name").value,  80);
  const email = sanitize(document.getElementById("staff-email").value, 120);
  const phone = sanitize(document.getElementById("staff-phone").value, 30);
  if (!name) { showToast("Please enter a name.", "error"); return; }

  const btn = document.getElementById("btn-submit-staff");
  btn.disabled = true;

  try {
    if (updateMode) {
      await withPin(async () => {
        await updateStaff(updateTargetId, name, email, phone);
        exitUpdateMode();
      });
    } else {
      await withPin(async () => {
        await addStaff(name, email, phone);
        document.getElementById("staff-name").value  = "";
        document.getElementById("staff-email").value = "";
        document.getElementById("staff-phone").value = "";
      });
    }
  } catch (err) {
    if (err.message !== "PIN cancelled") showToast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-cancel-update").addEventListener("click", exitUpdateMode);

document.getElementById("btn-view-staff").addEventListener("click", async () => {
  await refreshDisplay();
  showToast("Data refreshed!", "success");
});


// ===== QR Code ==============================================================
function showQrForStaff(staffId) {
  const qrPreview = document.getElementById("qr-preview");
  qrPreview.innerHTML = "";
  const wrapper = document.createElement("div");
  qrPreview.appendChild(wrapper);
  new QRCode(wrapper, {
    text: staffId, width: 280, height: 280,
    colorDark: "#000000", colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.H
  });
  setTimeout(() => {
    const img    = wrapper.querySelector("img");
    const canvas = wrapper.querySelector("canvas");
    const dl     = document.getElementById("download-qr");
    if (img?.src)  dl.href = img.src;
    else if (canvas) dl.href = canvas.toDataURL("image/png");
    dl.download = `qr-${staffId}.png`;
  }, 300);
  openModal("qr-modal");
}


// ===== QR Scanner ===========================================================
let html5Scanner = null;

function startScan(type) {
  document.getElementById("scanner-title").textContent =
    type === "check_in" ? "📷 Scan QR – Check In" : "📷 Scan QR – Check Out";
  openModal("scanner-modal");
  const container = document.getElementById("scanner-container");
  container.innerHTML = '<div id="qr-reader" style="width:100%"></div>';
  html5Scanner = new Html5Qrcode("qr-reader");
  html5Scanner.start(
    { facingMode: "environment" },
    { fps: 10, qrbox: { width: 250, height: 250 } },
    async decodedText => {
      const staffId = sanitize(decodedText, 20);
      closeModal();
      try { await recordAttendance(type, staffId); }
      catch (err) { showToast(err.message, "error"); }
    }
  ).catch(() => {
    showToast("Unable to start camera. Check permissions.", "error");
    closeModal();
  });
}


// ===== Modal Helpers ========================================================
function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
  document.querySelectorAll(".modal").forEach(m => m.classList.add("hidden"));
  if (html5Scanner) {
    html5Scanner.stop().catch(() => null);
    html5Scanner = null;
  }
}

function openModal(id) {
  document.getElementById("modal-overlay").classList.remove("hidden");
  document.getElementById(id).classList.remove("hidden");
}

document.getElementById("modal-overlay").addEventListener("click", e => {
  // Don't close if pin modal is open and user clicks overlay
  if (!document.getElementById("pin-modal").classList.contains("hidden")) return;
  closeModal();
});
document.getElementById("btn-close-scanner").addEventListener("click", closeModal);
document.getElementById("btn-close-qr").addEventListener("click",      closeModal);
document.getElementById("btn-stop-scanner").addEventListener("click",  closeModal);
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && document.getElementById("pin-modal").classList.contains("hidden")) closeModal();
});


// ===== Context Menu =========================================================
const staffTableBody = document.querySelector("#staff-table tbody");
const contextMenu    = document.getElementById("context-menu");
let contextTargetId  = null;

function showContextMenu(x, y, row) {
  staffTableBody.querySelectorAll("tr").forEach(r => r.classList.remove("selected"));
  row.classList.add("selected");
  contextTargetId = row.children[0].textContent;
  contextMenu.style.top  = `${Math.min(y, window.innerHeight - 160)}px`;
  contextMenu.style.left = `${Math.min(x, window.innerWidth  - 190)}px`;
  contextMenu.classList.remove("hidden");
}

staffTableBody.addEventListener("contextmenu", e => {
  e.preventDefault();
  const row = e.target.closest("tr");
  if (!row) return;
  showContextMenu(e.pageX, e.pageY, row);
});

let longPressTimer = null;
staffTableBody.addEventListener("touchstart", e => {
  const row = e.target.closest("tr");
  if (!row) return;
  longPressTimer = setTimeout(() => {
    const touch = e.touches[0];
    showContextMenu(touch.pageX, touch.pageY, row);
  }, 600);
}, { passive: true });
staffTableBody.addEventListener("touchend", () => clearTimeout(longPressTimer), { passive: true });

document.addEventListener("click", e => {
  if (!contextMenu.contains(e.target)) contextMenu.classList.add("hidden");
});

document.querySelectorAll("#context-menu button").forEach(btn => {
  btn.addEventListener("click", async e => {
    const action = e.currentTarget.dataset.action;
    const id     = contextTargetId;
    contextMenu.classList.add("hidden");
    if (!id) return;

    if (action === "update") {
      try {
        const staff  = await listStaff();
        const person = staff.find(s => s.id === id);
        if (person) {
          enterUpdateMode(person.id, person.name, person.email, person.phone);
          document.getElementById("staff-form").scrollIntoView({ behavior: "smooth" });
        }
      } catch (err) { showToast(err.message, "error"); }
    }

    if (action === "remove") {
      await withPin(async () => {
        await removeStaff(id);
      });
    }

    if (action === "qr") showQrForStaff(id);
  });
});


// ===== Scan Buttons =========================================================
document.getElementById("btn-scan-checkin").addEventListener("click",  () => startScan("check_in"));
document.getElementById("btn-scan-checkout").addEventListener("click", () => startScan("check_out"));


// ===== Enter key in auth forms ==============================================
document.getElementById("login-password").addEventListener("keydown",   e => { if (e.key === "Enter") handleLogin(); });
document.getElementById("reg-pin").addEventListener("keydown",          e => { if (e.key === "Enter") handleRegister(); });


// ===== Init =================================================================
if (Auth.isLoggedIn()) {
  showAppShell();
} else {
  showAuthShell();
}
