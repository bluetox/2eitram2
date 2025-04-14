const { invoke } = window.__TAURI__.core;

let step = 1;
let tempProfileName = '';
let tempPassword = '';
let tempMnemonic = '';
console.log(await invoke("generate_mnemonic"));
async function load_profiles() {
  let profiles = await invoke("get_profiles");
  const profilesDiv = document.getElementById('profiles');
  profilesDiv.innerHTML = '';

  for (const profile of profiles) {
    const profileDiv = document.createElement('div');
    profileDiv.className = 'profile';
    profileDiv.onclick = async () => {
      await selectProfile(profile.profile_name);
    };

    const img = document.createElement('img');
    img.src = "https://wallpapers.com/images/high/netflix-profile-pictures-5yup5hd2i60x7ew3.webp";
    img.alt = profile.profile_name;

    const p = document.createElement('p');
    p.textContent = profile.profile_name;

    profileDiv.appendChild(img);
    profileDiv.appendChild(p);
    profilesDiv.appendChild(profileDiv);
  }
}

async function selectProfile(name) {
  await invoke("set_profile_name", { name });
  window.location.href = 'chat.html';
}

function closeModal() {
  document.getElementById('account-modal').classList.remove('active');
  document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
  tempMnemonic = tempPassword = tempProfileName = '';
}

function showStep(n) {
  document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
  document.getElementById(`step-${n}`).classList.add('active');
}

async function nextStep(current) {
  if (current === 1) {
    tempProfileName = document.getElementById('profile-name-input').value.trim();
    if (!tempProfileName) return alert("Name required");
    showStep(2);
  } else if (current === 2) {
    tempPassword = document.getElementById('password-input').value;
    alert(tempPassword);
    if (!tempPassword) return alert("Password required");
    try {
      tempMnemonic = await invoke("generate_mnemonic");
      document.getElementById('mnemonic-display').textContent = tempMnemonic;
      showStep(3);
    } catch (err) {
      alert("Mnemonic generation failed");
    }
  } else if (current === 3) {
    showStep(4);
  }
}

async function submitAccount() {
  const confirm = document.getElementById('mnemonic-confirm').value.trim();
  if (confirm !== tempMnemonic) return alert("Mnemonic doesn't match.");

  try {
    await invoke("create_profile_secure", {
      name: tempProfileName,
      password: tempPassword,
      mnemonic: tempMnemonic
    });
    console.log("password", tempPassword);
    closeModal();
    load_profiles();
  } catch (e) {
    alert("Profile creation failed.");
    console.error(e);
  }
}

document.getElementById("add-profile-button").addEventListener('click', () => {
  document.getElementById('account-modal').classList.add('active');
  showStep(1);
});

load_profiles();
