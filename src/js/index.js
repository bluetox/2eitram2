const { invoke } = window.__TAURI__.core;

let mnemonicPhrase = null;
async function load_profiles() {
    let profiles = await invoke("get_profiles");
    const profilesDiv = document.getElementById('profiles');
    console.log(profiles);
    for (const profile of profiles) {
        let html_element = createProfileCard(profile.profile_name, "assets/pp1.jpg");
        profilesDiv.appendChild(html_element);
    }
  }
  async function selectProfile(name) {
    await invoke("set_profile_name", { name });
    window.location.href = 'chat.html';
  }
  function createProfileCard(name, imageUrl) {
    const card = document.createElement("div");
    card.className = "profile-card";
  
    const avatar = document.createElement("div");
    avatar.className = "profile-avatar";
    avatar.style.backgroundImage = `url(${imageUrl})`;
    avatar.style.backgroundSize = "cover";
    avatar.style.backgroundPosition = "center";
  
    const heading = document.createElement("h2");
    heading.textContent = name;
  
    card.appendChild(avatar);
    card.appendChild(heading);
    card.addEventListener('click', async () => {
        await selectProfile(name);
    });
    return card;
  }
  load_profiles();
const pages = {
  select: document.getElementById('profile-select-page'),
  add:    document.getElementById('add-profile-page'),
};
const steps = [
  document.getElementById('step1'),
  document.getElementById('step2'),
  document.getElementById('step3'),
  document.getElementById('step4'),
];
const indicator = document.getElementById('step-indicator');
let currentStep = 0;

function showStep(n) {
  steps.forEach((s,i)=> {
    s.style.display = i===n ? 'block' : 'none';
  });
  indicator.textContent = `Step ${n+1} of ${steps.length}`;
}

showStep(0);

document.getElementById('add-profile').onclick = () => {
  pages.select.classList.remove('active');
  pages.add .classList.add('active');
  showStep(0);
};
document.getElementById('exit-add-profile').onclick = () => {
  pages.add   .classList.remove('active');
  pages.select.classList.add('active');
};

const nameInput = document.getElementById('profile-name');
const nameBtn = document.getElementById('save-profile-name');
nameInput.addEventListener('input', () => {
  nameBtn.disabled = !nameInput.value.trim();
});
nameBtn.onclick = () => {
  console.log("Step 1 done:", nameInput.value);
  currentStep = 1;
  showStep(currentStep);
};

const pwdInput = document.getElementById('password');
const pwdBtn = document.getElementById('to-step-3');
pwdInput.addEventListener('input', () => {
  pwdBtn.disabled = !pwdInput.value;
});
pwdBtn.onclick = () => {
  console.log("Step 2 password chosen");
  currentStep = 2;
  showStep(currentStep);
};

const confirmInput = document.getElementById('re-typed-password');
const confirmBtn = document.getElementById('to-step-4');
confirmInput.addEventListener('input', () => {
  confirmBtn.disabled = !confirmInput.value;
});
confirmBtn.onclick = async () => {
  if (confirmInput.value !== pwdInput.value) {
    alert("Passwords don't match!");
    return;
  }
  console.log("Step 3 password confirmed");
  currentStep = 3;
  let mnemonicContainer = document.getElementById("mnemonic-container");
  mnemonicPhrase = await invoke("generate_mnemonic");
  mnemonicPhrase.forEach(word => {
    const div = document.createElement("div");
    div.className = "mnemonic-word";
    div.textContent = word;
    mnemonicContainer.appendChild(div);
  });

  console.log(mnemonicPhrase);
  showStep(currentStep);
};

document.getElementById('finish').onclick = async () => {
  console.log("Final step - submit all data");
  const password = document.getElementById("password");
  const name = document.getElementById("profile-name");
  console.log(mnemonicPhrase.join(""));
  await invoke("create_profil", {name: name.value, password: password.value, phrase: mnemonicPhrase.join(" ")});
  pages.add.classList.remove('active');
  pages.select.classList.add('active');
  let mnemonicContainer = document.getElementById("mnemonic-container");
  mnemonicContainer.innerHTML = ""
};