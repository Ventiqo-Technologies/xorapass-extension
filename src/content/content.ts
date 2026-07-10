// XoraPass Content Script (Manifest V3)
import browser from 'webextension-polyfill';

interface MatchingCredential {
  id: string;
  label: string;
  username: string;
  value: string;
}

let activeCredentials: MatchingCredential[] = [];
let scannedForms: Set<HTMLInputElement> = new Set();
let overlayElements: HTMLElement[] = [];

// Request matching credentials for the current tab domain
function loadCredentials() {
  const hostname = window.location.hostname;
  browser.runtime.sendMessage(
    { type: 'GET_MATCHING_CREDENTIALS', payload: { hostname } }
  ).then((response) => {
    if (response && response.credentials) {
      activeCredentials = response.credentials;
      if (activeCredentials.length > 0) {
        scanForLoginFields();
      }
    }
  });
}

// Injects autofill overlays into discovered input fields
function scanForLoginFields() {
  if (activeCredentials.length === 0) return;

  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
  
  passwordInputs.forEach((passInput) => {
    if (scannedForms.has(passInput)) return;
    
    // Find the corresponding username/email input (usually preceding text/email input)
    const usernameInput = findUsernameField(passInput);
    if (!usernameInput) return;

    scannedForms.add(passInput);
    scannedForms.add(usernameInput);

    injectAutofillIcon(usernameInput, passInput);
    injectAutofillIcon(passInput, passInput); // also put it on the password field
  });
}

// Attempts to locate username field preceding a password input
function findUsernameField(passInput: HTMLInputElement): HTMLInputElement | null {
  const form = passInput.form;
  
  if (form) {
    const inputs = Array.from(form.querySelectorAll('input')) as HTMLInputElement[];
    const passIdx = inputs.indexOf(passInput);
    // Scan backwards for text/email input
    for (let i = passIdx - 1; i >= 0; i--) {
      const type = inputs[i].type;
      if (type === 'email' || type === 'text' || type === 'username') {
        return inputs[i];
      }
    }
  }

  // Fallback: search DOM sibling elements preceding the password input
  let sibling = passInput.previousElementSibling;
  while (sibling) {
    const input = sibling.querySelector('input') || (sibling.tagName === 'INPUT' ? sibling : null) as HTMLInputElement | null;
    if (input && (input.type === 'text' || input.type === 'email')) {
      return input;
    }
    sibling = sibling.previousElementSibling;
  }
  
  return null;
}

// Injects the CloudPass icon overlay into a given input field
function injectAutofillIcon(inputEl: HTMLInputElement, passEl: HTMLInputElement) {
  // Ensure the input has a relative positioning container context or use absolute coordinates
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';
  wrapper.style.width = '100%';
  
  // Create the overlay button
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'xorapass-autofill-btn';
  button.setAttribute('aria-label', 'XoraPass Autofill');
  button.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00D2FF" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `;
  
  // Style the overlay button
  Object.assign(button.style, {
    position: 'absolute',
    right: '8px',
    top: '50%',
    transform: 'translateY(-50%)',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    zIndex: '99999',
    padding: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px',
    transition: 'background-color 0.2s',
  });

  button.addEventListener('mouseover', () => {
    button.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
  });
  button.addEventListener('mouseout', () => {
    button.style.backgroundColor = 'transparent';
  });

  // Position wrapper around input
  inputEl.parentNode?.insertBefore(wrapper, inputEl);
  wrapper.appendChild(inputEl);
  wrapper.appendChild(button);

  // When clicked, open the credential selection dropdown
  button.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    openAutofillDropdown(button, inputEl, passEl);
  });
  
  overlayElements.push(wrapper);
}

// Renders the auto-fill credential selection menu
function openAutofillDropdown(anchor: HTMLElement, usernameEl: HTMLInputElement, passwordEl: HTMLInputElement) {
  // Remove any existing dropdowns first
  closeAllDropdowns();

  const dropdown = document.createElement('div');
  dropdown.className = 'xorapass-dropdown';
  
  // Dark Glassmorphism Premium Style
  Object.assign(dropdown.style, {
    position: 'absolute',
    top: `${anchor.offsetTop + anchor.offsetHeight + 6}px`,
    right: '0',
    width: '240px',
    backgroundColor: '#0f172a', // Slate 900
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '10px',
    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 15px rgba(0, 210, 255, 0.1)',
    zIndex: '100000',
    overflow: 'hidden',
    fontFamily: 'Inter, system-ui, sans-serif',
  });

  // Header
  const header = document.createElement('div');
  header.innerText = 'XoraPass Autofill';
  Object.assign(header.style, {
    padding: '8px 12px',
    fontSize: '10px',
    fontWeight: 'bold',
    color: '#00D2FF',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
    backgroundColor: '#020617',
  });
  dropdown.appendChild(header);

  // List matching credentials
  activeCredentials.forEach((cred) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'xorapass-dropdown-item';
    item.innerHTML = `
      <div style="font-weight: 600; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${cred.label}</div>
      <div style="font-size: 10px; color: #64748b; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; margin-top: 2px;">${cred.username}</div>
    `;

    Object.assign(item.style, {
      width: '100%',
      padding: '10px 12px',
      background: 'none',
      border: 'none',
      cursor: 'pointer',
      fontSize: '12px',
      color: '#e2e8f0',
      borderBottom: '1px solid rgba(255, 255, 255, 0.03)',
      transition: 'background-color 0.15s, color 0.15s',
      display: 'block',
    });

    item.addEventListener('mouseover', () => {
      item.style.backgroundColor = 'rgba(0, 210, 255, 0.08)';
      item.style.color = '#00D2FF';
    });
    item.addEventListener('mouseout', () => {
      item.style.backgroundColor = 'transparent';
      item.style.color = '#e2e8f0';
    });

    item.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      // Perform Autofill!
      autofillField(usernameEl, cred.username);
      autofillField(passwordEl, cred.value);

      closeAllDropdowns();
    });

    dropdown.appendChild(item);
  });

  anchor.parentElement?.appendChild(dropdown);

  // Close dropdown on click outside
  document.addEventListener('click', closeDropdownsOnOutsideClick);
}

function autofillField(el: HTMLInputElement, value: string) {
  el.value = value;
  // Trigger DOM events so modern UI frameworks (React, Vue, Angular) detect change
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  el.dispatchEvent(new Event('blur', { bubbles: true }));
}

function closeAllDropdowns() {
  const dropdowns = document.querySelectorAll('.xorapass-dropdown');
  dropdowns.forEach((d) => d.remove());
  document.removeEventListener('click', closeDropdownsOnOutsideClick);
}

function closeDropdownsOnOutsideClick(e: MouseEvent) {
  if (!(e.target as HTMLElement).closest('.xorapass-dropdown') && !(e.target as HTMLElement).closest('.xorapass-autofill-btn')) {
    closeAllDropdowns();
  }
}

// Initialize and poll DOM scan to accommodate dynamic single page apps (React, Vue, etc.)
loadCredentials();
setInterval(scanForLoginFields, 2500);

// Re-check credentials cache when tab focus returns
window.addEventListener('focus', loadCredentials);
