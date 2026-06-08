function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return buffer;
}

function prepareCredentialCreationOptions(options) {
  options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
  options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
  if (options.publicKey.excludeCredentials) {
    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
      ...c, id: base64urlToBuffer(c.id)
    }));
  }
  return options;
}

function prepareCredentialRequestOptions(options) {
  options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
      ...c, id: base64urlToBuffer(c.id)
    }));
  }
  return options;
}

function encodeCredentialCreation(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
    }
  };
}

function encodeCredentialAssertion(credential) {
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
    }
  };
}

async function beginPasskeyLogin(beginURL, finishURL, redirectURI, oidcRequest, errorEl) {
  try {
    const beginResp = await fetch(beginURL, { method: 'POST' });
    const sessID = beginResp.headers.get('X-Passkey-Session');
    const options = prepareCredentialRequestOptions(await beginResp.json());
    const credential = await navigator.credentials.get(options);
    const params = new URLSearchParams();
    if (redirectURI) params.set('redirect_uri', redirectURI);
    if (oidcRequest) params.set('oidc_request', oidcRequest);
    const finish = params.toString() ? finishURL + '?' + params.toString() : finishURL;
    const finishResp = await fetch(finish, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Passkey-Session': sessID },
      body: JSON.stringify(encodeCredentialAssertion(credential)),
    });
    if (finishResp.ok) {
      const target = (await finishResp.text()).trim();
      window.location.href = target || '/';
    } else {
      const text = await finishResp.text();
      errorEl.textContent = text || 'Authentication failed.';
      errorEl.style.display = '';
    }
  } catch (err) {
    errorEl.textContent = err.message || 'Authentication failed.';
    errorEl.style.display = '';
  }
}

async function beginPasskeyRegister(beginURL, finishURL, errorEl, successEl) {
  try {
    const beginResp = await fetch(beginURL, { method: 'POST' });
    const sessID = beginResp.headers.get('X-Passkey-Session');
    const options = prepareCredentialCreationOptions(await beginResp.json());
    const credential = await navigator.credentials.create(options);
    const finishResp = await fetch(finishURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Passkey-Session': sessID },
      body: JSON.stringify(encodeCredentialCreation(credential)),
    });
    if (finishResp.ok) {
      successEl.style.display = '';
      successEl.textContent = 'Passkey registered successfully.';
    } else {
      const text = await finishResp.text();
      errorEl.textContent = text || 'Registration failed.';
      errorEl.style.display = '';
    }
  } catch (err) {
    errorEl.textContent = err.message || 'Registration failed.';
    errorEl.style.display = '';
  }
}

// Auto-initialize buttons from data attributes so templates need no inline scripts.
document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('gk-passkey-login-btn');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      beginPasskeyLogin(
        loginBtn.dataset.begin,
        loginBtn.dataset.finish,
        loginBtn.dataset.redirect || '',
        loginBtn.dataset.oidcRequest || '',
        document.getElementById('gk-passkey-error')
      );
    });
  }

  const registerBtn = document.getElementById('gk-passkey-register-btn');
  if (registerBtn) {
    registerBtn.addEventListener('click', () => {
      const nameEl = document.getElementById('gk-passkey-name');
      const name = nameEl ? nameEl.value : 'Passkey';
      const finish = registerBtn.dataset.finish + '?name=' + encodeURIComponent(name);
      beginPasskeyRegister(
        registerBtn.dataset.begin,
        finish,
        document.getElementById('gk-passkey-error'),
        document.getElementById('gk-passkey-success')
      );
    });
  }
});
