document.addEventListener('DOMContentLoaded', function () {
  var tabs = document.querySelectorAll('.seg button[data-mode]');
  var pwFields = document.getElementById('pw-fields');
  var submitBtn = document.getElementById('login-submit');
  var loginForm = document.getElementById('login-form');
  var qrPanel = document.getElementById('qr-panel');
  var qrImg = document.getElementById('qr-img');
  var qrStatus = document.getElementById('qr-status');

  var qrPollTimer = null;
  var qrToken = null;

  function stopQR() {
    if (qrPollTimer) { clearInterval(qrPollTimer); qrPollTimer = null; }
    qrToken = null;
  }

  function startQR() {
    stopQR();
    qrStatus.textContent = 'Loading...';
    qrImg.src = '';

    var oidcRequest = document.querySelector('input[name="oidc_request"]');
    var redirectURI = document.querySelector('input[name="redirect_uri"]');
    var params = new URLSearchParams();
    if (oidcRequest && oidcRequest.value) params.set('oidc_request', oidcRequest.value);
    if (redirectURI && redirectURI.value) params.set('redirect_uri', redirectURI.value);
    var qs = params.toString() ? '?' + params.toString() : '';

    fetch('/login/qr/begin' + qs, { method: 'POST' })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        qrToken = data.token;
        qrImg.src = data.qr;
        qrStatus.textContent = 'Open your camera and scan this code to sign in.';
        qrPollTimer = setInterval(pollQR, 2000);
      })
      .catch(function () { qrStatus.textContent = 'Failed to load QR code.'; });
  }

  function pollQR() {
    if (!qrToken) return;
    fetch('/login/qr/poll?token=' + encodeURIComponent(qrToken))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.status === 'approved') {
          stopQR();
          qrStatus.textContent = 'Approved! Signing you in...';
          window.location.href = data.redirect || '/';
        } else if (data.status === 'expired') {
          stopQR();
          qrStatus.textContent = 'QR code expired.';
          setTimeout(startQR, 1500);
        }
      })
      .catch(function () {});
  }

  function setMode(mode) {
    tabs.forEach(function (t) {
      t.classList.toggle('on', t.dataset.mode === mode);
    });
    var isQR = mode === 'qr';
    if (loginForm) loginForm.style.display = isQR ? 'none' : '';
    if (qrPanel) qrPanel.style.display = isQR ? '' : 'none';
    if (pwFields) pwFields.style.display = mode === 'password' ? '' : (isQR ? 'none' : 'none');
    if (submitBtn) submitBtn.textContent = mode === 'password' ? 'Continue →' : (isQR ? '' : 'Send code →');
    var loginModeEl = document.getElementById('login-mode');
    if (loginModeEl) loginModeEl.value = mode;

    if (isQR) {
      startQR();
    } else {
      stopQR();
    }
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () { setMode(t.dataset.mode); });
  });
});
