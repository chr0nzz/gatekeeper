document.addEventListener('DOMContentLoaded', function () {
  var tabs = document.querySelectorAll('.seg button[data-mode]');
  var pwFields = document.getElementById('pw-fields');
  var submitBtn = document.getElementById('login-submit');

  function setMode(mode) {
    tabs.forEach(function (t) {
      t.classList.toggle('on', t.dataset.mode === mode);
    });
    if (pwFields) {
      pwFields.style.display = mode === 'password' ? '' : 'none';
    }
    if (submitBtn) {
      submitBtn.textContent = mode === 'password' ? 'Continue →' : 'Send code →';
    }
    document.getElementById('login-mode').value = mode;
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () { setMode(t.dataset.mode); });
  });
});
