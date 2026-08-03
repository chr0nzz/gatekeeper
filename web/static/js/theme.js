(function () {
  function apply(pref) {
    var doc = document.documentElement;
    var dark = pref === 'dark' || (pref === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    doc.setAttribute('data-theme', dark ? 'dark' : 'light');
    doc.setAttribute('data-theme-pref', pref);
  }

  function current() {
    return document.documentElement.getAttribute('data-theme-pref') || localStorage.getItem('gk_theme') || 'auto';
  }

  function currentAccent() {
    return document.documentElement.getAttribute('data-accent') || '';
  }

  function applyAccent(accent) {
    var doc = document.documentElement;
    if (accent) doc.setAttribute('data-accent', accent);
    else doc.removeAttribute('data-accent');
  }

  function renderTheme() {
    var t = current();
    document.querySelectorAll('.theme-toggle button[data-theme]').forEach(function (btn) {
      btn.classList.toggle('on', btn.dataset.theme === t);
    });
  }

  function renderAccent() {
    var a = currentAccent();
    document.querySelectorAll('.ac-swatch[data-accent]').forEach(function (btn) {
      btn.classList.toggle('on', btn.dataset.accent === a);
    });
    var dot = document.getElementById('ac-trigger-dot');
    if (dot) dot.style.background = a ? 'var(--ac)' : 'var(--ac)';
  }

  document.addEventListener('DOMContentLoaded', function () {
    renderTheme();
    renderAccent();

    document.querySelectorAll('.theme-toggle button[data-theme]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var t = btn.dataset.theme;
        try { localStorage.setItem('gk_theme', t); } catch (e) {}
        apply(t);
        renderTheme();
        renderAccent();
      });
    });

    var trigger = document.getElementById('accent-trigger');
    var menu = document.getElementById('accent-menu');

    if (trigger && menu) {
      trigger.addEventListener('click', function (e) {
        e.stopPropagation();
        menu.classList.toggle('open');
      });

      document.addEventListener('click', function () {
        menu.classList.remove('open');
      });

      menu.addEventListener('click', function (e) {
        e.stopPropagation();
      });
    }

    document.querySelectorAll('.ac-swatch[data-accent]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var a = btn.dataset.accent;
        var active = currentAccent();
        var next = active === a ? '' : a;
        try {
          if (next) localStorage.setItem('gk_accent', next);
          else localStorage.removeItem('gk_accent');
        } catch (e) {}
        applyAccent(next);
        renderAccent();
        if (menu) menu.classList.remove('open');
      });
    });

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (current() === 'auto') apply('auto');
    });
  });
})();

// Delegated handlers replacing inline event attributes, which a nonce-based
// Content-Security-Policy does not permit.
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-hide-on-error]').forEach(function (el) {
    el.addEventListener('error', function () { el.style.display = 'none'; });
  });
});

document.addEventListener('click', function (e) {
  var el = e.target.closest('[data-confirm]');
  if (el && !window.confirm(el.getAttribute('data-confirm'))) {
    e.preventDefault();
    e.stopPropagation();
  }
}, true);

document.addEventListener('DOMContentLoaded', function () {
  var iconFallback = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16v10H4zM4 7l8 6 8-6M4 4h16"/></svg>';

  function bindFallbackIcons(root) {
    (root || document).querySelectorAll('[data-fallback-icon]').forEach(function (img) {
      if (img.dataset.fallbackBound) return;
      img.dataset.fallbackBound = '1';
      img.addEventListener('error', function () { img.parentNode.innerHTML = iconFallback; });
    });
  }
  bindFallbackIcons(document);
  new MutationObserver(function () { bindFallbackIcons(document); })
    .observe(document.body, { childList: true, subtree: true });

  document.querySelectorAll('[data-sync-target]').forEach(function (el) {
    el.addEventListener('input', function () {
      var t = document.querySelector(el.getAttribute('data-sync-target'));
      if (t) t.value = el.value;
    });
  });

  document.querySelectorAll('[data-toggle-literal]').forEach(function (el) {
    el.addEventListener('change', function () {
      var f = document.getElementById('literal-field');
      if (f) f.style.display = el.value === 'literal' ? 'flex' : 'none';
    });
  });

  document.querySelectorAll('[data-storage-select]').forEach(function (el) {
    el.addEventListener('change', function () {
      if (typeof window.updateStorageFields === 'function') window.updateStorageFields();
    });
  });
});

document.addEventListener('click', function (e) {
  var el;

  if ((el = e.target.closest('[data-toggle-name-form]'))) {
    var form = document.getElementById('name-form');
    if (form) form.style.display = form.style.display === 'none' ? 'flex' : 'none';
    return;
  }
  if ((el = e.target.closest('[data-user-method]'))) {
    var m = el.getAttribute('data-user-method');
    var fn = window.setMethod || window.setNewUserMethod || window.setDashUserMethod;
    if (typeof fn === 'function') fn(el, m);
    return;
  }
  if (e.target.closest('[data-open-update-modal]')) {
    if (typeof window.openUpdateModal === 'function') window.openUpdateModal();
    return;
  }
  if ((el = e.target.closest('[data-copy-invite]'))) {
    if (typeof window.copyInviteLink === 'function') window.copyInviteLink(el);
  }
});
