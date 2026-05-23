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
