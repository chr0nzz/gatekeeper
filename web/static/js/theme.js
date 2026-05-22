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

  function render() {
    var t = current();
    document.querySelectorAll('.theme-toggle button[data-theme]').forEach(function (btn) {
      btn.classList.toggle('on', btn.dataset.theme === t);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    render();
    document.querySelectorAll('.theme-toggle button[data-theme]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var t = btn.dataset.theme;
        try { localStorage.setItem('gk_theme', t); } catch (e) {}
        apply(t);
        render();
      });
    });
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (current() === 'auto') apply('auto');
    });
  });
})();
