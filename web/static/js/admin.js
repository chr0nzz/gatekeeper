document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-open-dialog]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var id = btn.dataset.openDialog;
      var dialog = document.getElementById(id);
      if (dialog) dialog.showModal();
    });
  });

  document.querySelectorAll('[data-close-dialog]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var dialog = btn.closest('dialog');
      if (dialog) dialog.close();
    });
  });

  document.querySelectorAll('dialog').forEach(function (dialog) {
    dialog.addEventListener('click', function (e) {
      if (e.target === dialog) dialog.close();
    });
  });

  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.dataset.copy;
      try {
        navigator.clipboard.writeText(text).then(function () {
          GK.toast({ kind: 'ok', title: 'Copied', body: text.length > 48 ? text.slice(0, 48) + '…' : text });
          btn.setAttribute('data-copied', '1');
          setTimeout(function () { btn.removeAttribute('data-copied'); }, 1400);
        });
      } catch (e) {}
    });
  });
});

var GK = (function () {
  var stack = null;

  function getStack() {
    if (!stack) {
      stack = document.getElementById('toast-stack');
      if (!stack) {
        stack = document.createElement('div');
        stack.className = 'toast-stack';
        stack.id = 'toast-stack';
        document.body.appendChild(stack);
      }
    }
    return stack;
  }

  function toast(opts) {
    var s = getStack();
    var el = document.createElement('div');
    el.className = 'toast ' + (opts.kind || 'info');

    var iconPaths = {
      ok: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1 14l-4-4 1.5-1.5L11 13l5-5L17.5 9.5z',
      err: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-4 6 8 8m0-8-8 8',
      warn: 'M12 2L1 21h22zM12 9v5M12 18v.5',
      info: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 9v6M12 7v.5'
    };
    var iconName = opts.kind === 'ok' ? 'ok' : opts.kind === 'err' ? 'err' : opts.kind === 'warn' ? 'warn' : 'info';

    var body = '<svg class="ic" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="' + iconPaths[iconName] + '"/></svg>';
    body += '<div style="flex:1;min-width:0"><b>' + escHtml(opts.title || '') + '</b>';
    if (opts.body) body += '<p>' + escHtml(opts.body) + '</p>';
    body += '</div>';
    body += '<button class="x" aria-label="Dismiss"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg></button>';

    el.innerHTML = body;
    s.appendChild(el);
    el.querySelector('.x').addEventListener('click', function () { dismiss(el); });
    var dur = opts.duration !== undefined ? opts.duration : 3600;
    if (dur > 0) setTimeout(function () { dismiss(el); }, dur);
  }

  function dismiss(el) {
    el.style.opacity = '0';
    el.style.transform = 'translateX(12px)';
    setTimeout(function () { el.parentNode && el.parentNode.removeChild(el); }, 200);
  }

  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return { toast: toast };
})();

(function () {
  var open = false;
  var sel = 0;
  var allItems = [];
  var debounceTimer = null;

  var navCommands = [
    { group: 'Navigate', icon: 'dashboard',     label: 'Dashboard',    href: '/admin' },
    { group: 'Navigate', icon: 'users',          label: 'Users',        href: '/admin/users' },
    { group: 'Navigate', icon: 'clients',        label: 'OIDC Clients', href: '/admin/clients' },
    { group: 'Navigate', icon: 'policies',       label: 'Policies',     href: '/admin/policies' },
    { group: 'Navigate', icon: 'audit',          label: 'Audit Log',    href: '/admin/audit' },
    { group: 'Navigate', icon: 'integrations',   label: 'Integrations', href: '/admin/integrations' },
    { group: 'Navigate', icon: 'social',          label: 'Social login', href: '/admin/social' },
    { group: 'Navigate', icon: 'webhooks',       label: 'Webhooks',     href: '/admin/webhooks' },
    { group: 'Navigate', icon: 'admins',         label: 'Admins',       href: '/admin/admins' },
    { group: 'Navigate', icon: 'profile',        label: 'My account',   href: '/admin/profile' },
    { group: 'Navigate', icon: 'settings',       label: 'Settings',     href: '/admin/settings' },
    { group: 'Actions',  icon: 'plus',           label: 'New user',     href: '/admin/users/new' },
    { group: 'Actions',  icon: 'plus',           label: 'New OIDC client', href: '/admin/clients' },
    { group: 'Actions',  icon: 'plus',           label: 'New policy',   href: '/admin/policies' },
  ];

  var iconPaths = {
    dashboard:    'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
    users:        'M16 14a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-8 0a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm0 2c-3 0-7 1.5-7 5v1h10v-1c0-1.5.7-2.7 1.8-3.6C12 16.6 10.4 16 8 16zm8 0c-.6 0-1.2 0-1.7.1 1.8 1.2 2.7 2.9 2.7 4.9V22h6v-1c0-3.5-4-5-7-5z',
    clients:      'M4 7h16v10H4zM4 7l8 6 8-6M4 4h16',
    policies:     'M12 2 4 5v7c0 5 3.5 9 8 10 4.5-1 8-5 8-10V5z',
    audit:        'M8 4h9l4 4v12a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm8 0v5h5M9 13h7M9 17h5',
    integrations: 'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
    social:       'M18 5a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 19a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.59 13.51l6.83 3.98M15.41 6.51l-6.82 3.98',
    webhooks:     'M18 8a6 6 0 0 0-6-6M6 8a6 6 0 0 1 6-6m0 0v4M9 21h6M12 17v4M5 8H3a1 1 0 0 0-1 1v3a1 1 0 0 0 1 1h18a1 1 0 0 0 1-1V9a1 1 0 0 0-1-1h-2',
    settings:     'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    admins:       'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-8 9c0-4 4-6 8-6s8 2 8 6v1H4zM19 8v6M22 11h-6',
    profile:      'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-8 9c0-4 4-6 8-6s8 2 8 6v1H4z',
    plus:         'M12 5v14M5 12h14',
    user:         'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-8 9c0-4 4-6 8-6s8 2 8 6v1H4z',
    arrow_r:      'M5 12h14M13 6l6 6-6 6',
  };

  function iconSvg(name) {
    var d = iconPaths[name] || iconPaths.arrow_r;
    return '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="' + d + '"/></svg>';
  }

  function renderList() {
    var list = document.querySelector('.cmdk-list');
    if (!list) return;
    if (!allItems.length) {
      list.innerHTML = '<div style="padding:20px;color:var(--tx-3);font-size:12.5px">No results.</div>';
      return;
    }
    var groups = [];
    allItems.forEach(function (c, i) {
      var last = groups[groups.length - 1];
      if (last && last.name === (c.group || '')) last.items.push({ c: c, i: i });
      else groups.push({ name: c.group || '', items: [{ c: c, i: i }] });
    });
    list.innerHTML = groups.map(function (g) {
      return (g.name ? '<div class="cmdk-group-label">' + g.name + '</div>' : '') +
        g.items.map(function (x) {
          var sub = x.c.sub ? '<span style="color:var(--tx-3);font-size:11px;margin-left:6px;font-family:var(--font-mono)">' + x.c.sub + '</span>' : '';
          return '<div class="cmdk-item' + (x.i === sel ? ' on' : '') + '" data-idx="' + x.i + '">' +
            iconSvg(x.c.icon) + '<span>' + x.c.label + '</span>' + sub + '</div>';
        }).join('');
    }).join('');
    list.querySelectorAll('.cmdk-item').forEach(function (el) {
      el.addEventListener('mouseenter', function () {
        sel = parseInt(el.dataset.idx);
        list.querySelectorAll('.cmdk-item').forEach(function (e) { e.classList.toggle('on', e === el); });
      });
      el.addEventListener('click', function () { run(allItems[parseInt(el.dataset.idx)]); });
    });
    var active = list.querySelector('.cmdk-item.on');
    if (active) active.scrollIntoView({ block: 'nearest' });
  }

  function setLoading() {
    var list = document.querySelector('.cmdk-list');
    if (list) list.innerHTML = '<div style="padding:20px;color:var(--tx-3);font-size:12.5px">Searching…</div>';
  }

  function search(q) {
    var k = q.trim().toLowerCase();
    if (!k) {
      allItems = navCommands.slice();
      sel = 0;
      renderList();
      return;
    }

    var localMatches = navCommands.filter(function (c) {
      return (c.label + ' ' + (c.group || '')).toLowerCase().indexOf(k) !== -1;
    });

    setLoading();
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      fetch('/admin/api/search?q=' + encodeURIComponent(q))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var serverResults = (data || []).map(function (r) {
            return { group: 'Results', icon: r.icon, label: r.label, sub: r.sub, href: r.url };
          });
          allItems = serverResults.concat(localMatches.map(function(c) { return Object.assign({}, c, {group: 'Pages'}); }));
          sel = 0;
          renderList();
        })
        .catch(function () {
          allItems = localMatches;
          sel = 0;
          renderList();
        });
    }, 180);
  }

  function run(c) {
    if (c && c.href) window.location.href = c.href;
    closeCmd();
  }

  function openCmd() {
    var scrim = document.getElementById('cmdk-scrim');
    if (!scrim) return;
    open = true;
    scrim.style.display = 'flex';
    var inp = scrim.querySelector('.cmdk-input');
    if (inp) { inp.value = ''; inp.focus(); }
    allItems = navCommands.slice();
    sel = 0;
    renderList();
  }

  function closeCmd() {
    var scrim = document.getElementById('cmdk-scrim');
    if (scrim) scrim.style.display = 'none';
    open = false;
  }

  document.addEventListener('DOMContentLoaded', function () {
    var trigger = document.getElementById('search-trigger');
    if (trigger) trigger.addEventListener('click', openCmd);

    var scrim = document.getElementById('cmdk-scrim');
    if (scrim) {
      scrim.addEventListener('click', function (e) { if (e.target === scrim) closeCmd(); });
      var inp = scrim.querySelector('.cmdk-input');
      if (inp) inp.addEventListener('input', function () { search(inp.value); });
    }

    var gSeq = '';
    var gTimer = null;
    window.addEventListener('keydown', function (e) {
      var inInput = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        open ? closeCmd() : openCmd();
        return;
      }
      if (open) {
        if (e.key === 'Escape') { e.preventDefault(); closeCmd(); return; }
        if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, allItems.length - 1); renderList(); return; }
        if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); renderList(); return; }
        if (e.key === 'Enter') { e.preventDefault(); run(allItems[sel]); return; }
        return;
      }
      if (inInput) return;
      if (e.key === '/') { e.preventDefault(); openCmd(); return; }
      gSeq += e.key;
      clearTimeout(gTimer);
      gTimer = setTimeout(function () { gSeq = ''; }, 700);
      var navMap = { 'gd': '/admin', 'gu': '/admin/users', 'gc': '/admin/clients', 'ga': '/admin/audit', 'gs': '/admin/settings', 'gp': '/admin/profile' };
      if (navMap[gSeq]) { window.location.href = navMap[gSeq]; gSeq = ''; }
    });
  });
})();
