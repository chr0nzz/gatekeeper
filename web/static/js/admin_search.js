document.addEventListener('DOMContentLoaded', function () {
  var searchInput = document.getElementById('gk-search');
  var filterBtns = document.querySelectorAll('[data-filter]');
  var rows = document.querySelectorAll('[data-searchable]');
  var activeFilter = 'all';

  function applyFilters() {
    var q = searchInput ? searchInput.value.toLowerCase() : '';
    rows.forEach(function (row) {
      var text = (row.dataset.searchable || '').toLowerCase();
      var status = row.dataset.status || '';
      var totp = row.dataset.totp || '';
      var matchesSearch = !q || text.includes(q);
      var matchesFilter =
        activeFilter === 'all' ||
        (activeFilter === 'active' && status === 'active') ||
        (activeFilter === 'locked' && status === 'locked') ||
        (activeFilter === 'disabled' && status === 'disabled') ||
        (activeFilter === 'no2fa' && totp === '0');
      row.style.display = matchesSearch && matchesFilter ? '' : 'none';
    });
  }

  if (searchInput) searchInput.addEventListener('input', applyFilters);

  filterBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      activeFilter = btn.dataset.filter;
      filterBtns.forEach(function (b) { b.classList.toggle('on', b.dataset.filter === activeFilter); });
      applyFilters();
    });
  });

  var auditSearch = document.getElementById('gk-audit-search');
  var auditRows = document.querySelectorAll('[data-audit-row]');
  var auditDayHeaders = document.querySelectorAll('[data-day-header]');
  var kindBtns = document.querySelectorAll('[data-kind]');
  var methodBtns = document.querySelectorAll('[data-method]');
  var auditCount = document.getElementById('audit-count');
  var activeKind = 'all';
  var activeMethod = 'all';

  function applyAuditFilters() {
    var q = auditSearch ? auditSearch.value.toLowerCase() : '';
    var visible = 0;
    auditRows.forEach(function (row) {
      var text = (row.dataset.auditRow || '').toLowerCase();
      var kind = row.dataset.kind || '';
      var method = row.dataset.method || '';
      var matchesSearch = !q || text.includes(q);
      var matchesKind = activeKind === 'all' || kind === activeKind;
      var matchesMethod = activeMethod === 'all' || method === activeMethod;
      var show = matchesSearch && matchesKind && matchesMethod;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    if (auditCount) auditCount.textContent = visible + ' event' + (visible !== 1 ? 's' : '');
    auditDayHeaders.forEach(function (hdr) {
      var day = hdr.dataset.dayHeader;
      var anyVisible = Array.from(document.querySelectorAll('[data-audit-row][data-day="' + day + '"]')).some(function (r) {
        return r.style.display !== 'none';
      });
      hdr.style.display = anyVisible ? '' : 'none';
    });
  }

  var clearBtn = document.getElementById('audit-search-clear');

  function updateClearBtn() {
    if (clearBtn) clearBtn.style.display = auditSearch && auditSearch.value ? '' : 'none';
  }

  if (auditSearch) {
    auditSearch.addEventListener('input', function () { applyAuditFilters(); updateClearBtn(); });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      if (auditSearch) { auditSearch.value = ''; applyAuditFilters(); updateClearBtn(); }
    });
  }

  kindBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      activeKind = btn.dataset.kind;
      kindBtns.forEach(function (b) { b.classList.toggle('on', b.dataset.kind === activeKind); });
      applyAuditFilters();
    });
  });

  methodBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      activeMethod = btn.dataset.method;
      methodBtns.forEach(function (b) { b.classList.toggle('on', b.dataset.method === activeMethod); });
      applyAuditFilters();
    });
  });

  document.querySelectorAll('.audit-filter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var event = btn.dataset.event;
      if (!auditSearch) return;
      if (auditSearch.value === event) {
        auditSearch.value = '';
      } else {
        auditSearch.value = event;
      }
      applyAuditFilters();
      updateClearBtn();
    });
  });

  var exportBtn = document.getElementById('audit-export-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', function () {
      var rows = [];
      auditRows.forEach(function (row) {
        if (row.style.display === 'none') return;
        var cells = row.querySelectorAll('span');
        rows.push({
          time:   (cells[0] && cells[0].textContent.trim()) || '',
          event:  row.dataset.auditRow ? row.dataset.auditRow.split(' ')[0] : '',
          user:   (cells[2] && cells[2].textContent.trim()) || '',
          email:  (cells[3] && cells[3].textContent.trim()) || '',
          method: (cells[4] && cells[4].textContent.trim()) || '',
          detail: (cells[5] && cells[5].textContent.trim()) || '',
          ip:     (cells[6] && cells[6].textContent.trim()) || '',
          kind:   row.dataset.kind || ''
        });
      });
      var blob = new Blob([JSON.stringify(rows, null, 2)], {type: 'application/json'});
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'audit-log-' + new Date().toISOString().slice(0,10) + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }
});
