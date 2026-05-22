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
  var eventTypeBtns = document.querySelectorAll('[data-event-type]');
  var auditCount = document.getElementById('audit-count');
  var activeKind = 'all';
  var activeEvent = 'all';

  function applyAuditFilters() {
    var q = auditSearch ? auditSearch.value.toLowerCase() : '';
    var visible = 0;
    auditRows.forEach(function (row) {
      var text = (row.dataset.auditRow || '').toLowerCase();
      var kind = row.dataset.kind || '';
      var prefix = row.dataset.eventPrefix || '';
      var matchesSearch = !q || text.includes(q);
      var matchesKind = activeKind === 'all' || kind === activeKind;
      var matchesEvent = activeEvent === 'all' || prefix === activeEvent;
      var show = matchesSearch && matchesKind && matchesEvent;
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

  if (auditSearch) auditSearch.addEventListener('input', applyAuditFilters);

  kindBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      activeKind = btn.dataset.kind;
      kindBtns.forEach(function (b) { b.classList.toggle('on', b.dataset.kind === activeKind); });
      applyAuditFilters();
    });
  });

  eventTypeBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      activeEvent = btn.dataset.eventType;
      eventTypeBtns.forEach(function (b) { b.classList.toggle('on', b.dataset.eventType === activeEvent); });
      applyAuditFilters();
    });
  });

  document.querySelectorAll('.audit-filter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var event = btn.dataset.event;
      if (auditSearch) { auditSearch.value = event; applyAuditFilters(); }
    });
  });
});
