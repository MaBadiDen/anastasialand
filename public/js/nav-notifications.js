(function(){
  var bell = document.getElementById('notifBell');
  var dot = document.getElementById('notifDot');
  var panelEl = document.getElementById('notificationsPanel');
  var panel;
  function ensurePanel(){
    if (!panel && window.bootstrap) panel = new bootstrap.Offcanvas(panelEl);
  }
  function refreshBadge(){
    fetch('/api/notifications/unread-count', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function(r){ return r.json(); })
      .then(function(d){ if (d && d.count > 0) { dot.classList.remove('d-none'); } else { dot.classList.add('d-none'); } })
      .catch(function(){ dot.classList.add('d-none'); });
  }
  function loadList(){
    var list = document.getElementById('notifList');
    list.innerHTML = '<div class="list-group-item text-muted">Загрузка…</div>';
    fetch('/api/notifications', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function(r){ if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function(items){
        if (!Array.isArray(items) || items.length === 0) {
          list.innerHTML = '<div class="list-group-item text-muted">Нет уведомлений</div>';
          return;
        }
        list.innerHTML = '';
        items.forEach(function(n){
          var read = !!n.read_at;
          var el = document.createElement('div');
          el.className = 'list-group-item d-flex justify-content-between align-items-start';
          if (!read) { el.className += ' border border-2 border-primary-subtle rounded-2'; }
          el.innerHTML = '<div class="me-2"><div class="fw-semibold">' + (n.title || 'Уведомление') + '</div>' + (n.body ? ('<div class="text-muted">' + n.body + '</div>') : '') + '</div>' +
            (read ? '' : '<button class="btn btn-sm btn-outline-primary mark-read" data-id="' + n.id + '">Прочитано</button>');
          list.appendChild(el);
        });
      })
      .catch(function(){
        list.innerHTML = '<div class="list-group-item text-danger">Не удалось загрузить уведомления. Войдите заново и попробуйте ещё раз.</div>';
      });
  }
  function getCookie(name){
    var m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : undefined;
  }
  document.addEventListener('click', function(e){
    var btn = e.target && (e.target.closest && e.target.closest('#notifBell'));
    if (btn) { ensurePanel(); if (panel) { panel.show(); loadList(); } }
    var readAll = e.target && e.target.closest && e.target.closest('#notifReadAll');
    if (readAll) {
      var btnEl = document.getElementById('notifReadAll');
      if (btnEl) { btnEl.disabled = true; }
      function doPost(){
        var token = getCookie('XSRF-TOKEN') || '';
        fetch('/api/notifications/read-all', { method: 'POST', headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': token }, body: '', credentials: 'same-origin' })
          .then(function(r){ if (!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
          .then(function(d){ if (d && d.ok) { loadList(); refreshBadge(); } })
          .catch(function(){ /* no-op UI error */ })
          .finally(function(){ if (btnEl) { btnEl.disabled = false; } });
      }
      var token = getCookie('XSRF-TOKEN');
      if (!token) { fetch('/api/csrf', { credentials: 'same-origin' }).then(function(){ doPost(); }); } else { doPost(); }
    }
    var clearAll = e.target && e.target.closest && e.target.closest('#notifClearAll');
    if (clearAll) {
      var btnEl2 = document.getElementById('notifClearAll');
      if (btnEl2) { btnEl2.disabled = true; }
      function doPost(){
        var token2 = getCookie('XSRF-TOKEN') || '';
        fetch('/api/notifications/clear-all', { method: 'POST', headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': token2 }, body: '', credentials: 'same-origin' })
          .then(function(r){ if (!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
          .then(function(d){ if (d && d.ok) { loadList(); refreshBadge(); } })
          .catch(function(){ /* no-op UI error */ })
          .finally(function(){ if (btnEl2) { btnEl2.disabled = false; } });
      }
      var token2 = getCookie('XSRF-TOKEN');
      if (!token2) { fetch('/api/csrf', { credentials: 'same-origin' }).then(function(){ doPost(); }); } else { doPost(); }
    }
    var mark = e.target && e.target.closest && e.target.closest('.mark-read');
    if (mark) {
      var id = mark.getAttribute('data-id');
      function doPost(){
        var token3 = getCookie('XSRF-TOKEN') || '';
        var fd = new URLSearchParams();
        fetch('/api/notifications/' + id + '/read', { method: 'POST', headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': token3 }, body: fd.toString(), credentials: 'same-origin' })
          .then(function(r){ return r.json(); }).then(function(d){
            if (d && d.ok) {
              var row = mark.closest('.list-group-item');
              if (row) { row.classList.remove('border','border-2','border-primary-subtle','rounded-2'); mark.remove(); }
              refreshBadge();
            }
          });
      }
      var token3 = getCookie('XSRF-TOKEN');
      if (!token3) { fetch('/api/csrf', { credentials: 'same-origin' }).then(function(){ doPost(); }); } else { doPost(); }
    }
  });
  refreshBadge();
  setInterval(refreshBadge, 30000);
  window.addEventListener('notifications:refresh', refreshBadge);
})();
