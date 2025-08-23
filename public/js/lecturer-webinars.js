// lecturer-webinars.js
// Extracted from views/lecturer/webinars.ejs to comply with strict CSP.
(function(){
  'use strict';
  if (window.__lecturerWebinarsLoaded) return; // idempotent for turbolinks-like setups
  window.__lecturerWebinarsLoaded = true;

  function onReady(fn){ if (document.readyState !== 'loading') fn(); else document.addEventListener('DOMContentLoaded', fn, { once: true }); }

  onReady(function(){
    // Bootstrap tooltips
    try {
      var tooltipTriggerList = Array.prototype.slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.forEach(function (el) { try { new bootstrap.Tooltip(el); } catch(e) {} });
    } catch(e) {}

    // localize datetime-local inputs from stored UTC
    document.querySelectorAll('input[type="datetime-local"][data-utc]').forEach(function(inp){
      var iso = (inp.getAttribute('data-utc')||'').trim();
      if (!iso) return;
      try {
        var d = new Date(iso);
        if (isNaN(d.getTime())) return;
        var pad = function(n){ return n<10 ? '0'+n : ''+n; };
        var y = d.getFullYear();
        var m = pad(d.getMonth()+1);
        var day = pad(d.getDate());
        var hh = pad(d.getHours());
        var mm = pad(d.getMinutes());
        inp.value = y + '-' + m + '-' + day + 'T' + hh + ':' + mm;
      } catch(e) {}
    });

    // Localize any span.dt-local with data-utc
    (function localizeInlineDates(){
      var els = document.querySelectorAll('.dt-local[data-utc]');
      els.forEach(function(el){
        var iso = (el.getAttribute('data-utc')||'').trim();
        if (!iso) return;
        var d = new Date(iso);
        if (isNaN(d.getTime())) return;
        try { el.textContent = d.toLocaleString(); } catch(e) { el.textContent = iso; }
      });
    })();

    // Compute relative time labels
    (function relTime(){
      var rtf;
      try { rtf = new Intl.RelativeTimeFormat('ru', { numeric: 'auto' }); } catch(e) { rtf = null; }
      function fmt(ms){
        var s = Math.round(ms/1000);
        var abs = Math.abs(s);
        if (!rtf) return (s >= 0 ? 'через ' : '') + Math.round(abs/60) + ' мин';
        if (abs < 60) return rtf.format(Math.round(s), 'second');
        var m = Math.round(s/60); abs = Math.abs(m);
        if (abs < 60) return rtf.format(m, 'minute');
        var h = Math.round(m/60); abs = Math.abs(h);
        if (abs < 24) return rtf.format(h, 'hour');
        var d = Math.round(h/24);
        return rtf.format(d, 'day');
      }
      function update(){
        var now = Date.now();
        document.querySelectorAll('.rel-time[data-utc]').forEach(function(el){
          var iso = (el.getAttribute('data-utc')||'').trim();
          if (!iso) return;
          var t = new Date(iso).getTime();
          if (isNaN(t)) return;
          el.textContent = fmt(t - now);
        });
      }
      update();
      setInterval(update, 30000);
    })();

    // Webinar live status badge (Идет/Запланирован/Завершен)
    (function webinarStatus(){
      function setBadge(el, text, cls){ el.className = 'webinar-status badge rounded-pill ' + cls; el.textContent = text; }
      function update(){
        var now = Date.now();
        document.querySelectorAll('.webinar-status').forEach(function(el){
          var start = new Date(el.getAttribute('data-start-utc')||'').getTime();
          var end = new Date(el.getAttribute('data-end-utc')||'').getTime();
          if (isNaN(start) && isNaN(end)) { setBadge(el, '—', 'text-bg-light'); return; }
          if (!isNaN(start) && now < start) { setBadge(el, 'Запланирован', 'text-bg-info'); return; }
          if (!isNaN(start) && !isNaN(end) && now >= start && now <= end) { setBadge(el, 'Идет', 'text-bg-success'); return; }
          if (!isNaN(end) && now > end) { setBadge(el, 'Завершен', 'text-bg-secondary'); return; }
          // Fallbacks
          if (!isNaN(start) && isNaN(end) && now >= start) { setBadge(el, 'Идет', 'text-bg-success'); return; }
          setBadge(el, '—', 'text-bg-light');
        });
      }
      update();
      setInterval(update, 60000);
    })();

    function decodeJsonAttr(el, attr) {
      try { return JSON.parse(decodeURIComponent((el && el.getAttribute && el.getAttribute(attr)) || '[]')); } catch(e) { return []; }
    }
    // In-memory state of attendees per webinar to avoid relying on DOM-only scanning
    var attendeesState = {}; // { [webinarId]: { users: Set<string>, groups: Set<number> } }

    function getState(modalEl) {
      var wid = modalEl && modalEl.getAttribute('data-webinar-id');
      if (!wid) return null;
      if (!attendeesState[wid]) {
        attendeesState[wid] = { users: new Set(), groups: new Set() };
      }
      return attendeesState[wid];
    }

    function hydrateStateFromDOM(modalEl) {
      var state = getState(modalEl);
      if (!state) return;
      state.users.clear();
      state.groups.clear();
      modalEl.querySelectorAll('.attendee-remove-form input[name="username"]').forEach(function(i){ if (i.value) state.users.add(i.value); });
      modalEl.querySelectorAll('.attendee-remove-form input[name="groupId"]').forEach(function(i){ if (i.value) { var n = Number(i.value); if (!Number.isNaN(n)) state.groups.add(n); } });
    }

    function rebuildEntitySelect(modalEl) {
      if (!modalEl) return;
      var select = modalEl.querySelector('.attendee-add-form select[name="entity"]');
      if (!select) return;
      var allUsers = decodeJsonAttr(modalEl, 'data-users-json');
      var allGroups = decodeJsonAttr(modalEl, 'data-groups-json');
      // Current attendees from in-memory state; hydrate from DOM if empty
      var state = getState(modalEl);
      if (state && state.users.size === 0 && state.groups.size === 0) {
        hydrateStateFromDOM(modalEl);
      }
      var currentUsers = state ? Array.from(state.users) : [];
      var currentGroupIds = state ? Array.from(state.groups) : [];
      // Preserve placeholder option
      var placeholder = select.querySelector('option[value=""]');
      // Clear everything
      while (select.firstChild) select.removeChild(select.firstChild);
      // Re-add placeholder
      if (placeholder) { select.appendChild(placeholder); } else {
        var ph = document.createElement('option'); ph.value=''; ph.textContent='— выбрать —'; select.appendChild(ph);
      }
      // Build users
      var ogUsers = document.createElement('optgroup'); ogUsers.label = 'Пользователи';
      var usersAvail = (allUsers||[]).filter(function(u){ return currentUsers.indexOf(u) === -1; }).sort(function(a,b){ return String(a).localeCompare(String(b), 'ru'); });
      usersAvail.forEach(function(u){ var o = document.createElement('option'); o.value = 'user:' + u; o.textContent = u; ogUsers.appendChild(o); });
      select.appendChild(ogUsers);
      // Build groups
      var ogGroups = document.createElement('optgroup'); ogGroups.label = 'Группы';
      var groupAvail = (allGroups||[]).filter(function(g){ return currentGroupIds.indexOf(Number(g && g.id)) === -1; }).sort(function(a,b){ return String(a && a.name).localeCompare(String(b && b.name), 'ru'); });
      groupAvail.forEach(function(g){ var o = document.createElement('option'); o.value = 'group:' + g.id; o.textContent = g.name; ogGroups.appendChild(o); });
      select.appendChild(ogGroups);
      // Reset selection
      select.value = '';
    }

    // Map of modalId -> baseline attendee snapshot (array of usernames)
    var attendeeBaseline = {};

    // When modal opens, capture baseline of flattened attendees from server
    document.querySelectorAll('.modal[id^="attendeesModal-"]').forEach(function(modalEl){
      modalEl.addEventListener('show.bs.modal', function(){
        var wid = modalEl.getAttribute('data-webinar-id');
        if (!wid) return;
        fetch('/api/webinars/' + wid + '/attendees/users', { credentials: 'same-origin' })
          .then(function(r){ return r.json(); })
          .then(function(list){ attendeeBaseline[wid] = Array.isArray(list) ? list.slice() : []; })
          .catch(function(){ attendeeBaseline[wid] = []; });
        // Also hydrate state from current DOM
        hydrateStateFromDOM(modalEl);
      });
      // Also ensure select is freshly rebuilt on open
      modalEl.addEventListener('shown.bs.modal', function(){ rebuildEntitySelect(modalEl); });
    });

    // Add attendee via JSON without closing modal
    document.querySelectorAll('.attendee-add-form').forEach(function(form){
      form.addEventListener('submit', function(e){
        e.preventDefault();
        var select = form.querySelector('select[name="entity"]');
        var val = select && select.value || '';
        if (!val) return;
        var parts = val.split(':');
        if (parts.length !== 2) return;
        var kind = parts[0];
        var id = parts[1];
        var fd = new URLSearchParams();
        fd.set('_csrf', form.querySelector('input[name="_csrf"]').value);
        fd.set('webinarId', form.querySelector('input[name="webinarId"]').value);
        var url = '';
        if (kind === 'user') { url = '/lecturer/webinars/attendees/user/add'; fd.set('username', id); }
        else if (kind === 'group') { url = '/lecturer/webinars/attendees/group/add'; fd.set('groupId', id); }
        else { return; }
        fetch(url, { method: 'POST', headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }, body: fd.toString() })
          .then(function(r){ return r.json().catch(function(){ return { ok:false }; }); })
          .then(function(data){
            if (!data || !data.ok) return;
            // Update UI: add item to the list and disable selected option
            var modalBody = form.closest('.modal-body');
            var list = modalBody.querySelector('.list-group');
            // Remove placeholder if present
            var placeholder = list.querySelector('.list-group-item.text-muted');
            if (placeholder) placeholder.remove();
            if (data.kind === 'user') {
              var li = document.createElement('li');
              li.className = 'list-group-item d-flex justify-content-between align-items-center';
              li.innerHTML = '<span><span class="badge text-bg-primary me-2">user<\/span>' + data.username + '</span>' +
                '<form method="post" action="/lecturer/webinars/attendees/user/remove" class="mb-0 attendee-remove-form">' +
                '<input type="hidden" name="_csrf" value="' + form.querySelector('input[name="_csrf"]').value + '">' +
                '<input type="hidden" name="webinarId" value="' + form.querySelector('input[name="webinarId"]').value + '">' +
                '<input type="hidden" name="username" value="' + data.username + '">' +
                '<button class="btn btn-sm btn-outline-danger">Удалить<\/button>' +
                '</form>';
              list.appendChild(li);
              // Update state
              var st = getState(form.closest('.modal'));
              if (st) { st.users.add(data.username); }
            } else if (data.kind === 'group') {
              var li2 = document.createElement('li');
              li2.className = 'list-group-item d-flex justify-content-between align-items-center';
              li2.innerHTML = '<span><span class="badge text-bg-secondary me-2">group<\/span>' + (data.groupName || ('ID ' + data.groupId)) + '</span>' +
                '<form method="post" action="/lecturer/webinars/attendees/group/remove" class="mb-0 attendee-remove-form">' +
                '<input type="hidden" name="_csrf" value="' + form.querySelector('input[name="_csrf"]').value + '">' +
                '<input type="hidden" name="webinarId" value="' + form.querySelector('input[name="webinarId"]').value + '">' +
                '<input type="hidden" name="groupId" value="' + data.groupId + '">' +
                '<button class="btn btn-sm btn-outline-danger">Удалить<\/button>' +
                '</form>';
              list.appendChild(li2);
              var st2 = getState(form.closest('.modal'));
              if (st2) { var n2 = Number(data.groupId); if (!Number.isNaN(n2)) st2.groups.add(n2); }
            }
            // Rebuild select using fresh state from DOM to avoid any drift
            var modalRoot = form.closest('.modal');
            hydrateStateFromDOM(modalRoot);
            rebuildEntitySelect(modalRoot);
            // proactively refresh notifications badge in navbar
            window.dispatchEvent(new Event('notifications:refresh'));
          });
      });
    });

    // Remove attendee via JSON
    document.addEventListener('submit', function(e){
      var form = e.target;
      if (form && form.classList.contains('attendee-remove-form')) {
        e.preventDefault();
        var url = form.getAttribute('action') || '';
        var fd = new URLSearchParams();
        Array.prototype.forEach.call(form.elements, function(el){
          if (!el.name) return;
          if (el.type === 'submit') return;
          fd.set(el.name, el.value);
        });
        fetch(url, { method: 'POST', headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }, body: fd.toString() })
          .then(function(r){ return r.json().catch(function(){ return { ok:false }; }); })
          .then(function(data){
            if (data && data.ok) {
              var item = form.closest('.list-group-item');
              if (item) item.remove();
              var modalBody = form.closest('.modal-body');
              // Update state
              var st = getState(form.closest('.modal'));
              if (st) {
                if (form.action.indexOf('/user/remove') !== -1) {
                  var u = form.querySelector('input[name="username"]').value;
                  if (u) st.users.delete(u);
                } else if (form.action.indexOf('/group/remove') !== -1) {
                  var gid = Number(form.querySelector('input[name="groupId"]').value);
                  if (!Number.isNaN(gid)) st.groups.delete(gid);
                }
              }
              // Rebuild select to restore removed attendee back to available choices (hydrate from DOM first)
              var modalRoot = form.closest('.modal');
              hydrateStateFromDOM(modalRoot);
              rebuildEntitySelect(modalRoot);
              // If list becomes empty, show placeholder
              var list = modalBody && modalBody.querySelector('.list-group');
              if (list && !list.querySelector('.list-group-item')) {
                var placeholder = document.createElement('li');
                placeholder.className = 'list-group-item text-muted';
                placeholder.textContent = 'никого';
                list.appendChild(placeholder);
              }
              // refresh notifications badge proactively
              window.dispatchEvent(new Event('notifications:refresh'));
            }
          });
      }
    }, true);

    // On modal close, compute diff vs baseline and notify
    document.querySelectorAll('.modal[id^="attendeesModal-"]').forEach(function(modalEl){
      modalEl.addEventListener('hide.bs.modal', function(){
        var wid = modalEl.getAttribute('data-webinar-id');
        if (!wid) return;
        var baseline = attendeeBaseline[wid] || [];
        // Send snapshot to server; server will diff against current DB state and notify added/removed users
        var fd = new URLSearchParams();
        fd.set('snapshot', JSON.stringify(baseline));
        // Ensure CSRF cookie exists
        function getCookie(name){
          var m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
          return m ? decodeURIComponent(m[1]) : undefined;
        }
        function postNotify(){
          var token = getCookie('XSRF-TOKEN') || '';
          var headers = { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' };
          if (token) headers['X-XSRF-TOKEN'] = token;
          fetch('/api/webinars/' + wid + '/attendees/notify-diff', { method: 'POST', headers: headers, body: fd.toString(), credentials: 'same-origin' })
            .then(function(){ window.dispatchEvent(new Event('notifications:refresh')); })
            .catch(function(){});
        }
        if (!getCookie('XSRF-TOKEN')) {
          fetch('/api/csrf', { credentials: 'same-origin' }).then(function(){ postNotify(); }).catch(function(){ postNotify(); });
        } else {
          postNotify();
        }
      });
    });
  });
})();
