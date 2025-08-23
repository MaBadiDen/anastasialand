(function(){
  function toFormBody(form){
    var data = new URLSearchParams();
    Array.from(new FormData(form).entries()).forEach(function(entry){ data.append(entry[0], String(entry[1])); });
    return data.toString();
  }
  function setMembers(modal, members, csrfToken, groupId){
    var tbody = modal.querySelector('#gm-members-table tbody');
    var empty = modal.querySelector('#gm-members-empty');
    if (!tbody || !empty) return;
    if (!members || members.length === 0){
      empty.classList.remove('d-none');
      tbody.innerHTML = '';
    } else {
      empty.classList.add('d-none');
      tbody.innerHTML = members.map(function(m){ return (
        '<tr>'+
          '<td>'+m.username+'</td>'+
          '<td class="text-end">'+
            '<form method="post" action="/admin/groups/members/remove" class="d-inline gm-remove">'+
              '<input type="hidden" name="_csrf" value="'+csrfToken+'">'+
              '<input type="hidden" name="username" value="'+m.username+'">'+
              '<input type="hidden" name="groupId" value="'+groupId+'">'+
              '<button class="btn btn-sm btn-outline-danger">Убрать</button>'+
            '</form>'+
          '</td>'+
        '</tr>'
      ); }).join('');
    }
  }
  function setAvailable(modal, available){
    var select = modal.querySelector('#gm-add-select');
    if (!select) return;
    if (!available || available.length === 0){
      select.innerHTML = '<option disabled>Нет доступных пользователей</option>';
      select.disabled = true;
    } else {
      select.disabled = false;
      select.innerHTML = available.map(function(u){ return '<option value="'+u.username+'">'+u.username+'</option>'; }).join('');
    }
  }
  var currentGroupId = null;
  var csrfToken = (function(){ var el=document.querySelector('input[name="_csrf"]'); return el? el.value : ''; })();
  var modalEl = document.getElementById('groupModal');
  var modal = modalEl && window.bootstrap ? new window.bootstrap.Modal(modalEl) : null;
  var titleId = document.getElementById('gm-id');
  var titleName = document.getElementById('gm-name');
  var renameForm = document.getElementById('gm-rename');
  var renameId = document.getElementById('gm-rename-id');
  var renameName = document.getElementById('gm-rename-name');
  var addForm = document.getElementById('gm-add');
  var addId = document.getElementById('gm-add-id');
  function openGroup(id, name){
    currentGroupId = id;
    if (titleId) titleId.textContent = String(id);
    if (titleName) titleName.textContent = name;
    if (renameId) renameId.value = String(id);
    if (renameName) renameName.value = name;
    if (addId) addId.value = String(id);
    fetch('/admin/groups/'+id, { headers: { 'Accept': 'application/json' }})
      .then(function(r){ return r.json(); })
      .then(function(json){
        if (!json || json.ok === false) throw new Error('load');
        setMembers(modalEl, json.members || [], csrfToken, id);
        setAvailable(modalEl, json.availableUsers || []);
      })
      .catch(function(){ setMembers(modalEl, [], csrfToken, id); setAvailable(modalEl, []); });
    if (modal) modal.show();
  }
  document.querySelectorAll('#groupsTable .btn-edit').forEach(function(btn){
    btn.addEventListener('click', function(){
      var id = Number((btn.getAttribute('data-id')||'').trim());
      var name = btn.getAttribute('data-name') || '';
      openGroup(id, name);
    });
  });
  if (renameForm) {
    renameForm.addEventListener('submit', function(e){
      e.preventDefault();
      fetch(renameForm.action, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, body: toFormBody(renameForm) })
        .then(function(r){ return r.json(); })
        .then(function(json){
          if (!json || json.ok === false) throw new Error('save');
          var name = json.group && json.group.name ? json.group.name : renameName.value;
          if (titleName) titleName.textContent = name;
          var row = document.querySelector('tr[data-group-id="'+currentGroupId+'"][data-group-name] .gname');
          if (row) row.textContent = name;
          var btn = document.querySelector('#groupsTable tr[data-group-id="'+currentGroupId+'"][data-group-name] .btn-edit');
          if (btn) btn.setAttribute('data-name', name);
        })
        .catch(function(){ alert('Не удалось сохранить изменения'); });
    });
  }
  if (addForm) {
    addForm.addEventListener('submit', function(e){
      e.preventDefault();
      fetch(addForm.action, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, body: toFormBody(addForm) })
        .then(function(r){ return r.json(); })
        .then(function(json){
          if (!json || json.ok === false) throw new Error('save');
          setMembers(modalEl, json.members || [], csrfToken, currentGroupId);
          setAvailable(modalEl, json.availableUsers || []);
        })
        .catch(function(){ alert('Не удалось сохранить изменения'); });
    });
  }
  if (modalEl) {
    modalEl.addEventListener('submit', function(e){
      var form = e.target;
      if (!(form && form.classList && form.classList.contains('gm-remove'))) return;
      e.preventDefault();
      fetch(form.action, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, body: toFormBody(form) })
        .then(function(r){ return r.json(); })
        .then(function(json){
          if (!json || json.ok === false) throw new Error('save');
          setMembers(modalEl, json.members || [], csrfToken, currentGroupId);
          setAvailable(modalEl, json.availableUsers || []);
        })
        .catch(function(){ alert('Не удалось сохранить изменения'); });
    });
  }
})();
