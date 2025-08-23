// Wire edit and delete modals with selected row data
(function(){
  function onShowEdit(e){
    var btn = e.relatedTarget;
    if (!btn) return;
    var user = btn.getAttribute('data-username') || '';
    var role = btn.getAttribute('data-role') || 'user';
    var email = btn.getAttribute('data-email') || '';
    var m = document.getElementById('editUserModal');
    if (!m) return;
    m.querySelector('input[name="username"]').value = user;
    m.querySelector('input[name="email"]').value = email;
    m.querySelector('select[name="role"]').value = role;
    m.querySelector('input[name="password"]').value = '';
  }
  function onShowDelete(e){
    var btn = e.relatedTarget;
    if (!btn) return;
    var user = btn.getAttribute('data-username') || '';
    var m = document.getElementById('deleteUserModal');
    if (!m) return;
    m.querySelector('input[name="username"]').value = user;
    var lbl = m.querySelector('[data-role="username"]');
    if (lbl) lbl.textContent = user;
  }
  document.addEventListener('DOMContentLoaded', function(){
    var editModal = document.getElementById('editUserModal');
    if (editModal) { editModal.addEventListener('show.bs.modal', onShowEdit); }
    var delModal = document.getElementById('deleteUserModal');
    if (delModal) { delModal.addEventListener('show.bs.modal', onShowDelete); }
  });
})();
