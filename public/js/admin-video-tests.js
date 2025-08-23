(function(){
  function handleClick(e){
    var btn = e.target && e.target.closest && e.target.closest('.js-del-test');
    if (!btn) return;
    var id = btn.getAttribute('data-id');
    var csrf = btn.getAttribute('data-csrf');
    if (!id || !csrf) return;
    if (!confirm('Удалить вопрос?')) return;
    var f = document.createElement('form');
    f.method = 'post';
    f.action = '/admin/video-tests/delete';
    var i1 = document.createElement('input'); i1.type='hidden'; i1.name='_csrf'; i1.value=csrf; f.appendChild(i1);
    var i2 = document.createElement('input'); i2.type='hidden'; i2.name='id'; i2.value=id; f.appendChild(i2);
    document.body.appendChild(f);
    f.submit();
  }
  document.addEventListener('click', handleClick);
})();
