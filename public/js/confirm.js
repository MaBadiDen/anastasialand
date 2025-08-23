(function(){
  document.addEventListener('click', function(e){
    var btn = e.target && e.target.closest && e.target.closest('.js-confirm');
    if (!btn) return;
    var msg = btn.getAttribute('data-confirm') || 'Вы уверены?';
    if (!confirm(msg)) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  });
})();
