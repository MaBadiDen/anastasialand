// admin-user-progress.js
(function(){
  'use strict';
  function onReady(fn){ if (document.readyState !== 'loading') fn(); else document.addEventListener('DOMContentLoaded', fn, { once: true }); }
  onReady(function(){
    document.querySelectorAll('select.js-autosubmit').forEach(function(sel){
      sel.addEventListener('change', function(){
        var form = sel.closest('form');
        if (form) form.submit();
      });
    });
  });
})();
