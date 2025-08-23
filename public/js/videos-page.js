(function(){
  function getCookie(name){
    var m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : undefined;
  }
  // Apply computed progress values to CSS variable for badges
  document.querySelectorAll('.progress-badge[data-progress]').forEach(function(el){
    var p = Number(el.getAttribute('data-progress')||'0');
    if (!Number.isFinite(p) || p < 0) p = 0; if (p > 100) p = 100;
    el.style.setProperty('--progress', String(p));
  });
  var token = getCookie('XSRF-TOKEN');
  var toastEl = document.getElementById('watchToast');
  var toast = null;
  document.querySelectorAll('video[data-topic][data-index]').forEach(function(v){
    v.addEventListener('ended', function(){
      var topic = decodeURIComponent(v.getAttribute('data-topic')||'');
      var index = Number(v.getAttribute('data-index')||'0');
      fetch('/api/progress/watch', {method:'POST', headers:{'Content-Type':'application/json','x-csrf-token': decodeURIComponent(token||'')}, body: JSON.stringify({topic: topic, index: index})})
        .then(function(r){
          if (!r.ok) return;
          try {
            var cta = document.querySelector('[data-test-cta][data-topic="' + encodeURIComponent(topic) + '"]');
            if (cta) {
              cta.classList.remove('d-none');
              cta.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
            var headerBtn = v.closest('.accordion-item') && v.closest('.accordion-item').querySelector('.accordion-button');
            if (headerBtn && !headerBtn.classList.contains('video-status-passed')) {
              headerBtn.classList.add('video-status-watched');
            }
            if (toastEl && (!toast) && window.bootstrap && window.bootstrap.Toast) {
              toast = new window.bootstrap.Toast(toastEl);
            }
            if (toast) { toast.show(); }
          } catch(e) { /* ignore */ }
        })
        .catch(function(){ /* ignore network errors */ });
    });
  });
  document.querySelectorAll('[data-test-cta]').forEach(function(el){
    var on = el.getAttribute('data-visible') === '1';
    el.classList.toggle('d-none', !on);
  });
})();
