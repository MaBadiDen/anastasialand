(function(){
  var dataEl = document.getElementById('test-data');
  var payload = {};
  try { payload = JSON.parse(decodeURIComponent((dataEl && dataEl.getAttribute('data-json')) || '{}')); } catch(e) { payload = {}; }
  var test = Array.isArray(payload.test) ? payload.test : [];
  var topic = payload.topic || null;
  var form = document.getElementById('testForm');
  var result = document.getElementById('result');
  function getCookie(n){
    var m = document.cookie.match(new RegExp('(?:^|; )' + n.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : undefined;
  }
  var token = getCookie('XSRF-TOKEN');
  if (form) {
    form.addEventListener('submit', function(e){
      e.preventDefault();
      var correct = 0;
      for (var i = 0; i < test.length; i++) {
        var sel = document.querySelector('input[name="q' + i + '"]:checked');
        if (sel && Number(sel.value) === test[i].answer) correct++;
      }
      if (result) {
        result.classList.remove('d-none');
        result.textContent = 'Ваш результат: ' + correct + ' из ' + test.length;
        result.className = 'alert ' + (correct === test.length ? 'alert-success' : 'alert-info');
      }
      if (topic && correct === test.length) {
        fetch('/api/progress/test-pass', {method:'POST', headers:{'Content-Type':'application/json','x-csrf-token': decodeURIComponent(token||'')}, body: JSON.stringify({ topic: topic })})
          .then(function(){ /* unlocked */ });
      }
    });
  }
})();
