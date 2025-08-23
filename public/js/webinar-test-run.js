(function(){
  var dataEl = document.getElementById('wt-data');
  var payload = {};
  try { payload = JSON.parse(decodeURIComponent((dataEl && dataEl.getAttribute('data-json')) || '{}')); } catch {}
  var test = Array.isArray(payload.test) ? payload.test : [];
  var form = document.getElementById('webinarTestForm');
  var result = document.getElementById('result');
  if (!form) return;
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
  });
})();
