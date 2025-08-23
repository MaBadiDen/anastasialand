(function(){
  var token = (function(){
    var m = document.cookie.match(/(?:^|; )XSRF-TOKEN=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : '';
  })();
  function renumber(ul){
    if(!ul) return;
    Array.from(ul.querySelectorAll('li')).forEach(function(li, i){
      var badge = li.querySelector('.order-badge');
      if (badge) badge.textContent = '#' + (i + 1);
    });
  }
  function renumberAll(){
    document.querySelectorAll('ul.list-group[data-topic]').forEach(renumber);
  }
  function saveOrder(topic){
    var ul = document.querySelector('ul[data-topic="' + topic + '"]');
    if (!ul) return;
    var ids = Array.from(ul.querySelectorAll('li')).map(function(li){ return Number(li.getAttribute('data-id')); });
    fetch('/admin/videos/reorder',{
      method:'POST',
      headers:{'Content-Type':'application/json','x-csrf-token': token},
      body: JSON.stringify({ topic: topic, ids: ids })
    }).then(function(r){ return r.json(); }).then(function(){
      var url = new URL(location.href);
      if (!url.searchParams.get('topic')) url.searchParams.set('topic', topic);
      location.href = url.toString();
    });
  }
  document.addEventListener('click', function(e){
    var btn = e.target && e.target.closest && e.target.closest('button[data-action="save"]');
    if(btn){ saveOrder(btn.getAttribute('data-topic')); }
  });
  var dragged = null;
  document.addEventListener('dragstart', function(e){
    var li = e.target && e.target.closest && e.target.closest('li');
    if(!li) return;
    dragged = li; li.classList.add('ghost'); if (e.dataTransfer) e.dataTransfer.effectAllowed='move';
  });
  document.addEventListener('dragend', function(){
    if(dragged){ var ul = dragged.parentElement; dragged.classList.remove('ghost'); renumber(ul); dragged=null; }
  });
  document.addEventListener('dragover', function(e){
    var li = e.target && e.target.closest && e.target.closest('li');
    if(!li || !dragged || li===dragged) return;
    e.preventDefault();
    var ul = li.parentElement;
    var rect = li.getBoundingClientRect();
    var after = (e.clientY - rect.top) > rect.height/2;
    ul.insertBefore(dragged, after? li.nextSibling : li);
    renumber(ul);
  });
  document.querySelectorAll('li').forEach(function(li){ li.setAttribute('draggable','true'); });
  renumberAll();
  var delModalEl = document.getElementById('confirmDeleteTopicModal');
  if (delModalEl) {
    delModalEl.addEventListener('show.bs.modal', function (event) {
      var button = event.relatedTarget;
      if (!button) return;
      var id = button.getAttribute('data-topic-id') || '';
      var name = button.getAttribute('data-topic-name') || '';
      delModalEl.querySelector('input[name="id"]').value = id;
      delModalEl.querySelector('input[name="name"]').value = name;
      var tn = delModalEl.querySelector('[data-role="topic-name"]');
      if (tn) tn.textContent = name;
    });
  }
})();
