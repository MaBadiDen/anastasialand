// Common auth page helper: show error from query and inject CSRF token from cookie into hidden field
(function () {
  function getCookie(name) {
    return document.cookie
      .split('; ')
      .find((row) => row.startsWith(name + '='))?.split('=')[1];
  }

  function showErrorFromQuery() {
    try {
      const params = new URLSearchParams(window.location.search);
      const msg = params.get('error') || params.get('warning');
      if (!msg) return;
      const el = document.getElementById('error-message');
      if (!el) return;
      el.textContent = msg;
      el.classList.remove('d-none');
    } catch {}
  }

  function injectCsrf() {
    try {
      const token = getCookie('XSRF-TOKEN');
      if (!token) return;
      const input = document.querySelector('input[name="_csrf"]');
      if (input) input.value = decodeURIComponent(token);
    } catch {}
  }

  document.addEventListener('DOMContentLoaded', function () {
    showErrorFromQuery();
    injectCsrf();
  });
})();
