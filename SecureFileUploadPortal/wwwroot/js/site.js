// Behaviour wired through data-* attributes so pages work under a strict Content-Security-Policy (no inline script).
document.addEventListener('submit', function (e) {
    var form = e.target.closest('form[data-confirm]');
    if (form && !window.confirm(form.getAttribute('data-confirm'))) e.preventDefault();
});

(function () {
    var el = document.querySelector('[data-auto-refresh]');
    var seconds = el ? parseInt(el.getAttribute('data-auto-refresh'), 10) : 0;
    if (seconds > 0) setTimeout(function () { window.location.reload(); }, seconds * 1000);
})();
