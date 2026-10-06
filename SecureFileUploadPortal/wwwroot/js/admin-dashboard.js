(function () {
    document.querySelectorAll('.pipeline-bar [data-pct]').forEach(function (el) {
        el.style.width = el.getAttribute('data-pct') + '%';
    });

    var canvas = document.getElementById('activityChart');
    if (!canvas || !window.Chart) return;
    var days = JSON.parse(canvas.getAttribute('data-days'));
    Chart.defaults.color = '#9aa7b4';
    Chart.defaults.borderColor = '#2c3e50';
    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: days.map(function (d) { return d.label; }),
            datasets: [
                { label: 'Uploads', data: days.map(function (d) { return d.uploads; }), backgroundColor: '#3498db', borderRadius: 4 },
                { label: 'Downloads', data: days.map(function (d) { return d.downloads; }), backgroundColor: '#1abc9c', borderRadius: 4 },
                { label: 'Sign-ins', data: days.map(function (d) { return d.logins; }), backgroundColor: '#27ae60', borderRadius: 4 },
                { label: 'Denied / failed actions', data: days.map(function (d) { return d.failedActions; }), backgroundColor: '#e74c3c', borderRadius: 4 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 12 } } },
            scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
})();
