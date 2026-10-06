(function () {
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
                { label: 'Uploads', data: days.map(function (d) { return d.uploads; }), backgroundColor: '#3498db' },
                { label: 'Downloads', data: days.map(function (d) { return d.downloads; }), backgroundColor: '#1abc9c' },
                { label: 'Sign-ins', data: days.map(function (d) { return d.logins; }), backgroundColor: '#27ae60' },
                { label: 'Failed sign-ins', data: days.map(function (d) { return d.failedLogins; }), backgroundColor: '#e74c3c' }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
})();
