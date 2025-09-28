const vulnerabilities = [
    { severity: 'High', type: 'SQL Injection', location: 'Login.java:15', description: 'User input is concatenated directly into a SQL query, allowing for injection attacks.' },
    { severity: 'Medium', type: 'XSS', location: 'Profile.jsp:32', description: 'Unsanitized user input is rendered on the page, which can be exploited to run malicious scripts.' },
    { severity: 'Low', type: 'Hardcoded Credential', location: 'Config.java:5', description: 'A database password is hardcoded directly in the source code.' },
    { severity: 'High', type: 'Insecure Deserialization', location: 'DataHandler.java:45', description: 'The application is deserializing untrusted data without validation.' }
];

document.getElementById('total-issues').innerText = vulnerabilities.length;
const tableBody = document.getElementById('vulnerability-table');
vulnerabilities.forEach(vuln => {
    const row = tableBody.insertRow();
    row.innerHTML = `
        <td>${vuln.severity}</td>
        <td>${vuln.type}</td>
        <td>${vuln.location}</td>
        <td>${vuln.description}</td>
    `;
});

// Chart.js data
const severityCounts = vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
}, {});

const typeCounts = vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.type] = (acc[vuln.type] || 0) + 1;
    return acc;
}, {});

// Vulnerability Count Chart
const vulnCtx = document.getElementById('vulnerabilityChart').getContext('2d');
new Chart(vulnCtx, {
    type: 'bar',
    data: {
        labels: Object.keys(severityCounts),
        datasets: [{
            label: '# of Vulnerabilities',
            data: Object.values(severityCounts),
            backgroundColor: ['#FF6384', '#FFCE56', '#36A2EB'],
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: { beginAtZero: true }
        }
    }
});

// Vulnerability Types Chart
const typeCtx = document.getElementById('typeChart').getContext('2d');
new Chart(typeCtx, {
    type: 'doughnut',
    data: {
        labels: Object.keys(typeCounts),
        datasets: [{
            data: Object.values(typeCounts),
            backgroundColor: ['#FF6384', '#4BC0C0', '#FFCE56', '#36A2EB'],
        }]
    },
    options: {
        responsive: true,
    }
});