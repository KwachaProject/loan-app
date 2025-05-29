// Loan Portfolio Chart
const loanPortfolioCtx = document.getElementById('loanPortfolioChart').getContext('2d');
new Chart(loanPortfolioCtx, {
    type: 'doughnut',
    data: {
        labels: JSON.parse('{{ loan_types|tojson|safe }}'),
        datasets: [{
            data: JSON.parse('{{ loan_amounts|tojson|safe }}'),
            backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc']
        }]
    }
});

// Repayment Trend Chart
const repaymentCtx = document.getElementById('repaymentTrendChart').getContext('2d');
new Chart(repaymentCtx, {
    type: 'line',
    data: {
        labels: JSON.parse('{{ dates|tojson|safe }}'),
        datasets: [{
            label: 'Daily Repayments',
            data: JSON.parse('{{ amounts|tojson|safe }}'),
            borderColor: '#4e73df'
        }]
    }
});