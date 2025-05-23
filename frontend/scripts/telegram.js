function showNotification() {
    if (localStorage.getItem('telegramNotificationDismissed') === 'true') return;
    document.getElementById('telegram-notification').classList.add('show');
}

function closeNotification() {
    document.getElementById('telegram-notification').classList.remove('show');
    localStorage.setItem('telegramNotificationDismissed', 'true');
}

function dismissNotification() {
    document.getElementById('telegram-notification').classList.remove('show');
    setTimeout(showNotification, 30 * 60 * 1000);
}
document.addEventListener('DOMContentLoaded', async () => {
    try {
        setTimeout(showNotification, 10000);
    } catch (error) {
        console.error('Initialization error:', error);
    }
});