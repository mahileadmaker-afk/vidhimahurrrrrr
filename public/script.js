document.addEventListener('DOMContentLoaded', () => {
    const passwordGate = document.getElementById('password-gate');
    const gateForm = document.getElementById('gate-form');
    const gatePassword = document.getElementById('gate-password');
    const gateError = document.getElementById('gate-error');
    const gateErrorText = document.getElementById('gate-error-text');
    const mainApp = document.getElementById('main-app');
    const logoutBtn = document.getElementById('logout-btn');

    const toggleGatePass = document.getElementById('toggle-gate-password');
    const toggleDashPass = document.getElementById('toggle-password');
    const dashPasswordInput = document.getElementById('dashboard-password');

    const recipientsInput = document.getElementById('recipients-input');
    const detectedCount = document.getElementById('detected-count');

    const sendBtn = document.getElementById('send-btn');
    const stopBtn = document.getElementById('stop-btn');

    const statTotal = document.getElementById('stat-total');
    const statSent = document.getElementById('stat-sent');
    const statFailed = document.getElementById('stat-failed');
    const statRemaining = document.getElementById('stat-remaining');
    const progressBar = document.getElementById('progress-bar');
    const statusText = document.getElementById('status-text');
    const statusIcon = document.getElementById('status-icon');

    let abortController = null;

    const savedToken = sessionStorage.getItem('console_token');
    if (savedToken) {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    }

    toggleGatePass?.addEventListener('click', () => {
        gatePassword.type = gatePassword.type === 'password' ? 'text' : 'password';
    });
    toggleDashPass?.addEventListener('click', () => {
        dashPasswordInput.type = dashPasswordInput.type === 'password' ? 'text' : 'password';
    });

    gateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        gateError.classList.add('hidden');

        try {
            const res = await fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: gatePassword.value })
            });

            const data = await res.json();
            if (data.success) {
                sessionStorage.setItem('console_token', data.token);
                passwordGate.classList.add('hidden');
                mainApp.classList.remove('hidden');
            } else {
                gateErrorText.innerText = data.message || 'Incorrect Password';
                gateError.classList.remove('hidden');
            }
        } catch (err) {
            gateErrorText.innerText = 'Server connection error';
            gateError.classList.remove('hidden');
        }
    });

    logoutBtn.addEventListener('dblclick', () => {
        sessionStorage.removeItem('console_token');
        location.reload();
    });

    function getRecipients() {
        const text = recipientsInput.value;
        const matches = text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g) || [];
        return [...new Set(matches)];
    }

    recipientsInput.addEventListener('input', () => {
        const list = getRecipients();
        detectedCount.innerText = `${list.length} found`;
        statTotal.innerText = list.length;
        statRemaining.innerText = list.length;
    });

    sendBtn.addEventListener('click', async () => {
        const recipients = getRecipients();
        const senderName = document.getElementById('sender-name').value.trim();
        const email = document.getElementById('dashboard-email').value.trim();
        const appPassword = dashPasswordInput.value.trim();
        const subject = document.getElementById('subject').value.trim();
        const body = document.getElementById('message-body').value.trim();
        const cfToken = document.querySelector('[name="cf-turnstile-response"]')?.value || '';
        const authToken = sessionStorage.getItem('console_token');

        if (!email || !appPassword || !subject || !body) {
            alert('Please fill out all required email fields.');
            return;
        }

        if (recipients.length === 0) {
            alert('Please add at least 1 valid recipient email.');
            return;
        }

        sendBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        statSent.innerText = '0';
        statFailed.innerText = '0';
        progressBar.style.width = '0%';
        statusText.innerText = 'Sending in batches of 2...';
        statusIcon.className = 'fa-solid fa-spinner fa-spin text-primary';

        abortController = new AbortController();

        try {
            const response = await fetch('/api/send-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: abortController.signal,
                body: JSON.stringify({
                    senderName, email, appPassword, subject, body, recipients, cfToken, authToken
                })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const event = JSON.parse(line.replace('data: ', ''));

                        if (event.type === 'start') {
                            statTotal.innerText = event.total;
                        } else if (event.type === 'progress') {
                            statSent.innerText = event.sentCount;
                            statFailed.innerText = event.failedCount;
                            const remaining = event.total - (event.sentCount + event.failedCount);
                            statRemaining.innerText = Math.max(0, remaining);

                            const percent = Math.round(((event.sentCount + event.failedCount) / event.total) * 100);
                            progressBar.style.width = `${percent}%`;
                            statusText.innerText = `Sending (${percent}%) - Last: ${event.recipient}`;
                        } else if (event.type === 'complete') {
                            statusText.innerText = `Finished! ${event.sentCount} sent, ${event.failedCount} failed.`;
                            statusIcon.className = 'fa-solid fa-circle-check text-success';
                        } else if (event.type === 'fatal_error') {
                            alert(event.message);
                            statusText.innerText = 'Error: ' + event.message;
                            statusIcon.className = 'fa-solid fa-triangle-exclamation text-danger';
                        }
                    }
                }
            }
        } catch (err) {
            if (err.name === 'AbortError') {
                statusText.innerText = 'Stopped by user.';
            } else {
                statusText.innerText = 'Stream error.';
            }
            statusIcon.className = 'fa-solid fa-circle-xmark text-danger';
        } finally {
            sendBtn.classList.remove('hidden');
            stopBtn.classList.add('hidden');
        }
    });

    stopBtn.addEventListener('click', () => {
        if (abortController) {
            abortController.abort();
            statusText.innerText = 'Stopping dispatch...';
        }
    });
});
