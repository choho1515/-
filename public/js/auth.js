document.addEventListener('DOMContentLoaded', () => {
    if (typeof authData === 'undefined') return;

    initializeDevToolsBlocker();
    
    if (authData.error && authData.error !== 'null' && authData.stage !== 'error') {
        displayAlert('error', authData.error);
    }
    
    switch (authData.stage) {
        case 'email_fingerprint':
            setupEmailStage();
            break;
        case 'code_submit':
            setupCodeSubmitStage();
            break;
    }
});

function displayAlert(type, message) {
    const box = document.getElementById('alert-box');
    const icon = document.getElementById('alert-icon');
    const msg = document.getElementById('alert-message');
    if (!box || !icon || !msg) return;

    box.className = 'p-4 mb-4 text-sm rounded-lg flex items-center';
    icon.innerHTML = '';
    if (type === 'error') {
        box.classList.add('bg-error-bg', 'dark:bg-dark-error-bg', 'text-error-text', 'dark:text-dark-error-text');
        icon.innerHTML = '<svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM10 15a1 1 0 1 1 0-2 1 1 0 0 1 0 2Zm1-4a1 1 0 0 1-2 0V6a1 1 0 0 1 2 0v5Z"/></svg>';
    }
    msg.textContent = message;
    box.classList.remove('hidden');
}

function setupEmailStage() {
    const fingerprintIdInput = document.getElementById('fingerprint-id');
    const submitButton = document.getElementById('submit-button');
    if (!fingerprintIdInput || !submitButton) return;

    FingerprintJS.load()
        .then(fp => fp.get())
        .then(result => {
            fingerprintIdInput.value = result.visitorId;
            submitButton.disabled = false;
            submitButton.classList.remove('bg-gray-400', 'cursor-not-allowed');
            submitButton.classList.add('bg-discord-blue', 'hover:bg-indigo-600');
            submitButton.textContent = '인증 코드 요청하기';
        })
        .catch(error => {
            displayAlert('error', '기기 정보 수집에 실패했습니다. 다른 브라우저로 시도해주세요.');
            submitButton.textContent = '오류 발생';
        });
}

function setupCodeSubmitStage() {
    const verifyForm = document.getElementById('verify-form');
    if (!verifyForm) return;
    verifyForm.addEventListener('submit', () => {
        const mainContent = document.getElementById('main-content');
        const loadingOverlay = document.getElementById('loading-overlay');
        if (mainContent) mainContent.style.opacity = '0';
        if (loadingOverlay) loadingOverlay.classList.remove('hidden');
    });
}

function initializeDevToolsBlocker() {
    const threshold = 160;
    const blockPage = () => {
        document.body.innerHTML = `
            <div class="flex items-center justify-center min-h-screen bg-light-bg dark:bg-dark-bg text-light-text dark:text-dark-text">
                <div class="p-8 text-center bg-light-card dark:bg-dark-card rounded-xl shadow-2xl">
                    <div class="text-6xl">🚫</div>
                    <h2 class="text-xl font-bold mt-4">보안 정책 위반</h2>
                    <p class="text-error-text dark:text-dark-error-text font-medium mt-2">개발자 도구를 사용할 수 없습니다.</p>
                </div>
            </div>`;
    };
    const check = () => {
        if ((window.outerWidth - window.innerWidth > threshold) || (window.outerHeight - window.innerHeight > threshold)) {
            blockPage();
        }
    };
    setInterval(check, 1000);
}
