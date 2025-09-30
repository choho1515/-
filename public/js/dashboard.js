document.addEventListener('DOMContentLoaded', function () {
    if (typeof statsData === 'undefined') {
        console.error('Stats data is not available.');
        return;
    }
    const stats = statsData;
    const getChartColor = () => window.matchMedia('(prefers-color-scheme: dark)').matches ? '#e5e7eb' : '#1f2937';

    new Chart(document.getElementById('timeSeriesChart'), {
        type: 'line',
        data: {
            labels: stats.timeSeriesData.labels,
            datasets: [
                { label: '성공', data: stats.timeSeriesData.allowed, borderColor: '#22c55e', tension: 0.1 },
                { label: '실패', data: stats.timeSeriesData.denied, borderColor: '#ef4444', tension: 0.1 },
                { label: '경고', data: stats.timeSeriesData.warning, borderColor: '#f59e0b', tension: 0.1 }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: getChartColor(), stepSize: 1 } }, x: { ticks: { color: getChartColor() } } }, plugins: { legend: { labels: { color: getChartColor() } } } }
    });
    new Chart(document.getElementById('verificationChart'), {
        type: 'doughnut',
        data: { labels: ['성공', '실패', '경고'], datasets: [{ data: [stats.chartData.allowed, stats.chartData.denied, stats.chartData.warning], backgroundColor: ['#22c55e', '#ef4444', '#f59e0b'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: getChartColor() } } } }
    });
    new Chart(document.getElementById('ageDistributionChart'), {
        type: 'bar',
        data: { labels: stats.ageDistributionChart.labels, datasets: [{ label: '계정 수', data: stats.ageDistributionChart.data, backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'] }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { color: getChartColor(), stepSize: 1 } }, x: { ticks: { color: getChartColor() } } }, plugins: { legend: { display: false } } }
    });

    const urlParams = new URLSearchParams(window.location.search);
    const viewUserId = urlParams.get('viewUser');
    if (viewUserId) {
        showUserDetails(viewUserId);
    }
});

function searchUsers() {
    const input = document.getElementById('userSearch').value.toLowerCase();
    const table = document.getElementById('userTable');
    const tr = table.getElementsByTagName('tr');
    for (let i = 1; i < tr.length; i++) {
        const td1 = tr[i].getElementsByTagName('td')[0];
        const td2 = tr[i].getElementsByTagName('td')[1];
        if (td1 || td2) {
            const textValue = (td1.textContent || td1.innerText) + (td2.textContent || td2.innerText);
            tr[i].style.display = textValue.toLowerCase().indexOf(input) > -1 ? '' : 'none';
        }
    }
}

const modal = document.getElementById('userDetailsModal');
const modalLoader = document.getElementById('modal-loader');
const modalData = document.getElementById('modal-data');
if (modal) {
    modal.addEventListener('click', closeModal);
}

function closeModal() { if (modal) modal.style.display = 'none'; }

function translateLogReason(log) {
    const reasonText = log.reason || '';
    switch (log.result) {
        case 'allowed':
            return `✅ <b>인증 성공</b>: AI 위험도 '${log.riskLevel || '낮음'}'으로 판정되었습니다.<br><small class="text-gray-500">${log.reasoning || '특이사항 없음.'}</small>`;
        case 'denied':
            if (reasonText.includes('fingerprint_duplicate')) {
                return '🚨 <b>인증 실패 (기기 중복)</b>: 이미 서버에 등록된 기기입니다.';
            }
            if (reasonText.includes('email_duplicate')) {
                return '🚨 <b>인증 실패 (이메일 중복)</b>: 이미 사용된 이메일 주소입니다.';
            }
            return `🚨 <b>인증 실패</b>: 알 수 없는 원인 (${reasonText})`;
        case 'warning':
            const riskLevel = reasonText.split(':')[1] || log.riskLevel || '정보 없음';
            return `⚠️ <b>인증 경고 (AI 분석)</b>: AI가 위험도 '${riskLevel}'의 잠재적 위험을 감지했습니다.<br><small class="text-gray-500">${log.reasoning || '추가 정보 없음.'}</small>`;
        default:
            return `${log.result.toUpperCase()}: ${reasonText}`;
    }
}

async function showUserDetails(userId, guildId) {
    if (!modal) return;
    modal.style.display = 'flex';
    modalLoader.style.display = 'block';
    modalData.style.display = 'none';
    modalLoader.textContent = '불러오는 중...';

    try {
        const response = await fetch(`/dashboard/api/user/${userId}?guildId=${guildId}`);
        if (!response.ok) throw new Error('데이터를 불러오는데 실패했습니다.');
        const data = await response.json();

        document.getElementById('modal-avatar').src = data.discordInfo.avatarURL || 'https://cdn.discordapp.com/embed/avatars/0.png';
        document.getElementById('modal-username').textContent = data.discordInfo.username;
        document.getElementById('modal-userid').textContent = data.discordInfo.id;
        document.getElementById('modal-createdat').textContent = new Date(data.discordInfo.createdAt).toLocaleString('ko-KR');
        document.getElementById('modal-email').textContent = data.verificationData.email || 'N/A';
        document.getElementById('modal-fingerprint').textContent = data.verificationData.fingerprint || 'N/A';

        const emailContainer = document.getElementById('modal-email').parentElement;
        const oldWarning = emailContainer.querySelector('.similar-email-warning');
        if (oldWarning) oldWarning.remove();

        let warningHTML = '';

        if (data.verificationData.similarEmailInfo?.isSimilar) {
            const info = data.verificationData.similarEmailInfo;
            warningHTML = `🚨 <b>유사 이메일 감지:</b> 이 계정은 <code>${info.matchedEmail}</code> (ID: <code>${info.matchedUserId}</code>)와(과) 유사합니다.`;
        } 
        else if (data.relatedAccounts.bySimilarEmail.length > 0) {
            const similarUsersList = data.relatedAccounts.bySimilarEmail
                .map(rel => `<code>${rel.email}</code> (ID: <code>${rel.userId}</code>)`)
                .join(', ');
            warningHTML = `🚨 <b>유사 이메일 감지:</b> 이 계정은 <code>${similarUsersList}</code>와(과) 유사합니다.`;
        }

        if (warningHTML) {
            const warningEl = document.createElement('div');
            warningEl.className = 'similar-email-warning text-xs text-yellow-600 dark:text-yellow-400 mt-1 p-2 bg-yellow-500/10 rounded';
            warningEl.innerHTML = warningHTML;
            emailContainer.appendChild(warningEl);
        }

        const relatedSection = document.getElementById('related-accounts-section');
        const relatedDiv = document.getElementById('modal-related-accounts');
        relatedDiv.innerHTML = ''; 

        let hasRelatedAccounts = false;
        if (data.relatedAccounts.byFingerprint.length > 0) {
            hasRelatedAccounts = true;
            relatedDiv.innerHTML = `<h4 class="font-bold text-sm mt-2">동일 기기 사용자:</h4>` +
                data.relatedAccounts.byFingerprint.map(id => `<div>- <code>${id}</code></div>`).join('');
        }
        
        relatedSection.style.display = hasRelatedAccounts ? 'block' : 'none';

        const logsDiv = document.getElementById('modal-logs');
        if (data.authLogs.length > 0) {
            logsDiv.innerHTML = data.authLogs.map(log => {
                const date = new Date(log.timestamp).toLocaleString('ko-KR');
                const translation = translateLogReason(log);
                return `<div class="p-2 rounded-md mb-1 ${log.result === 'allowed' ? 'bg-green-500/10' : log.result === 'denied' ? 'bg-red-500/10' : 'bg-yellow-500/10'}">
                    <p class="text-sm">${translation}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono">${date}</p>
                </div>`;
            }).join('');
        } else {
            logsDiv.innerHTML = '<div class="text-gray-400">기록된 인증 로그가 없습니다.</div>';
        }
        
        modalLoader.style.display = 'none';
        modalData.style.display = 'block';
    } catch (error) {
        modalLoader.textContent = error.message;
    }
}

function deleteUser(userId, guildId) {
    if (!confirm(`경고: 사용자 ID ${userId}의 모든 인증 기록을 영구 파기합니다. 계속하시겠습니까?`)) {
        return;
    }
    fetch('/dashboard/data', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, guildId })
    })
        .then(response => {
            if (response.ok) {
                alert('데이터 파기 성공. 페이지를 새로고침하여 반영합니다.');
                window.location.reload();
            } else {
                return response.json().then(err => { throw new Error(err.error) });
            }
        })
        .catch(error => {
            console.error('Fetch error:', error);
            alert(`데이터 파기 실패: ${error.message}`);
        });
}
