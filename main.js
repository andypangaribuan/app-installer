document.addEventListener('DOMContentLoaded', () => {
    const loadingState = document.getElementById('loading-state');
    const dynamicHeader = document.getElementById('dynamic-header');
    const dynamicContent = document.getElementById('dynamic-content');
    const controlsWrapper = document.getElementById('controls-wrapper');
    const osIconSlot = document.getElementById('os-icon-slot');
    const tabBtns = document.querySelectorAll('.tab-btn');
    const loginOverlay = document.getElementById('login-overlay');
    const appContainer = document.getElementById('app');
    const loginError = document.getElementById('login-error');
    const adminLinkWrapper = document.getElementById('admin-link-wrapper');
    const logoutBtn = document.getElementById('logout-btn');
    const logoutWrapper = document.getElementById('logout-wrapper');
    const qrModal = document.getElementById('qr-modal');
    const qrImage = document.getElementById('qr-image');

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/logout');
                if (res.ok) {
                    location.href = '/';
                }
            } catch (err) { }
        });
    }

    // 2. DEBUGGING / SAFETY
    window.onerror = (msg, url, line, col, error) => {
        const err = `Error: ${msg} at ${line}:${col}`;
        if (loadingState) loadingState.classList.add('hidden');
        if (dynamicContent) {
            dynamicContent.innerHTML = `<div style="color:#ef4444;text-align:center;padding:20px;"><p>System Error</p><small>${err}</small></div>`;
            dynamicContent.classList.remove('hidden');
        }
        return false;
    };

    // Safety: Always hide loading after 12 seconds no matter what
    setTimeout(() => {
        if (loadingState && !loadingState.classList.contains('hidden')) {
            loadingState.classList.add('hidden');
            if (dynamicContent) dynamicContent.classList.remove('hidden');
        }
    }, 12000);

    // 3. STATE
    const ANDROID_JSON = '/public/android_versions.json';
    const IOS_JSON = '/public/ios_versions.json';
    let currentOs = 'unknown';
    let currentEnv = 'prod';
    let cachedData = [];
    let appConfig = {};

    // Pagination State
    let currentPage = 1;
    const ITEMS_PER_PAGE = 3;

    // 4. AUTH LOGIC
    const handleCredentialResponse = async (response) => {
        try {
            const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id_token: response.credential })
            });
            if (res.ok) {
                location.reload();
            } else {
                const data = await res.json();
                showLoginError(data.error || 'Unauthorized');
            }
        } catch (err) {
            showLoginError('Connection failed');
        }
    };

    const showApp = () => {
        loginOverlay.classList.add('hidden');
        appContainer.classList.remove('hidden');
    };

    const showLogin = () => {
        loginOverlay.classList.remove('hidden');
        appContainer.classList.add('hidden');
        initGoogleSignIn();
    };

    const showLoginError = (msg) => {
        if (loginError) {
            loginError.textContent = msg;
            loginError.classList.remove('hidden');
        }
    };

    const initGoogleSignIn = (retries = 0) => {
        const btnContainer = document.getElementById("google-signin-btn");
        if (!btnContainer) return;

        // Check if library is ready
        const isGsiReady = typeof google !== 'undefined' && google.accounts && google.accounts.id;

        if (!isGsiReady) {
            if (retries < 30) { // Try for 15 seconds
                if (retries === 0) btnContainer.innerHTML = '<p style="color:var(--text-muted);font-size:13px;opacity:0.8;">Preparing Sign-In...</p>';
                setTimeout(() => initGoogleSignIn(retries + 1), 500);
                return;
            }
            btnContainer.innerHTML = '<p style="color:#ef4444;font-size:13px;">Google library blocked or failed to load. Please try turning off Content Blockers or Incognito mode.</p>';
            return;
        }

        const clientIdMeta = document.querySelector('meta[name="google-client-id"]');
        const clientId = clientIdMeta ? clientIdMeta.content : '';
        if (!clientId || clientId.includes('PLACEHOLDER')) {
            showLoginError('Google Client ID not configured');
            return;
        }

        // Use a small delay before rendering to ensure DOM is settled
        setTimeout(() => {
            btnContainer.innerHTML = '';
            try {
                google.accounts.id.initialize({
                    client_id: clientId,
                    callback: handleCredentialResponse,
                    auto_select: false,
                    prompt_parent_id: 'login-overlay'
                });

                google.accounts.id.renderButton(btnContainer, {
                    theme: "outline",
                    size: "large",
                    width: btnContainer.offsetWidth || 280,
                    text: "signin_with",
                    shape: "pill",
                    logo_alignment: "left"
                });
            } catch (err) {
                btnContainer.innerHTML = '<p style="color:#ef4444;font-size:12px;">Sign-In initialization failed.</p>';
            }
        }, 100);
    };

    const startExpiryTimer = (expiresAt) => {
        const timer = setInterval(() => {
            if (Date.now() / 1000 >= expiresAt) {
                clearInterval(timer);
                location.reload();
            }
        }, 1000);
    };

    // 5. APP LOGIC
    const detectOS = () => {
        const userAgent = navigator.userAgent || navigator.vendor || window.opera;
        if (/iPad|iPhone|iPod/.test(userAgent) && !window.MSStream) return 'iOS';
        if (/android/i.test(userAgent)) return 'Android';
        return 'unknown';
    };

    const formatDate = (ds) => {
        const d = new Date(ds);
        return `${d.getFullYear()} ${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}`;
    };

    window.closeQrModal = () => {
        if (qrModal) qrModal.style.display = 'none';
        if (qrImage) qrImage.src = '';
    };

    window.showQrModal = async (url, isIOS = false, manifestUrl = '') => {
        if (!qrModal || !qrImage) return;

        try {
            // Get magic token first
            const res = await fetch('/api/qr/token');
            if (!res.ok) throw new Error('Failed to get token');
            const data = await res.json();

            let finalUrl = url;

            // For iOS, create a redirect URL that will handle the installation
            if (isIOS && manifestUrl) {
                // Parse manifest URL to extract parameters
                const manifestUrlObj = new URL(manifestUrl);
                const params = new URLSearchParams(manifestUrlObj.search);

                // Build install-ios.html URL with all parameters including magic_token
                const installUrl = new URL(`${window.location.origin}/install-ios.html`);
                installUrl.searchParams.set('appName', params.get('appName'));
                installUrl.searchParams.set('bundleId', params.get('bundleId'));
                installUrl.searchParams.set('version', params.get('version'));
                installUrl.searchParams.set('ipa', params.get('ipa'));
                installUrl.searchParams.set('magic_token', data.token);

                finalUrl = installUrl.toString();
            } else {
                // For Android, just add token to the URL
                const separator = url.includes('?') ? '&' : '?';
                finalUrl = `${url}${separator}magic_token=${data.token}`;
            }

            // Get QR image - pass the final URL directly (don't add token again on server)
            // Add cache buster to prevent browser from using old QR code
            const qrUrl = `/api/qr/image?token=${data.token}&url=${encodeURIComponent(finalUrl)}&t=${Date.now()}`;
            qrImage.src = qrUrl;

            qrModal.style.display = 'flex';
        } catch (err) {
            alert('Failed to generate QR code');
        }
    };

    const renderHeader = (os) => {
        if (!osIconSlot) return;
        osIconSlot.innerHTML = '';
        if (os === 'iOS') osIconSlot.innerHTML = `<div class="mini-os-icon ios-mini-glow"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" fill="currentColor"><path d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"/></svg></div>`;
        else if (os === 'Android') osIconSlot.innerHTML = `<div class="mini-os-icon android-mini-glow"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M17.523 15.3414C17.523 16.7126 16.4102 17.8256 15.0388 17.8256C13.6675 17.8256 12.5547 16.7126 12.5547 15.3414C12.5547 13.9702 13.6675 12.8572 15.0388 12.8572C16.4102 12.8572 17.523 13.9702 17.523 15.3414ZM6.4764 15.3414C6.4764 16.7126 5.3636 17.8256 3.9922 17.8256C2.6208 17.8256 1.508 16.7126 1.508 15.3414C1.508 13.9702 2.6208 12.8572 3.9922 12.8572C5.3636 12.8572 6.4764 13.9702 6.4764 15.3414ZM18.4357 5.5106L20.4494 2.0227C20.5593 1.8318 20.4947 1.587 20.3038 1.4771C20.1129 1.3672 19.8681 1.4318 19.7582 1.6227L17.7262 5.1422C16.0357 4.3684 14.1167 3.9189 12.0625 3.9189C10.0083 3.9189 8.0893 4.3684 6.3988 5.1422L4.3668 1.6227C4.2569 1.4318 4.0121 1.3672 3.8212 1.4771C3.6303 1.587 3.5657 1.8318 3.6756 2.0227L5.6893 5.5106C2.5152 7.247 0.3546 10.4906 0 14.2494H24.125C23.7704 10.4906 21.6098 7.247 18.4357 5.5106Z"/></svg></div>`;
    };

    const renderVersionCard = (item, os, isLatest) => {
        const card = document.createElement('div');
        card.className = 'version-card';
        let link = '#';
        let mUrl = '';
        if (os === 'iOS') {
            mUrl = `${window.location.origin}/manifest.plist?appName=${encodeURIComponent(item.appName)}&version=${encodeURIComponent(item.version)}&bundleId=${encodeURIComponent(item.bundleId)}&ipa=${encodeURIComponent(item.ipaFile)}`;
            link = `itms-services://?action=download-manifest&url=${encodeURIComponent(mUrl)}`;
        } else link = `/public/downloads/apk/${item.apkFile}`;

        const bTxt = os === 'iOS' ? 'Install' : 'Download';
        const bIcon = '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>';

        const changelogHtml = item.changelog ? `<div class="version-changelog">${item.changelog}</div>` : '';

        card.innerHTML = `
            <div class="version-main-row">
                <div class="version-info">
                    <div class="version-title">
                        ${item.version} 
                        ${isLatest ? '<span class="badge badge-latest">Latest</span>' : ''}
                    </div>
                    <div class="version-meta">${formatDate(item.date)}</div>
                </div>
                <div style="display:flex; gap:8px;">
                    <button onclick="showQrModal('${os === 'iOS' ? link : window.location.origin + link}', ${os === 'iOS'}, '${os === 'iOS' ? mUrl : ''}')" class="btn btn-secondary btn-sm" style="width: auto; padding: 8px 10px;" title="Show QR Code">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="3" width="7" height="7"></rect>
                            <rect x="14" y="3" width="7" height="7"></rect>
                            <rect x="14" y="14" width="7" height="7"></rect>
                            <path d="M3 14h7v7H3z"></path>
                        </svg>
                    </button>
                    <a href="${link}" class="btn btn-primary btn-sm" ${os === 'Android' ? `download="${item.apkFile}"` : ''} style="width: auto; padding: 8px 10px;" title="${bTxt}">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${bIcon}</svg>
                    </a>
                </div>
            </div>
            ${changelogHtml}
        `;
        dynamicContent.appendChild(card);
    };

    const renderList = () => {
        if (!dynamicContent) return;
        dynamicContent.innerHTML = '';
        renderHeader(currentOs);

        const allowedEnvs = appConfig.permissions?.availableEnv || ['prod'];
        const filtered = cachedData.filter(i => {
            const env = i.environment || 'prod';
            return allowedEnvs.includes(env) && env === currentEnv;
        });

        if (filtered.length === 0) {
            dynamicContent.innerHTML = `<p style="text-align:center;padding:32px;opacity:0.6;">No ${currentEnv.toUpperCase()} versions available.</p>`;
            document.getElementById('app-pagination').classList.add('hidden');
        } else {
            // Pagination Logic
            const totalPages = Math.ceil(filtered.length / ITEMS_PER_PAGE);
            const paginator = document.getElementById('app-pagination');

            if (totalPages > 1) {
                paginator.classList.remove('hidden');
                document.getElementById('page-indicator').textContent = `${currentPage}/${totalPages}`;
                const btnPrev = document.getElementById('btn-prev');
                const btnNext = document.getElementById('btn-next');

                if (btnPrev) btnPrev.disabled = currentPage === 1;
                if (btnNext) btnNext.disabled = currentPage === totalPages;
            } else {
                paginator.classList.add('hidden');
            }

            const start = (currentPage - 1) * ITEMS_PER_PAGE;
            const end = start + ITEMS_PER_PAGE;
            const pageItems = filtered.slice(start, end);

            pageItems.forEach((item, index) => renderVersionCard(item, currentOs, index === 0 && currentPage === 1));
        }
    };

    const changePage = (dir) => {
        const allowedEnvs = appConfig.permissions?.availableEnv || ['prod'];
        const filtered = cachedData.filter(i => {
            const env = i.environment || 'prod';
            return allowedEnvs.includes(env) && env === currentEnv;
        });

        const totalPages = Math.ceil(filtered.length / ITEMS_PER_PAGE);
        const newPage = currentPage + dir;

        if (newPage >= 1 && newPage <= totalPages) {
            currentPage = newPage;
            renderList();
            document.getElementById('dynamic-content').scrollTop = 0;
        }
    };

    const loadVersions = async (os) => {
        currentOs = os;
        if (loadingState) loadingState.classList.remove('hidden');
        if (dynamicContent) dynamicContent.classList.add('hidden');
        if (dynamicHeader) dynamicHeader.classList.add('hidden');
        if (controlsWrapper) controlsWrapper.classList.add('hidden');

        try {
            const res = await fetch(`/api/user/versions?os=${os}&t=${Date.now()}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            cachedData = await res.json();
            currentPage = 1;
            renderList();
            if (loadingState) loadingState.classList.add('hidden');
            if (dynamicHeader) dynamicHeader.classList.remove('hidden');
            if (controlsWrapper) controlsWrapper.classList.remove('hidden');
            if (dynamicContent) dynamicContent.classList.remove('hidden');
        } catch (err) {
            if (err.message.includes('401')) {
                showLogin();
                return;
            }
            if (loadingState) loadingState.classList.add('hidden');
            if (dynamicHeader) dynamicHeader.classList.remove('hidden');
            if (dynamicContent) {
                dynamicContent.innerHTML = `<p style="color:#ef4444;text-align:center;">Load failed: ${err.message}</p>`;
                dynamicContent.classList.remove('hidden');
            }
        }
    };

    const renderDesktopOptions = () => {
        if (!dynamicContent) return;
        const allowedOs = appConfig.permissions?.availableOs || ['android', 'ios'];

        let html = '<div class="desktop-options">';
        if (allowedOs.includes('android')) {
            html += `<div class="option-card"><h3>Android</h3><p class="small">View Android versions</p><button id="view-android" class="btn btn-secondary btn-sm">View Versions</button></div>`;
        }
        if (allowedOs.includes('ios')) {
            html += `<div class="option-card"><h3>iOS</h3><p class="small">View iOS versions</p><button id="view-ios" class="btn btn-secondary btn-sm">View Versions</button></div>`;
        }
        html += '</div>';

        if (html === '<div class="desktop-options"></div>') {
            html = '<p style="text-align:center;padding:32px;opacity:0.6;">No platforms authorized.</p>';
        }

        dynamicContent.innerHTML = html;

        if (allowedOs.includes('android')) document.getElementById('view-android').addEventListener('click', () => loadVersions('Android'));
        if (allowedOs.includes('ios')) document.getElementById('view-ios').addEventListener('click', () => loadVersions('iOS'));

        if (loadingState) loadingState.classList.add('hidden');
        if (dynamicContent) dynamicContent.classList.remove('hidden');
        if (dynamicHeader) dynamicHeader.classList.remove('hidden');
    };

    // 6. INITIALIZATION
    const initApp = async (config) => {
        appConfig = config;
        if (config && config.appName) {
            document.title = config.appName;
            const t = document.getElementById('app-title'); if (t) t.textContent = config.appName;
            const f = document.getElementById('app-footer'); if (f) f.textContent = `© ${new Date().getFullYear()} ${config.appName}. All rights reserved.`;
            if (config.isAdmin && adminLinkWrapper) adminLinkWrapper.classList.remove('hidden');
            if (config.secureLogin && config.expires > 0 && logoutWrapper) logoutWrapper.classList.remove('hidden');
        }

        // Filter environment tabs
        const allowedEnvs = config.permissions?.availableEnv || ['prod'];
        tabBtns.forEach(btn => {
            if (!allowedEnvs.includes(btn.dataset.env)) {
                btn.classList.add('hidden');
            } else {
                btn.classList.remove('hidden');
            }
        });

        // Set default env if current is not allowed
        if (!allowedEnvs.includes(currentEnv)) {
            currentEnv = allowedEnvs[0] || 'prod';
            tabBtns.forEach(b => {
                if (b.dataset.env === currentEnv) b.classList.add('active');
                else b.classList.remove('active');
            });
        }

        const os = detectOS();
        const allowedOs = config.permissions?.availableOs || ['android', 'ios'];

        if (os === 'unknown') {
            renderDesktopOptions();
        } else {
            // If handheld but OS not allowed
            const osKey = os.toLowerCase();
            if (!allowedOs.includes(osKey)) {
                dynamicContent.innerHTML = `<p style="text-align:center;padding:32px;opacity:0.6;">The ${os} platform is not authorized for your account.</p>`;
                if (loadingState) loadingState.classList.add('hidden');
                dynamicContent.classList.remove('hidden');
                dynamicHeader.classList.remove('hidden');
            } else {
                loadVersions(os);
            }
        }
    };

    const startApp = async () => {
        try {
            const res = await fetch(`/config?t=${Date.now()}`);
            if (res.ok) {
                const config = await res.json();

                // If secure login is on, but user is NOT authenticated (expires is 0)
                if (config.secureLogin && (!config.expires || config.expires <= Date.now() / 1000)) {
                    showLogin();
                } else {
                    showApp();
                }

                initApp(config);
                if (config.secureLogin && config.expires) startExpiryTimer(config.expires);
            } else {
                showLogin();
            }
        } catch (err) {
            showLogin();
        }
    };

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentEnv = btn.dataset.env;
            currentPage = 1;
            renderList();
        });
    });

    // Pagination Listeners
    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');
    if (btnPrev) btnPrev.addEventListener('click', () => changePage(-1));
    if (btnNext) btnNext.addEventListener('click', () => changePage(1));

    startApp();
});
