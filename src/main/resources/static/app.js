const endpoints = [
    // Authentication
    {
        id: 'login', category: 'auth', name: 'Login', method: 'POST', path: '/api/v1/auth/login',
        desc: 'Authenticate to get tokens',
        fields: [{ name: 'email', type: 'email' }, { name: 'password', type: 'password' }, { name: 'mfaCode', type: 'text', placeholder: 'Optional MFA Code' }]
    },
    {
        id: 'register', category: 'auth', name: 'Register', method: 'POST', path: '/api/v1/auth/register',
        desc: 'Registers a new user',
        fields: [{ name: 'email', type: 'email'}, { name: 'password', type: 'password'}, { name: 'fullName', type: 'text'}]
    },
    {
        id: 'refresh', category: 'auth', name: 'Refresh Token', method: 'POST', path: '/api/v1/auth/refresh',
        desc: 'Refresh session using refresh token (usually via cookie)',
        fields: [{ name: 'refreshToken', type: 'text', placeholder: 'Optional (defaults to cookie)' }]
    },
    {
        id: 'logout', category: 'auth', name: 'Logout', method: 'POST', path: '/api/v1/auth/logout',
        desc: 'Ends the current session',
        fields: []
    },
    {
        id: 'reauth', category: 'auth', name: 'Reauthenticate', method: 'POST', path: '/api/v1/auth/reauthenticate',
        desc: 'Elevate session trust for sensitive actions',
        fields: [{ name: 'password', type: 'password' }, { name: 'mfaCode', type: 'text', placeholder: 'Optional' }]
    },
    {
        id: 'logout-all', category: 'auth', name: 'Logout All', method: 'POST', path: '/api/v1/auth/logout-all-sessions',
        desc: 'Revoke all active sessions',
        fields: []
    },

    // Account & Password
    {
        id: 'change-password', category: 'account', name: 'Change Password', method: 'POST', path: '/api/v1/auth/change-password',
        desc: 'Change current user password',
        fields: [{ name: 'currentPassword', type: 'password'}, { name: 'newPassword', type: 'password'}]
    },
    {
        id: 'change-email', category: 'account', name: 'Change Email', method: 'POST', path: '/api/v1/auth/change-email',
        desc: 'Change current user email',
        fields: [{ name: 'newEmail', type: 'email'}]
    },
    {
        id: 'forgot-password', category: 'account', name: 'Forgot Password', method: 'POST', path: '/api/v1/auth/forgot-password',
        desc: 'Request a password reset email',
        fields: [{ name: 'email', type: 'email'}]
    },
    {
        id: 'reset-password', category: 'account', name: 'Reset Password', method: 'POST', path: '/api/v1/auth/reset-password',
        desc: 'Reset password using token',
        fields: [{ name: 'token', type: 'text'}, { name: 'newPassword', type: 'password'}]
    },
    {
        id: 'delete-account', category: 'account', name: 'Delete Account', method: 'POST', path: '/api/v1/auth/delete-account',
        desc: 'Permanently delete your account',
        fields: []
    },

    // MFA & Verification
    {
        id: 'mfa-setup', category: 'mfa', name: 'Setup TOTP', method: 'POST', path: '/api/v1/auth/mfa/totp/setup',
        desc: 'Generate a new TOTP secret',
        fields: []
    },
    {
        id: 'mfa-confirm', category: 'mfa', name: 'Confirm TOTP', method: 'POST', path: '/api/v1/auth/mfa/totp/confirm',
        desc: 'Confirm TOTP configuration',
        fields: [{ name: 'code', type: 'text' }]
    },
    {
        id: 'mfa-disable', category: 'mfa', name: 'Disable TOTP', method: 'POST', path: '/api/v1/auth/mfa/totp/disable',
        desc: 'Disable TOTP authentication',
        fields: [{ name: 'code', type: 'text' }]
    },
    {
        id: 'email-req', category: 'mfa', name: 'Req. Email Verify', method: 'POST', path: '/api/v1/auth/email-verification/request',
        desc: 'Request to verify email',
        fields: [{ name: 'email', type: 'email'}]
    },
    {
        id: 'email-confirm', category: 'mfa', name: 'Confirm Email', method: 'POST', path: '/api/v1/auth/email-verification/confirm',
        desc: 'Confirm email using token',
        fields: [{ name: 'token', type: 'text'}]
    },

    // User Data
    {
        id: 'me', category: 'user', name: 'Get Me', method: 'GET', path: '/api/v1/me',
        desc: 'Fetch current user details',
        fields: []
    }
];

const MSAL_CONFIG = {
    auth: {
        clientId: 'f38de9de-fd01-472b-8346-80630b135bec',
        authority: "https://login.microsoftonline.com/common"
    }
};
const GOOGLE_CLIENT_ID = '683592222646-b8jgmked1c1a9buaq44urv7tgvjqneaj.apps.googleusercontent.com';

let GlobalState = {
    accessToken: null,
    msalInstance: null
};

// --- DOM Elements ---
const navAuth = document.getElementById('nav-auth');
const navAccount = document.getElementById('nav-account');
const navMfa = document.getElementById('nav-mfa');
const navUser = document.getElementById('nav-user');
const currentMethod = document.getElementById('current-method');
const currentPath = document.getElementById('current-path');
const formTitle = document.getElementById('form-title');
const formDesc = document.getElementById('form-desc');
const dynamicForm = document.getElementById('dynamic-form');
const authIndicator = document.getElementById('auth-status-indicator');
const authText = document.getElementById('auth-status-text');
const clearTokenBtn = document.getElementById('clear-token-btn');
const responseBody = document.getElementById('response-body');
const resStatus = document.getElementById('res-status');
const resTime = document.getElementById('res-time');
const responseMeta = document.getElementById('response-meta');
const federatedLoginContainer = document.getElementById('federated-login-container');
const submitBtn = document.getElementById('submit-btn');

let currentEndpoint = null;

// Initialize Microsoft MSAL
async function initMSAL() {
    GlobalState.msalInstance = new msal.PublicClientApplication(MSAL_CONFIG);
    await GlobalState.msalInstance.initialize();
}
if(window.msal) initMSAL();


function updateAuthState(token) {
    if(token) {
        GlobalState.accessToken = token;
        authIndicator.classList.add('auth-active');
        authText.textContent = "Authenticated";
        clearTokenBtn.classList.remove('hidden');
    } else {
        GlobalState.accessToken = null;
        authIndicator.classList.remove('auth-active');
        authText.textContent = "Not Authenticated";
        clearTokenBtn.classList.add('hidden');
    }
}

clearTokenBtn.addEventListener('click', () => updateAuthState(null));

function initSidebar() {
    endpoints.forEach(ep => {
        const li = document.createElement('li');
        li.dataset.id = ep.id;
        li.innerHTML = `<span class="mini-badge ${ep.method.toLowerCase()}">${ep.method}</span> ${ep.name}`;
        li.onclick = () => selectEndpoint(ep.id, li);
        
        if (ep.category === 'auth') navAuth.appendChild(li);
        if (ep.category === 'account') navAccount.appendChild(li);
        if (ep.category === 'mfa') navMfa.appendChild(li);
        if (ep.category === 'user') navUser.appendChild(li);
    });

    // Select first by default
    selectEndpoint(endpoints[0].id, navAuth.firstChild);
}

function selectEndpoint(id, listItemElement) {
    document.querySelectorAll('.nav-links li').forEach(el => el.classList.remove('active'));
    if(listItemElement) listItemElement.classList.add('active');

    currentEndpoint = endpoints.find(e => e.id === id);
    
    currentMethod.textContent = currentEndpoint.method;
    currentMethod.className = `method badge ${currentEndpoint.method}`;
    currentPath.textContent = currentEndpoint.path;
    formTitle.textContent = currentEndpoint.name;
    formDesc.textContent = currentEndpoint.desc;
    
    // Build Form
    dynamicForm.innerHTML = '';
    
    currentEndpoint.fields.forEach(f => {
        const group = document.createElement('div');
        group.className = 'form-group';
        
        const label = document.createElement('label');
        label.textContent = f.name;
        
        const input = document.createElement('input');
        input.type = f.type;
        input.name = f.name;
        input.placeholder = f.placeholder || `Enter ${f.name}`;
        
        // Disable required logic temporally for easier tests, or enable if needed
        if(!f.placeholder?.includes('Optional')) input.required = true;
        
        group.appendChild(label);
        group.appendChild(input);
        dynamicForm.appendChild(group);
    });
    
    if(currentEndpoint.fields.length === 0) {
        dynamicForm.innerHTML = '<p class="text-muted">No request parameters required.</p>';
    }

    if(id === 'login') {
        federatedLoginContainer.classList.remove('hidden');
        renderGoogleButton();
    } else {
        federatedLoginContainer.classList.add('hidden');
    }

    // Reset response
    responseBody.textContent = 'Hit "Send Request" to see the response...';
    responseMeta.classList.add('hidden');
    document.getElementById('qr-container')?.classList.add('hidden');
}


dynamicForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if(!currentEndpoint) return;
    
    const formData = new FormData(dynamicForm);
    const bodyObj = {};
    formData.forEach((value, key) => {
        if(value) bodyObj[key] = value;
    });

    await executeApiCall(currentEndpoint.path, currentEndpoint.method, bodyObj);
});


async function executeApiCall(path, method, bodyObj) {
    submitBtn.textContent = 'Sending...';
    submitBtn.disabled = true;

    const start = performance.now();
    
    const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    if(GlobalState.accessToken) {
        headers['Authorization'] = `Bearer ${GlobalState.accessToken}`;
    }

    const fetchOptions = {
        method: method,
        headers: headers
    };

    if(method !== 'GET' && Object.keys(bodyObj).length > 0) {
        fetchOptions.body = JSON.stringify(bodyObj);
    }

    try {
        const res = await fetch(path, fetchOptions);
        const time = Math.round(performance.now() - start);
        
        let resData = null;
        let isJson = res.headers.get('content-type')?.includes('application/json');
        
        const text = await res.text();
        if(isJson && text) {
            try { resData = JSON.parse(text); } catch(e){}
        }

        // Handle auto-storing token on success auth endpoints
        if(res.ok && resData && resData.accessToken) {
            updateAuthState(resData.accessToken);
        }
        
        if (res.ok && currentEndpoint.id === 'logout') {
            updateAuthState(null);
        }

        displayResponse(res.status, res.statusText, time, (resData ? JSON.stringify(resData, null, 2) : text || '<Empty Response>'), resData);
        
    } catch(err) {
        displayResponse('ERROR', 'Failed to fetch', Math.round(performance.now() - start), err.message, null);
    } finally {
        submitBtn.textContent = 'Send Request';
        submitBtn.disabled = false;
    }
}

function displayResponse(status, statusText, time, bodyStr, dataObj) {
    responseMeta.classList.remove('hidden');
    resStatus.textContent = `${status} ${statusText}`;
    resTime.textContent = `${time}ms`;
    
    resStatus.className = `status-code badge ${String(status).startsWith('2') ? 'success' : 'error'}`;
    
    responseBody.textContent = bodyStr;

    const qrContainer = document.getElementById('qr-container');
    const qrImg = document.getElementById('qr-code-img');
    if (qrContainer && qrImg) {
        qrContainer.classList.add('hidden');
        if (dataObj && dataObj.otpauthUrl) {
            qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(dataObj.otpauthUrl)}`;
            qrContainer.classList.remove('hidden');
        }
    }
}


// --- Federated Login Handlers ---
function renderGoogleButton() {
    if(!window.google) {
        setTimeout(renderGoogleButton, 500); // wait for script load
        return;
    }
    document.getElementById('google-signin-button').innerHTML = '';
    google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: handleGoogleCredentialResponse
    });
    google.accounts.id.renderButton(
        document.getElementById('google-signin-button'),
        { theme: 'outline', size: 'large', width: '100%' }
    );
}

function handleGoogleCredentialResponse(response) {
    if(response.credential) {
        const mfaCode = document.querySelector('input[name="mfaCode"]')?.value || undefined;
        const payload = { idToken: response.credential };
        if(mfaCode) payload.mfaCode = mfaCode;
        executeApiCall('/api/v1/auth/login/google', 'POST', payload);
    }
}

document.getElementById('microsoft-signin-button').addEventListener('click', async (e) => {
    e.preventDefault();
    if(!GlobalState.msalInstance) return alert('MSAL not initialized');
    
    try {
        const loginRequest = { scopes: ["openid", "profile", "email"] };
        const response = await GlobalState.msalInstance.loginPopup(loginRequest);
        if(response && response.idToken) {
            const mfaCode = document.querySelector('input[name="mfaCode"]')?.value || undefined;
            const payload = { idToken: response.idToken };
            if(mfaCode) payload.mfaCode = mfaCode;
            executeApiCall('/api/v1/auth/login/microsoft', 'POST', payload);
        }
    } catch (err) {
        console.error(err);
        displayResponse('MSAL ERROR', '', 0, err.message);
    }
});


// Boot
initSidebar();

// Handle Deep Linking / Query Params
window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get('action'); // e.g. "email-confirm" or "reset-password"
    const token = urlParams.get('token');

    if (action) {
        const targetEndpoint = endpoints.find(e => e.id === action);
        if (targetEndpoint) {
            const targetLi = document.querySelector(`.nav-links li[data-id="${action}"]`);
            selectEndpoint(action, targetLi);
            
            if (token) {
                const tokenInput = document.querySelector('input[name="token"]');
                if (tokenInput) {
                    tokenInput.value = token;
                }
            }
        }
    }
});
