'use strict';
const byId = id => document.getElementById(id);
const show = (id, value) => { byId(id).textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); };
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
const decode = token => {
    const part = value => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))));
    const [header, payload] = token.split('.');
    return {header: part(header), payload: part(payload)};
};
let discovery;
let pending = JSON.parse(sessionStorage.getItem('mldsa-pending') || 'null');
let tokens = JSON.parse(sessionStorage.getItem('mldsa-tokens') || 'null');
function render() {
    byId('redeem').disabled = !pending?.code;
    byId('refresh').disabled = !tokens?.refresh_token;
    byId('userinfo').disabled = !tokens?.access_token;
    if (tokens) {
        show('tokens', tokens);
        show('decoded', Object.fromEntries(['id_token', 'access_token'].filter(k => tokens[k]).map(k => [k, decode(tokens[k])])));
    }
}
async function requestToken(parameters) {
    const response = await fetch(discovery.token_endpoint, {
        method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams(parameters),
    });
    const body = await response.json();
    if (!response.ok) { show('details', body); throw Error(`Token endpoint returned ${response.status}`); }
    tokens = body;
    sessionStorage.setItem('mldsa-tokens', JSON.stringify(tokens));
    render();
    show('status', 'Tokens received. Inspect the request and response in Burp.');
}
async function act(action) { try { await action(); } catch (error) { show('status', error.message); } }
byId('login').onclick = () => act(async () => {
    const verifier = random();
    pending = {client: byId('client').value, verifier, state: random(), nonce: random()};
    sessionStorage.setItem('mldsa-pending', JSON.stringify(pending));
    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
        client_id: pending.client, response_type: 'code', scope: 'openid profile email offline_access',
        redirect_uri: location.origin + '/callback.html', state: pending.state, nonce: pending.nonce,
        code_challenge: b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))),
        code_challenge_method: 'S256', prompt: 'consent',
    });
    location.assign(url);
});
byId('redeem').onclick = () => act(async () => {
    await requestToken({grant_type: 'authorization_code', client_id: pending.client,
        code: pending.code, code_verifier: pending.verifier, redirect_uri: location.origin + '/callback.html'});
    pending.code = null;
    sessionStorage.setItem('mldsa-pending', JSON.stringify(pending));
    render();
});
byId('refresh').onclick = () => act(() => requestToken({grant_type: 'refresh_token', client_id: pending.client, refresh_token: tokens.refresh_token}));
byId('userinfo').onclick = () => act(async () => {
    const response = await fetch(discovery.userinfo_endpoint, {headers: {Authorization: 'Bearer ' + tokens.access_token}});
    show('details', await response.json());
});
byId('clear').onclick = () => { sessionStorage.removeItem('mldsa-pending'); sessionStorage.removeItem('mldsa-tokens'); location.assign('/'); };
act(async () => {
    discovery = await (await fetch('/.well-known/openid-configuration')).json();
    byId('jwks').href = discovery.jwks_uri;
    byId('login').disabled = false;
    const params = new URLSearchParams(location.search);
    if (params.has('error')) { show('details', Object.fromEntries(params)); throw Error('Authorization failed.'); }
    if (params.has('code')) {
        if (!pending || params.get('state') !== pending.state) throw Error('Authorization state mismatch.');
        pending.code = params.get('code');
        sessionStorage.setItem('mldsa-pending', JSON.stringify(pending));
        history.replaceState(null, '', '/callback.html');
        show('status', 'Authorization code received. Click Redeem to make the token request.');
    } else show('status', 'Ready. Published ID-token algorithms: ' + discovery.id_token_signing_alg_values_supported.join(', '));
    render();
});
