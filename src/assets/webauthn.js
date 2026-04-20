// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
// Browser WebAuthn helpers. Leptos/WASM invokes these via wasm-bindgen.

(function () {
  function b64urlDecode(input) {
    const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
    const b64 = (input + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  function b64urlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodePublicKey(pk) {
    const out = Object.assign({}, pk);
    out.challenge = b64urlDecode(pk.challenge);
    if (pk.user) {
      out.user = Object.assign({}, pk.user, { id: b64urlDecode(pk.user.id) });
    }
    if (pk.allowCredentials) {
      out.allowCredentials = pk.allowCredentials.map(c =>
        Object.assign({}, c, { id: b64urlDecode(c.id) })
      );
    }
    if (pk.excludeCredentials) {
      out.excludeCredentials = pk.excludeCredentials.map(c =>
        Object.assign({}, c, { id: b64urlDecode(c.id) })
      );
    }
    return out;
  }

  function encodeRegistration(credential) {
    const resp = credential.response;
    return {
      id: credential.id,
      rawId: b64urlEncode(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: b64urlEncode(resp.attestationObject),
        clientDataJSON: b64urlEncode(resp.clientDataJSON),
      },
      extensions: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
  }

  function encodeAssertion(credential) {
    const resp = credential.response;
    return {
      id: credential.id,
      rawId: b64urlEncode(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: b64urlEncode(resp.authenticatorData),
        clientDataJSON: b64urlEncode(resp.clientDataJSON),
        signature: b64urlEncode(resp.signature),
        userHandle: resp.userHandle ? b64urlEncode(resp.userHandle) : null,
      },
      extensions: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
  }

  async function register(optionsJson) {
    const options = typeof optionsJson === 'string' ? JSON.parse(optionsJson) : optionsJson;
    const publicKey = decodePublicKey(options.publicKey);
    const credential = await navigator.credentials.create({ publicKey });
    return JSON.stringify(encodeRegistration(credential));
  }

  async function authenticate(optionsJson) {
    const options = typeof optionsJson === 'string' ? JSON.parse(optionsJson) : optionsJson;
    const publicKey = decodePublicKey(options.publicKey);
    const credential = await navigator.credentials.get({ publicKey });
    return JSON.stringify(encodeAssertion(credential));
  }

  function supported() {
    return typeof window !== 'undefined'
      && typeof window.PublicKeyCredential !== 'undefined'
      && typeof navigator !== 'undefined'
      && !!navigator.credentials;
  }

  window.stalwartWebauthn = { register, authenticate, supported };
})();
