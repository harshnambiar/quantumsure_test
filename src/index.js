import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import ChaCha20 from 'js-chacha20';
import { Buffer } from 'buffer';
import Web3 from 'web3';


const API_BASE_URL = 'http://localhost:5000/api'; // Update to your server URL




// Post-quantum symmetric encryption with ChaCha20
function postQuantumEncrypt(data, key) {
  const nonce = randomBytes(12); // 12-byte nonce for ChaCha20
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(dataBytes); // Returns Uint8Array
  return {
    encrypted: encode(encrypted), // Base64-encoded ciphertext
    nonce: encode(nonce), // Base64-encoded nonce
  };
}

// Post-quantum symmetric decryption with ChaCha20
async function postQuantumDecrypt(encryptedB64, nonceB64, key, authTagB64) {
  const encrypted = Buffer.from(decode(encryptedB64));
  const nonce = Buffer.from(decode(nonceB64));
  // Verify MAC
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted); // Returns Uint8Array
  return new TextDecoder().decode(decrypted);
}

// Quantum-resistant encryption with MlKem1024
async function quantumResistantEncrypt(inputData, pubKeyB64) {
  // Decode public key
  const publicKey = Buffer.from(decode(pubKeyB64));

  // ML-KEM: Encapsulate shared secret
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);

  // Encrypt data with ChaCha20
  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);

  // Compute MAC for authentication
  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);

  // Format: kem_ciphertext:nonce:encrypted_data:auth_tag
  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

// Quantum-resistant decryption with MlKem1024
async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = encryptedData.split(':');
  if (!ciphertextB64 || !nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted data format');
  }

  // ML-KEM: Decapsulate to recover shared secret
  const privateKey = Buffer.from(decode(privateKeyB64));
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(Buffer.from(decode(ciphertextB64)), privateKey);

  // Decrypt data with ChaCha20 and verify MAC
  const decryptedData = await postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
  return decryptedData;
}

// Browser-compatible randomBytes using crypto.getRandomValues
function randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}

// Compute a SHA-256 MAC for authentication (post-quantum-safe)
async function computeMac(data, key) {
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const combined = Buffer.concat([Buffer.from(dataBytes), Buffer.from(keyBytes)]);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return Buffer.from(hash);
}

// Encrypt private key with ChaCha20
async function encryptPrivateKey(privateKey, masterPassword) {
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32)); // 256-bit key
  const nonce = randomBytes(12);
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(privateKey));
  const combinedData = new TextEncoder().encode(`${encode(nonce)}${encode(encrypted)}`);
  const authTag = await computeMac(combinedData, key);
  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

// Decrypt private key with ChaCha20
async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const nonce = Buffer.from(decode(nonceB64));
  const encrypted = Buffer.from(decode(encryptedB64));
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

// Password Manager Functions
async function createAccount1(secretPhrase, masterPassword) {
  try {
    const recipient = new MlKem1024();
    const [publicKey, privateKey] = await recipient.generateKeyPair();
    const publicKeyB64 = encode(publicKey);
    const privateKeyB64 = encode(privateKey); // Base64 for storage
    const encryptedPrivateKey = await encryptPrivateKey(privateKeyB64, masterPassword);

    localStorage.setItem('encryptedPrivateKey', encryptedPrivateKey);
    const response = await fetch(`${API_BASE_URL}/quser/createAccount`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { public_key: publicKeyB64, secret_phrase: secretPhrase } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to create account: ${response.statusText}`);
    }

    const result = await response.json();
    localStorage.setItem('apiKey', result.api_key);
    return { apiKey: result.api_key, message: result.message };
  } catch (err) {
    console.log(err);
    throw new Error(`Create account error: ${err.message}`);
  }
}

async function getPublicKey1(apiKey) {
  try {
    const response = await fetch(`${API_BASE_URL}/quser/getPublicKey`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get public key: ${response.statusText}`);
    }

    const { public_key } = await response.json();
    return public_key;
  } catch (err) {
    throw new Error(`Get public key error: ${err.message}`);
  }
}

async function storePassword1(apiKey, site, username, password) {
  try {
    const publicKey = await getPublicKey1(apiKey);
    const { encrypted_data } = await quantumResistantEncrypt(password, publicKey);
    const response = await fetch(`${API_BASE_URL}/qpassword/storePassword`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
      body: JSON.stringify({ data: { site, username, encrypted_text: encrypted_data } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to store password: ${response.statusText}`);
    }

    return await response.json();
  } catch (err) {
    throw new Error(`Store password error: ${err.message}`);
  }
}

async function getPassword1(apiKey, passwordId, masterPassword, encryptedPrivateKey) {
  try {
    const response = await fetch(`${API_BASE_URL}/qpassword/getPassword`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
      body: JSON.stringify({ data: { password_id: passwordId } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to retrieve password: ${response.statusText}`);
    }

    const { encrypted_text, site, username } = await response.json();
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    const decryptedPassword = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    return { site, username, password: decryptedPassword };
  } catch (err) {
    throw new Error(`Get password error: ${err.message}`);
  }
}

async function listPasswords1(apiKey) {
  try {
    const response = await fetch(`${API_BASE_URL}/qpassword/listPasswords`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to list passwords: ${response.statusText}`);
    }

    return await response.json();
  } catch (err) {
    throw new Error(`List passwords error: ${err.message}`);
  }
}

async function generateShareToken1(apiKey, passwordId, masterPassword, encryptedPrivateKey) {
  try {
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    const response = await fetch(`${API_BASE_URL}/qpassword/getPassword`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
      body: JSON.stringify({ data: { password_id: passwordId } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to retrieve password: ${response.statusText}`);
    }

    const { encrypted_text } = await response.json();

    const plaintextPassword = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    const { encrypted_data } = await quantumResistantEncrypt(plaintextPassword, recipientPublicKey);

    const tokenResponse = await fetch(`${API_BASE_URL}/qtoken/generateShareToken`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
      body: JSON.stringify({
        data: {
          password_id: passwordId,
          encrypted_data: encrypted_data,
          expires_in: '7d',
        },
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(`Failed to generate share token: ${tokenResponse.statusText}`);
    }

    return await tokenResponse.json();
  } catch (err) {
    throw new Error(`Generate share token error: ${err.message}`);
  }
}

async function accessSharedPassword1(shareToken, masterPassword, encryptedPrivateKey) {
  try {
    const response = await fetch(`${API_BASE_URL}/qtoken/accessSharedData`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { share_token: shareToken } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to access shared password: ${response.statusText}`);
    }

    const { encrypted_text, site, username } = await response.json();
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    const decryptedPassword = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    return { site, username, password: decryptedPassword };
  } catch (err) {
    throw new Error(`Access shared password error: ${err.message}`);
  }
}

async function revokeShareToken1(apiKey, shareToken) {
  try {
    const response = await fetch(`${API_BASE_URL}/qtoken/revokeShareToken`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api_key': apiKey,
      },
      body: JSON.stringify({ data: { share_token: shareToken } }),
    });

    if (!response.ok) {
      throw new Error(`Failed to revoke share token: ${response.statusText}`);
    }

    return await response.json();
  } catch (err) {
    throw new Error(`Revoke share token error: ${err.message}`);
  }
}

function generatePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  const bytes = randomBytes(length);
  return Array.from(bytes)
    .map(byte => chars[byte % chars.length])
    .join('');
}

// UI Interaction Functions
window.createAccount = async () => {
  const masterPassword = document.getElementById('create-master-password').value;
  const secretPhrase = document.getElementById('secret-phrase').value;
  try {
    const result = await createAccount1(secretPhrase, masterPassword);
    document.getElementById('output').innerText = `Success: ${result.message}\nAPI Key: ${result.apiKey}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.storePassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const site = document.getElementById('site').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  try {
    const result = await storePassword1(apiKey, site, username, password);
    document.getElementById('output').innerText = `Success: ${result.message}\nPassword ID: ${result.password_id}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.listPasswords = async () => {
  const apiKey = localStorage.getItem('apiKey');
  try {
    const result = await listPasswords1(apiKey);
    const list = document.getElementById('password-list');
    list.innerHTML = '';
    result.passwords.forEach(p => {
      const li = document.createElement('li');
      li.innerText = `${p.site} - ${p.username} (ID: ${p.id})`;
      list.appendChild(li);
    });
    document.getElementById('output').innerText = `Success: ${result.message}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.getPassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const passwordId = document.getElementById('password-id').value;
  const masterPassword = document.getElementById('retrieve-master-password').value;
  const encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
  try {
    const result = await getPassword1(apiKey, passwordId, masterPassword, encryptedPrivateKey);
    document.getElementById('output').innerText = `Success: Password for ${result.site}: ${result.password}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.generateShareToken = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const passwordId = document.getElementById('share-password-id').value;
  const masterPassword = document.getElementById('share-master-password').value;
  const encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
  console.log(passwordId);
  try {
    const result = await generateShareToken1(apiKey, passwordId, masterPassword, encryptedPrivateKey);
    document.getElementById('output').innerText = `Success: ${result.message}\nShare Token: ${result.share_token}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.accessSharedPassword = async () => {
  const shareToken = document.getElementById('share-token').value;
  const masterPassword = document.getElementById('access-master-password').value;
  const encryptedPrivateKey = localStorage.getItem('encryptedPrivateKey');
  try {
    const result = await accessSharedPassword1(shareToken, masterPassword, encryptedPrivateKey);
    document.getElementById('output').innerText = `Success: Shared password for ${result.site}: ${result.password}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.revokeShareToken = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const shareToken = document.getElementById('revoke-share-token').value;
  try {
    const result = await revokeShareToken1(apiKey, shareToken);
    document.getElementById('output').innerText = `Success: ${result.message}`;
  } catch (err) {
    document.getElementById('output').innerText = `Error: ${err.message}`;
  }
};

window.generatePassword = () => {
  const newPassword = generatePassword();
  document.getElementById('password').value = newPassword;
  document.getElementById('output').innerText = 'Generated new password!';
};
