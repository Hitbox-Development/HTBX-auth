# HTBX Auth v2

HTBX Auth v2 is a secure, WebSocket-based authentication system for Minecraft mods and services. It uses **ECDH key exchange** to derive a shared secret, which is then used with **AES-256-GCM** for encrypted communication between the client and server.

## 🚀 Features

- 🔐 ECDH (Elliptic Curve Diffie-Hellman) key exchange
- 🔒 AES-256-GCM encrypted message transmission
- 🧠 Secure login and registration with bcrypt-hashed passwords
- 📡 Stateless WebSocket-based communication
- 🪪 JWT-based session tokens stored server-side with expiration
- 🧾 SQLite for lightweight, local user/token storage

## 📂 Project Structure

```
/client             # Frontend (not detailed here)
/server
├── modules
│   ├── auth.js     # Handles login/register requests
│   ├── crypto.js   # Handles encryption/decryption and key generation
│   ├── db.js       # SQLite DB setup
│   ├── logger.js   # Custom logger utility
│   └── ws-sessions.js # WebSocket session tracking
├── routes
│   └── login.js    # WebSocket login route logic
├── index.js        # Main server entry point
└── .env            # Environment variables (JWT secret, TTL, etc.)
````

## ⚙️ Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Hitbox-Development/HTBX-auth.git
cd HTBX-auth
````

### 2. Install Dependencies

```bash
cd server
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in `/server` with the following:

```env
JWT_SECRET=your-super-secret-key
TTL=3600
```

### 4. Run the Server

```bash
npm start
```

> Server will listen on `ws://localhost:PORT/login` for WebSocket connections.

## 🔑 How It Works

1. **Client connects** to WebSocket endpoint and sends their **ECDH public key**.
2. **Server responds** with its ECDH public key and both sides derive a shared AES key.
3. Client encrypts login/register message with **AES-256-GCM**, sends `{ iv, payload, tag }`.
4. Server decrypts message, processes it, and sends an encrypted response.

## 📬 WebSocket Message Format

### Key Exchange

* `client-public-key` → `{ type: "client-public-key", key: "<PEM>" }`
* `server-public-key` ← `{ type: "server-public-key", serverPubKey: "<Base64>" }`

### Encrypted Payload

```json
{
  "iv": "<hex>",
  "payload": "<hex>",
  "tag": "<hex>"
}
```

Payload contains JSON such as:

```json
{
  "type": "login",
  "username": "Fierra",
  "password": "securepassword123",
  "uuid": "client-uuid"
}
```

### Response

Encrypted JSON:

```json
{
  "type": "success",
  "message": "Login successful",
  "token": "<JWT>"
}
```

## 🧪 Development Notes

* Use [`crypto.diffieHellman`](https://nodejs.org/api/crypto.html#crypto_crypto_diffiehellman_options) to derive shared secret
* Ensure shared secret is 32 bytes for `aes-256-gcm`
* All errors are logged and returned as `{ type: "error", message: "..." }`
* A pretty logger (server) by [ptkdev](https://github.com/ptkdev/ptkdev-logger)

## 📝To-Do's
* Re-write auth module
* Implement tokens database
* Static UUID for clients
* Mock dashboard for client after logins and tokens

## 📄 License

[GPLv3](./LICENSE)

> Made with pain, caffeine, and WebSocket rage 💀
