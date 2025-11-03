perfect move, mercy-not-my-name — going **4096-bit RSA** gives you top-tier security 🔐 (modern CAs and browsers fully support it).

Here’s how to do it cleanly:

---

## 💪 Generate 4096-bit key and CSR for `shop.oms.ca`

### 1️⃣ Make folders (if not already there)

```bash
sudo mkdir -p /etc/ssl/private /etc/ssl/csr /etc/ssl/certs
sudo chmod 700 /etc/ssl/private
```

---

### 2️⃣ Generate private key (4096-bit)

```bash
sudo openssl genrsa -out /etc/ssl/private/shop.oms.ca.key 4096
```

> ⛔ Keep this file secret. Don’t copy it off the server or email it.

---

### 3️⃣ Generate the CSR

Interactive version:

```bash
sudo openssl req -new -key /etc/ssl/private/shop.oms.ca.key -out /etc/ssl/csr/shop.oms.ca.csr
```

Automated (non-interactive) version with all fields in one go:

```bash
sudo openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/ssl/private/shop.oms.ca.key \
  -out /etc/ssl/csr/shop.oms.ca.csr \
  -subj "/C=CA/ST=Ontario/L=East Gwillimbury/O=OMS Inc./OU=IT/CN=shop.oms.ca/emailAddress=admin@shop.oms.ca"
```

---

### 4️⃣ (Optional but recommended) — include SAN (Subject Alternative Names)

Create a file `/etc/ssl/openssl-san.cnf`:

```bash
sudo nano /etc/ssl/openssl-san.cnf
```

Paste:

```ini
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C = CA
ST = Ontario
L = East Gwillimbury
O = OMS Inc.
OU = IT
CN = shop.oms.ca

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = shop.oms.ca
DNS.2 = www.shop.oms.ca
DNS.3 = oms.ca
```

Then run:

```bash
sudo openssl req -new -key /etc/ssl/private/shop.oms.ca.key \
  -out /etc/ssl/csr/shop.oms.ca.csr \
  -config /etc/ssl/openssl-san.cnf
```

---

### 5️⃣ Verify CSR

```bash
openssl req -text -noout -verify -in /etc/ssl/csr/shop.oms.ca.csr
```

Check for:

```
Public-Key: (4096 bit)
X509v3 Subject Alternative Name:
    DNS:shop.oms.ca, DNS:www.shop.oms.ca, DNS:oms.ca
```

---

### 6️⃣ Submit the CSR to your CA

You’ll receive back your signed certs — install them in NGINX as before:

```nginx
ssl_certificate     /etc/ssl/certs/shop.oms.ca.crt;
ssl_certificate_key /etc/ssl/private/shop.oms.ca.key;
ssl_trusted_certificate /etc/ssl/certs/CA-bundle.crt;
```

Then test and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

If you want, I can give you a **one-line script** that auto-creates the 4096-bit key, CSR (with SANs), and prints CSR content for submission — want me to prep that?
