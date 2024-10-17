const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const forge = require("node-forge");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/generate-key", (req, res) => {
  const { algorithm } = req.body;

  switch (algorithm) {
    case "AES": {
      const key = crypto.randomBytes(32).toString("hex");
      res.json({ algorithm, key });
      break;
    }

    case "RSA": {
      const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);

      res.json({
        algorithm,
        privateKey: forge.pki.privateKeyToPem(privateKey),
        publicKey: forge.pki.publicKeyToPem(publicKey),
      });
      break;
    }

    case "3DES": {
      const key = crypto.randomBytes(24).toString("hex");
      res.json({ algorithm, key });
      break;
    }

    default:
      res.status(400).json({ error: "Unsupported algorithm" });
  }
});

app.post("/encrypt", (req, res) => {
  const { algorithm, data, key } = req.body;
  let encrypted = "";

  switch (algorithm) {
    case "AES": {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(
        "aes-256-cbc",
        Buffer.from(key, "hex"),
        iv
      );

      encrypted = Buffer.concat([
        cipher.update(data, "utf8"),
        cipher.final(),
      ]).toString("hex");

      res.json({ algorithm, iv: iv.toString("hex"), encrypted });
      break;
    }

    case "RSA": {
      const publicKey = forge.pki.publicKeyFromPem(
        key.replace(/\\r\\n/g, "\n")
      );
      encrypted = publicKey.encrypt(data, "RSA-OAEP", {
        md: forge.md.sha256.create(),
      });
      encrypted = forge.util.encode64(encrypted);
      res.json({ algorithm, encrypted });
      break;
    }

    case "3DES": {
      const KEY = Buffer.from(key, "hex");
      const iv = crypto.randomBytes(8);
      const cipher = crypto.createCipheriv("des-ede3-cbc", KEY, iv);
      encrypted = Buffer.concat([
        cipher.update(data, "utf8"),
        cipher.final(),
      ]).toString("hex");
      res.json({ algorithm, iv: iv.toString("hex"), encrypted });
      break;
    }

    default:
      res.status(400).json({ error: "Unsupported algorithm" });
  }
});

app.post("/decrypt", (req, res) => {
  const { algorithm, encrypted, iv, key } = req.body;
  let decrypted = "";

  switch (algorithm) {
    case "AES": {
      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        Buffer.from(key, "hex"),
        Buffer.from(iv, "hex")
      );
      decrypted = Buffer.concat([
        decipher.update(Buffer.from(encrypted, "hex")),
        decipher.final(),
      ]).toString("utf8");
      res.json({ algorithm, decrypted });
      break;
    }

    case "RSA": {
      const privateKey = forge.pki.privateKeyFromPem(
        key.replace(/\\r\\n/g, "\n")
      );
      decrypted = privateKey.decrypt(
        forge.util.decode64(encrypted),
        "RSA-OAEP",
        {
          md: forge.md.sha256.create(),
        }
      );
      res.json({ algorithm, decrypted });
      break;
    }

    case "3DES": {
      const KEY = Buffer.from(key, "hex");
      const decipher = crypto.createDecipheriv(
        "des-ede3-cbc",
        KEY,
        Buffer.from(iv, "hex")
      );
      decrypted = Buffer.concat([
        decipher.update(Buffer.from(encrypted, "hex")),
        decipher.final(),
      ]).toString("utf8");
      res.json({ algorithm, decrypted });
      break;
    }

    default:
      res.status(400).json({ error: "Unsupported algorithm" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
