import express from "express";
import speakeasy from "speakeasy";
import crypto from "crypto";
import bodyParser from "body-parser";
import { Buffer } from "node:buffer";
const app = express();

app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ limit: "5mb", extended: false }));

app.all("/*path", (req, res, next) => {
  console.log(req.url);
  next();
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

const encryptData = (data, publicKey) => {
  const buffer = Buffer.from(data);
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    buffer,
  );
  return encrypted.toString("base64");
};

app.post("/getRsa", (req, res) => {
  const params = req.body;
  return res.send({
    key: encryptData(
      params.data,
      Buffer.from(params.publicKey, "base64").toString(),
    ),
  });
});

// 修改另一个padding
const encryptData2 = (data, publicKey) => {
  const buffer = Buffer.from(data);
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    buffer,
  );
  return encrypted.toString("base64");
};

app.post("/getRsa2", (req, res) => {
  const params = req.body;
  return res.send({
    key: encryptData2(
      params.data,
      Buffer.from(params.publicKey, "base64").toString(),
    ),
  });
});

app.post("/2fa-token", (req, res) => {
  const params = req.body;
  const token = speakeasy.totp({
    secret: params.base32 || "",
    encoding: "base32",
  });
  return res.send({
    token: token,
  });
});

app.post("/getAes", (req, res) => {
  const params = req.body;
  const key = params.aesKey;
  const plainText = params.plainText;
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(key, "hex"),
    nonce,
    {
      authTagLength: 16,
    },
  );
  const encrypted = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final(),
  ]);
  const result = Buffer.concat([
    nonce,
    cipher.getAuthTag(),
    encrypted,
  ]).toString("base64");
  return res.send({
    result,
  });
});

app.post("/decryptAes", (req, res) => {
  const params = req.body;
  const key = params.aesKey;
  const cipherText = params.cipherText;
  let result;
  try {
    const data = Buffer.from(cipherText, "base64");

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      Buffer.from(key, "hex"),
      data.subarray(0, 12),
      { authTagLength: 16 },
    );
    decipher.setAuthTag(data.subarray(12, 28));
    const decrypted = Buffer.concat([
      decipher.update(data.subarray(28)),
      decipher.final(),
    ]);
    result = decrypted.toString("utf8");
  } catch (e) {
    result = null;
  }
  return res.send({
    result,
  });
});

app.listen(5200, () => {
  console.log("Express server initialized");
});
