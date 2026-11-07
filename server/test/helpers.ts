import request from "supertest";
import type { Express } from "express";
import * as opaque from "@serenity-kit/opaque";
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, toBase64 } from "@e2e-chat/crypto";

export interface TestUser {
  username: string;
  password: string;
  accountId: string;
  deviceId: string;
  sessionToken: string;
  identity: ReturnType<typeof generateIdentityKeyPair>;
  signedPreKey: ReturnType<typeof generateSignedPreKey>;
}

let counter = 0;

export async function registerTestUser(app: Express, usernamePrefix = "user"): Promise<TestUser> {
  await opaque.ready;
  const username = `${usernamePrefix}_${Date.now()}_${counter++}`;
  const password = "correct horse battery staple";

  const identity = generateIdentityKeyPair();
  const signedPreKey = generateSignedPreKey(identity.signing.privateKey, 1);
  const otpks = generateOneTimePreKeys(1, 10);

  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password });

  const startRes = await request(app).post("/api/auth/register/start").send({ username, registrationRequest });
  if (startRes.status !== 200) throw new Error(`register/start failed: ${JSON.stringify(startRes.body)}`);

  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse: startRes.body.registrationResponse,
    password,
  });

  const finishRes = await request(app)
    .post("/api/auth/register/finish")
    .send({
      username,
      registrationRecord,
      identitySigningPublicKey: toBase64(identity.signing.publicKey),
      identityDhKey: toBase64(identity.dh.publicKey),
      device: {
        label: "test-device",
        signedPreKeyId: signedPreKey.keyId,
        signedPreKeyPublic: toBase64(signedPreKey.keyPair.publicKey),
        signedPreKeySignature: toBase64(signedPreKey.signature),
        oneTimePreKeys: otpks.map((o) => ({ keyId: o.keyId, publicKey: toBase64(o.keyPair.publicKey) })),
      },
    });
  if (finishRes.status !== 201) throw new Error(`register/finish failed: ${JSON.stringify(finishRes.body)}`);

  return {
    username,
    password,
    accountId: finishRes.body.accountId,
    deviceId: finishRes.body.deviceId,
    sessionToken: finishRes.body.sessionToken,
    identity,
    signedPreKey,
  };
}

export function authHeader(user: TestUser) {
  return { authorization: `Bearer ${user.sessionToken}` };
}
