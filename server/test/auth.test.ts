import { describe, it, expect } from "vitest";
import request from "supertest";
import * as opaque from "@serenity-kit/opaque";
import { createApp } from "../src/app.js";
import { registerTestUser, authHeader } from "./helpers.js";

const app = createApp();

describe("OPAQUE registration + login", () => {
  it("registers a user without ever sending the server a password", async () => {
    const user = await registerTestUser(app, "alice");
    expect(user.accountId).toBeTruthy();
    expect(user.deviceId).toBeTruthy();
    expect(user.sessionToken).toBeTruthy();
  });

  it("logs back in with the correct password and rejects the wrong one", async () => {
    const user = await registerTestUser(app, "bob");

    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: user.password });
    const startRes = await request(app).post("/api/auth/login/start").send({ username: user.username, startLoginRequest });
    expect(startRes.status).toBe(200);

    const loginResult = opaque.client.finishLogin({
      clientLoginState,
      loginResponse: startRes.body.loginResponse,
      password: user.password,
    });
    expect(loginResult).toBeTruthy();

    const finishRes = await request(app)
      .post("/api/auth/login/finish")
      .send({ loginId: startRes.body.loginId, finishLoginRequest: loginResult!.finishLoginRequest, deviceId: user.deviceId });
    expect(finishRes.status).toBe(200);
    expect(finishRes.body.sessionToken).toBeTruthy();

    // Wrong password: the client-side finishLogin already fails locally...
    const { clientLoginState: cls2, startLoginRequest: slr2 } = opaque.client.startLogin({ password: "totally wrong password" });
    const wrongStart = await request(app).post("/api/auth/login/start").send({ username: user.username, startLoginRequest: slr2 });
    const wrongResult = opaque.client.finishLogin({ clientLoginState: cls2, loginResponse: wrongStart.body.loginResponse, password: "totally wrong password" });
    expect(wrongResult).toBeUndefined();
  });

  it("rejects a replayed login/finish request (single-use pending login)", async () => {
    const user = await registerTestUser(app, "carol");
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: user.password });
    const startRes = await request(app).post("/api/auth/login/start").send({ username: user.username, startLoginRequest });
    const loginResult = opaque.client.finishLogin({ clientLoginState, loginResponse: startRes.body.loginResponse, password: user.password });

    const first = await request(app)
      .post("/api/auth/login/finish")
      .send({ loginId: startRes.body.loginId, finishLoginRequest: loginResult!.finishLoginRequest, deviceId: user.deviceId });
    expect(first.status).toBe(200);

    const replay = await request(app)
      .post("/api/auth/login/finish")
      .send({ loginId: startRes.body.loginId, finishLoginRequest: loginResult!.finishLoginRequest, deviceId: user.deviceId });
    expect(replay.status).toBe(401);
  });

  it("does not reveal whether a username exists via the login/start response shape", async () => {
    const { startLoginRequest } = opaque.client.startLogin({ password: "whatever" });
    const res = await request(app).post("/api/auth/login/start").send({ username: "definitely_not_registered_12345", startLoginRequest });
    expect(res.status).toBe(200);
    expect(res.body.loginResponse).toBeTruthy();
  });

  it("rejects login/finish for a deviceId that doesn't belong to the account", async () => {
    const user = await registerTestUser(app, "dave");
    const other = await registerTestUser(app, "eve");

    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: user.password });
    const startRes = await request(app).post("/api/auth/login/start").send({ username: user.username, startLoginRequest });
    const loginResult = opaque.client.finishLogin({ clientLoginState, loginResponse: startRes.body.loginResponse, password: user.password });

    const finishRes = await request(app)
      .post("/api/auth/login/finish")
      .send({ loginId: startRes.body.loginId, finishLoginRequest: loginResult!.finishLoginRequest, deviceId: other.deviceId });
    expect(finishRes.status).toBe(403);
  });

  it("rejects duplicate username registration", async () => {
    const user = await registerTestUser(app, "frank");
    const { registrationRequest } = opaque.client.startRegistration({ password: "whatever" });
    const res = await request(app).post("/api/auth/register/start").send({ username: user.username, registrationRequest });
    expect(res.status).toBe(409);
  });

  it("requires a bearer token for authenticated endpoints", async () => {
    const res = await request(app).get("/api/keys/prekeys/count");
    expect(res.status).toBe(401);
  });

  void authHeader; // used by other test files
});
