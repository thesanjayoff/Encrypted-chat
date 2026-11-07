import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import * as opaque from "@serenity-kit/opaque";
import { createApp } from "../src/app.js";

describe("rate limiting", () => {
  const previous = process.env.RATE_LIMIT_AUTH;

  beforeAll(() => {
    process.env.RATE_LIMIT_AUTH = "3";
  });
  afterAll(() => {
    process.env.RATE_LIMIT_AUTH = previous;
  });

  it("returns 429 once the auth endpoint limit is exceeded", async () => {
    await opaque.ready;
    const app = createApp();

    let lastStatus = 0;
    for (let i = 0; i < 5; i++) {
      const { registrationRequest } = opaque.client.startRegistration({ password: "x" });
      const res = await request(app)
        .post("/api/auth/register/start")
        .send({ username: `ratelimit_probe_${i}`, registrationRequest });
      lastStatus = res.status;
      if (res.status === 429) break;
    }
    expect(lastStatus).toBe(429);
  });
});
