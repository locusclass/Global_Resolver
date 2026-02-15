import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createObjectDraftHash, createPresencePayloadHash, generateEd25519KeyPair, signEd25519 } from "./shared/index.js";
import { buildApp } from "./app.js";
import { query } from "./db/index.js";
import { migrateUp } from "./db/migrate.js";
function parseJson(body) {
    return JSON.parse(body);
}
async function buildPresence() {
    const keyPair = await generateEd25519KeyPair();
    const payload = {
        lat: 37.7749,
        lng: -122.4194,
        accuracy_m: 5,
        timestamp_ms: Date.now(),
        nonce: randomUUID().replace(/-/g, ""),
        signer_public_key: keyPair.publicKey
    };
    const payloadHash = await createPresencePayloadHash(payload);
    const signature = await signEd25519(payloadHash, keyPair.privateKey);
    return {
        ...payload,
        algorithm: "ed25519",
        payload_hash: payloadHash,
        signature
    };
}
async function buildObjectDraft(payload) {
    const keyPair = await generateEd25519KeyPair();
    const base = {
        schema_id: "note",
        radius_m: 80,
        payload,
        creator_public_key: keyPair.publicKey
    };
    const hash = await createObjectDraftHash(base);
    const signature = await signEd25519(hash, keyPair.privateKey);
    return {
        ...base,
        creator_signature: signature
    };
}
test("credential lifecycle end-to-end", async (t) => {
    try {
        await migrateUp();
        await query("SELECT 1");
    }
    catch {
        t.skip("Postgres not available; skipping integration test");
        return;
    }
    await query(`TRUNCATE TABLE
      api_keys,
      projects,
      developers,
      resolver_objects,
      usage_counters
    RESTART IDENTITY CASCADE`);
    const app = buildApp();
    t.after(async () => {
        await app.close();
    });
    const register = await app.inject({
        method: "POST",
        url: "/v1/dev/register",
        payload: { email: "integration@example.com" }
    });
    assert.equal(register.statusCode, 200);
    const developerId = parseJson(register.body).developer_id;
    assert.ok(developerId);
    const projectRes = await app.inject({
        method: "POST",
        url: "/v1/projects",
        payload: { developer_id: developerId, name: "integration-project" }
    });
    assert.equal(projectRes.statusCode, 201);
    const projectId = parseJson(projectRes.body).project_id;
    assert.ok(projectId);
    const createKey = await app.inject({
        method: "POST",
        url: `/v1/projects/${projectId}/keys`,
        payload: { label: "primary" }
    });
    assert.equal(createKey.statusCode, 201);
    const createdKeyJson = parseJson(createKey.body);
    const keyId = createdKeyJson.key_id;
    const apiSecret = createdKeyJson.api_secret;
    assert.ok(keyId);
    assert.ok(apiSecret);
    const mint = await app.inject({
        method: "POST",
        url: "/v1/auth/token",
        payload: { key_id: keyId, api_secret: apiSecret }
    });
    assert.equal(mint.statusCode, 200);
    const accessToken = parseJson(mint.body).access_token;
    assert.ok(accessToken);
    const resolve = await app.inject({
        method: "POST",
        url: "/v1/resolve",
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { presence: await buildPresence(), includeHistory: false }
    });
    assert.equal(resolve.statusCode, 200);
    const anchor = await app.inject({
        method: "POST",
        url: "/v1/anchor",
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
            presence: await buildPresence(),
            objectDraft: await buildObjectDraft({ title: "v1" })
        }
    });
    assert.equal(anchor.statusCode, 201);
    const anchoredObjectId = parseJson(anchor.body).object.object_id;
    assert.ok(anchoredObjectId);
    const supersede = await app.inject({
        method: "POST",
        url: "/v1/supersede",
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
            presence: await buildPresence(),
            supersedes_object_id: anchoredObjectId,
            objectDraft: await buildObjectDraft({ title: "v2" })
        }
    });
    assert.equal(supersede.statusCode, 201);
    const rotate = await app.inject({
        method: "POST",
        url: `/v1/projects/${projectId}/keys/${keyId}/rotate`,
        payload: {}
    });
    assert.equal(rotate.statusCode, 200);
    const rotatedSecret = parseJson(rotate.body).api_secret;
    const oldMint = await app.inject({
        method: "POST",
        url: "/v1/auth/token",
        payload: { key_id: keyId, api_secret: apiSecret }
    });
    assert.equal(oldMint.statusCode, 401);
    const newMint = await app.inject({
        method: "POST",
        url: "/v1/auth/token",
        payload: { key_id: keyId, api_secret: rotatedSecret }
    });
    assert.equal(newMint.statusCode, 200);
    const newToken = parseJson(newMint.body).access_token;
    const revoke = await app.inject({
        method: "POST",
        url: `/v1/projects/${projectId}/keys/${keyId}/revoke`,
        payload: {}
    });
    assert.equal(revoke.statusCode, 200);
    const mintAfterRevoke = await app.inject({
        method: "POST",
        url: "/v1/auth/token",
        payload: { key_id: keyId, api_secret: rotatedSecret }
    });
    assert.equal(mintAfterRevoke.statusCode, 401);
    const resolveAfterRevoke = await app.inject({
        method: "POST",
        url: "/v1/resolve",
        headers: { authorization: `Bearer ${newToken}` },
        payload: { presence: await buildPresence(), includeHistory: false }
    });
    assert.equal(resolveAfterRevoke.statusCode, 401);
});
