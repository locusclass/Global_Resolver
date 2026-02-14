import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyId, generateSecret } from "./crypto/keys.js";
test("key and secret format", () => {
    assert.match(generateKeyId(), /^lk_[A-Za-z0-9_-]+$/);
    assert.match(generateSecret(), /^ls_[A-Za-z0-9_-]+$/);
});
//# sourceMappingURL=smoke.test.js.map