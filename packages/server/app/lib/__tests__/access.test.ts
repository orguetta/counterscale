import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import {
    verifyAccessJWT,
    isAccessEnabled,
    isEmailAllowed,
    clearAccessCertsCache,
} from "../access";

const TEAM = "myteam.cloudflareaccess.com";
const AUD = "test-aud-tag";
const KID = "test-kid";

function b64url(input: ArrayBuffer | Uint8Array | string): string {
    const bytes =
        typeof input === "string"
            ? new TextEncoder().encode(input)
            : new Uint8Array(input as ArrayBuffer);
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeKeyPair() {
    return (await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    )) as CryptoKeyPair;
}

async function signToken(
    privateKey: CryptoKey,
    claims: Record<string, unknown>,
    header: Record<string, unknown> = { alg: "RS256", kid: KID },
) {
    const h = b64url(JSON.stringify(header));
    const p = b64url(JSON.stringify(claims));
    const sig = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        new TextEncoder().encode(`${h}.${p}`),
    );
    return `${h}.${p}.${b64url(sig)}`;
}

function validClaims(overrides: Record<string, unknown> = {}) {
    return {
        aud: [AUD],
        iss: `https://${TEAM}`,
        exp: Math.floor(Date.now() / 1000) + 600,
        email: "dana@example.com",
        ...overrides,
    };
}

const baseEnv = {
    CF_ACCESS_TEAM_DOMAIN: TEAM,
    CF_ACCESS_AUD: AUD,
} as unknown as Env;

function requestWith(token?: string): Request {
    const headers = new Headers();
    if (token) headers.set("Cf-Access-Jwt-Assertion", token);
    return new Request("https://example.workers.dev/dashboard", { headers });
}

describe("access", () => {
    let keyPair: CryptoKeyPair;
    let publicJwk: JsonWebKey & { kid?: string };

    beforeEach(async () => {
        clearAccessCertsCache();
        keyPair = await makeKeyPair();
        publicJwk = {
            ...(await crypto.subtle.exportKey("jwk", keyPair.publicKey)),
            kid: KID,
            alg: "RS256",
            use: "sig",
        };
        vi.stubGlobal(
            "fetch",
            vi.fn(async () => new Response(JSON.stringify({ keys: [publicJwk] }))),
        );
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    describe("isAccessEnabled", () => {
        test("is true only when team domain and AUD are both set", () => {
            expect(isAccessEnabled(baseEnv)).toBe(true);
            expect(isAccessEnabled({ CF_ACCESS_TEAM_DOMAIN: TEAM } as unknown as Env)).toBe(false);
            expect(isAccessEnabled({ CF_ACCESS_AUD: AUD } as unknown as Env)).toBe(false);
            expect(isAccessEnabled({} as Env)).toBe(false);
        });
    });

    describe("isEmailAllowed", () => {
        test("allows everyone when no allowlist is set", () => {
            expect(isEmailAllowed("anyone@example.com")).toBe(true);
            expect(isEmailAllowed("anyone@example.com", "  ")).toBe(true);
        });

        test("matches allowlist case-insensitively", () => {
            expect(isEmailAllowed("Dana@Example.com", "dana@example.com, ops@example.com")).toBe(true);
            expect(isEmailAllowed("eve@example.com", "dana@example.com")).toBe(false);
        });
    });

    describe("verifyAccessJWT", () => {
        test("returns null when Access is not configured", async () => {
            const token = await signToken(keyPair.privateKey, validClaims());
            expect(await verifyAccessJWT(requestWith(token), {} as Env)).toBeNull();
        });

        test("returns null when the header is missing", async () => {
            expect(await verifyAccessJWT(requestWith(), baseEnv)).toBeNull();
        });

        test("accepts a valid token and returns the email", async () => {
            const token = await signToken(keyPair.privateKey, validClaims());
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toEqual({
                email: "dana@example.com",
            });
        });

        test("rejects a token signed with a different key", async () => {
            const other = await makeKeyPair();
            const token = await signToken(other.privateKey, validClaims());
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toBeNull();
        });

        test("rejects a token with the wrong audience", async () => {
            const token = await signToken(keyPair.privateKey, validClaims({ aud: ["other-app"] }));
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toBeNull();
        });

        test("rejects a token from the wrong issuer", async () => {
            const token = await signToken(
                keyPair.privateKey,
                validClaims({ iss: "https://evil.cloudflareaccess.com" }),
            );
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toBeNull();
        });

        test("rejects an expired token", async () => {
            const token = await signToken(
                keyPair.privateKey,
                validClaims({ exp: Math.floor(Date.now() / 1000) - 10 }),
            );
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toBeNull();
        });

        test("rejects a non-RS256 algorithm", async () => {
            const token = await signToken(keyPair.privateKey, validClaims(), {
                alg: "none",
                kid: KID,
            });
            expect(await verifyAccessJWT(requestWith(token), baseEnv)).toBeNull();
        });

        test("rejects an email outside the allowlist", async () => {
            const token = await signToken(keyPair.privateKey, validClaims());
            const env = { ...baseEnv, CF_ACCESS_ALLOWED_EMAILS: "ops@example.com" } as unknown as Env;
            expect(await verifyAccessJWT(requestWith(token), env)).toBeNull();
        });

        test("accepts an email inside the allowlist", async () => {
            const token = await signToken(keyPair.privateKey, validClaims());
            const env = { ...baseEnv, CF_ACCESS_ALLOWED_EMAILS: "dana@example.com" } as unknown as Env;
            expect(await verifyAccessJWT(requestWith(token), env)).toEqual({
                email: "dana@example.com",
            });
        });

        test("returns null on malformed tokens", async () => {
            expect(await verifyAccessJWT(requestWith("not-a-jwt"), baseEnv)).toBeNull();
        });
    });
});
