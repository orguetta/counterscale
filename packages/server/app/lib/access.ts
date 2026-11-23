/**
 * Cloudflare Access support.
 *
 * When Cloudflare Access sits in front of the dashboard, every request that
 * passes Access carries a signed JWT in the `Cf-Access-Jwt-Assertion` header.
 * We verify that JWT ourselves (signature, issuer, audience, expiry) so the
 * Worker never trusts the header on its own, even though the Worker is also
 * reachable on its workers.dev hostname.
 *
 * Configuration (all optional; Access mode is on only when the first two are set):
 *   CF_ACCESS_TEAM_DOMAIN     e.g. "myteam.cloudflareaccess.com"
 *   CF_ACCESS_AUD             the Application Audience (AUD) tag of the Access app
 *   CF_ACCESS_ALLOWED_EMAILS  optional comma-separated allowlist of emails
 */

const CERTS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

type SigningKey = JsonWebKey & { kid?: string };

const certsCache = new Map<string, { keys: SigningKey[]; fetchedAt: number }>();

/** Clears cached signing keys. Intended for tests. */
export function clearAccessCertsCache(): void {
    certsCache.clear();
}

export function isAccessEnabled(env: Env): boolean {
    return Boolean(env.CF_ACCESS_TEAM_DOMAIN && env.CF_ACCESS_AUD);
}

export function isEmailAllowed(email: string, allowlist?: string): boolean {
    if (!allowlist || !allowlist.trim()) {
        return true;
    }
    const allowed = allowlist
        .split(",")
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean);
    return allowed.includes(email.toLowerCase());
}

function base64UrlToBytes(input: string): Uint8Array {
    const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeSegment<T>(segment: string): T {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as T;
}

async function getSigningKeys(teamDomain: string): Promise<SigningKey[]> {
    const cached = certsCache.get(teamDomain);
    if (cached && Date.now() - cached.fetchedAt < CERTS_CACHE_TTL_MS) {
        return cached.keys;
    }

    const response = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
    if (!response.ok) {
        throw new Error(`Failed to fetch Access certs: ${response.status}`);
    }
    const body = (await response.json()) as { keys: SigningKey[] };
    certsCache.set(teamDomain, { keys: body.keys, fetchedAt: Date.now() });
    return body.keys;
}

export interface AccessIdentity {
    email: string;
}

/**
 * Returns the identity of the user who passed Cloudflare Access, or null when
 * Access is not configured, the header is missing, or the token is not valid.
 */
export async function verifyAccessJWT(
    request: Request,
    env: Env,
): Promise<AccessIdentity | null> {
    if (!isAccessEnabled(env)) {
        return null;
    }

    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!token) {
        return null;
    }

    try {
        const parts = token.split(".");
        if (parts.length !== 3) {
            return null;
        }
        const [headerSegment, payloadSegment, signatureSegment] = parts;

        const header = decodeSegment<{ alg?: string; kid?: string }>(headerSegment);
        if (header.alg !== "RS256") {
            return null;
        }

        const payload = decodeSegment<{
            aud?: string | string[];
            iss?: string;
            exp?: number;
            email?: string;
        }>(payloadSegment);

        const nowInSeconds = Math.floor(Date.now() / 1000);
        if (typeof payload.exp !== "number" || payload.exp <= nowInSeconds) {
            return null;
        }

        const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audiences.includes(env.CF_ACCESS_AUD)) {
            return null;
        }

        if (payload.iss !== `https://${env.CF_ACCESS_TEAM_DOMAIN}`) {
            return null;
        }

        const teamDomain = env.CF_ACCESS_TEAM_DOMAIN;
        if (!teamDomain) {
            return null;
        }
        const keys = await getSigningKeys(teamDomain);
        const jwk = keys.find((key) => key.kid === header.kid);
        if (!jwk) {
            return null;
        }

        const publicKey = await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"],
        );
        const signedData = new TextEncoder().encode(
            `${headerSegment}.${payloadSegment}`,
        );
        const signatureValid = await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            publicKey,
            base64UrlToBytes(signatureSegment),
            signedData,
        );
        if (!signatureValid) {
            return null;
        }

        if (!payload.email || !isEmailAllowed(payload.email, env.CF_ACCESS_ALLOWED_EMAILS)) {
            return null;
        }

        return { email: payload.email };
    } catch {
        return null;
    }
}
