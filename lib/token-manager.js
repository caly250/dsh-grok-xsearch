import * as grok from './grok-oauth.js'
import { parseBlob, serializeBlob } from './blob.js'

const SKEW_MS = 60 * 1000

export function credentialRef(ref) {
  // DSH's credentials seam addresses a secret by a branded *string* reference
  // (an environment-variable-style name such as `GROK_XSEARCH_OAUTH_1`), not an
  // object. Passing `{ type, id }` made every credential provider call
  // `lookupKey(object)` -> `name.toUpperCase is not a function` on Windows, and
  // nothing was ever stored. Normalise the legacy object form back to its `id`
  // string so existing callers keep working.
  if (typeof ref === 'string') return ref
  if (ref && typeof ref === 'object' && typeof ref.id === 'string') return ref.id
  return ref
}

function credentialsService(ctx) {
  return (typeof ctx?.get === 'function' ? ctx.get('credentials') : ctx?.credentials) || null
}

export async function loadBlob(ctx) {
  const creds = credentialsService(ctx)
  if (!creds || typeof creds.resolve !== 'function') return null
  const ref = credentialRef(grok.OAUTH_REF)
  const raw = await creds.resolve(ref).then((r) => r?.value || '').catch(() => '')
  if (!raw) return null
  try {
    return parseBlob(raw)
  } catch {
    return null
  }
}

export async function saveBlob(ctx, blob) {
  const creds = credentialsService(ctx)
  if (!creds || typeof creds.set !== 'function') return
  const ref = credentialRef(grok.OAUTH_REF)
  await creds.set(ref, serializeBlob(blob))
}

export async function clearBlob(ctx) {
  const creds = credentialsService(ctx)
  if (!creds || typeof creds.unset !== 'function') return
  const ref = credentialRef(grok.OAUTH_REF)
  await creds.unset(ref).catch(() => {})
}

let refreshInFlight = null

export function clearRefreshMutex() {
  refreshInFlight = null
}

function isFatalGrantError(err) {
  const msg = String(err?.message || '').toLowerCase()
  const status = Number(err?.status) || 0
  return status === 400 || status === 401 || msg.includes('invalid_grant') || msg.includes('revoked')
}

export async function getValidAccessToken(ctx, cfg, forceRefresh = false, fetchImpl = fetch) {
  const blob = await loadBlob(ctx)
  if (!blob?.accessToken) return ''
  if (!forceRefresh && blob.expiresAt && blob.expiresAt > Date.now() + SKEW_MS) {
    return blob.accessToken
  }
  if (!blob.refreshToken) return blob.accessToken

  if (refreshInFlight) {
    return refreshInFlight
  }

  refreshInFlight = (async () => {
    try {
      const next = await grok.refresh(cfg, blob, fetchImpl)
      await saveBlob(ctx, next)
      return next.accessToken
    } catch (err) {
      if (isFatalGrantError(err)) {
        await clearBlob(ctx)
      }
      throw err
    } finally {
      refreshInFlight = null
    }
  })()

  return refreshInFlight
}
