import { isIP } from 'node:net'
import { domainToUnicode } from 'node:url'
import { getDomain, getPublicSuffix, getSubdomain } from 'tldts'

export type NormalizedSiteCandidate = {
  rawUrl: string
  normalizedUrl: string
  protocol: 'http:' | 'https:'
  hostname: string
  asciiHostname: string
  unicodeHostname: string
  registrableDomain: string | null
  publicSuffix: string | null
  subdomain: string | null
  isIp: boolean
  port: string | null
  path: string
  query: string
}

export function normalizeHostname(value: string): string | null {
  const trimmed = value.trim().toLowerCase().replace(/\.+$/g, '').replace(/^\*\./, '').replace(/^\./, '')

  if (trimmed.length === 0) {
    return null
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    return trimmed
  }

  if (!/^[a-z0-9.-]+$/i.test(trimmed)) {
    return null
  }

  return trimmed
}

export function getHostnameFromUrl(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)
    return normalizeHostname(parsedUrl.hostname)
  } catch {
    return null
  }
}

export function extractDomainBlocklistHostnames(payload: string): Set<string> {
  const hostnames = new Set<string>()

  for (const rawLine of payload.split(/\r?\n/)) {
    const commentIndex = rawLine.indexOf('#')
    const line = (commentIndex >= 0 ? rawLine.slice(0, commentIndex) : rawLine).trim()

    if (line.length === 0) {
      continue
    }

    const tokens = line.split(/\s+/).filter(Boolean)

    for (const token of tokens) {
      let nextHostname: string | null = null

      if (/^https?:\/\//i.test(token)) {
        nextHostname = getHostnameFromUrl(token)
      } else {
        nextHostname = normalizeHostname(token)
      }

      if (nextHostname) {
        hostnames.add(nextHostname)
      }
    }
  }

  return hostnames
}

export function isHostnameBlocked(hostname: string, blockedEntries: Set<string>): string | null {
  for (const blockedEntry of blockedEntries) {
    if (hostname === blockedEntry || hostname.endsWith(`.${blockedEntry}`)) {
      return blockedEntry
    }
  }

  return null
}

export function normalizeSiteCandidate(rawUrl: string): NormalizedSiteCandidate {
  const parsedUrl = new URL(rawUrl)
  const asciiHostname = normalizeHostname(parsedUrl.hostname)

  if (!asciiHostname) {
    throw new Error(`Nie udało się znormalizować hosta dla adresu: ${rawUrl}`)
  }

  const unicodeHostname = domainToUnicode(asciiHostname).toLowerCase() || asciiHostname

  return {
    rawUrl,
    normalizedUrl: parsedUrl.toString(),
    protocol: parsedUrl.protocol as 'http:' | 'https:',
    hostname: asciiHostname,
    asciiHostname,
    unicodeHostname,
    registrableDomain: getDomain(asciiHostname) ?? null,
    publicSuffix: getPublicSuffix(asciiHostname) ?? null,
    subdomain: getSubdomain(asciiHostname) || null,
    isIp: isIP(asciiHostname) !== 0,
    port: parsedUrl.port || null,
    path: parsedUrl.pathname,
    query: parsedUrl.search
  }
}

export function hasNonLatinLetters(value: string): boolean {
  for (const char of value) {
    if (!/\p{Letter}/u.test(char)) {
      continue
    }

    if (!/\p{Script=Latin}/u.test(char)) {
      return true
    }
  }

  return false
}

export function isTrustedDomainEntryMentionedInSubdomain(
  candidate: Pick<NormalizedSiteCandidate, 'registrableDomain' | 'subdomain' | 'isIp'>,
  trustedDomain: string,
  trustedLabel?: string | null
): boolean {
  if (!candidate.registrableDomain || !candidate.subdomain || candidate.isIp) {
    return false
  }

  const normalizedTrustedDomain = normalizeHostname(trustedDomain)

  if (!normalizedTrustedDomain || normalizedTrustedDomain === candidate.registrableDomain) {
    return false
  }

  const subdomain = candidate.subdomain.toLowerCase()

  if (
    subdomain === normalizedTrustedDomain ||
    subdomain.startsWith(`${normalizedTrustedDomain}.`) ||
    subdomain.endsWith(`.${normalizedTrustedDomain}`) ||
    subdomain.includes(`.${normalizedTrustedDomain}.`)
  ) {
    return true
  }

  const label = (trustedLabel ?? normalizedTrustedDomain.split('.')[0] ?? '').toLowerCase()

  if (label.length < 5) {
    return false
  }

  return (
    subdomain === label ||
    subdomain.startsWith(`${label}.`) ||
    subdomain.endsWith(`.${label}`) ||
    subdomain.includes(`.${label}.`) ||
    subdomain.startsWith(`${label}-`) ||
    subdomain.endsWith(`-${label}`) ||
    subdomain.includes(`-${label}-`)
  )
}
