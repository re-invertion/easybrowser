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

export type ContentTrustedBrand = {
  domain: string
  label: string
  isGenericLabel?: boolean
}

export type ContentAnalysisFindingId =
  | 'content-sensitive-form'
  | 'content-cross-origin-form'
  | 'content-brand-impersonation'
  | 'content-urgent-language'
  | 'content-suspicious-iframe'
  | 'content-download-risk'
  | 'content-threat-link-catalog'

export type ContentAnalysisFinding = {
  id: ContentAnalysisFindingId
  matched: boolean
  code: string
  message: string
  evidence?: string
}

type HtmlForm = {
  actionHostname: string | null
  hasSensitiveInput: boolean
}

const SAFE_TECHNICAL_INPUT_PATTERN =
  /(?:__requestverificationtoken|csrf|xsrf|authenticity_token|captcha|recaptcha)/i
const NEWSLETTER_CONTEXT_PATTERN =
  /\b(?:newsletter|subskry|subscribe|zapisz|zapisz si[ęe]|adres e-?mail|tw[oó]j adres e-?mail)\b/i
const CREDENTIAL_INPUT_PATTERN =
  /(?:type\s*=\s*["']?password|name\s*=\s*["']?[^"'\s>]*(?:pass|password|passwd|pwd|login|card|cc|cvv|cvc|pesel|blik|otp|sms)[^"'\s>]*|id\s*=\s*["']?[^"'\s>]*(?:pass|password|passwd|pwd|login|card|cc|cvv|cvc|pesel|blik|otp|sms)[^"'\s>]*|autocomplete\s*=\s*["']?(?:cc-number|cc-csc|one-time-code|current-password|new-password))/i
const EMAIL_OR_PHONE_INPUT_PATTERN =
  /(?:type\s*=\s*["']?(?:email|tel)|name\s*=\s*["']?[^"'\s>]*(?:email|phone)[^"'\s>]*|id\s*=\s*["']?[^"'\s>]*(?:email|phone)[^"'\s>]*)/i
const KNOWN_TELEMETRY_IFRAME_HOSTS = new Set([
  'www.googletagmanager.com',
  'googletagmanager.com',
  'www.google-analytics.com',
  'google-analytics.com'
])

const URGENT_LANGUAGE_PATTERNS = [
  /\bverify (?:your )?(?:account|identity|payment|card|login)\b/i,
  /\baccount verification\b/i,
  /\burgent (?:action|verification|security|payment|login)\b/i,
  /\bsuspended\b/i,
  /\baccount (?:blocked|locked|suspended)\b/i,
  /\bconfirm (?:your )?(?:account|identity|payment|card|login|details)\b/i,
  /\bupdate your account\b/i,
  /\bsecurity alert\b/i,
  /\blogin required\b/i,
  /\bkonto zablokowane\b/i,
  /\bpotwierd[źz] (?:konto|to[żz]samo[śs][ćc]|p[łl]atno[śs][ćc]|kart[ęe]|dane|logowanie)\b/i,
  /\bweryfikacj[aaei] (?:konta|to[żz]samo[śs]ci|p[łl]atno[śs]ci|karty|danych|logowania)\b/i,
  /\bpilne (?:dzia[łl]anie|potwierdzenie|weryfikacja|logowanie)\b/i,
  /\balert bezpiecze[ńn]stwa\b/i,
  /\bzaktualizuj dane\b/i
]

const DOWNLOAD_RISK_PATTERN = /\.(?:exe|msi|scr|bat|cmd|vbs|ps1|jar|zip|rar|7z)(?:[?#"'\s>]|$)/i
const THREAT_CATALOG_CATEGORY_PATTERNS: Array<[string, RegExp]> = [
  ['phishing', /\b(?:phishing|social engineering)\b/i],
  ['malware', /\bmalware\b/i],
  ['unwanted', /\b(?:unwanted software|potentially unwanted|pua)\b/i],
  ['billing', /\b(?:billing warning|trick(?:s|ed)? to bill|payment warning)\b/i],
  ['cookie-theft', /\bcookie theft\b/i],
  ['low-reputation', /\b(?:low reputation|suspicious level|suspicious site warning)\b/i],
  ['dangerous-download', /\b(?:dangerous host|dangerous file|harmful file|malicious warning|uncommon warning)\b/i],
  ['restricted-content', /\brestricted content\b/i]
]
const THREAT_CATALOG_ACTION_PATTERN =
  /\b(?:should show|should trigger|should return|should create|warning|blocked|malicious|dangerous|harmful)\b/gi
const BRAND_IMPERSONATION_CONTEXT_PATTERNS = [
  /type\s*=\s*["']?password/i,
  /\blogin\b/i,
  /\bsign in\b/i,
  /\bverify (?:your )?(?:account|identity|payment|card|login)\b/i,
  /\baccount verification\b/i,
  /\bsecurity alert\b/i,
  /\bkonto zablokowane\b/i,
  /\bweryfikacj[aaei] (?:konta|to[żz]samo[śs]ci|p[łl]atno[śs]ci|karty|danych|logowania)\b/i,
  /\bpotwierd[źz] (?:konto|to[żz]samo[śs][ćc]|p[łl]atno[śs][ćc]|kart[ęe]|dane|logowanie)\b/i
]

function stripHtml(value: string): string {
  return value
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
}

function removeLowRiskConsentBlocks(value: string): string {
  return value
    .replace(/<form\b[^>]*(?:data-cookieman-form|cookie|consent)[^>]*>[\s\S]*?<\/form>/gi, ' ')
    .replace(/<div\b[^>]*(?:id|class)\s*=\s*["'][^"']*(?:cookie|cookieman|consent)[^"']*["'][^>]*>[\s\S]*?<\/div>/gi, ' ')
}

function getHtmlAttribute(tag: string, attributeName: string): string | null {
  const match = new RegExp(`${attributeName}\\s*=\\s*["']([^"']+)["']`, 'i').exec(tag)
  return match?.[1] ?? null
}

function isHiddenInput(tag: string): boolean {
  return /type\s*=\s*["']?hidden/i.test(tag)
}

function isSafeTechnicalInput(tag: string): boolean {
  return SAFE_TECHNICAL_INPUT_PATTERN.test(tag)
}

function hasSensitiveInput(value: string): boolean {
  let hasContactOnlyInput = false

  const controlMatches = value.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)

  for (const match of controlMatches) {
    const tag = match[0]

    if (isHiddenInput(tag) && isSafeTechnicalInput(tag)) {
      continue
    }

    if (CREDENTIAL_INPUT_PATTERN.test(tag)) {
      return true
    }

    if (EMAIL_OR_PHONE_INPUT_PATTERN.test(tag)) {
      hasContactOnlyInput = true
    }
  }

  return hasContactOnlyInput && !NEWSLETTER_CONTEXT_PATTERN.test(value)
}

function isKnownTelemetryIframe(srcHostname: string | null): boolean {
  return srcHostname !== null && KNOWN_TELEMETRY_IFRAME_HOSTS.has(srcHostname)
}

function hasRiskyDownloadUrl(html: string): boolean {
  const attributeMatches = html.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)

  for (const match of attributeMatches) {
    const value = match[1] ?? ''

    if (DOWNLOAD_RISK_PATTERN.test(value)) {
      return true
    }
  }

  return false
}

function getThreatCatalogCategoryCount(value: string): number {
  const matchedCategories = new Set<string>()

  for (const [category, pattern] of THREAT_CATALOG_CATEGORY_PATTERNS) {
    if (pattern.test(value)) {
      matchedCategories.add(category)
    }
  }

  return matchedCategories.size
}

function hasThreatLinkCatalog(text: string, html: string): boolean {
  const anchorMatches = Array.from(html.matchAll(/<a\b[^>]*>[\s\S]*?<\/a>/gi)).map((match) =>
    match[0]
  )
  const linkedThreatAnchors = anchorMatches.filter((anchor) => {
    const href = getHtmlAttribute(anchor, 'href') ?? ''
    const anchorText = stripHtml(anchor)
    return getThreatCatalogCategoryCount(`${href} ${anchorText}`) > 0
  })
  const categoryCount = getThreatCatalogCategoryCount(`${text} ${linkedThreatAnchors.join(' ')}`)
  const actionSignalCount = Array.from(text.matchAll(THREAT_CATALOG_ACTION_PATTERN)).length

  return categoryCount >= 3 && (linkedThreatAnchors.length >= 3 || actionSignalCount >= 3)
}

function extractForms(html: string): HtmlForm[] {
  const forms: HtmlForm[] = []
  const formMatches = html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)

  for (const match of formMatches) {
    const formHtml = match[0]
    const action = getHtmlAttribute(formHtml, 'action')
    forms.push({
      actionHostname: action ? getHostnameFromUrl(action) : null,
      hasSensitiveInput: hasSensitiveInput(formHtml)
    })
  }

  const looseSensitiveInput = Array.from(html.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)).some(
    (match) => hasSensitiveInput(match[0])
  )

  if (forms.length === 0 && looseSensitiveInput) {
    forms.push({
      actionHostname: null,
      hasSensitiveInput: true
    })
  }

  return forms
}

function containsBrand(value: string, brand: ContentTrustedBrand): boolean {
  const label = brand.label.toLowerCase()
  const domain = brand.domain.toLowerCase()
  const lowerValue = value.toLowerCase()

  if (label.length < 5) {
    return lowerValue.includes(domain)
  }

  if (lowerValue.includes(domain)) {
    return true
  }

  if (brand.isGenericLabel) {
    return false
  }

  return new RegExp(`(^|[^a-z0-9])${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`, 'i').test(value)
}

export function analyzePageContent(
  html: string,
  candidate: NormalizedSiteCandidate,
  trustedBrands: ContentTrustedBrand[]
): ContentAnalysisFinding[] {
  const findings: ContentAnalysisFinding[] = []
  const analysisHtml = removeLowRiskConsentBlocks(html)
  const text = stripHtml(analysisHtml)
  const searchable = `${text} ${analysisHtml}`.slice(0, 250_000)
  const forms = extractForms(analysisHtml)
  const sensitiveForm = forms.find((form) => form.hasSensitiveInput)

  if (sensitiveForm) {
    findings.push({
      id: 'content-sensitive-form',
      matched: true,
      code: 'content-sensitive-form',
      message: 'Strona zawiera formularz proszący o dane logowania, kontaktowe lub płatnicze.'
    })
  }

  const crossOriginForm = forms.find((form) => {
    if (!form.hasSensitiveInput || !form.actionHostname) {
      return false
    }

    return form.actionHostname !== candidate.asciiHostname
  })

  if (crossOriginForm?.actionHostname) {
    findings.push({
      id: 'content-cross-origin-form',
      matched: true,
      code: `content-cross-origin-form:${crossOriginForm.actionHostname}`,
      message: 'Formularz z danymi wrażliwymi wysyła informacje do innej domeny.'
    })
  }

  const matchedBrand = trustedBrands.find((brand) => {
    if (
      brand.domain === candidate.registrableDomain ||
      brand.domain === candidate.asciiHostname ||
      isTrustedDomainMatchAllowed(candidate.asciiHostname, brand.domain)
    ) {
      return false
    }

    return containsBrand(searchable, brand)
  })

  const hasBrandImpersonationContext =
    Boolean(sensitiveForm) || BRAND_IMPERSONATION_CONTEXT_PATTERNS.some((pattern) => pattern.test(searchable))

  if (matchedBrand && hasBrandImpersonationContext) {
    findings.push({
      id: 'content-brand-impersonation',
      matched: true,
      code: `content-brand-impersonation:${matchedBrand.domain}`,
      message:
        'Treść strony nawiązuje do zaufanej marki, ale adres strony nie należy do tej marki.'
    })
  }

  if (URGENT_LANGUAGE_PATTERNS.some((pattern) => pattern.test(text))) {
    findings.push({
      id: 'content-urgent-language',
      matched: true,
      code: 'content-urgent-language',
      message:
        'Treść strony używa języka presji lub pilnej weryfikacji, co często występuje w phishingu.'
    })
  }

  const iframeMatches = Array.from(analysisHtml.matchAll(/<iframe\b[^>]*>/gi)).map((match) => match[0])
  const suspiciousIframe = iframeMatches.find((iframe) => {
    const srcHostname = getHostnameFromUrl(getHtmlAttribute(iframe, 'src') ?? '')
    const srcDomain = srcHostname ? getDomain(srcHostname) : null
    const hidden =
      /display\s*:\s*none/i.test(iframe) ||
      /visibility\s*:\s*hidden/i.test(iframe) ||
      /width\s*=\s*["']?0/i.test(iframe) ||
      /height\s*=\s*["']?0/i.test(iframe)

    if (isKnownTelemetryIframe(srcHostname)) {
      return false
    }

    if (hidden && !isKnownTelemetryIframe(srcHostname)) {
      return true
    }

    return srcHostname !== null && srcDomain !== candidate.registrableDomain
  })

  if (suspiciousIframe) {
    findings.push({
      id: 'content-suspicious-iframe',
      matched: true,
      code: 'content-suspicious-iframe',
      message: 'Strona używa ukrytej ramki lub ramki z innej domeny.'
    })
  }

  if (hasRiskyDownloadUrl(html)) {
    findings.push({
      id: 'content-download-risk',
      matched: true,
      code: 'content-download-risk',
      message: 'Strona zawiera link do potencjalnie ryzykownego pliku do pobrania.'
    })
  }

  if (hasThreatLinkCatalog(text, html)) {
    findings.push({
      id: 'content-threat-link-catalog',
      matched: true,
      code: 'content-threat-link-catalog',
      message:
        'Strona wygląda jak katalog linków do wielu typów zagrożeń, takich jak phishing, malware, fałszywe płatności lub ryzykowne pobrania.'
    })
  }

  return findings
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

export function normalizeCustomTrustedDomain(value: string): string | null {
  let hostnameValue = value.trim()

  if (/^https?:\/\//i.test(hostnameValue)) {
    try {
      hostnameValue = new URL(hostnameValue).hostname
    } catch {
      return null
    }
  }

  const normalizedHostname = normalizeHostname(hostnameValue)

  if (!normalizedHostname || isIP(normalizedHostname) !== 0) {
    return null
  }

  return normalizedHostname
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

export function isGovernmentDomainCandidate(
  candidate: Pick<NormalizedSiteCandidate, 'publicSuffix' | 'isIp'>
): boolean {
  if (candidate.isIp || !candidate.publicSuffix) {
    return false
  }

  return candidate.publicSuffix === 'gov' || candidate.publicSuffix.startsWith('gov.')
}

function isGovernmentPublicSuffix(value: string): boolean {
  const publicSuffix = getPublicSuffix(value)

  return publicSuffix === value && (value === 'gov' || value.startsWith('gov.'))
}

export function isTrustedDomainMatchAllowed(hostname: string, trustedDomain: string): boolean {
  const normalizedHostname = normalizeHostname(hostname)
  const normalizedTrustedDomain = normalizeHostname(trustedDomain)

  if (!normalizedHostname || !normalizedTrustedDomain) {
    return false
  }

  if (normalizedHostname === normalizedTrustedDomain) {
    return true
  }

  if (!normalizedHostname.endsWith(`.${normalizedTrustedDomain}`)) {
    return false
  }

  if (isGovernmentPublicSuffix(normalizedTrustedDomain)) {
    return true
  }

  const privateRegistrableDomain =
    getDomain(normalizedHostname, { allowPrivateDomains: true }) ?? normalizedHostname

  return privateRegistrableDomain === normalizedTrustedDomain
}

export function isTrustedDomainEntryMentionedInSubdomain(
  candidate: Pick<
    NormalizedSiteCandidate,
    'asciiHostname' | 'registrableDomain' | 'subdomain' | 'isIp'
  >,
  trustedDomain: string,
  trustedLabel?: string | null,
  isGenericTrustedLabel = false
): boolean {
  if (!candidate.registrableDomain || !candidate.subdomain || candidate.isIp) {
    return false
  }

  const normalizedTrustedDomain = normalizeHostname(trustedDomain)

  if (
    !normalizedTrustedDomain ||
    normalizedTrustedDomain === candidate.registrableDomain ||
    isTrustedDomainMatchAllowed(candidate.asciiHostname, normalizedTrustedDomain)
  ) {
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

  if (label.length < 5 || isGenericTrustedLabel) {
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
