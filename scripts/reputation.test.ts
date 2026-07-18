import assert from 'node:assert/strict'
import {
  getDomainLabelForLookalike,
  getLevenshteinDistance,
  getLookalikeSkeleton,
  getTrustedDomainLookalikeMetadata,
  isLookalikeDomain
} from '../src/main/lookalike'
import {
  extractDomainBlocklistHostnames,
  getHostnameFromUrl,
  hasNonLatinLetters,
  isHostnameBlocked,
  isTrustedDomainEntryMentionedInSubdomain,
  normalizeHostname,
  normalizeSiteCandidate
} from '../src/main/reputationCore'

type TestCase = {
  name: string
  run: () => void | Promise<void>
}

const tests: TestCase[] = []

function test(name: string, run: TestCase['run']): void {
  tests.push({ name, run })
}

function assertSameMembers<T>(actual: Iterable<T>, expected: Iterable<T>): void {
  assert.deepEqual(Array.from(actual).sort(), Array.from(expected).sort())
}

function getRuleIdsForScenario(input: {
  url: string
  trustedDomains?: string[]
  blocklistedDomains?: string[]
  httpScore?: number
  nonLatinScore?: number
  ipScore?: number
  lookalikeScore?: number
  trustedDomainInSubdomainScore?: number
}): { score: number; ruleIds: string[]; decision: 'allow' | 'warning' | 'blocked' } {
  const candidate = normalizeSiteCandidate(input.url)
  const trustedDomains = input.trustedDomains ?? []
  const blocklistedDomains = new Set(input.blocklistedDomains ?? [])
  const ruleIds: string[] = []
  let score = 0

  if (candidate.protocol === 'http:') {
    ruleIds.push('insecure-http')
    score += input.httpScore ?? 50
  }

  if (isHostnameBlocked(candidate.asciiHostname, blocklistedDomains)) {
    ruleIds.push('domain-blocklist')
    score += 100
  }

  if (hasNonLatinLetters(candidate.unicodeHostname)) {
    ruleIds.push('non-latin-script')
    score += input.nonLatinScore ?? 25
  }

  if (
    candidate.registrableDomain &&
    !candidate.isIp &&
    trustedDomains.some((domain) => isLookalikeDomain(candidate.registrableDomain!, domain))
  ) {
    ruleIds.push('lookalike-trusted-domain')
    score += input.lookalikeScore ?? 60
  }

  if (
    trustedDomains.some((domain) =>
      isTrustedDomainEntryMentionedInSubdomain(
        candidate,
        domain,
        getTrustedDomainLookalikeMetadata(domain).label
      )
    )
  ) {
    ruleIds.push('trusted-domain-in-subdomain')
    score += input.trustedDomainInSubdomainScore ?? 50
  }

  if (candidate.isIp) {
    ruleIds.push('is-ip')
    score += input.ipScore ?? 40
  }

  return {
    score,
    ruleIds,
    decision: score >= 70 ? 'blocked' : score >= 50 ? 'warning' : 'allow'
  }
}

test('normalizeHostname trims, lowercases and removes wildcard/dot wrappers', () => {
  assert.equal(normalizeHostname('  *.Example.COM.  '), 'example.com')
  assert.equal(normalizeHostname('.Sub.Example.COM..'), 'sub.example.com')
})

test('normalizeHostname accepts IPv4-like hostnames and rejects empty/unsafe hostnames', () => {
  assert.equal(normalizeHostname('192.168.0.1'), '192.168.0.1')
  assert.equal(normalizeHostname(''), null)
  assert.equal(normalizeHostname('evil_domain.com'), null)
  assert.equal(normalizeHostname('evil domain.com'), null)
  assert.equal(normalizeHostname('żółć.example'), null)
})

test('getHostnameFromUrl extracts and normalizes hostnames from URLs', () => {
  assert.equal(getHostnameFromUrl('https://Sub.Example.com/path?q=1'), 'sub.example.com')
  assert.equal(getHostnameFromUrl('not a url'), null)
})

test('normalizeSiteCandidate exposes URL, host, registrable domain and subdomain parts', () => {
  const candidate = normalizeSiteCandidate('https://login.paypal.fake.xyz:8443/a?b=1')

  assert.equal(candidate.normalizedUrl, 'https://login.paypal.fake.xyz:8443/a?b=1')
  assert.equal(candidate.protocol, 'https:')
  assert.equal(candidate.hostname, 'login.paypal.fake.xyz')
  assert.equal(candidate.registrableDomain, 'fake.xyz')
  assert.equal(candidate.publicSuffix, 'xyz')
  assert.equal(candidate.subdomain, 'login.paypal')
  assert.equal(candidate.port, '8443')
  assert.equal(candidate.path, '/a')
  assert.equal(candidate.query, '?b=1')
  assert.equal(candidate.isIp, false)
})

test('normalizeSiteCandidate marks IP navigations', () => {
  const candidate = normalizeSiteCandidate('http://127.0.0.1/login')

  assert.equal(candidate.hostname, '127.0.0.1')
  assert.equal(candidate.registrableDomain, null)
  assert.equal(candidate.isIp, true)
})

test('normalizeSiteCandidate converts Unicode hostnames to ASCII hostname and Unicode mirror', () => {
  const candidate = normalizeSiteCandidate('https://раураl.com/login')

  assert.equal(candidate.hostname, 'xn--l-7sba6dbr.com')
  assert.equal(candidate.unicodeHostname, 'раураl.com')
  assert.equal(candidate.registrableDomain, 'xn--l-7sba6dbr.com')
  assert.equal(candidate.isIp, false)
})

test('normalizeSiteCandidate keeps percent-safe normalized URL shape', () => {
  const candidate = normalizeSiteCandidate('https://Example.com/a b?q=hello world')

  assert.equal(candidate.normalizedUrl, 'https://example.com/a%20b?q=hello%20world')
  assert.equal(candidate.path, '/a%20b')
  assert.equal(candidate.query, '?q=hello%20world')
})

test('extractDomainBlocklistHostnames reads domains, URLs, comments and hosts-like rows', () => {
  const entries = extractDomainBlocklistHostnames(`
    # comment
    example.com
    https://Bad.Example.net/path?q=1 # inline comment
    0.0.0.0 phishing.test
    invalid_domain.test
  `)

  assertSameMembers(entries, ['example.com', 'bad.example.net', '0.0.0.0', 'phishing.test'])
})

test('extractDomainBlocklistHostnames deduplicates repeated domains and lowercases URLs', () => {
  const entries = extractDomainBlocklistHostnames(`
    EXAMPLE.com
    https://example.com/login
    sub.Example.com
    https://Sub.Example.com/other
  `)

  assertSameMembers(entries, ['example.com', 'sub.example.com'])
})

test('extractDomainBlocklistHostnames ignores empty lines and unsafe tokens', () => {
  const entries = extractDomainBlocklistHostnames(`

    invalid_domain.test
    https://bad_host.test
    also_bad.test_
    good.test
  `)

  assertSameMembers(entries, ['good.test'])
})

test('isHostnameBlocked blocks exact hostnames and their subdomains only', () => {
  const blocked = new Set(['evil.example', 'login.bank.test'])

  assert.equal(isHostnameBlocked('evil.example', blocked), 'evil.example')
  assert.equal(isHostnameBlocked('a.b.evil.example', blocked), 'evil.example')
  assert.equal(isHostnameBlocked('login.bank.test', blocked), 'login.bank.test')
  assert.equal(isHostnameBlocked('bank.test', blocked), null)
  assert.equal(isHostnameBlocked('notevil.example', blocked), null)
})

test('hasNonLatinLetters detects Cyrillic/Greek letters but ignores digits and punctuation', () => {
  assert.equal(hasNonLatinLetters('paypal.com'), false)
  assert.equal(hasNonLatinLetters('pay-pal-123.com'), false)
  assert.equal(hasNonLatinLetters('раураl.com'), true)
  assert.equal(hasNonLatinLetters('παypal.com'), true)
})

test('hasNonLatinLetters detects Unicode hostnames after candidate normalization', () => {
  const candidate = normalizeSiteCandidate('https://раураl.com')

  assert.equal(hasNonLatinLetters(candidate.unicodeHostname), true)
})

test('hasNonLatinLetters does not treat accented Latin letters as non-latin script', () => {
  assert.equal(hasNonLatinLetters('zażółć.pl'), false)
  assert.equal(hasNonLatinLetters('mañana.example'), false)
})

test('lookalike label extraction uses the first domain label', () => {
  assert.equal(getDomainLabelForLookalike('paypal.com'), 'paypal')
  assert.equal(getDomainLabelForLookalike('sub.paypal.com'), 'sub')
})

test('lookalike skeleton normalizes common ASCII substitutions', () => {
  assert.equal(getLookalikeSkeleton('paypa1'), 'paypal')
  assert.equal(getLookalikeSkeleton('g00gle'), 'google')
  assert.equal(getLookalikeSkeleton('micr0s0ft'), 'microsoft')
})

test('lookalike skeleton normalizes common Cyrillic confusables', () => {
  assert.equal(getLookalikeSkeleton('раураl'), 'paypal')
  assert.equal(getLookalikeSkeleton('сосa'), 'coca')
})

test('lookalike skeleton normalizes Greek confusables', () => {
  assert.equal(getLookalikeSkeleton('ΡΑΥΡΑL'), 'paypal')
  assert.equal(getLookalikeSkeleton('βank'), 'bank')
})

test('lookalike skeleton removes punctuation and marks after normalization', () => {
  assert.equal(getLookalikeSkeleton('páy-pal'), 'paypal')
  assert.equal(getLookalikeSkeleton('g.o-o_gle'), 'google')
})

test('getTrustedDomainLookalikeMetadata returns label, skeleton and length', () => {
  assert.deepEqual(getTrustedDomainLookalikeMetadata('paypa1.example'), {
    label: 'paypa1',
    skeleton: 'paypal',
    labelLength: 6
  })
})

test('getLevenshteinDistance handles exact, insertion, replacement and empty strings', () => {
  assert.equal(getLevenshteinDistance('paypal', 'paypal'), 0)
  assert.equal(getLevenshteinDistance('paypal', 'paypa1'), 1)
  assert.equal(getLevenshteinDistance('google', 'gogle'), 1)
  assert.equal(getLevenshteinDistance('', 'bank'), 4)
})

test('isLookalikeDomain rejects exact trusted domains', () => {
  assert.equal(isLookalikeDomain('paypal.com', 'paypal.com'), false)
})

test('isLookalikeDomain rejects very short labels to limit false positives', () => {
  assert.equal(isLookalikeDomain('ab.com', 'ac.com'), false)
})

test('isLookalikeDomain catches one-character substitutions', () => {
  assert.equal(isLookalikeDomain('paypa1.com', 'paypal.com'), true)
  assert.equal(isLookalikeDomain('gooogle.com', 'google.com'), true)
})

test('isLookalikeDomain catches two-character distance for longer trusted brands', () => {
  assert.equal(isLookalikeDomain('micros0fft.com', 'microsoft.com'), true)
})

test('isLookalikeDomain catches Unicode confusable domains', () => {
  assert.equal(isLookalikeDomain('xn--l-7sba6dbr.com', 'paypal.com'), true)
})

test('isLookalikeDomain catches Unicode input directly, not only punycode', () => {
  assert.equal(isLookalikeDomain('раураl.com', 'paypal.com'), true)
})

test('isLookalikeDomain rejects unrelated domains with different labels', () => {
  assert.equal(isLookalikeDomain('weather.com', 'paypal.com'), false)
  assert.equal(isLookalikeDomain('tiny.example', 'microsoft.com'), false)
})

test('isLookalikeDomain rejects labels with too-large length delta', () => {
  assert.equal(isLookalikeDomain('paypal-secure-login.com', 'paypal.com'), false)
})

test('trusted domain in subdomain catches full domain prefix', () => {
  const candidate = normalizeSiteCandidate('https://paypal.com.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), true)
})

test('trusted domain in subdomain catches full domain in deeper subdomain', () => {
  const candidate = normalizeSiteCandidate('https://login.paypal.com.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), true)
})

test('trusted domain in subdomain catches brand label as standalone subdomain', () => {
  const candidate = normalizeSiteCandidate('https://paypal.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), true)
})

test('trusted domain in subdomain catches brand label joined with hyphens', () => {
  const left = normalizeSiteCandidate('https://login-paypal.fake.xyz')
  const middle = normalizeSiteCandidate('https://secure-paypal-login.fake.xyz')
  const right = normalizeSiteCandidate('https://paypal-login.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(left, 'paypal.com', 'paypal'), true)
  assert.equal(isTrustedDomainEntryMentionedInSubdomain(middle, 'paypal.com', 'paypal'), true)
  assert.equal(isTrustedDomainEntryMentionedInSubdomain(right, 'paypal.com', 'paypal'), true)
})

test('trusted domain in subdomain catches brand label surrounded by dot labels', () => {
  const candidate = normalizeSiteCandidate('https://secure.paypal.login.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), true)
})

test('trusted domain in subdomain ignores official domain and direct subdomains', () => {
  const direct = normalizeSiteCandidate('https://paypal.com')
  const officialSubdomain = normalizeSiteCandidate('https://login.paypal.com')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(direct, 'paypal.com', 'paypal'), false)
  assert.equal(
    isTrustedDomainEntryMentionedInSubdomain(officialSubdomain, 'paypal.com', 'paypal'),
    false
  )
})

test('trusted domain in subdomain ignores short labels to reduce noisy matches', () => {
  const candidate = normalizeSiteCandidate('https://app.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'app.com', 'app'), false)
})

test('trusted domain in subdomain avoids substring-only matches without separators', () => {
  const candidate = normalizeSiteCandidate('https://notpaypal.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), false)
})

test('trusted domain in subdomain avoids matching the same registrable domain even with label', () => {
  const candidate = normalizeSiteCandidate('https://secure.paypal.com')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'paypal.com', 'paypal'), false)
})

test('trusted domain in subdomain works when label is derived from trusted domain', () => {
  const candidate = normalizeSiteCandidate('https://secure-microsoft-login.fake.xyz')

  assert.equal(isTrustedDomainEntryMentionedInSubdomain(candidate, 'microsoft.com'), true)
})

test('scenario scoring returns allow for normal HTTPS domain', () => {
  const result = getRuleIdsForScenario({
    url: 'https://example.com',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 0)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, [])
})

test('scenario scoring returns warning for HTTP only', () => {
  const result = getRuleIdsForScenario({ url: 'http://example.com' })

  assert.equal(result.score, 50)
  assert.equal(result.decision, 'warning')
  assert.deepEqual(result.ruleIds, ['insecure-http'])
})

test('scenario scoring returns blocked for blocklisted domain', () => {
  const result = getRuleIdsForScenario({
    url: 'https://a.evil.example',
    blocklistedDomains: ['evil.example']
  })

  assert.equal(result.score, 100)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['domain-blocklist'])
})

test('scenario scoring combines HTTP and IP into blocked score', () => {
  const result = getRuleIdsForScenario({ url: 'http://10.0.0.5/login' })

  assert.equal(result.score, 90)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['insecure-http', 'is-ip'])
})

test('scenario scoring catches lookalike trusted domain as warning', () => {
  const result = getRuleIdsForScenario({
    url: 'https://paypa1.com',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 60)
  assert.equal(result.decision, 'warning')
  assert.deepEqual(result.ruleIds, ['lookalike-trusted-domain'])
})

test('scenario scoring catches Unicode lookalike trusted domain as warning', () => {
  const result = getRuleIdsForScenario({
    url: 'https://раураl.com',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 85)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['non-latin-script', 'lookalike-trusted-domain'])
})

test('scenario scoring catches trusted brand in unofficial subdomain as warning', () => {
  const result = getRuleIdsForScenario({
    url: 'https://secure-paypal-login.fake.xyz',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 50)
  assert.equal(result.decision, 'warning')
  assert.deepEqual(result.ruleIds, ['trusted-domain-in-subdomain'])
})

test('scenario scoring does not flag official trusted subdomain as brand-in-subdomain', () => {
  const result = getRuleIdsForScenario({
    url: 'https://secure.paypal.com',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 0)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, [])
})

test('scenario scoring combines multiple heuristics into blocked decision', () => {
  const result = getRuleIdsForScenario({
    url: 'http://secure-paypal-login.fake.xyz',
    trustedDomains: ['paypal.com'],
    blocklistedDomains: ['fake.xyz']
  })

  assert.equal(result.score, 200)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, [
    'insecure-http',
    'domain-blocklist',
    'trusted-domain-in-subdomain'
  ])
})

test('scenario scoring can use custom rule weights', () => {
  const result = getRuleIdsForScenario({
    url: 'http://paypa1.com',
    trustedDomains: ['paypal.com'],
    httpScore: 20,
    lookalikeScore: 40
  })

  assert.equal(result.score, 60)
  assert.equal(result.decision, 'warning')
  assert.deepEqual(result.ruleIds, ['insecure-http', 'lookalike-trusted-domain'])
})

test('scenario scoring combines non-latin, HTTP and lookalike into blocked decision', () => {
  const result = getRuleIdsForScenario({
    url: 'http://раураl.com',
    trustedDomains: ['paypal.com']
  })

  assert.equal(result.score, 135)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, [
    'insecure-http',
    'non-latin-script',
    'lookalike-trusted-domain'
  ])
})

test('scenario scoring keeps non-latin alone below warning threshold by default', () => {
  const result = getRuleIdsForScenario({ url: 'https://пример.test' })

  assert.equal(result.score, 25)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, ['non-latin-script'])
})

test('scenario scoring can raise non-latin to warning with custom score', () => {
  const result = getRuleIdsForScenario({
    url: 'https://пример.test',
    nonLatinScore: 50
  })

  assert.equal(result.score, 50)
  assert.equal(result.decision, 'warning')
  assert.deepEqual(result.ruleIds, ['non-latin-script'])
})

async function run(): Promise<void> {
  const startedAt = Date.now()

  for (const [index, entry] of tests.entries()) {
    await entry.run()
    console.log(`ok ${index + 1} - ${entry.name}`)
  }

  console.log(`\n${tests.length} reputation tests passed in ${Date.now() - startedAt}ms`)
}

void run().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
