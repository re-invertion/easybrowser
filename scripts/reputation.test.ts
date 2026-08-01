import assert from 'node:assert/strict'
import {
  getDomainLabelForLookalike,
  getLevenshteinDistance,
  getLookalikeSkeleton,
  getTrustedDomainLookalikeMetadata,
  isLookalikeDomain
} from '../src/main/lookalike'
import {
  analyzePageContent,
  extractDomainBlocklistHostnames,
  getHostnameFromUrl,
  hasNonLatinLetters,
  isGovernmentDomainCandidate,
  isHostnameBlocked,
  isTrustedDomainMatchAllowed,
  isTrustedDomainEntryMentionedInSubdomain,
  normalizeCustomTrustedDomain,
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
  urlRiskPatternScore?: number
  html?: string
  contentScores?: Partial<Record<string, number>>
}): { score: number; ruleIds: string[]; decision: 'allow' | 'warning' | 'blocked' } {
  const candidate = normalizeSiteCandidate(input.url)

  if (isGovernmentDomainCandidate(candidate)) {
    return {
      score: 0,
      ruleIds: [],
      decision: 'allow'
    }
  }

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

  const urlRiskPatternMatch = [
    /\bphishing\b/i,
    /\bmalware\b/i,
    /\bunwanted\b/i,
    /\bpua\b/i,
    /\bsuspicious\b/i,
    /\bbad[_-]login\b/i,
    /\blow[_-]rep[_-]login\b/i,
    /\btrick[_-]to[_-]bill\b/i,
    /\bcookie[_-]theft\b/i,
    /\bbadrep\b/i,
    /\bbad[_-]app\b/i,
    /\bforce[_-]csd\b/i,
    /\blocal[_-]trigger[_-]csd\b/i,
    /\brestricted[_-]content\b/i,
    /\.(?:exe|apk|msi|scr|bat|cmd|vbs|ps1|jar)(?:$|[?#])/i,
    /\.(?:zip|rar|7z)(?:$|[?#])/i
  ].some((pattern) => pattern.test(`${candidate.path}${candidate.query}`))

  if (urlRiskPatternMatch) {
    ruleIds.push('url-risk-pattern')
    score += input.urlRiskPatternScore ?? 70
  }

  if (input.html && score < 70) {
    const findings = analyzePageContent(
      input.html,
      candidate,
      trustedDomains.map((domain) => ({
        domain,
        label: getTrustedDomainLookalikeMetadata(domain).label
      }))
    )

    for (const finding of findings) {
      ruleIds.push(finding.id)
      score += input.contentScores?.[finding.id] ?? {
        'content-sensitive-form': 30,
        'content-cross-origin-form': 45,
        'content-brand-impersonation': 55,
        'content-urgent-language': 15,
        'content-suspicious-iframe': 25,
        'content-download-risk': 30,
        'content-threat-link-catalog': 70
      }[finding.id]
    }
  }

  const cappedScore = Math.min(100, score)

  return {
    score: cappedScore,
    ruleIds,
    decision: cappedScore >= 70 ? 'blocked' : cappedScore >= 50 ? 'warning' : 'allow'
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

test('normalizeCustomTrustedDomain preserves manually entered subdomains', () => {
  assert.equal(
    normalizeCustomTrustedDomain('testsafebrowsing.appspot.com'),
    'testsafebrowsing.appspot.com'
  )
  assert.equal(
    normalizeCustomTrustedDomain('https://TestsafeBrowsing.appspot.com/path?q=1'),
    'testsafebrowsing.appspot.com'
  )
})

test('normalizeCustomTrustedDomain rejects IP and unsafe manual entries', () => {
  assert.equal(normalizeCustomTrustedDomain('127.0.0.1'), null)
  assert.equal(normalizeCustomTrustedDomain('bad host.example'), null)
  assert.equal(normalizeCustomTrustedDomain('https://'), null)
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

test('government domain detection trusts public gov suffixes only', () => {
  assert.equal(isGovernmentDomainCandidate(normalizeSiteCandidate('https://agency.gov')), true)
  assert.equal(isGovernmentDomainCandidate(normalizeSiteCandidate('https://www.gov.pl')), true)
  assert.equal(
    isGovernmentDomainCandidate(
      normalizeSiteCandidate('https://login.gov.pl/login/SingleSignOnService')
    ),
    true
  )
  assert.equal(
    isGovernmentDomainCandidate(
      normalizeSiteCandidate('https://find-and-update.company-information.service.gov.uk')
    ),
    true
  )
  assert.equal(isGovernmentDomainCandidate(normalizeSiteCandidate('https://gov-example.com')), false)
  assert.equal(isGovernmentDomainCandidate(normalizeSiteCandidate('https://gov.pl.fake.xyz')), false)
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

test('trusted domain in subdomain ignores allowed trusted service subdomains', () => {
  const candidate = normalizeSiteCandidate(
    'https://find-and-update.company-information.service.gov.uk/company/11545706'
  )

  assert.equal(
    isTrustedDomainEntryMentionedInSubdomain(
      candidate,
      'company-information.service.gov.uk',
      'company-information'
    ),
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

test('trusted domain matching allows normal first-party subdomains', () => {
  assert.equal(isTrustedDomainMatchAllowed('www.google.com', 'google.com'), true)
  assert.equal(isTrustedDomainMatchAllowed('accounts.google.com', 'google.com'), true)
})

test('trusted domain matching does not trust private hosting tenant subdomains', () => {
  assert.equal(isTrustedDomainMatchAllowed('testsafebrowsing.appspot.com', 'appspot.com'), false)
  assert.equal(isTrustedDomainMatchAllowed('example.github.io', 'github.io'), false)
})

test('trusted domain matching allows government public suffix subdomains', () => {
  assert.equal(isTrustedDomainMatchAllowed('login.gov.pl', 'gov.pl'), true)
  assert.equal(isTrustedDomainMatchAllowed('find-and-update.company-information.service.gov.uk', 'gov.uk'), true)
})

test('trusted domain matching still allows exact private hosting domains', () => {
  assert.equal(isTrustedDomainMatchAllowed('appspot.com', 'appspot.com'), true)
  assert.equal(
    isTrustedDomainMatchAllowed('testsafebrowsing.appspot.com', 'testsafebrowsing.appspot.com'),
    true
  )
})

test('analyzePageContent detects sensitive login form', () => {
  const findings = analyzePageContent(
    '<html><form><input type="email"><input type="password"></form></html>',
    normalizeSiteCandidate('https://example.com/login'),
    []
  )

  assertSameMembers(findings.map((finding) => finding.id), ['content-sensitive-form'])
})

test('analyzePageContent detects cross-origin sensitive form', () => {
  const findings = analyzePageContent(
    '<form action="https://collector.example/submit"><input name="password"></form>',
    normalizeSiteCandidate('https://bank-login.example/login'),
    []
  )

  assertSameMembers(findings.map((finding) => finding.id), [
    'content-sensitive-form',
    'content-cross-origin-form'
  ])
})

test('analyzePageContent ignores non-sensitive cross-origin form', () => {
  const findings = analyzePageContent(
    '<form action="https://newsletter.example/submit"><input name="query"></form>',
    normalizeSiteCandidate('https://blog.example'),
    []
  )

  assert.deepEqual(findings.map((finding) => finding.id), [])
})

test('analyzePageContent ignores cookie consent forms with technical anti-forgery tokens', () => {
  const findings = analyzePageContent(
    `
      <form data-cookieman-form>
        <input type="checkbox" name="mandatory" checked>
        <input type="hidden" name="__RequestVerificationToken" value="abc">
        <button>Akceptuj wszystkie pliki cookie</button>
      </form>
    `,
    normalizeSiteCandidate('https://example.com'),
    []
  )

  assert.deepEqual(findings.map((finding) => finding.id), [])
})

test('analyzePageContent ignores newsletter email-only forms', () => {
  const findings = analyzePageContent(
    `
      <form>
        <label for="email">Twój adres email</label>
        <input type="email" id="email" name="email" placeholder="Twój adres email...">
        <input id="honeypot" type="text" class="hidden" name="honeypot">
        <button type="submit">Zapisz</button>
      </form>
    `,
    normalizeSiteCandidate('https://basketball.example'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-sensitive-form'))
})

test('analyzePageContent ignores news article brand mentions with newsletter forms', () => {
  const findings = analyzePageContent(
    `
      <article>
        <h1>Tunel na Hetmańskiej i wiadukt na Malowniczej. Podpisano porozumienia</h1>
        <p>Łódź i PLK wybudują tunel oraz wiadukt. Sprawdź harmonogram prac.</p>
      </article>
      <form class="space-y-3.5">
        <input type="email" required placeholder="twoj@email.pl" aria-label="Twój e-mail" value="">
        <button type="submit" disabled><span>Zapisz się</span></button>
      </form>
      <form class="space-y-3">
        <label for="footer-newsletter-email" class="sr-only">Twój e-mail</label>
        <input id="footer-newsletter-email" type="email" required placeholder="twoj@email.pl" value="">
        <button type="submit" disabled><span>Zapisz</span></button>
      </form>
    `,
    normalizeSiteCandidate('https://lodzplus.pl/artykul/tunel-na-hetmanskiej-i-wiadukt-na-malowniczej-lodz-plk'),
    [{ domain: 'plk.pl', label: 'plk' }]
  )

  assert.deepEqual(findings.map((finding) => finding.id), [])
})

test('analyzePageContent detects trusted brand mentioned on unofficial domain', () => {
  const findings = analyzePageContent(
    '<title>PayPal Login</title><main>Verify your PayPal account</main><form><input type="password"></form>',
    normalizeSiteCandidate('https://secure-login.example'),
    [{ domain: 'paypal.com', label: 'paypal' }]
  )

  assert(findings.some((finding) => finding.id === 'content-brand-impersonation'))
})

test('analyzePageContent ignores trusted brand on official domain', () => {
  const findings = analyzePageContent(
    '<title>PayPal Login</title><main>Verify your PayPal account</main><form><input type="password"></form>',
    normalizeSiteCandidate('https://paypal.com/signin'),
    [{ domain: 'paypal.com', label: 'paypal' }]
  )

  assert(!findings.some((finding) => finding.id === 'content-brand-impersonation'))
})

test('analyzePageContent ignores trusted service brand on allowed subdomain', () => {
  const findings = analyzePageContent(
    `
      <title>DSADSA LIMITED overview - Find and update company information - GOV.UK</title>
      <main>Free company information from Companies House.</main>
      <form id="search" action="/search" method="get" role="search">
        <label for="site-search-text">Search for a company or officer</label>
        <input type="search" id="site-search-text" name="q" autocomplete="off">
      </form>
    `,
    normalizeSiteCandidate('https://find-and-update.company-information.service.gov.uk/company/11545706'),
    [{ domain: 'company-information.service.gov.uk', label: 'company-information' }]
  )

  assert(!findings.some((finding) => finding.id === 'content-brand-impersonation'))
})

test('analyzePageContent ignores social trusted brand links without phishing context', () => {
  const findings = analyzePageContent(
    `
      <main>
        <a href="https://www.facebook.com/example">Facebook</a>
        <a href="https://www.linkedin.com/company/example">LinkedIn</a>
      </main>
      <form data-cookieman-form>
        <input type="hidden" name="__RequestVerificationToken" value="abc">
        <p>Token zabezpieczający przed fałszerstwem, który identyfikuje i weryfikuje informacje.</p>
      </form>
    `,
    normalizeSiteCandidate('https://public-institution.example'),
    [
      { domain: 'facebook.com', label: 'facebook' },
      { domain: 'linkedin.com', label: 'linkedin' }
    ]
  )

  assert(!findings.some((finding) => finding.id === 'content-brand-impersonation'))
})

test('analyzePageContent detects urgent phishing language', () => {
  const findings = analyzePageContent(
    '<main>Pilne: konto zablokowane. Potwierdź dane, aby przywrócić dostęp.</main>',
    normalizeSiteCandidate('https://example.com'),
    []
  )

  assert(findings.some((finding) => finding.id === 'content-urgent-language'))
})

test('analyzePageContent ignores generic security wording without pressure', () => {
  const findings = analyzePageContent(
    '<main>Bezpieczeństwa aplikacji, infrastruktura, dobre praktyki i audyty.</main>',
    normalizeSiteCandidate('https://portfolio.example'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-urgent-language'))
})

test('analyzePageContent detects hidden iframe and cross-domain iframe', () => {
  const hidden = analyzePageContent(
    '<iframe src="https://example.com/a" width="0" height="0"></iframe>',
    normalizeSiteCandidate('https://example.com'),
    []
  )
  const crossDomain = analyzePageContent(
    '<iframe src="https://other.example/a"></iframe>',
    normalizeSiteCandidate('https://example.com'),
    []
  )

  assert(hidden.some((finding) => finding.id === 'content-suspicious-iframe'))
  assert(crossDomain.some((finding) => finding.id === 'content-suspicious-iframe'))
})

test('analyzePageContent ignores visible iframes from the same registrable domain', () => {
  const findings = analyzePageContent(
    '<iframe src="https://widget.example.com/search" title="Wyszukiwarka"></iframe>',
    normalizeSiteCandidate('https://www.example.com'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-suspicious-iframe'))
})

test('analyzePageContent ignores hidden Google Tag Manager telemetry iframe', () => {
  const findings = analyzePageContent(
    '<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-123" height="0" width="0" style="display:none;visibility:hidden"></iframe>',
    normalizeSiteCandidate('https://basketball.example'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-suspicious-iframe'))
})

test('analyzePageContent detects risky download links', () => {
  const findings = analyzePageContent(
    '<a href="/download/security-update.exe">Pobierz aktualizację</a>',
    normalizeSiteCandidate('https://example.com'),
    []
  )

  assert(findings.some((finding) => finding.id === 'content-download-risk'))
})

test('analyzePageContent ignores normal application JavaScript bundles', () => {
  const findings = analyzePageContent(
    '<script src="/_next/static/chunks/app.js" async></script>',
    normalizeSiteCandidate('https://portfolio.example'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-download-risk'))
})

test('analyzePageContent ignores JavaScript command queue properties', () => {
  const findings = analyzePageContent(
    '<script>window.googletag = window.googletag || {}; window.googletag.cmd = window.googletag.cmd || []; window.Yieldbird.cmd = window.Yieldbird.cmd || [];</script>',
    normalizeSiteCandidate('https://tekstowo.example'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-download-risk'))
})

test('analyzePageContent ignores portfolio technology brand mentions without phishing context', () => {
  const findings = analyzePageContent(
    '<main>Pracuję z GitHub, React, Next, LinkedIn, TypeScript i Node. Bezpieczeństwa aplikacji.</main><script src="/_next/static/chunks/app.js"></script>',
    normalizeSiteCandidate('https://p4tkry.pl'),
    [
      { domain: 'github.com', label: 'github' },
      { domain: 'react.dev', label: 'react' },
      { domain: 'linkedin.com', label: 'linkedin' },
      { domain: 'typescriptlang.org', label: 'typescript' }
    ]
  )

  assert.deepEqual(findings.map((finding) => finding.id), [])
})

test('analyzePageContent detects generic threat link catalogs', () => {
  const findings = analyzePageContent(
    `
      <h1>Security Testing Links</h1>
      <p>Should show a phishing warning: <a href="/s/phishing.html">link</a></p>
      <p>Should show a malware warning: <a href="/s/malware.html">link</a></p>
      <p>Should show an unwanted software warning: <a href="/s/unwanted.html">link</a></p>
      <p>Should show a billing warning: <a href="/s/trick_to_bill.html">link</a></p>
      <p>Should show a cookie theft warning: <a href="/s/cookie_theft.exe">link</a></p>
    `,
    normalizeSiteCandidate('https://security-tests.example'),
    []
  )

  assert(findings.some((finding) => finding.id === 'content-threat-link-catalog'))
})

test('analyzePageContent ignores ordinary security articles mentioning phishing once', () => {
  const findings = analyzePageContent(
    `
      <article>
        <h1>Jak rozpoznać phishing</h1>
        <p>Ten poradnik opisuje dobre praktyki bezpieczeństwa i pokazuje,
        dlaczego warto sprawdzać adres strony przed logowaniem.</p>
        <a href="/blog/security">Czytaj dalej</a>
      </article>
    `,
    normalizeSiteCandidate('https://blog.example/security'),
    []
  )

  assert(!findings.some((finding) => finding.id === 'content-threat-link-catalog'))
})

test('analyzePageContent combines multiple phishing content signals', () => {
  const findings = analyzePageContent(
    `
      <title>PayPal security alert</title>
      <form action="https://collector.example/submit">
        <input name="email">
        <input type="password">
      </form>
      <iframe src="https://tracker.example" style="display:none"></iframe>
      <a href="/verify.zip">Download verification package</a>
    `,
    normalizeSiteCandidate('https://secure-paypal-login.example'),
    [{ domain: 'paypal.com', label: 'paypal' }]
  )

  assertSameMembers(findings.map((finding) => finding.id), [
    'content-sensitive-form',
    'content-cross-origin-form',
    'content-brand-impersonation',
    'content-urgent-language',
    'content-suspicious-iframe',
    'content-download-risk'
  ])
})

test('scenario scoring blocks generic threat link catalogs from content analysis', () => {
  const result = getRuleIdsForScenario({
    url: 'https://security-tests.example',
    html: `
      <p>Should show a phishing warning: <a href="/s/phishing.html">link</a></p>
      <p>Should show a malware warning: <a href="/s/malware.html">link</a></p>
      <p>Should show an unwanted software warning: <a href="/s/unwanted.html">link</a></p>
      <p>Should show a billing warning: <a href="/s/trick_to_bill.html">link</a></p>
    `
  })

  assert.equal(result.score, 70)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['content-threat-link-catalog'])
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

test('scenario scoring always allows public gov suffix domains', () => {
  const result = getRuleIdsForScenario({
    url: 'https://find-and-update.company-information.service.gov.uk/s/phishing.html',
    trustedDomains: ['company-information.service.gov.uk'],
    html: '<title>Security alert</title><form><input type="password"></form>'
  })

  assert.equal(result.score, 0)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, [])
})

test('scenario scoring allows login.gov.pl SSO under gov.pl', () => {
  const result = getRuleIdsForScenario({
    url: 'https://login.gov.pl/login/SingleSignOnService',
    trustedDomains: ['gov.pl'],
    html: '<title>Login.gov.pl</title><form><input type="password"></form>'
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

test('scenario scoring blocks generic phishing URL patterns', () => {
  const result = getRuleIdsForScenario({ url: 'https://example.test/s/phishing.html' })

  assert.equal(result.score, 70)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['url-risk-pattern'])
})

test('scenario scoring blocks generic malware and unwanted URL patterns', () => {
  const malware = getRuleIdsForScenario({ url: 'https://cdn.example/files/malware.html' })
  const unwanted = getRuleIdsForScenario({ url: 'https://cdn.example/files/unwanted.html' })

  assert.equal(malware.score, 70)
  assert.equal(malware.decision, 'blocked')
  assert.deepEqual(malware.ruleIds, ['url-risk-pattern'])
  assert.equal(unwanted.score, 70)
  assert.equal(unwanted.decision, 'blocked')
  assert.deepEqual(unwanted.ruleIds, ['url-risk-pattern'])
})

test('scenario scoring blocks generic login and billing trap URL patterns', () => {
  const badLogin = getRuleIdsForScenario({ url: 'https://example.test/s/bad_login.html' })
  const billingTrap = getRuleIdsForScenario({ url: 'https://example.test/s/trick_to_bill.html' })

  assert.equal(badLogin.score, 70)
  assert.equal(badLogin.decision, 'blocked')
  assert.deepEqual(badLogin.ruleIds, ['url-risk-pattern'])
  assert.equal(billingTrap.score, 70)
  assert.equal(billingTrap.decision, 'blocked')
  assert.deepEqual(billingTrap.ruleIds, ['url-risk-pattern'])
})

test('scenario scoring blocks generic dangerous download URL patterns', () => {
  const result = getRuleIdsForScenario({ url: 'https://downloads.example/security-update.exe' })

  assert.equal(result.score, 70)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, ['url-risk-pattern'])
})

test('scenario scoring does not hardcode a Safe Browsing test host', () => {
  const result = getRuleIdsForScenario({ url: 'https://testsafebrowsing.appspot.com/' })

  assert.equal(result.score, 0)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, [])
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

  assert.equal(result.score, 100)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, [
    'insecure-http',
    'domain-blocklist',
    'trusted-domain-in-subdomain'
  ])
})

test('scenario scoring caps reputation score at 100', () => {
  const result = getRuleIdsForScenario({
    url: 'http://secure-paypal-login.fake.xyz/s/phishing.exe',
    trustedDomains: ['paypal.com'],
    blocklistedDomains: ['fake.xyz']
  })

  assert.equal(result.score, 100)
  assert.equal(result.decision, 'blocked')
  assert(result.ruleIds.length > 2)
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

  assert.equal(result.score, 100)
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

test('scenario scoring analyzes content even when there is no earlier risk signal', () => {
  const result = getRuleIdsForScenario({
    url: 'https://example.com/login',
    html: '<form><input type="password"></form>'
  })

  assert.equal(result.score, 30)
  assert.equal(result.decision, 'allow')
  assert.deepEqual(result.ruleIds, ['content-sensitive-form'])
})

test('scenario scoring blocks strong content phishing combination', () => {
  const result = getRuleIdsForScenario({
    url: 'https://secure-paypal-login.fake.xyz',
    trustedDomains: ['paypal.com'],
    html: `
      <title>PayPal security alert</title>
      <form action="https://collector.example/submit">
        <input name="email">
        <input type="password">
      </form>
    `
  })

  assert.equal(result.score, 100)
  assert.equal(result.decision, 'blocked')
  assert.deepEqual(result.ruleIds, [
    'trusted-domain-in-subdomain',
    'content-sensitive-form',
    'content-cross-origin-form',
    'content-brand-impersonation',
    'content-urgent-language'
  ])
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
