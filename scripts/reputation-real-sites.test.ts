import assert from 'node:assert/strict'
import {
  analyzePageContent,
  type ContentAnalysisFindingId,
  type ContentTrustedBrand,
  normalizeSiteCandidate
} from '../src/main/reputationCore'

type RealSiteCase = {
  name: string
  url: string
  trustedBrands: ContentTrustedBrand[]
  forbiddenFindings: ContentAnalysisFindingId[]
  requiredText?: RegExp
}

type TestResult = {
  caseName: string
  status: 'ok' | 'skip'
  reason?: string
}

const REQUEST_TIMEOUT_MS = 12_000
const MAX_HTML_CHARS = 1_000_000
const STRICT_NETWORK = process.env.REAL_SITE_STRICT === '1'

const trustedBrands: ContentTrustedBrand[] = [
  { domain: 'p4tkry.pl', label: 'p4tkry' },
  { domain: 'tekstowo.pl', label: 'tekstowo' },
  { domain: 'plk.pl', label: 'plk' },
  { domain: 'plk-sa.pl', label: 'plk-sa' },
  { domain: 'gov.pl', label: 'gov', isGenericLabel: true },
  { domain: 'login.gov.pl', label: 'login', isGenericLabel: true },
  { domain: 'company-information.service.gov.uk', label: 'company-information' },
  { domain: 'gov.uk', label: 'gov', isGenericLabel: true },
  { domain: 'luxmed.pl', label: 'luxmed' },
  { domain: 'cmp.med.pl', label: 'cmp' },
  { domain: 'portalpacjenta.gov.pl', label: 'portalpacjenta', isGenericLabel: true },
  { domain: 'paypal.com', label: 'paypal' },
  { domain: 'google.com', label: 'google' },
  { domain: 'facebook.com', label: 'facebook' },
  { domain: 'linkedin.com', label: 'linkedin' },
  { domain: 'youtube.com', label: 'youtube' },
  { domain: 'doubleclick.net', label: 'doubleclick' },
  { domain: 'gstatic.com', label: 'gstatic' }
]

const safeSiteCases: RealSiteCase[] = [
  {
    name: 'p4tkry.pl',
    url: 'https://p4tkry.pl/',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'tekstowo.pl',
    url: 'https://www.tekstowo.pl/',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'plk.pl',
    url: 'https://plk.pl/',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'lodzplus.pl PLK article',
    url: 'https://lodzplus.pl/artykul/tunel-na-hetmanskiej-i-wiadukt-na-malowniczej-lodz-plk',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'UK Companies House company page',
    url: 'https://find-and-update.company-information.service.gov.uk/company/11545706',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'luxmed.pl',
    url: 'https://www.luxmed.pl/',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  },
  {
    name: 'cmp.med.pl portal pacjenta',
    url: 'https://cmp.med.pl/portal-pacjenta/',
    trustedBrands,
    forbiddenFindings: ['content-brand-impersonation', 'content-threat-link-catalog']
  }
]

async function fetchHtml(url: string): Promise<string> {
  const response = await fetch(url, {
    headers: {
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'accept-language': 'pl,en-US;q=0.8,en;q=0.7',
      'user-agent':
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) EasyBrowserRealSiteTest/1.0'
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  })

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }

  const contentType = response.headers.get('content-type') ?? ''

  if (!contentType.toLowerCase().includes('text/html')) {
    throw new Error(`unexpected content-type: ${contentType || 'unknown'}`)
  }

  return (await response.text()).slice(0, MAX_HTML_CHARS)
}

async function runCase(testCase: RealSiteCase): Promise<TestResult> {
  let html: string

  try {
    html = await fetchHtml(testCase.url)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)

    if (STRICT_NETWORK) {
      throw new Error(`${testCase.name}: could not fetch ${testCase.url}: ${reason}`)
    }

    return {
      caseName: testCase.name,
      status: 'skip',
      reason
    }
  }

  if (testCase.requiredText) {
    assert.match(html, testCase.requiredText, `${testCase.name}: expected real page marker was not found`)
  }

  const findings = analyzePageContent(html, normalizeSiteCandidate(testCase.url), testCase.trustedBrands)
  const findingIds = findings.map((finding) => finding.id)

  for (const forbiddenFinding of testCase.forbiddenFindings) {
    assert(
      !findingIds.includes(forbiddenFinding),
      `${testCase.name}: unexpected ${forbiddenFinding}; findings: ${JSON.stringify(findings)}`
    )
  }

  console.log(`ok - ${testCase.name}: ${findingIds.length ? findingIds.join(', ') : 'no content findings'}`)

  return {
    caseName: testCase.name,
    status: 'ok'
  }
}

async function run(): Promise<void> {
  const startedAt = Date.now()
  const results: TestResult[] = []

  for (const testCase of safeSiteCases) {
    results.push(await runCase(testCase))
  }

  const skippedResults = results.filter((result) => result.status === 'skip')

  for (const result of skippedResults) {
    console.warn(`skip - ${result.caseName}: ${result.reason}`)
  }

  console.log(
    `\n${results.length - skippedResults.length} real-site reputation tests passed, ${
      skippedResults.length
    } skipped in ${Date.now() - startedAt}ms`
  )
}

run().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
