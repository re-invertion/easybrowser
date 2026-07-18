import { domainToUnicode } from 'node:url'

const CONFUSABLE_CHARACTERS: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  '!': 'l',
  '|': 'l',
  '3': 'e',
  '4': 'a',
  '@': 'a',
  '5': 's',
  '$': 's',
  '7': 't',
  '8': 'b',
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ї: 'i',
  ј: 'j',
  ѕ: 's',
  ӏ: 'l',
  Α: 'a',
  α: 'a',
  Β: 'b',
  β: 'b',
  Ε: 'e',
  ε: 'e',
  Ζ: 'z',
  Η: 'h',
  Ι: 'i',
  ι: 'i',
  Κ: 'k',
  κ: 'k',
  Μ: 'm',
  μ: 'm',
  Ν: 'n',
  Ο: 'o',
  ο: 'o',
  Ρ: 'p',
  ρ: 'p',
  Τ: 't',
  τ: 't',
  Χ: 'x',
  χ: 'x',
  Υ: 'y',
  υ: 'y'
}

export type LookalikeDomainMetadata = {
  label: string
  skeleton: string
  labelLength: number
}

export function getDomainLabelForLookalike(domain: string): string {
  const unicodeDomain = domainToUnicode(domain).toLowerCase() || domain.toLowerCase()
  return unicodeDomain.split('.')[0] ?? unicodeDomain
}

export function getLookalikeSkeleton(value: string): string {
  const normalizedValue = domainToUnicode(value)
    .normalize('NFKD')
    .replace(/\p{Mark}/gu, '')
    .toLowerCase()
  let skeleton = ''

  for (const char of normalizedValue) {
    skeleton += CONFUSABLE_CHARACTERS[char] ?? char
  }

  return skeleton.replace(/[^a-z0-9]/g, '')
}

export function getTrustedDomainLookalikeMetadata(domain: string): LookalikeDomainMetadata {
  const label = getDomainLabelForLookalike(domain)
  const skeleton = getLookalikeSkeleton(label)

  return {
    label,
    skeleton,
    labelLength: label.length
  }
}

export function getLevenshteinDistance(left: string, right: string): number {
  if (left === right) {
    return 0
  }

  if (left.length === 0) {
    return right.length
  }

  if (right.length === 0) {
    return left.length
  }

  const previous = Array.from({ length: right.length + 1 }, (_value, index) => index)
  const current = Array.from({ length: right.length + 1 }, () => 0)

  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    current[0] = leftIndex

    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const substitutionCost = left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1
      current[rightIndex] = Math.min(
        current[rightIndex - 1] + 1,
        previous[rightIndex] + 1,
        previous[rightIndex - 1] + substitutionCost
      )
    }

    for (let index = 0; index < previous.length; index += 1) {
      previous[index] = current[index]
    }
  }

  return previous[right.length] ?? Number.MAX_SAFE_INTEGER
}

export function isLookalikeDomain(candidateDomain: string, trustedDomain: string): boolean {
  if (candidateDomain === trustedDomain) {
    return false
  }

  const candidateMetadata = getTrustedDomainLookalikeMetadata(candidateDomain)
  const trustedMetadata = getTrustedDomainLookalikeMetadata(trustedDomain)

  if (candidateMetadata.labelLength < 4 || trustedMetadata.labelLength < 4) {
    return false
  }

  if (Math.abs(candidateMetadata.labelLength - trustedMetadata.labelLength) > 2) {
    return false
  }

  if (candidateMetadata.skeleton === trustedMetadata.skeleton) {
    return true
  }

  const maxDistance =
    Math.max(candidateMetadata.skeleton.length, trustedMetadata.skeleton.length) <= 6 ? 1 : 2
  return getLevenshteinDistance(candidateMetadata.skeleton, trustedMetadata.skeleton) <= maxDistance
}
