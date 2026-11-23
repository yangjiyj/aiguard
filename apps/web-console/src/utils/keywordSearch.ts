export function minimumKeywordLength(value: string): 2 | 3 {
  if (!value) return 2

  for (const character of value) {
    if ((character.codePointAt(0) ?? 0) > 0x7f) return 2
  }

  return 3
}
