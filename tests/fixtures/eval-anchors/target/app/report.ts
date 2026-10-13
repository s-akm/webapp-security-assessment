export function report(q: string) {
  // VULN: the report title is not escaped
  // the next line renders it as HTML
  return `<h1>${q}</h1>`
}
