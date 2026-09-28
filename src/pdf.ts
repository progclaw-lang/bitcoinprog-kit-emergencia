// Leer el respaldo que el usuario sube al kit — SIN internet, en su navegador.
//
//   · El PDF de BitcoinProg lleva ADJUNTOS (EmbeddedFiles) por multifirma:
//     descriptor.txt, coldcard.txt, specter.json, bsms.bsms, LEEME.txt; con
//     varias multifirmas van con prefijo «1-Nombre-…», «2-Otra-…».
//   · Si alguien volvió a guardar el PDF con otra app, los adjuntos pueden
//     venir comprimidos (FlateDecode): se inflan con DecompressionStream.
//   · También acepta sueltos: descriptor.txt, coldcard.txt, specter.json,
//     .bsms, o cualquier texto que traiga «wsh(sortedmulti(…».
// Lógica pura: se prueba aparte (sin DOM).

export interface LlaveLeida { etiqueta: string; fingerprint: string; ruta: string; xpub: string; boveda?: boolean }
export interface CarteraLeida { nombre: string; umbral: number; externo: string; interno: string; primera?: string; llaves: LlaveLeida[] }

const latin1 = (b: Uint8Array) => { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return s }
const texto = (b: Uint8Array) => new TextDecoder().decode(b)

async function inflar(b: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate')
  const r = new Response(new Blob([b as BlobPart]).stream().pipeThrough(ds))
  return new Uint8Array(await r.arrayBuffer())
}

/** Cadena literal PDF «(…)» → texto (con los escapes \\ \( \) \nnn). */
function literalPdf(s: string): string {
  return s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, (_, c: string) =>
    /^[0-7]+$/.test(c) ? String.fromCharCode(parseInt(c, 8)) : ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' } as Record<string, string>)[c] ?? c)
}

/** Los ficheros adjuntos de un PDF: nombre → bytes. */
export async function adjuntosDePdf(bytes: Uint8Array): Promise<Map<string, Uint8Array>> {
  const s = latin1(bytes)
  const inicio = new Map<number, number>()
  const reObj = /(\d+)\s+0\s+obj\b/g
  let m: RegExpExecArray | null
  while ((m = reObj.exec(s)) !== null) inicio.set(Number(m[1]), m.index + m[0].length)

  const cuerpo = (num: number) => {
    const i = inicio.get(num)
    if (i === undefined) return null
    const fin = s.indexOf('endobj', i)
    return fin < 0 ? null : { i, fin }
  }
  const stream = async (num: number): Promise<Uint8Array | null> => {
    const c = cuerpo(num)
    if (!c) return null
    const k = s.indexOf('stream', c.i)
    if (k < 0 || k > c.fin) return null
    const dict = s.slice(c.i, k)
    let a = k + 6
    if (s[a] === '\r') a++
    if (s[a] === '\n') a++
    let z = s.indexOf('endstream', a)
    if (z < 0) return null
    const largo = dict.match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/)
    if (largo && a + Number(largo[1]) <= z) z = a + Number(largo[1])
    else { while (z > a && (s[z - 1] === '\n' || s[z - 1] === '\r')) z-- }
    const datos = bytes.subarray(a, z)
    return /\/FlateDecode/.test(dict) ? inflar(datos) : datos
  }

  const out = new Map<string, Uint8Array>()
  for (const [num] of inicio) {
    const c = cuerpo(num)
    if (!c) continue
    const d = s.slice(c.i, c.fin)
    if (!/\/Type\s*\/Filespec/.test(d)) continue
    const nom = d.match(/\/UF\s*\(((?:\\.|[^\\)])*)\)/) ?? d.match(/\/F\s*\(((?:\\.|[^\\)])*)\)/)
    const ef = d.match(/\/EF\s*<<[\s\S]*?\/F\s+(\d+)\s+0\s+R/)
    if (!nom || !ef) continue
    try {
      const b = await stream(Number(ef[1]))
      if (b) out.set(literalPdf(nom[1]), b)
    } catch { /* adjunto ilegible: se salta */ }
  }
  return out
}

const RE_LLAVE = /\[([0-9a-fA-F]{8})((?:\/\d+['h]?)*)\]([xtyzuvYZUV]pub[1-9A-HJ-NP-Za-km-z]{100,120})/g

/** Una multifirma a partir de su descriptor externo (el interno se deriva). */
export function carteraDeDescriptor(desc: string, nombre = 'Multifirma'): CarteraLeida | null {
  const txt = desc.trim().split('#')[0].replace(/\s+/g, '')
  const mm = txt.match(/^wsh\(sortedmulti\((\d+),(.+)\)\)$/)
  if (!mm) return null
  const llaves: LlaveLeida[] = []
  let x: RegExpExecArray | null
  const re = new RegExp(RE_LLAVE.source, 'g')
  while ((x = re.exec(mm[2])) !== null) llaves.push({ etiqueta: x[1].toUpperCase(), fingerprint: x[1].toUpperCase(), ruta: 'm' + x[2].replace(/h/g, "'"), xpub: x[3] })
  if (llaves.length < 2 || Number(mm[1]) < 1 || Number(mm[1]) > llaves.length) return null
  // `/**` (BSMS) o `/<0;1>/*` → rama externa /0/*
  const externo = txt.replace(/\/<0;1>\/\*/g, '/0/*').replace(/\/\*\*/g, '/0/*')
  return { nombre, umbral: Number(mm[1]), externo, interno: externo.replace(/\/0\/\*/g, '/1/*'), llaves }
}

/** El .txt de Coldcard (Policy / Derivation / FP: xpub) → descriptor. */
function carteraDeColdcard(t: string): CarteraLeida | null {
  const pol = t.match(/Policy:\s*(\d+)\s*(?:of|de)\s*(\d+)/i)
  const der = t.match(/Derivation:\s*(m\/[0-9'h/]+)/i)
  if (!pol) return null
  const ruta = (der?.[1] ?? "m/48'/0'/0'/2'").replace(/^m\//, '').replace(/'/g, 'h')
  const patas: string[] = []
  const re = /^([0-9A-Fa-f]{8})\s*:\s*([xtyzuvYZUV]pub\S+)/gm
  let x: RegExpExecArray | null
  while ((x = re.exec(t)) !== null) patas.push(`[${x[1].toLowerCase()}/${ruta}]${x[2]}/0/*`)
  if (patas.length !== Number(pol[2])) return null
  const nombre = t.match(/^Name:\s*(.+)$/m)?.[1]?.trim()
  return carteraDeDescriptor(`wsh(sortedmulti(${pol[1]},${patas.join(',')}))`, nombre || undefined)
}

/** Cualquier texto con un descriptor dentro (o un .txt de Coldcard, o BSMS). */
export function carterasDeTexto(t: string): CarteraLeida[] {
  const out: CarteraLeida[] = []
  const vistos = new Set<string>()
  for (const m of t.matchAll(/wsh\(sortedmulti\([^\s)]+\)\)(?:#[a-z0-9]{8})?/g)) {
    const c = carteraDeDescriptor(m[0])
    if (c && !vistos.has(c.externo)) { vistos.add(c.externo); out.push(c) }
  }
  // quita los de cambio (/1/*) si ya está su externo
  const ext = out.filter((c) => !/\/1\/\*/.test(c.externo) || !out.some((o) => o.interno === c.externo))
  if (ext.length) {
    // BSMS: la 4ª línea es la primera dirección
    const bsms = t.match(/^BSMS 1\.0\s*\n.*\n.*\n(bc1[a-z0-9]{20,90})/m)
    if (bsms && ext.length === 1) ext[0].primera = bsms[1]
    try {
      const j = JSON.parse(t) as { label?: string; devices?: { label?: string }[] }
      if (j.label && ext.length === 1) ext[0].nombre = j.label
    } catch { /* no es JSON */ }
    return ext
  }
  const cc = carteraDeColdcard(t)
  return cc ? [cc] : []
}

/**
 * El paquete de adjuntos de NUESTRO PDF → una multifirma por prefijo.
 * Sin prefijo = una sola. Toma el nombre y las etiquetas de specter.json y la
 * primera dirección de bsms.bsms.
 */
export function carterasDeAdjuntos(adj: Map<string, Uint8Array>): CarteraLeida[] {
  const grupos = new Map<string, Map<string, string>>()
  for (const [nombre, b] of adj) {
    const m = nombre.match(/^(?:(\d+)-(.*?)-)?(descriptor\.txt|coldcard\.txt|specter\.json|bsms\.bsms)$/)
    if (!m) continue
    const clave = m[1] ?? '0'
    if (!grupos.has(clave)) grupos.set(clave, new Map([['_prefijo', m[2] ?? '']]))
    grupos.get(clave)!.set(m[3], texto(b))
  }
  const out: CarteraLeida[] = []
  for (const [, g] of [...grupos].sort((a, b) => Number(a[0]) - Number(b[0]))) {
    let c: CarteraLeida | null = null
    const d = g.get('descriptor.txt')
    if (d) c = carteraDeDescriptor(d.split('\n')[0])
    if (!c && g.get('bsms.bsms')) c = carterasDeTexto(g.get('bsms.bsms')!)[0] ?? null
    if (!c && g.get('coldcard.txt')) c = carteraDeColdcard(g.get('coldcard.txt')!)
    if (!c) continue
    const lineas = d?.split('\n') ?? []
    if (lineas[1] && /^wsh\(/.test(lineas[1].trim())) c.interno = lineas[1].trim().split('#')[0]
    try {
      const sp = JSON.parse(g.get('specter.json') ?? '') as { label?: string; devices?: { label?: string }[] }
      if (sp.label) c.nombre = sp.label
      if (sp.devices?.length === c.llaves.length) {
        sp.devices.forEach((dv, i) => { if (dv.label) c!.llaves[i].etiqueta = dv.label })
      }
    } catch { /* sin specter */ }
    if (c.nombre === 'Multifirma' && g.get('_prefijo')) c.nombre = g.get('_prefijo')!.replace(/-/g, ' ')
    const bs = g.get('bsms.bsms')?.split('\n')[3]?.trim()
    if (bs && /^bc1/.test(bs)) c.primera = bs
    c.llaves.forEach((k) => { if (/b[oó]veda/i.test(k.etiqueta)) k.boveda = true })
    out.push(c)
  }
  return out
}

/** Lo que el usuario sube (PDF o texto) → sus multifirmas. */
export async function leerArchivo(nombre: string, bytes: Uint8Array): Promise<{ carteras: CarteraLeida[]; esPdf: boolean; adjuntos: number }> {
  const esPdf = bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 // %PDF
  if (!esPdf) return { carteras: carterasDeTexto(texto(bytes)), esPdf: false, adjuntos: 0 }
  const adj = await adjuntosDePdf(bytes)
  let carteras = carterasDeAdjuntos(adj)
  // Plan B: buscar el descriptor escrito en el propio PDF (si viene en claro).
  if (!carteras.length) carteras = carterasDeTexto(latin1(bytes))
  void nombre
  return { carteras, esPdf: true, adjuntos: adj.size }
}
