// Kit de emergencia de BitcoinProg Wallet — funciona SIN internet y SIN
// BitcoinProg. Código abierto: https://github.com/progclaw-lang/bitcoinprog-kit-emergencia
//
// Lleva (si la app lo metió) el descriptor de cada multifirma y, sólo si el
// usuario lo activó, el paquete cifrado de BóvedaProg. Con sus palabras se
// abre AQUÍ, en el navegador, con el mismo cifrado que la app:
//   Argon2id(palabras, sal; m/t/p DEL PAQUETE) → XChaCha20-Poly1305.
//   Bóvedas hasta oct-2026: 5 palabras, m=19456 KiB, t=2. Nuevas: 7 palabras, m=65536 KiB, t=3.
// La versión en blanco deja SUBIR el PDF de respaldo (se lee aquí mismo: sus
// adjuntos traen el descriptor de cada multifirma) o pegar el descriptor.
// Nada sale de esta página: no hace ninguna petición de red.
//
// 28-sep: con el estilo de bitcoinprogwallet.com y botón ES / EN (Leo).

import { argon2idAsync } from '@noble/hashes/argon2.js'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { HDKey } from '@scure/bip32'
import { mnemonicToSeed } from '@scure/bip39'
import { leerArchivo, carteraDeDescriptor } from './pdf'

interface Llave { etiqueta: string; fingerprint: string; ruta: string; xpub: string; boveda?: boolean }
interface Cartera {
  nombre: string
  umbral: number
  externo: string
  interno: string
  primera?: string
  llaves: Llave[]
  paquetes?: string[]
}
interface Datos { v: 1; idioma?: string; creado?: string; carteras: Cartera[] }

const ES = {
  eyebrow: 'Kit de emergencia',
  titulo: 'Recupera tu multifirma sin BitcoinProg',
  sub: 'Funciona sin internet · no guarda ni envía nada',
  conBovHdr: 'Esta versión INCLUYE la llave BóvedaProg cifrada: se abre con tus palabras. Guárdala lejos de ellas.',
  sinBovHdr: 'Esta versión NO incluye la llave BóvedaProg.',
  intro: 'Si la app o nuestros servidores no están, con esta página y tus llaves puedes volver a armar tu multifirma en Sparrow Wallet (gratis, de código abierto) y mover tu dinero. Esta página no se conecta a nada.',
  politica: '{m} de {n}: hacen falta {m} firmas de {n} llaves.',
  descriptor: 'Descriptor para recibir',
  cambio: 'Descriptor de cambio',
  primera: 'Primera dirección (para comprobar)',
  llaves: 'Las llaves',
  copiar: 'Copiar',
  copiado: 'Copiado',
  bovT: 'Abrir la llave BóvedaProg',
  bovL: 'Escribe tus palabras de BóvedaProg (5 o 7). Se descifran aquí mismo, en este navegador; tarda unos segundos.',
  bovBoton: 'Abrir',
  bovAbriendo: 'Abriendo…',
  bovMal: 'Esas palabras no abren esta bóveda. Revisa que sean las 5 y en orden.',
  bovOk: 'Estas son las 12 palabras de tu llave BóvedaProg. Úsalas en Sparrow como una llave más.',
  bovCoincide: '✓ Es la llave BóvedaProg de esta multifirma ({fp}).',
  bovNoCoincide: '⚠ Esta semilla no es la llave BóvedaProg de esta multifirma.',
  bovAviso: 'Cualquiera que vea estas palabras tiene esa llave. Ciérralas al terminar.',
  sinPaquete: 'Este kit no trae el paquete de BóvedaProg. Si lo tienes (del kit «con BóvedaProg»), pégalo aquí; si no y BitcoinProg no está, mueve el dinero con las otras llaves.',
  pegarPaquete: 'Pega el paquete de BóvedaProg (empieza con {"v":1,"kdf":"argon2id"…)',
  usarPaquete: 'Usar este paquete',
  pasosT: 'Cómo mover tu dinero con Sparrow Wallet',
  pasos: [
    'Instala Sparrow Wallet en una computadora: sparrowwallet.com.',
    'File → New Wallet → ponle un nombre.',
    'Policy Type: Multi Signature. Pon las firmas ({m}) y las llaves ({n}). Script Type: Native Segwit (P2WSH).',
    'En cada llave (Keystore): tu hardware wallet → «Connected Hardware Wallet» (o «Airgapped» si va por QR o microSD). La llave BóvedaProg → «New or Imported Software Wallet» → «Mnemonic Words (BIP39)» → sus 12 palabras → derivación m/48\'/0\'/0\'/2\'. Las demás → «xPub / Watch Only» con la xpub y la huella de la lista de arriba.',
    'Apply. En Addresses, la primera dirección tiene que ser la de esta página. Si sale otra, revisa las llaves.',
    'Send: pega tu dirección nueva, Create Transaction → Finalize → firma con {m} llaves → Broadcast.',
  ],
  cargaT: 'Carga tu respaldo',
  cargaL: 'Esta es la versión en blanco del kit. Tienes dos caminos; los dos se quedan en este navegador.',
  subirT: '1 · Sube el PDF de respaldo (lo más fácil)',
  subirL: 'Elige el PDF que te dio la app («BitcoinProg-respaldo-multifirmas-…pdf»). Lleva dentro, como archivos adjuntos, el descriptor de cada multifirma: esta página los lee sola. Si tu PDF trae varias multifirmas, te las enseña todas para que elijas.',
  subirBoton: 'Elegir el PDF…',
  subirOtros: 'También sirve descriptor.txt, coldcard.txt, specter.json o .bsms.',
  leyendo: 'Leyendo «{archivo}»…',
  encontradas: 'Encontré {n} multifirmas en «{archivo}». Elige cuál abrir:',
  encontrada: 'Encontré 1 multifirma en «{archivo}».',
  ninguna: 'No encontré ninguna multifirma en «{archivo}». Si lo volviste a guardar con otra app, quizá perdió los adjuntos: usa el camino 2.',
  todas: 'Ver todas',
  pegarT: '2 · O pega el descriptor',
  pegarL: 'No hace falta copiar todo el PDF: basta con UNA línea. En la hoja de tu multifirma, bajo «Descriptor para recibir», selecciona el texto que empieza con wsh(sortedmulti( y termina con #… — cópialo y pégalo aquí. El de cambio se saca solo. También puedes escanear el QR de esa hoja con el teléfono y pegar lo que lea.',
  pegarPaquete2: 'Paquete de BóvedaProg (opcional, empieza con {"v":1,"kdf":"argon2id"…)',
  pegarBoton: 'Cargar',
  pegarMal: 'No reconozco ese descriptor: tiene que empezar con wsh(sortedmulti(…',
  pie: 'Kit de emergencia de BitcoinProg Wallet. Código abierto y verificable; no guarda ni envía nada.',
  gh: 'Ver el código en GitHub',
  descargar: 'Descargar →',
}
const EN: typeof ES = {
  eyebrow: 'Emergency kit',
  titulo: 'Recover your multisig without BitcoinProg',
  sub: 'Works offline · stores and sends nothing',
  conBovHdr: 'This version INCLUDES the encrypted BóvedaProg key: it opens with your words. Keep it away from them.',
  sinBovHdr: 'This version does NOT include the BóvedaProg key.',
  intro: 'If the app or our servers are gone, with this page and your keys you can rebuild your multisig in Sparrow Wallet (free, open source) and move your money. This page connects to nothing.',
  politica: '{m} of {n}: {m} signatures from {n} keys are needed.',
  descriptor: 'Receive descriptor',
  cambio: 'Change descriptor',
  primera: 'First address (to check)',
  llaves: 'The keys',
  copiar: 'Copy',
  copiado: 'Copied',
  bovT: 'Open the BóvedaProg key',
  bovL: 'Enter your BóvedaProg words (5 or 7). They are decrypted right here, in this browser; it takes a few seconds.',
  bovBoton: 'Open',
  bovAbriendo: 'Opening…',
  bovMal: 'Those words don’t open this vault. Check that all 5 are there and in order.',
  bovOk: 'These are the 12 words of your BóvedaProg key. Use them in Sparrow as one more key.',
  bovCoincide: '✓ It’s this multisig’s BóvedaProg key ({fp}).',
  bovNoCoincide: '⚠ This seed isn’t this multisig’s BóvedaProg key.',
  bovAviso: 'Anyone who sees these words has that key. Close them when you’re done.',
  sinPaquete: 'This kit doesn’t include the BóvedaProg package. If you have it (from the kit “with BóvedaProg”), paste it here; if not and BitcoinProg is gone, move the money with your other keys.',
  pegarPaquete: 'Paste the BóvedaProg package (starts with {"v":1,"kdf":"argon2id"…)',
  usarPaquete: 'Use this package',
  pasosT: 'How to move your money with Sparrow Wallet',
  pasos: [
    'Install Sparrow Wallet on a computer: sparrowwallet.com.',
    'File → New Wallet → give it a name.',
    'Policy Type: Multi Signature. Set the signatures ({m}) and keys ({n}). Script Type: Native Segwit (P2WSH).',
    'For each key (Keystore): your hardware wallet → “Connected Hardware Wallet” (or “Airgapped” for QR or microSD). The BóvedaProg key → “New or Imported Software Wallet” → “Mnemonic Words (BIP39)” → its 12 words → derivation m/48\'/0\'/0\'/2\'. The others → “xPub / Watch Only” with the xpub and fingerprint listed above.',
    'Apply. Under Addresses, the first address must match this page. If it doesn’t, check the keys.',
    'Send: paste your new address, Create Transaction → Finalize → sign with {m} keys → Broadcast.',
  ],
  cargaT: 'Load your backup',
  cargaL: 'This is the blank version of the kit. There are two ways; both stay in this browser.',
  subirT: '1 · Upload the backup PDF (easiest)',
  subirL: 'Choose the PDF the app gave you («BitcoinProg-respaldo-multifirmas-…pdf»). It carries, as attached files, the descriptor of each multisig: this page reads them by itself. If your PDF has several multisigs, it shows them all so you can pick.',
  subirBoton: 'Choose the PDF…',
  subirOtros: 'descriptor.txt, coldcard.txt, specter.json or .bsms also work.',
  leyendo: 'Reading “{archivo}”…',
  encontradas: 'I found {n} multisigs in “{archivo}”. Choose which one to open:',
  encontrada: 'I found 1 multisig in “{archivo}”.',
  ninguna: 'I found no multisig in “{archivo}”. If you saved it again with another app, it may have lost its attachments: use way 2.',
  todas: 'Show all',
  pegarT: '2 · Or paste the descriptor',
  pegarL: 'You don’t need to copy the whole PDF: ONE line is enough. On your multisig’s sheet, under “Receive descriptor”, select the text that starts with wsh(sortedmulti( and ends with #… — copy it and paste it here. The change one is derived automatically. You can also scan that sheet’s QR with your phone and paste what it reads.',
  pegarPaquete2: 'BóvedaProg package (optional, starts with {"v":1,"kdf":"argon2id"…)',
  pegarBoton: 'Load',
  pegarMal: 'I don’t recognize that descriptor: it must start with wsh(sortedmulti(…',
  pie: 'BitcoinProg Wallet emergency kit. Open source and verifiable; it stores and sends nothing.',
  gh: 'View the code on GitHub',
  descargar: 'Download →',
}

const datosEl = document.getElementById('datos')
let datos: Datos | null = null
try {
  const txt = (datosEl?.textContent ?? '').trim()
  if (txt && txt !== '/*DATOS*/') datos = JSON.parse(txt) as Datos
} catch { datos = null }

// Idioma: el que eligió la persona (se recuerda), o el del kit, o el del navegador.
let idioma: 'es' | 'en' = 'es'
try { const g = localStorage.getItem('kit-idioma'); if (g === 'es' || g === 'en') idioma = g; else throw 0 } catch {
  idioma = ((datos?.idioma ?? navigator.language ?? 'es').slice(0, 2) === 'es') ? 'es' : 'en'
}
let T = idioma === 'es' ? ES : EN
const f = (s: string, v: Record<string, string>) => s.replace(/\{(\w+)\}/g, (_, k) => v[k] ?? '')

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {}, ...hijos: (Node | string)[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag)
  const { class: cls, ...resto } = props as Record<string, unknown>
  if (cls) e.className = String(cls)
  Object.assign(e, resto)
  for (const h of hijos) e.append(h)
  return e
}

function botonCopiar(texto: string): HTMLButtonElement {
  const b = el('button', { class: 'copiar', type: 'button', textContent: T.copiar })
  b.onclick = () => {
    const ok = () => { b.textContent = T.copiado; setTimeout(() => { b.textContent = T.copiar }, 1600) }
    navigator.clipboard?.writeText(texto).then(ok).catch(() => {
      const r = document.createRange(); const p = b.previousElementSibling
      if (p) { r.selectNodeContents(p); const s = getSelection(); s?.removeAllRanges(); s?.addRange(r) }
    })
  }
  return b
}

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

async function abrirPaquete(paquete: string, palabras: string): Promise<{ semilla: string } | null> {
  let p: { v: number; kdf: string; m: number; t: number; p: number; sal: string; nonce: string; ct: string }
  try { p = JSON.parse(paquete) } catch { return null }
  if (p.v !== 1 || p.kdf !== 'argon2id') return null
  const norm = palabras.split(/\s+/).map((w) => w.trim().toLowerCase()).filter(Boolean).join(' ')
  const k = await argon2idAsync(norm, unb64(p.sal), { t: p.t, m: p.m, p: p.p, dkLen: 32 })
  try {
    const claro = xchacha20poly1305(k, unb64(p.nonce)).decrypt(unb64(p.ct))
    return JSON.parse(new TextDecoder().decode(claro)) as { semilla: string }
  } catch { return null }
}

async function xpubDeSemilla(semilla: string): Promise<{ xpub: string; fp: string }> {
  const raiz = HDKey.fromMasterSeed(await mnemonicToSeed(semilla, ''))
  return { xpub: raiz.derive("m/48'/0'/0'/2'").publicExtendedKey, fp: (raiz.fingerprint >>> 0).toString(16).padStart(8, '0').toUpperCase() }
}

function seccionBoveda(c: Cartera): HTMLElement {
  const caja = el('section', { class: 'boveda' }, el('h3', { textContent: T.bovT }))
  if (!c.paquetes?.length) {
    // Sin paquete: se puede pegar el del kit «con BóvedaProg».
    const pq = el('textarea', { rows: 3, placeholder: T.pegarPaquete, spellcheck: false })
    const usar = el('button', { type: 'button', class: 'secundario', textContent: T.usarPaquete })
    usar.onclick = () => { const v = pq.value.trim(); if (v) { c.paquetes = [v]; caja.replaceWith(seccionBoveda(c)) } }
    caja.append(el('p', { class: 'nota', textContent: T.sinPaquete }), pq, usar)
    return caja
  }
  const inp = el('input', { type: 'text', placeholder: 'word word word word word', autocomplete: 'off', spellcheck: false })
  inp.setAttribute('autocapitalize', 'none')
  const btn = el('button', { type: 'button', class: 'primario', textContent: T.bovBoton })
  const res = el('div', { class: 'res' })
  caja.append(el('p', { textContent: T.bovL }), inp, btn, res)
  btn.onclick = async () => {
    btn.disabled = true; btn.textContent = T.bovAbriendo; res.textContent = ''
    try {
      let abierto: { semilla: string } | null = null
      for (const p of c.paquetes ?? []) { abierto = await abrirPaquete(p, inp.value); if (abierto) break }
      if (!abierto) { res.append(el('p', { class: 'mal', textContent: T.bovMal })); return }
      const { xpub, fp } = await xpubDeSemilla(abierto.semilla)
      const esta = c.llaves.find((k) => k.xpub === xpub)
      const lista = el('ol', { class: 'semilla' })
      abierto.semilla.split(' ').forEach((w) => lista.append(el('li', { textContent: w })))
      res.append(
        el('p', { textContent: T.bovOk }), lista,
        el('p', { class: esta ? 'bien' : 'mal', textContent: esta ? f(T.bovCoincide, { fp }) : T.bovNoCoincide }),
        el('p', { class: 'aviso', textContent: T.bovAviso }),
      )
    } finally { btn.disabled = false; btn.textContent = T.bovBoton }
  }
  return caja
}

function tarjeta(c: Cartera): HTMLElement {
  const m = String(c.umbral), n = String(c.llaves.length)
  const art = el('article', { class: 'cartera' },
    el('h2', { textContent: c.nombre }),
    el('p', { class: 'pol', textContent: f(T.politica, { m, n }) }),
    el('h3', { textContent: T.descriptor }), el('code', { textContent: c.externo }), botonCopiar(c.externo),
    el('h3', { textContent: T.cambio }), el('code', { textContent: c.interno }), botonCopiar(c.interno),
  )
  if (c.primera) art.append(el('h3', { textContent: T.primera }), el('code', { class: 'dir', textContent: c.primera }))
  const ul = el('ul', { class: 'llaves' })
  for (const k of c.llaves) {
    ul.append(el('li', {},
      el('b', { textContent: k.etiqueta + (k.boveda && !/b[oó]veda/i.test(k.etiqueta) ? ' · BóvedaProg' : '') }),
      el('span', { class: 'mono', textContent: `${k.fingerprint}  ${k.ruta}` }),
      el('code', { textContent: k.xpub }),
    ))
  }
  art.append(el('h3', { textContent: T.llaves }), ul)
  if (c.llaves.some((k) => k.boveda) || c.paquetes?.length) art.append(seccionBoveda(c))
  const ol = el('ol', { class: 'pasos' })
  T.pasos.forEach((p) => ol.append(el('li', { textContent: f(p, { m, n }) })))
  art.append(el('h3', { textContent: T.pasosT }), ol)
  return art
}

// ── Versión en blanco: subir el PDF o pegar el descriptor ─────────────────
let cargadas: Cartera[] = []
let elegida: number | 'todas' = 0
let aviso = ''
let pegado = ''
let pegadoPaquete = ''

function blanco(raiz: HTMLElement) {
  const archivo = el('input', { type: 'file', accept: '.pdf,application/pdf,.txt,.json,.bsms,text/plain', id: 'kit-archivo', class: 'oculto' })
  const elegir = el('label', { class: 'primario', htmlFor: 'kit-archivo', textContent: T.subirBoton })
  const estado = el('p', { class: 'estado', textContent: aviso })
  const salida = el('div', { class: 'salida' })

  archivo.onchange = async () => {
    const fch = archivo.files?.[0]
    if (!fch) return
    aviso = f(T.leyendo, { archivo: fch.name }); estado.textContent = aviso; estado.className = 'estado'
    try {
      const { carteras } = await leerArchivo(fch.name, new Uint8Array(await fch.arrayBuffer()))
      cargadas = carteras.map((c) => ({ ...c }))
      elegida = 0
      aviso = !carteras.length ? f(T.ninguna, { archivo: fch.name })
        : carteras.length === 1 ? f(T.encontrada, { archivo: fch.name })
          : f(T.encontradas, { n: String(carteras.length), archivo: fch.name })
    } catch {
      cargadas = []; aviso = f(T.ninguna, { archivo: fch.name })
    }
    archivo.value = ''
    pintar()
  }

  const d = el('textarea', { rows: 4, placeholder: 'wsh(sortedmulti(2,[a1b2c3d4/48h/0h/0h/2h]xpub…', spellcheck: false, value: pegado })
  const pq = el('textarea', { rows: 3, placeholder: T.pegarPaquete2, spellcheck: false, value: pegadoPaquete })
  const b = el('button', { type: 'button', class: 'secundario', textContent: T.pegarBoton })
  const msg = el('p', { class: 'mal' })
  d.oninput = () => { pegado = d.value }
  pq.oninput = () => { pegadoPaquete = pq.value }
  b.onclick = () => {
    msg.textContent = ''
    const c = carteraDeDescriptor(d.value, 'Multifirma')
    if (!c) { msg.textContent = T.pegarMal; return }
    const paquete = pq.value.trim()
    cargadas = [{ ...c, paquetes: paquete ? [paquete] : undefined }]
    elegida = 0; aviso = ''
    pintar()
  }

  raiz.append(el('section', { class: 'carga' },
    el('h2', { textContent: T.cargaT }),
    el('p', { textContent: T.cargaL }),
    el('div', { class: 'camino' }, el('h3', { textContent: T.subirT }), el('p', { textContent: T.subirL }), archivo, elegir, el('p', { class: 'nota', textContent: T.subirOtros })),
    el('div', { class: 'camino' }, el('h3', { textContent: T.pegarT }), el('p', { textContent: T.pegarL }), d, pq, b, msg),
    estado,
  ), salida)

  if (cargadas.length > 1) {
    const chips = el('div', { class: 'chips' })
    cargadas.forEach((c, i) => {
      const ch = el('button', { type: 'button', class: `chip${elegida === i ? ' on' : ''}`, textContent: `${c.nombre} · ${c.umbral}/${c.llaves.length}` })
      ch.onclick = () => { elegida = i; pintar() }
      chips.append(ch)
    })
    const t = el('button', { type: 'button', class: `chip${elegida === 'todas' ? ' on' : ''}`, textContent: T.todas })
    t.onclick = () => { elegida = 'todas'; pintar() }
    chips.append(t)
    salida.append(chips)
  }
  if (cargadas.length) {
    const lista = elegida === 'todas' ? cargadas : [cargadas[elegida] ?? cargadas[0]]
    lista.forEach((c) => salida.append(tarjeta(c)))
  }
}

// ── Menú y cambio de idioma (como bitcoinprogwallet.com) ──────────────────
function idiomaMenu() {
  document.documentElement.lang = idioma
  document.querySelectorAll<HTMLElement>('[data-es]').forEach((n) => { n.textContent = (idioma === 'es' ? n.dataset.es : n.dataset.en) ?? n.textContent })
  document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach((b) => b.classList.toggle('active', b.dataset.lang === idioma))
}
document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach((b) => {
  b.onclick = () => {
    idioma = b.dataset.lang === 'en' ? 'en' : 'es'
    T = idioma === 'es' ? ES : EN
    try { localStorage.setItem('kit-idioma', idioma) } catch { /* sin almacenamiento */ }
    pintar()
  }
})
const toggle = document.getElementById('navToggle')
toggle?.addEventListener('click', () => {
  const nav = toggle.closest('nav')
  const abierto = nav?.classList.toggle('mobile-open') ?? false
  toggle.classList.toggle('open', abierto)
  toggle.setAttribute('aria-expanded', String(abierto))
})

const GH_SVG = '<svg class="gh-ico" viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>'

function pintar() {
  idiomaMenu()
  const raiz = document.getElementById('kit')!
  raiz.textContent = ''
  raiz.append(el('header', {},
    el('div', { class: 'eyebrow', textContent: T.eyebrow }),
    el('h1', { textContent: T.titulo }),
    el('p', { class: 'sub', textContent: T.sub + (datos?.creado ? ` · ${datos.creado}` : '') }),
    el('p', { class: 'lede', textContent: T.intro }),
  ))
  // Qué versión es, bien visible arriba: con o sin la llave BóvedaProg (28-sep).
  if (datos?.carteras?.some((c) => c.paquetes?.length)) raiz.append(el('p', { class: 'version con', textContent: T.conBovHdr }))
  else if (datos?.carteras?.some((c) => c.llaves.some((k) => k.boveda))) raiz.append(el('p', { class: 'version', textContent: T.sinBovHdr }))
  if (datos?.carteras?.length) datos.carteras.forEach((c) => raiz.append(tarjeta(c)))
  else blanco(raiz)
  const gh = el('a', { href: 'https://github.com/progclaw-lang/bitcoinprog-kit-emergencia', rel: 'noopener', target: '_blank', class: 'gh' })
  gh.innerHTML = GH_SVG
  gh.append(T.gh)
  raiz.append(el('footer', { class: 'pie-kit' }, el('span', { textContent: T.pie }), gh))
}

pintar()
