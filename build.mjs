// Construye el kit: un solo HTML con el script embebido.
//  · dist/kit-emergencia.html      → versión en blanco (web y GitHub)
//  · ../src/lib/kit/plantillaKit.ts → la plantilla que usa la app para meter
//    los datos de cada usuario (reemplaza /*DATOS*/).
// Uso (desde la raíz del repo): node kit-emergencia/build.mjs
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

const aqui = (p) => fileURLToPath(new URL(p, import.meta.url))
mkdirSync(aqui('./dist/'), { recursive: true })
// Dentro de la app usa sus node_modules; en el repo suelto, los propios.
const modulos = existsSync(aqui('./node_modules')) ? aqui('./node_modules') : aqui('../node_modules')
execFileSync('npx', ['esbuild', aqui('./src/kit.ts'), '--bundle', '--minify', '--format=iife', '--platform=browser', '--target=es2020', `--outfile=${aqui('./dist/kit.js')}`, '--log-level=error'],
  { stdio: 'inherit', env: { ...process.env, NODE_PATH: modulos } })
const js = readFileSync(aqui('./dist/kit.js'), 'utf8').replace(/<\/script/gi, '<\\/script')
// Tipografías y logo del sitio DENTRO del archivo: el kit abre sin internet
// (su CSP sólo deja fuentes e imágenes `data:`). Sólo el subconjunto latino.
const b64 = (f) => readFileSync(aqui('./recursos/' + f)).toString('base64')
const fuentes = [
  ['Fraunces', '400', 'Fraunces-400.woff2'],
  ['Inter Tight', '400 700', 'InterTight.woff2'],
  ['JetBrains Mono', '400', 'JetBrainsMono-400.woff2'],
].map(([fam, peso, f]) => `@font-face{font-family:'${fam}';font-style:normal;font-weight:${peso};font-display:swap;src:url(data:font/woff2;base64,${b64(f)}) format('woff2')}`).join('\n')
const html = readFileSync(aqui('./plantilla.html'), 'utf8')
  .replace('/*FUENTES*/', () => fuentes)
  .replace('/*LOGO*/', () => 'data:image/png;base64,' + b64('logo.png'))
  .replace('/*SCRIPT*/', () => js)
writeFileSync(aqui('./dist/kit-emergencia.html'), html)
if (existsSync(aqui('../src/lib/'))) {
  mkdirSync(aqui('../src/lib/kit/'), { recursive: true })
  writeFileSync(aqui('../src/lib/kit/plantillaKit.ts'),
    '// GENERADO por kit-emergencia/build.mjs — no editar a mano.\n' +
    `export const PLANTILLA_KIT = ${JSON.stringify(html)}\n`)
}
console.log('kit', (html.length / 1024).toFixed(0) + ' KB', 'sha256', createHash('sha256').update(html).digest('hex').slice(0, 16))
