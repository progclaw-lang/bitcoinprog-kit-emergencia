# Kit de emergencia · BitcoinProg Wallet

Una sola página HTML que funciona **sin internet y sin BitcoinProg**. Sirve
para rearmar una multifirma de BitcoinProg Wallet en **Sparrow Wallet** y mover
el dinero si la app o nuestros servidores dejan de existir.

- La app genera un **kit personal**: esta misma página con los descriptores de
  tus multifirmas dentro y, sólo si lo activas, el paquete cifrado de
  BóvedaProg.
- `dist/kit-emergencia.html` es la **versión en blanco**. Dos caminos:
  - **Sube el PDF de respaldo**: se lee en tu navegador (sus adjuntos traen el
    descriptor de cada multifirma; con varias, eliges cuál). También sirve
    `descriptor.txt`, `coldcard.txt`, `specter.json` o `.bsms`.
  - **O pega el descriptor** (una línea: `wsh(sortedmulti(…`).
- No hace ninguna petición de red. Su CSP lo prohíbe:
  `default-src 'none'; script-src 'unsafe-inline'`.

## Cómo abre BóvedaProg

Es el mismo cifrado que la app:

- Argon2id(5 palabras, sal; m = 19456 KiB, t = 2, p = 1) → 32 bytes;
- XChaCha20-Poly1305 con el nonce del paquete.

Dentro está la semilla BIP39 de la llave BóvedaProg. El kit comprueba que su
llave m/48'/0'/0'/2' sea la de la multifirma antes de enseñarla.

⚠️ El paquete más las 5 palabras abren la llave **sin el 2FA**. Guarda el kit
lejos de las palabras.

## Construir y verificar

```
npm install && npm run build
shasum -a 256 dist/kit-emergencia.html
```

Versión en blanco actual: `sha256 31a00af130891da6c07063eb290d46033ee22554f06a9f78ebe1dac3a4287377`

Código: `src/kit.ts` (TypeScript, sin frameworks). Usa @noble/hashes (argon2),
@noble/ciphers (xchacha20poly1305), @scure/bip32 y @scure/bip39.

## Tipografías

Van dentro del HTML (subconjunto latino) para que abra sin internet: Fraunces,
Inter Tight y JetBrains Mono, todas con licencia SIL Open Font License 1.1.
