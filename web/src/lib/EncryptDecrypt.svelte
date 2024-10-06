<script lang="ts">
import { bech32 } from '@scure/base'
import { base64nopad, base64 } from '@scure/base'
import { onMount } from 'svelte'
import { Encrypter, Decrypter, x25519Wrap, Stanza } from 'age-encryption'
import { generateNewRecipient, wrapFileKey, unwrapFileKey, Fido2HmacPlugin } from '../util/plugin'

let files

let recipientOrIdentity = ''
let isEncryptedFile: undefined | boolean = undefined

const downloadFile = (buffer, name) => {
  const blob = new Blob([buffer])
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
}

const encryptOrDecrypt = async () => {
  const fileBuffer = await files[0].arrayBuffer()

  isEncryptedFile = new TextDecoder().decode(fileBuffer.slice(0, 21)) === 'age-encryption.org/v1'
  const isRecipient = /^[^A-Z]+$/.test(recipientOrIdentity)

  if (!isEncryptedFile) {
    const encrypter = new Encrypter()
    encrypter.registerPlugin(Fido2HmacPlugin)
    if (isRecipient) {
      encrypter.addRecipient(recipientOrIdentity)
    } else {
      encrypter.addIdentity(recipientOrIdentity)
    }
    const ciphertext = await encrypter.encrypt(new Uint8Array(fileBuffer))
    downloadFile(ciphertext.buffer, files[0].name + '.age')
  } else {
    const decrypter = new Decrypter()
    console.log(Fido2HmacPlugin)
    decrypter.registerPlugin(Fido2HmacPlugin)
    decrypter.addIdentity(recipientOrIdentity)
    const plaintext = await decrypter.decrypt(new Uint8Array(fileBuffer))
    downloadFile(plaintext.buffer, files[0].name.replace(/\.age$/i, ''))
  }
}

$: if (files) {
  if (files.length) {
    files[0].arrayBuffer().then((buf) => {
      isEncryptedFile = new TextDecoder().decode(buf.slice(0, 21)) === 'age-encryption.org/v1'
    })
  }
}
</script>

<label for="identity" class="form-label">Enter Recipient or Identity</label>
<div class="input-group mb-3">
  <input bind:value={recipientOrIdentity} type="text" class="form-control" id="identity" aria-describedby="identity">
</div>

<label for="file">File to encrypt or decrypt:</label>
<div class="input-group mb-3">
  <input bind:files type="file" class="form-control" id="file">
</div>
{#if isEncryptedFile}
<div>This file is encrypted with age</div>
{/if}

{#if isEncryptedFile === true && recipientOrIdentity}
<button class="btn btn-primary" on:click={encryptOrDecrypt}>Decrypt</button>
{/if}
{#if isEncryptedFile === false && recipientOrIdentity}
<button class="btn btn-primary" on:click={encryptOrDecrypt}>Encrypt</button>
{/if}


