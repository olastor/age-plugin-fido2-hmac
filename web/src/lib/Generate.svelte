<script lang="ts">
import { bech32 } from '@scure/base'
import { base64nopad, base64 } from '@scure/base'
import { onMount } from 'svelte'
import { Encrypter, Decrypter, x25519Wrap, Stanza } from 'age-encryption'
import { generateNewRecipient, wrapFileKey, unwrapFileKey } from '../util/plugin'

let newRecipient = ''
let newIdentity = ''

let symmetric = false
let asIdentity = true
let isMagicIdentity = false
let hideIdentity = false

const generate = async () => {
  const result = await generateNewRecipient(symmetric, asIdentity)
  newRecipient = result.recipient
  newIdentity = result.identity
}

const toggleHideIdentity = () => {
  hideIdentity = !hideIdentity
}
</script>

<div class="form-check">
  <input bind:checked={symmetric} class="form-check-input" type="checkbox" value="" id="flexCheckDefault">
  <label class="form-check-label" for="flexCheckDefault">
    Use symmetric encryption
  </label>
</div>
<div>
<small>When checked, a new symmetric secret is generated for every encrypted file. This means that the fido2 token <b>is required for encryption and decryption</b>. Otherwise, only one secret is obtained from the token and a public key is derived from it. In this case the fido2 token is not required for encryption, but for initial generation the PIN must be entered twice instead of once (for generating the credential and for obtaining the secret).</small>
</div>

<div class="form-check mt-3">
  <input bind:checked={asIdentity} class="form-check-input" type="checkbox" value="" id="flexCheckChecked">
  <label class="form-check-label" for="flexCheckChecked">
    Create a mandatory identity
  </label>
</div>
<div class="mb-4">
<small>When checked, then in addition to the fido2 token a unique identity string is generated and is <b>required for decryption</b>. In this case, no metadata that could link two encrypted files to the same recipient is included in the encrypted file.</small>
</div>

{#if newRecipient || newIdentity}
<label for="recipient" class="form-label">Your Recipient</label>
<div class="input-group mb-3">
  <input bind:value={newRecipient} type="text" class="form-control" id="recipient" aria-describedby="recipient" readonly>
</div>

<label for="identity" class="form-label">Your Identity</label>
<div class="input-group mb-3">
  {#if newIdentity && hideIdentity}
    <input value={'*'.repeat(32)} type="text" class="form-control" id="identity" aria-describedby="identity" readonly>
  {:else}
    <input bind:value={newIdentity} type="text" class="form-control" id="identity" aria-describedby="identity" readonly>
  {/if}
  {#if !isMagicIdentity && newIdentity}
    <button class="btn btn-outline-secondary" type="button" id="identity-copy" on:click={toggleHideIdentity}>
      {#if hideIdentity}
        show
      {:else}
        hide
      {/if}
    </button>
  {/if}
</div>
{/if}

<button class="btn btn-primary" on:click={generate}>Generate</button>
