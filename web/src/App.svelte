<script lang="ts">
import Generate from './lib/Generate.svelte'
import EncryptDecrypt from './lib/EncryptDecrypt.svelte'
</script>

<main>
  <div class="container mt-5" style="max-width: 700px;">
    <h1 class="mb-5">age-plugin-fido2-hmac</h1>
    <h3>Generate New Recipient/Identity</h3>
    <Generate></Generate>
    <hr>
    <h3>Encrypt/Decrypt File</h3>
    <EncryptDecrypt></EncryptDecrypt>
  </div>
</main>

