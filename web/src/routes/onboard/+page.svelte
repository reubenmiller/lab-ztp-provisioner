<script lang="ts">
  // Overview page: explains the three enrollment paths and links to each.
</script>

<h2>How ZTP works</h2>
<p class="lede">
  Zero Touch Provisioning automatically provisions devices at first boot.
  Choose the method that fits your deployment:
</p>

<div class="methods">
  <section class="method-card">
    <div class="method-icon" aria-hidden="true">📋</div>
    <h3>Pre-register devices</h3>
    <p>
      Know your device IDs, MACs, or serial numbers in advance?
      Add them to the <strong>Allowlist</strong> and they'll be approved
      automatically the moment they first connect — no human interaction needed.
    </p>
    <a href="/allowlist" class="method-btn">Manage Allowlist →</a>
  </section>

  <section class="method-card">
    <div class="method-icon" aria-hidden="true">📡</div>
    <h3>BLE proximity relay</h3>
    <p>
      Device can't reach the network? Use Bluetooth Low Energy to bridge enrollment
      over your phone or laptop. Run <code>ztp-agent-ble</code> on the device;
      your browser acts as the relay.
    </p>
    <a href="/onboard/ble" class="method-btn">Open BLE Relay →</a>
  </section>

  <section class="method-card">
    <div class="method-icon" aria-hidden="true">✅</div>
    <h3>Manual approval</h3>
    <p>
      Unknown device? Any device that doesn't match the allowlist lands in the
      <strong>pending queue</strong>. Review its hardware fingerprint and approve
      or reject with one click.
    </p>
    <a href="/pending" class="method-btn">Go to Fleet →</a>
  </section>
</div>

<style>
  h2 { margin-top: 0; }
  .lede { color: #8b949e; max-width: 60ch; margin-bottom: 2rem; }

  .methods {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 1.25rem;
  }

  .method-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
  }

  .method-icon {
    font-size: 2rem;
    line-height: 1;
  }

  .method-card h3 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: #e6edf3;
  }

  .method-card p {
    margin: 0;
    color: #8b949e;
    font-size: 0.9rem;
    line-height: 1.5;
    flex: 1;
  }

  .method-card code {
    background: #0d1117;
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    font-size: 0.85em;
  }

  .method-btn {
    display: inline-block;
    margin-top: 0.5rem;
    padding: 0.4rem 0.85rem;
    background: #1f6feb;
    color: #fff;
    border-radius: 5px;
    text-decoration: none;
    font-size: 0.875rem;
    align-self: flex-start;
  }
  .method-btn:hover { background: #388bfd; }
</style>
