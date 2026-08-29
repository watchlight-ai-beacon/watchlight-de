// Governance backend seam — the one object that graduation swaps.
//
// The authorize request/response shape is IDENTICAL in both editions
// (`{principal, action, resource, context}` → `{decision, reason}`), so the same
// govern/tool/hook code works either way:
//
//   * Developer Edition (default) — InProcessBackend runs the compiled
//     @watchlight/engine wasm core in-process. Zero infrastructure.
//   * Enterprise — set WATCHLIGHT_APDP_URL and NetworkedBackend POSTs the same
//     request to the control plane's /authorize (signed lineage, cross-tenant
//     isolation, IdP/mTLS attestation live there). No policy or code change.
//
// Fail-closed everywhere: any transport/engine error resolves to Deny.

import { Engine } from "@watchlight/engine";

export interface AuthorizeRequest {
  principal: string;
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}

export interface Decision {
  decision: string;
  reason: string;
}

export interface GovernanceBackend {
  readonly kind: "in-process" | "networked";
  /** A short human label for the dev announce line. */
  readonly label: string;
  /** Register a policy. In-process loads it; networked ignores it (policies are
   *  managed by the control plane) after warning once. */
  addPolicy(policy: { name: string; code: string }): void;
  /** Authorize a request. Fail-closed. */
  authorize(req: AuthorizeRequest): Promise<Decision>;
  /** The in-process engine (for local sub-agent attenuation), or null when
   *  networked — attenuation is enforced server-side in Enterprise. */
  engine(): Promise<Engine> | null;
}

/** DE default — the compiled engine in-process. */
export class InProcessBackend implements GovernanceBackend {
  readonly kind = "in-process" as const;
  readonly label = "dev mode, in-process engine";
  private _enginePromise?: Promise<Engine>;
  private _pending: { name: string; code: string }[] = [];

  addPolicy(policy: { name: string; code: string }): void {
    this._pending.push(policy);
  }

  private async _ready(): Promise<Engine> {
    if (!this._enginePromise) this._enginePromise = Engine.create();
    const engine = await this._enginePromise;
    if (this._pending.length) {
      const batch = this._pending;
      this._pending = [];
      for (const p of batch) await engine.addPolicy(p);
    }
    return engine;
  }

  async authorize(req: AuthorizeRequest): Promise<Decision> {
    const engine = await this._ready();
    const resp = await engine.authorize({
      principal: req.principal,
      action: req.action,
      resource: req.resource,
      context: req.context ?? {},
    });
    return { decision: (resp.decision as string) ?? "Deny", reason: (resp.reason as string) ?? "" };
  }

  engine(): Promise<Engine> {
    return this._ready();
  }
}

/** Enterprise — POST /authorize to the networked control plane. */
export class NetworkedBackend implements GovernanceBackend {
  readonly kind = "networked" as const;
  readonly label: string;
  private readonly _base: string;
  private readonly _token?: string;
  private readonly _tenantId?: string;
  private _warnedPolicy = false;

  constructor(url: string, token?: string, tenantId?: string) {
    this._base = url.replace(/\/+$/, "");
    this._token = token;
    this._tenantId = tenantId;
    this.label = `control plane: ${this._base}`;
  }

  addPolicy(): void {
    if (!this._warnedPolicy) {
      // eslint-disable-next-line no-console
      console.warn(
        "watchlight: WATCHLIGHT_APDP_URL is set — policies are managed by the " +
          "control plane; local allow()/load() is ignored."
      );
      this._warnedPolicy = true;
    }
  }

  async authorize(req: AuthorizeRequest): Promise<Decision> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this._token) headers["authorization"] = `Bearer ${this._token}`;
    if (this._tenantId) headers["x-wl-tenant-id"] = this._tenantId;
    try {
      const resp = await fetch(`${this._base}/authorize`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          principal: req.principal,
          action: req.action,
          resource: req.resource,
          context: req.context ?? {},
        }),
      });
      if (!resp.ok) return { decision: "Deny", reason: `APDP error: ${resp.status}` };
      const data = (await resp.json()) as Record<string, unknown>;
      return { decision: (data.decision as string) ?? "Deny", reason: (data.reason as string) ?? "" };
    } catch (e) {
      // Fail-closed: an unreachable control plane denies.
      return { decision: "Deny", reason: `APDP unreachable: ${String(e)}` };
    }
  }

  engine(): null {
    return null;
  }
}

/** Select the backend: networked when a URL is given (option or
 *  WATCHLIGHT_APDP_URL), in-process otherwise. */
export function selectBackend(opts: {
  apdpUrl?: string;
  token?: string;
  tenantId?: string;
}): GovernanceBackend {
  const url = opts.apdpUrl ?? process.env.WATCHLIGHT_APDP_URL;
  if (url && url.trim()) {
    return new NetworkedBackend(
      url.trim(),
      opts.token ?? process.env.WATCHLIGHT_PLUGIN_TOKEN,
      opts.tenantId ?? process.env.WATCHLIGHT_TENANT_ID
    );
  }
  return new InProcessBackend();
}
