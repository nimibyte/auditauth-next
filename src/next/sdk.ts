'use server'
import { NextRequest, NextResponse } from "next/server";
import { importSPKI, jwtVerify } from 'jose';
import {
  AuditAuthConfig,
  CookieAdapter,
  Metric,
  RequestMethod,
  Session,
  SessionUser
} from "./types";
import { SETTINGS } from "./settings";

/* -------------------------------------------------------------------------- */
/*                                    KEYS                                    */
/* -------------------------------------------------------------------------- */

let cachedKey: CryptoKey | null = null;

/* -------------------------------------------------------------------------- */
/*                               MAIN CLASS                                   */
/* -------------------------------------------------------------------------- */

class AuditAuthNext {
  private config: AuditAuthConfig;
  private cookies: CookieAdapter;

  constructor(config: AuditAuthConfig, cookies: CookieAdapter) {
    if (!cookies.get || !cookies.set) {
      throw new Error('Missing cookie adapter');
    }

    this.config = config;
    this.cookies = cookies;
  }

  /* ------------------------------------------------------------------------ */
  /*                             AUTH PRIMITIVES                              */
  /* ------------------------------------------------------------------------ */

  private async verifyAccessToken(token: string): Promise<boolean> {
    try {
      cachedKey =
        cachedKey ||
        await importSPKI(SETTINGS.jwt_public_key, 'RS256') as CryptoKey;

      await jwtVerify(token, cachedKey, {
        issuer: SETTINGS.jwt_issuer,
        audience: this.config.appId,
      });

      return true;
    } catch {
      return false;
    }
  }

  private getCookieTokens() {
    return {
      access: this.cookies.get(SETTINGS.cookies.access.name),
      refresh: this.cookies.get(SETTINGS.cookies.refresh.name),
    };
  }

  private setCookieTokens(tokens: { at: string; rt: string }) {
    this.cookies.set(
      SETTINGS.cookies.access.name,
      tokens.at,
      SETTINGS.cookies.access.config,
    );

    this.cookies.set(
      SETTINGS.cookies.refresh.name,
      tokens.rt,
      SETTINGS.cookies.refresh.config,
    );
  }

  /* ------------------------------------------------------------------------ */
  /*                              SESSION HELPERS                             */
  /* ------------------------------------------------------------------------ */

  getSession(): SessionUser | null {
    return JSON.parse(
      this.cookies.get(SETTINGS.cookies.session.name) || '{}'
    )?.user || null;
  }

  hasSession(): boolean {
    return !!this.cookies.get(SETTINGS.cookies.session.name);
  }

  /* ------------------------------------------------------------------------ */
  /*                              AUTH FLOWS                                  */
  /* ------------------------------------------------------------------------ */

  private async buildAuthUrl(): Promise<URL> {
    const response = await fetch(`${SETTINGS.domains.api}/apps/login`, {
      method: 'POST',
      headers: { 'x-api-key': this.config.apiKey },
    });

    if (!response.ok) {
      throw new Error('invalid_app');
    }

    const { code, redirectUrl } = await response.json();
    const url = new URL(redirectUrl);
    url.searchParams.set('code', code);

    return url;
  }

  async callback(request: NextRequest) {
    const code = new URL(request.url).searchParams.get('code');

    if (!code) {
      return {
        ok: false,
        url: `${SETTINGS.domains.client}/auth/invalid?reason=wrong_config`,
      };
    }

    const response = await fetch(`${SETTINGS.domains.api}/auth/authorize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, client_type: 'server' }),
    });

    if (!response.ok) {
      return {
        ok: false,
        url: `${SETTINGS.domains.client}/auth/invalid?reason=unauthorized`,
      };
    }

    const result = await response.json();

    const session: Session = {
      user: {
        _id: result.user._id.toString(),
        email: result.user.email,
        avatar: result.user.avatar,
        name: result.user.name,
      },
    };

    this.cookies.set(
      SETTINGS.cookies.session.name,
      JSON.stringify(session),
      SETTINGS.cookies.session.config,
    );

    this.setCookieTokens({
      at: result.access_token,
      rt: result.refresh_token,
    });

    return { ok: true, url: this.config.redirectUrl };
  }

  async logout() {
    const { access } = this.getCookieTokens();
    if (access) {
      await fetch(`${SETTINGS.domains.api}/auth/revoke`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${access}` },
      }).catch(() => { });
    }

    this.cookies.remove(SETTINGS.cookies.access.name);
    this.cookies.remove(SETTINGS.cookies.refresh.name);
    this.cookies.remove(SETTINGS.cookies.session.name);
  }

  async getPortalUrl() {
    const { access } = this.getCookieTokens();
    const res = await fetch(`${SETTINGS.domains.api}/portal/exchange`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${access}`,
      },
    });

    if (!res.ok && res.status === 401) {
      return { ok: false, url: null, reason: 'unathorized' };
    } else if (!res.ok) {
      return { ok: false, url: null, reason: 'fail' };
    }

    const body = await res.json();

    return { ok: true, url: `${body.redirectUrl}?code=${body.code}&redirectUrl=${this.config.redirectUrl}`, reason: null };
  }

  /* ------------------------------------------------------------------------ */
  /*                              REFRESH FLOW                                 */
  /* ------------------------------------------------------------------------ */

  private async refresh(refreshToken: string) {
    try {
      const response = await fetch(`${SETTINGS.domains.api}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          refresh_token: refreshToken,
          client_type: 'server',
        }),
      });

      if (!response.ok) return null;
      return response.json();
    } catch {
      return null;
    }
  }

  /* ------------------------------------------------------------------------ */
  /*                         REQUEST WITH AUTO-REFRESH                         */
  /* ------------------------------------------------------------------------ */

  async request(path: string, init: RequestInit = {}) {
    const { access, refresh } = this.getCookieTokens();

    const doFetch = (token?: string) =>
      fetch(`${this.config.requestUrl}${path}`, {
        ...init,
        headers: {
          ...init.headers,
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });

    const start = performance.now();
    let res = await doFetch(access);

    // Attempt refresh once on 401
    if (res.status === 401 && refresh) {
      const data = await this.refresh(refresh);
      if (data?.access_token && data?.refresh_token) {
        res = await doFetch(data.access_token);
      }
    }

    this.pushMetric({
      event_type: 'request',
      runtime: 'server',
      target: {
        type: 'api',
        method: (init.method as RequestMethod) || 'GET',
        path,
        status: res.status,
        duration_ms: Math.round(performance.now() - start),
      },
    });

    return res;
  }

  /* ------------------------------------------------------------------------ */
  /*                                METRICS                                    */
  /* ------------------------------------------------------------------------ */

  private pushMetric(payload: Metric) {
    let sid = this.cookies.get(SETTINGS.cookies.session_id.name);

    queueMicrotask(() => {
      fetch(`${this.config.baseUrl}${SETTINGS.bff.paths.metrics}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...payload, session_id: sid ?? crypto.randomUUID() }),
      }).catch(() => { });
    });
  }

  /* ------------------------------------------------------------------------ */
  /*                               MIDDLEWARE                                  */
  /* ------------------------------------------------------------------------ */

  async middleware(_request: NextRequest) {
    const { access, refresh } = this.getCookieTokens();

    if (access && await this.verifyAccessToken(access)) {
      return NextResponse.next();
    }

    if (refresh) {
      const data = await this.refresh(refresh);
      if (data?.access_token && data?.refresh_token) {
        this.setCookieTokens({
          at: data.access_token,
          rt: data.refresh_token,
        });
      }
    }

    return NextResponse.next();
  }

  /* ------------------------------------------------------------------------ */
  /*                               BFF HANDLERS                               */
  /* ------------------------------------------------------------------------ */

  getHandlers() {
    return {
      GET: async (req: NextRequest, ctx: { params: Promise<{ auditauth: string[] }> }) => {
        const action = (await ctx.params).auditauth[0];

        switch (action) {
          case 'login':
            return NextResponse.redirect(await this.buildAuthUrl());

          case 'callback': {
            const result = await this.callback(req);
            return NextResponse.redirect(result.url);
          }

          case 'logout':
            await this.logout();
            return NextResponse.redirect(this.config.redirectUrl);

          case 'portal': {
            const result = await this.getPortalUrl();
            return result.ok && result.url
              ? NextResponse.redirect(result.url)
              : NextResponse.redirect(`${SETTINGS.domains.client}/auth/invalid`);
          }

          case 'session': {
            const user = this.getSession();
            if (!user) return new NextResponse(null, { status: 401 });
            return NextResponse.json({ user });
          }

          default:
            return new Response('not found', { status: 404 });
        }
      },

      POST: async (req: Request, ctx: { params: Promise<{ auditauth: string[] }> }) => {
        const action = (await ctx.params).auditauth[0];
        if (action === 'metrics') {
          return this.metrics(await req.json());
        }
        return new Response('not found', { status: 404 });
      },
    };
  }

  async metrics(payload: Metric) {
    await fetch(`${SETTINGS.domains.api}/metrics`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-auditauth-app': this.config.appId,
        'x-auditauth-key': this.config.apiKey,
      },
      body: JSON.stringify(payload),
    });

    return new Response(null, { status: 204 });
  }
}

export { AuditAuthNext };
