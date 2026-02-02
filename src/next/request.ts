'use server'

import { cookies } from "next/headers";
import { SETTINGS } from "./settings";
import { RequestMethod } from "./types";
import { headers } from 'next/headers';

const getRequestOrigin = async (): Promise<string> => {
  const h = await headers();

  const proto =
    h.get('x-forwarded-proto') ??
    (process.env.NODE_ENV === 'production' ? 'https' : 'http');

  const host =
    h.get('x-forwarded-host') ??
    h.get('host');

  if (!host) {
    throw new Error('Cannot resolve request origin');
  }

  return `${proto}://${host}`;
}

const auditauthFetch = async (url: string, init: RequestInit = {}) => {
  const cookieManager = await cookies();
  const origin = await getRequestOrigin();
  const access_token = cookieManager.get(SETTINGS.cookies.access.name)?.value;
  const refresh_token = cookieManager.get(SETTINGS.cookies.refresh.name)?.value;
  const session_id = cookieManager.get(SETTINGS.cookies.session_id.name)?.value;

  const doFetch = (token?: string) =>
    fetch(url, {
      ...init,
      headers: {
        ...init.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });

  const start = performance.now();

  let response = await doFetch(access_token);

  if (response.status === 401 && refresh_token) {
    const refreshResponse = await fetch(`${SETTINGS.domains.api}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refresh_token,
        client_type: 'server',
      }),
    });

    if (!refreshResponse.ok) return response;

    const data = await refreshResponse.json();

    if (data?.access_token && data?.refresh_token) {
      response = await doFetch(data.access_token);
    }
  }

  queueMicrotask(() => {
    const payload = {
      event_type: 'request',
      runtime: 'server',
      target: {
        type: 'api',
        method: (init.method as RequestMethod) || 'GET',
        path: url,
        status: response.status,
        duration_ms: Math.round(performance.now() - start),
      },
    };

    fetch(`${origin}${SETTINGS.bff.paths.metrics}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, session_id }),
    }).catch(() => { });
  });

  return response;
};

export { auditauthFetch };
