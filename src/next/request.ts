'use server'

import { cookies } from "next/headers";
import { SETTINGS } from "./settings";
import { RequestMethod } from "./types";

const auditauthFetch = async (url: string, init: RequestInit = {}) => {
  const cookieManager = await cookies();
  const access_token = cookieManager.get(SETTINGS.cookies.access.name);
  const refresh_token = cookieManager.get(SETTINGS.cookies.refresh.name);

  const doFetch = (token?: string) =>
    fetch(url, {
      ...init,
      headers: {
        ...init.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });

  const start = performance.now();
  let response = await doFetch(access_token?.value);

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

  let sid = cookieManager.get(SETTINGS.cookies.session_id.name);

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

    fetch(`${SETTINGS.bff.paths.metrics}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, session_id: sid ?? crypto.randomUUID() }),
    }).catch(() => { });
  });

  return response;
};

export { auditauthFetch };
