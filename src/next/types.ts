type AuditAuthConfig = {
  apiKey: string;
  redirectUrl: string;
  baseUrl: string;
  appId: string;
};

type CredentialResponse = {
  access_token: string;
  access_expires_seconds: number;
  refresh_token: string;
  refresh_expires_seconds: number;
};

type SessionUser = {
  _id: string;
  name: string;
  email: string;
  avatar: {
    url: string | null;
  };
};

type Session = {
  user: SessionUser;
};

type CookieOptions = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  maxAge?: number;
};

type RequestMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

type Metric =
  | {
    event_type: 'request';
    runtime: 'browser' | 'server';
    target: {
      type: 'api';
      method: RequestMethod;
      path: string;
      status: number;
      duration_ms: number;
    };
  }
  | {
    event_type: 'navigation';
    runtime: 'browser' | 'server';
    target: {
      type: 'page';
      path: string;
    };
  };

type CookieAdapter = {
  get: (name: string) => string | undefined;
  set: (name: string, value: string, options?: CookieOptions) => void;
  remove: (name: string) => void;
};

export type {
  AuditAuthConfig,
  CredentialResponse,
  SessionUser,
  Session,
  RequestMethod,
  Metric,
  CookieOptions,
  CookieAdapter,
};
