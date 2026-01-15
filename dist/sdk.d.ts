import { NextRequest, NextResponse } from "next/server";
import { AuditAuthConfig, CookieAdapter, Metric, SessionUser } from "./types";
declare class AuditAuthNext {
    private config;
    private cookies;
    constructor(config: AuditAuthConfig, cookies: CookieAdapter);
    private verifyAccessToken;
    private getCookieTokens;
    private setCookieTokens;
    getSession(): SessionUser | null;
    hasSession(): boolean;
    private buildAuthUrl;
    callback(request: NextRequest): Promise<{
        ok: boolean;
        url: string;
    }>;
    logout(): Promise<void>;
    getPortalUrl(): Promise<{
        ok: boolean;
        url: null;
        reason: string;
    } | {
        ok: boolean;
        url: string;
        reason: null;
    }>;
    private refresh;
    request(path: string, init?: RequestInit): Promise<Response>;
    private pushMetric;
    middleware(_request: NextRequest): Promise<NextResponse<unknown>>;
    getHandlers(): {
        GET: (req: NextRequest, ctx: {
            params: Promise<{
                auditauth: string[];
            }>;
        }) => Promise<Response>;
        POST: (req: Request, ctx: {
            params: Promise<{
                auditauth: string[];
            }>;
        }) => Promise<Response>;
    };
    metrics(payload: Metric): Promise<Response>;
}
declare const login: () => void;
declare const logout: () => void;
declare const goToPortal: () => void;
export { AuditAuthNext, login, logout, goToPortal };
