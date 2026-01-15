'use client';
import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { SETTINGS } from "./settings";
const AuthContext = createContext(null);
const useAuditAuth = () => {
    const ctx = useContext(AuthContext);
    if (!ctx) {
        throw new Error('useAuditAuth must be used within AuditAuthProvider');
    }
    return ctx;
};
const AuditAuthGuard = (props) => {
    const [user, setUser] = useState(null);
    useEffect(() => {
        let cancelled = false;
        const checkSession = async () => {
            try {
                const response = await fetch(SETTINGS.bff.paths.session, {
                    credentials: 'include',
                    cache: 'no-store',
                });
                if (cancelled)
                    return;
                if (!response.ok) {
                    window.location.href = SETTINGS.bff.paths.login;
                    return;
                }
                const data = await response.json();
                setUser(data.user);
            }
            catch {
                window.location.href = SETTINGS.bff.paths.login;
                return;
            }
        };
        checkSession();
        return () => {
            cancelled = true;
        };
    }, []);
    const value = useMemo(() => ({
        user,
    }), [user]);
    if (!user)
        return null;
    return (_jsx(AuthContext.Provider, { value: value, children: props.children }));
};
export { AuditAuthGuard, useAuditAuth };
