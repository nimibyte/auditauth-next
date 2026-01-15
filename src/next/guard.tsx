'use client';

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { SessionUser } from "./types";
import { SETTINGS } from "./settings";

type AuthContextValue = {
  user: SessionUser;
};

const AuthContext = createContext<AuthContextValue | null>(null);

const useAuditAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuditAuth must be used within AuditAuthProvider');
  }
  return ctx;
}

type AuditAuthGuardProps = {
  children: React.ReactNode;
};

const AuditAuthGuard = (props: AuditAuthGuardProps) => {
  const [user, setUser] = useState<SessionUser>({} as SessionUser);

  useEffect(() => {
    let cancelled = false;

    const checkSession = async () => {
      try {
        const response = await fetch(SETTINGS.bff.paths.session, {
          credentials: 'include',
          cache: 'no-store',
        });

        if (cancelled) return;

        if (!response.ok) {
          window.location.href = SETTINGS.bff.paths.login;
          return;
        }

        const data = await response.json();
        setUser(data.user);
      } catch {
        window.location.href = SETTINGS.bff.paths.login;
        return;
      }
    };

    checkSession();

    return () => {
      cancelled = true;
    }
  }, []);

  const value = useMemo(() => ({
    user,
  }), [user]);

  if (!user.name) return null;

  return (
    <AuthContext.Provider value={value}>
      {props.children}
    </AuthContext.Provider>
  );
};

export { AuditAuthGuard, useAuditAuth };
