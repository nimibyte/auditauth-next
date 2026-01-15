import { SessionUser } from "./types";
type AuthContextValue = {
    user: SessionUser | null;
};
declare const useAuditAuth: () => AuthContextValue;
type AuditAuthGuardProps = {
    children: React.ReactNode;
};
declare const AuditAuthGuard: (props: AuditAuthGuardProps) => import("react/jsx-runtime").JSX.Element | null;
export { AuditAuthGuard, useAuditAuth };
