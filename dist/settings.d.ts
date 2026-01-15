declare const SETTINGS: {
    readonly jwt_public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2EYs4Q9OyjNuAEPqb4j\nIzc52JdfVcNvEbG43Xp8B2kI9QxwRyX7rtFSwKowj3W1BlCLaTIMK3TafWOf9QwH\nfemuL9Ni37PFcGptzpyuoCYYA650EuD82PENcO49lsObvty2cuXxQszbPPvAecm4\nJ/XG70td/W1UwbjAJcdmp8ktZGYR0JXM37hYA9Xq/aKwu7d0FTL6WdKTvt3L5VxL\nF6WNyLs65ZSbu+j8UEkwmoJ9h9Y0mLQmFtmkoh/HWOFyFDnBNiJX0vRb++RhJw6w\ncrSbqpbTu7z4vIep5lgSOut39P273SVTQZ3cGQIS+605Ur5wjkkSzzaJV1QLBBR9\nAQIDAQAB\n-----END PUBLIC KEY-----\n";
    readonly jwt_issuer: "https://api.auditauth.com";
    readonly domains: {
        readonly api: "http://localhost:4000/v1";
        readonly client: "http://localhost:3000";
    };
    readonly bff: {
        readonly paths: {
            readonly callback: "/api/auditauth/callback";
            readonly metrics: "/api/auditauth/metrics";
            readonly login: "/api/auditauth/login";
            readonly logout: "/api/auditauth/logout";
            readonly portal: "/api/auditauth/portal";
            readonly session: "/api/auditauth/session";
        };
    };
    readonly cookies: {
        readonly access: {
            readonly name: "auditauth_access";
            readonly config: {
                readonly httpOnly: true;
                readonly sameSite: "lax";
                readonly secure: false;
                readonly path: "/";
                readonly maxAge: number;
            };
        };
        readonly session: {
            readonly name: "auditauth_session";
            readonly config: {
                readonly maxAge: number;
                readonly httpOnly: true;
                readonly secure: false;
                readonly path: "/";
                readonly sameSite: "lax";
            };
        };
        readonly refresh: {
            readonly name: "auditauth_refresh";
            readonly config: {
                readonly httpOnly: true;
                readonly sameSite: "lax";
                readonly secure: false;
                readonly path: "/";
                readonly maxAge: number;
            };
        };
        readonly session_id: {
            readonly name: "auditauth_sid";
            readonly config: {
                readonly httpOnly: false;
                readonly sameSite: "lax";
                readonly secure: false;
                readonly path: "/";
                readonly maxAge: number;
            };
        };
    };
};
export { SETTINGS };
