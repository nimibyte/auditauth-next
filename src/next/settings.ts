const SETTINGS = {
  jwt_public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2EYs4Q9OyjNuAEPqb4j\nIzc52JdfVcNvEbG43Xp8B2kI9QxwRyX7rtFSwKowj3W1BlCLaTIMK3TafWOf9QwH\nfemuL9Ni37PFcGptzpyuoCYYA650EuD82PENcO49lsObvty2cuXxQszbPPvAecm4\nJ/XG70td/W1UwbjAJcdmp8ktZGYR0JXM37hYA9Xq/aKwu7d0FTL6WdKTvt3L5VxL\nF6WNyLs65ZSbu+j8UEkwmoJ9h9Y0mLQmFtmkoh/HWOFyFDnBNiJX0vRb++RhJw6w\ncrSbqpbTu7z4vIep5lgSOut39P273SVTQZ3cGQIS+605Ur5wjkkSzzaJV1QLBBR9\nAQIDAQAB\n-----END PUBLIC KEY-----\n",
  jwt_issuer: "https://api.auditauth.com",
  domains: {
    api: 'https://api.auditauth.com/v1',
    client: 'https://auditauth.com',
  },
  bff: {
    paths: {
      callback: '/api/auditauth/callback',
      metrics: '/api/auditauth/metrics',
      login: '/api/auditauth/login',
      logout: '/api/auditauth/logout',
      portal: '/api/auditauth/portal',
      session: '/api/auditauth/session',
    }
  },
  cookies: {
    access: {
      name: 'auditauth_access',
      config: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        path: '/',
        maxAge: 60 * 15,
      }
    },
    session: {
      name: 'auditauth_session',
      config: {
        maxAge: 60 * 60 * 24,
        httpOnly: true,
        secure: false,
        path: "/",
        sameSite: "lax",
      },
    },
    refresh: {
      name: 'auditauth_refresh',
      config: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        path: '/',
        maxAge: 60 * 60 * 24,
      }
    },
    session_id: {
      name: 'auditauth_sid',
      config: {
        httpOnly: false,
        sameSite: 'lax',
        secure: false,
        path: '/',
        maxAge: 60 * 60,
      }
    }
  }
} as const;

export { SETTINGS };
