export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://app.xorapass.com';

export const WEB_APP_URL = import.meta.env.VITE_WEB_APP_URL || 'https://app.xorapass.com';

export const SIGNUP_URL = `${WEB_APP_URL}/auth?intent=signup`;

export const RECOVERY_URL = `${WEB_APP_URL}/auth?intent=login`;
