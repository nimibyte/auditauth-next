/* -------------------------------------------------------------------------- */
/*                             CLIENT SHORTCUTS                               */
/* -------------------------------------------------------------------------- */

import { SETTINGS } from "./settings";

const login = () => {
  window.location.href = SETTINGS.bff.paths.login;
};

const logout = () => {
  window.location.href = SETTINGS.bff.paths.logout;
};

const goToPortal = () => {
  window.location.href = SETTINGS.bff.paths.portal;
};

export { login, logout, goToPortal };
