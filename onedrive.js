/*
  OneDrive "Save" integration via Microsoft Graph, using MSAL.js for OAuth.
  Files are written to the app's dedicated OneDrive folder (Apps/Surgical
  Case Log) using the Files.ReadWrite.AppFolder scope — this app never
  requests access to the rest of the signed-in user's OneDrive.
*/
(function () {
  let msalInstance = null;
  let initPromise = null;

  function redirectUri() {
    const dir = window.location.pathname.replace(/[^/]+$/, '');
    return window.location.origin + dir + 'index.html';
  }

  function getMsalInstance() {
    if (!window.ONEDRIVE_CLIENT_ID) {
      throw new Error('OneDrive is not set up yet — add your Client ID to onedrive-config.js.');
    }
    if (!msalInstance) {
      msalInstance = new msal.PublicClientApplication({
        auth: {
          clientId: window.ONEDRIVE_CLIENT_ID,
          authority: 'https://login.microsoftonline.com/common',
          redirectUri: redirectUri(),
        },
        cache: { cacheLocation: 'localStorage' },
      });
    }
    return msalInstance;
  }

  async function ensureInitialized() {
    const instance = getMsalInstance();
    if (!initPromise) initPromise = instance.initialize();
    await initPromise;
    return instance;
  }

  async function getAccessToken() {
    const instance = await ensureInitialized();
    const scopes = ['Files.ReadWrite.AppFolder'];
    const accounts = instance.getAllAccounts();
    if (accounts.length > 0) {
      try {
        const result = await instance.acquireTokenSilent({ scopes, account: accounts[0] });
        return result.accessToken;
      } catch (e) {
        // fall through to interactive login
      }
    }
    const result = await instance.loginPopup({ scopes });
    return result.accessToken;
  }

  async function uploadFile(filename, blob) {
    const accessToken = await getAccessToken();
    const res = await fetch(
      `https://graph.microsoft.com/v1.0/me/drive/special/approot:/${encodeURIComponent(filename)}:/content`,
      {
        method: 'PUT',
        headers: { Authorization: `Bearer ${accessToken}` },
        body: blob,
      }
    );
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Upload failed (${res.status}). ${text}`);
    }
    return res.json();
  }

  window.OneDriveExport = { uploadFile };
})();
