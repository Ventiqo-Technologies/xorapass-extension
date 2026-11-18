import { API_BASE_URL } from './config';
import { base64ToBytes, decryptPayload, CURRENT_KEY_VERSION } from './crypto';

export interface Workspace {
  id: string;
  name: string;
  type?: string;
  owner_id?: string;
  archived?: boolean;
  role?: string;
}

export interface SharedVault {
  id: string;
  name: string;
  description?: string;
  status?: string;
  permissions?: string[];
}

export interface SharedVaultKeyResponse {
  wrapped_key?: string;
}

export interface SharedVaultItemRaw {
  id: string;
  shared_vault_id: string;
  encrypted_payload: {
    ciphertext: string;
    tag: string;
    keyVersion?: number;
  };
  nonce: string;
}

export interface WorkspaceVaultItem {
  id: string;
  label: string;
  username: string;
  value: string;
  notes: string;
  category: string;
  url?: string;
  organization?: string;
  cardholderName?: string;
  cardNumber?: string;
  expiryDate?: string;
  cvv?: string;
  privateKey?: string;
  publicKey?: string;
  passphrase?: string;
  accountId?: string;
  totpSecret?: string;
  customFields?: Record<string, string>;
  workspaceId: string;
  workspaceName: string;
  vaultId: string;
  vaultName: string;
  readOnly: boolean;
}

/**
 * Fetches all accessible workspaces, shared vaults, keys, and decrypts shared items.
 * Returns an array of WorkspaceVaultItem tagged with workspace and vault metadata.
 */
export async function fetchAndDecryptWorkspaceSecrets(
  token: string,
  fetchFn: typeof fetch = fetch
): Promise<WorkspaceVaultItem[]> {
  if (!token) return [];

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
  };

  const results: WorkspaceVaultItem[] = [];

  try {
    const wsRes = await fetchFn(`${API_BASE_URL}/api/workspaces`, { headers });
    if (!wsRes.ok) {
      if (wsRes.status !== 401 && wsRes.status !== 404) {
        console.warn(`[XoraPass] Failed to list workspaces: HTTP ${wsRes.status}`);
      }
      return [];
    }

    const workspaces: Workspace[] = await wsRes.json();
    if (!Array.isArray(workspaces) || workspaces.length === 0) {
      return [];
    }

    // Process each unarchived workspace
    for (const ws of workspaces) {
      if (ws.archived) continue;

      try {
        const vaultsRes = await fetchFn(`${API_BASE_URL}/api/workspaces/${ws.id}/vaults`, { headers });
        if (!vaultsRes.ok) continue;

        const vaults: SharedVault[] = await vaultsRes.json();
        if (!Array.isArray(vaults) || vaults.length === 0) continue;

        for (const vault of vaults) {
          try {
            // Fetch the wrapped vault encryption key
            const keyRes = await fetchFn(
              `${API_BASE_URL}/api/workspaces/${ws.id}/vaults/${vault.id}/key`,
              { headers }
            );
            if (!keyRes.ok) continue;

            const keyData: SharedVaultKeyResponse = await keyRes.json();
            if (!keyData.wrapped_key) continue;

            let vaultKey: Uint8Array;
            try {
              vaultKey = base64ToBytes(keyData.wrapped_key);
            } catch (err) {
              console.warn(`[XoraPass] Invalid base64 key for vault ${vault.id}:`, err);
              continue;
            }

            // Fetch shared vault items
            const itemsRes = await fetchFn(
              `${API_BASE_URL}/api/workspaces/${ws.id}/vaults/${vault.id}/items`,
              { headers }
            );
            if (!itemsRes.ok) continue;

            const rawItems: SharedVaultItemRaw[] = await itemsRes.json();
            if (!Array.isArray(rawItems) || rawItems.length === 0) continue;

            const isReadOnly =
              vault.status === 'archived' ||
              !(vault.permissions || []).includes('edit');

            for (const item of rawItems) {
              try {
                const payload = {
                  ciphertext: item.encrypted_payload.ciphertext,
                  tag: item.encrypted_payload.tag,
                  nonce: item.nonce,
                  keyVersion: item.encrypted_payload.keyVersion ?? CURRENT_KEY_VERSION,
                };

                const plaintext = decryptPayload(payload, vaultKey);
                const parsed = JSON.parse(plaintext);

                results.push({
                  id: item.id,
                  label: parsed.label || 'Unnamed Shared Secret',
                  username: parsed.username || '',
                  value: parsed.value || '',
                  notes: parsed.notes || '',
                  category: parsed.category || 'login',
                  url: parsed.url || '',
                  organization: parsed.organization || ws.name,
                  cardholderName: parsed.cardholderName || '',
                  cardNumber: parsed.cardNumber || '',
                  expiryDate: parsed.expiryDate || '',
                  cvv: parsed.cvv || '',
                  privateKey: parsed.privateKey || '',
                  publicKey: parsed.publicKey || '',
                  passphrase: parsed.passphrase || '',
                  accountId: parsed.accountId || '',
                  totpSecret: parsed.totpSecret || parsed.totp || parsed.twoFactorSecret || '',
                  customFields: parsed.customFields || {},
                  workspaceId: ws.id,
                  workspaceName: ws.name,
                  vaultId: vault.id,
                  vaultName: vault.name,
                  readOnly: isReadOnly,
                });
              } catch (decryptErr) {
                console.warn(
                  `[XoraPass] Could not decrypt item ${item.id} in vault "${vault.name}":`,
                  decryptErr
                );
              }
            }
          } catch (vaultErr) {
            console.warn(`[XoraPass] Failed processing vault ${vault.id}:`, vaultErr);
          }
        }
      } catch (wsErr) {
        console.warn(`[XoraPass] Failed processing workspace ${ws.id}:`, wsErr);
      }
    }
  } catch (err) {
    console.warn('[XoraPass] Error fetching workspace secrets:', err);
  }

  return results;
}
