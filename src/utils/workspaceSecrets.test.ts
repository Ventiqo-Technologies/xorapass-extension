import { describe, it, expect, vi } from 'vitest';
import { fetchAndDecryptWorkspaceSecrets } from './workspaceSecrets';
import { encryptPayload, bytesToBase64 } from './crypto';

describe('fetchAndDecryptWorkspaceSecrets', () => {
  it('returns empty array when token is empty or invalid', async () => {
    const items = await fetchAndDecryptWorkspaceSecrets('');
    expect(items).toEqual([]);
  });

  it('returns empty array when user has no workspaces', async () => {
    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/api/workspaces')) {
        return { ok: true, status: 200, json: async () => [] };
      }
      return { ok: false, status: 404 };
    });

    const items = await fetchAndDecryptWorkspaceSecrets('fake-token', mockFetch as any);
    expect(items).toEqual([]);
  });

  it('fetches and decrypts shared vault items across workspaces', async () => {
    // 1. Generate a mock vault encryption key
    const vaultKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) vaultKey[i] = i + 1;
    const wrappedKey = bytesToBase64(vaultKey);

    // 2. Encrypt a test credential with the vault key
    const itemData = {
      label: 'Production DB Admin',
      username: 'db_admin',
      value: 'super-secret-pass-2026',
      url: 'https://db.internal.example.com',
      category: 'login',
      notes: 'Internal cluster admin',
      totpSecret: 'JBSWY3DPEHPK3PXP',
    };
    const encrypted = encryptPayload(JSON.stringify(itemData), vaultKey);

    const mockWorkspaces = [
      { id: 'ws-1', name: 'Acme Corp', archived: false, role: 'admin' },
      { id: 'ws-archived', name: 'Old Client', archived: true, role: 'member' },
    ];

    const mockVaults = [
      {
        id: 'vault-1',
        name: 'Infrastructure',
        description: 'Cloud & DB credentials',
        status: 'active',
        permissions: ['view', 'use'], // read-only for this member
      },
    ];

    const mockRawItems = [
      {
        id: 'item-101',
        shared_vault_id: 'vault-1',
        encrypted_payload: {
          ciphertext: encrypted.ciphertext,
          tag: encrypted.tag,
          keyVersion: encrypted.keyVersion,
        },
        nonce: encrypted.nonce,
      },
    ];

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/api/workspaces')) {
        return { ok: true, status: 200, json: async () => mockWorkspaces };
      }
      if (url.endsWith('/api/workspaces/ws-1/vaults')) {
        return { ok: true, status: 200, json: async () => mockVaults };
      }
      if (url.endsWith('/api/workspaces/ws-1/vaults/vault-1/key')) {
        return { ok: true, status: 200, json: async () => ({ wrapped_key: wrappedKey }) };
      }
      if (url.endsWith('/api/workspaces/ws-1/vaults/vault-1/items')) {
        return { ok: true, status: 200, json: async () => mockRawItems };
      }
      return { ok: false, status: 404 };
    });

    const items = await fetchAndDecryptWorkspaceSecrets('test-jwt-token', mockFetch as any);

    expect(items.length).toBe(1);
    const item = items[0];
    expect(item.id).toBe('item-101');
    expect(item.label).toBe('Production DB Admin');
    expect(item.username).toBe('db_admin');
    expect(item.value).toBe('super-secret-pass-2026');
    expect(item.url).toBe('https://db.internal.example.com');
    expect(item.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(item.workspaceId).toBe('ws-1');
    expect(item.workspaceName).toBe('Acme Corp');
    expect(item.vaultId).toBe('vault-1');
    expect(item.vaultName).toBe('Infrastructure');
    expect(item.readOnly).toBe(true); // because permissions only has view/use, not edit
  });

  it('marks items in archived vaults as readOnly even if member has edit role', async () => {
    const vaultKey = new Uint8Array(32);
    const wrappedKey = bytesToBase64(vaultKey);
    const encrypted = encryptPayload(JSON.stringify({ label: 'Archived API Key', value: 'key-123' }), vaultKey);

    const mockWorkspaces = [{ id: 'ws-1', name: 'DevOps', archived: false }];
    const mockVaults = [
      {
        id: 'vault-archived',
        name: 'Legacy Project',
        status: 'archived',
        permissions: ['view', 'edit', 'manage'],
      },
    ];
    const mockRawItems = [
      {
        id: 'item-202',
        shared_vault_id: 'vault-archived',
        encrypted_payload: { ciphertext: encrypted.ciphertext, tag: encrypted.tag },
        nonce: encrypted.nonce,
      },
    ];

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/api/workspaces')) return { ok: true, json: async () => mockWorkspaces };
      if (url.endsWith('/vaults')) return { ok: true, json: async () => mockVaults };
      if (url.endsWith('/key')) return { ok: true, json: async () => ({ wrapped_key: wrappedKey }) };
      if (url.endsWith('/items')) return { ok: true, json: async () => mockRawItems };
      return { ok: false, status: 404 };
    });

    const items = await fetchAndDecryptWorkspaceSecrets('token', mockFetch as any);
    expect(items.length).toBe(1);
    expect(items[0].readOnly).toBe(true);
  });
});

