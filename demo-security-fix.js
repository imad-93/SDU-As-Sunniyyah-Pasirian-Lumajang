(() => {
  if (window.__SDU_DEMO_FIXES_LOADED__) return;
  window.__SDU_DEMO_FIXES_LOADED__ = true;

  const STORAGE_KEY = 'assunniyyah_db_v2';
  const SESSION_KEY = 'assunniyyah_session_v1';
  const SESSION_TTL_MS = 1000 * 60 * 60 * 8;

  const textEncoder = new TextEncoder();

  function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function fromHex(hex) {
    const clean = (hex || '').trim();
    if (!clean) return new Uint8Array();
    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      const chunk = clean.slice(i, i + 2);
      if (chunk.length === 2) bytes.push(parseInt(chunk, 16));
    }
    return new Uint8Array(bytes);
  }

  function randomBytes(length = 16) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  async function hashPassword(password, saltBytes = randomBytes(16)) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 120000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return {
      hash: toHex(new Uint8Array(bits)),
      salt: toHex(saltBytes)
    };
  }

  async function verifyPassword(password, storedHash, storedSalt) {
    if (!password || !storedHash || !storedSalt) return false;
    const salt = fromHex(storedSalt);
    const derived = await hashPassword(password, salt);
    return derived.hash === storedHash;
  }

  function generateSessionToken() {
    return [...randomBytes(32)].map(x => x.toString(16).padStart(2, '0')).join('');
  }

  function readSession() {
    try {
      const value = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
      if (!value || !value.expiresAt || Date.now() > value.expiresAt) {
        sessionStorage.removeItem(SESSION_KEY);
        return null;
      }
      return value;
    } catch (e) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
  }

  function writeSession(user) {
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        userId: user && (user.id || user.u),
        role: user && user.role,
        name: user && user.name,
        expiresAt: Date.now() + SESSION_TTL_MS
      })
    );
  }

  function safeParseDb() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (e) {
      console.error('DB corrupt detected. Resetting to seed.', e);
      return null;
    }
  }

  function migrateDb(inputDb) {
    const safeDb = inputDb && typeof inputDb === 'object' ? inputDb : {};
    safeDb.settings = {
      ...(safeDb.settings || {}),
      limitHarian: safeDb.settings && safeDb.settings.limitHarian ? safeDb.settings.limitHarian : 20000,
      appVersion: 2
    };

    safeDb.users = Array.isArray(safeDb.users) ? safeDb.users : [];
    safeDb.auditLogs = Array.isArray(safeDb.auditLogs) ? safeDb.auditLogs : [];

    for (const user of safeDb.users) {
      if (!user.hash && user.p) {
        user.hash = user.p;
        user.p = undefined;
      }
      if (!user.hash && !user.p && !user.passwordHash) {
        user.hash = '';
      }
    }

    return safeDb;
  }

  async function migrateDbAsync() {
    const current = safeParseDb();
    const seeded = typeof window.seed === 'function' ? window.seed() : { users: [] };
    const liveDb = migrateDb(current || seeded);

    if (!Array.isArray(liveDb.users) || !liveDb.users.length) {
      liveDb.users = (seeded.users || []).map(u => ({ ...u }));
    }

    const userList = liveDb.users;
    for (let i = 0; i < userList.length; i++) {
      const user = userList[i];
      const plainPassword = user.p || user.password || user.rawPassword;
      if (user.hash && user.hash.length > 0 && !user.p) continue;
      if (plainPassword && !user.hash) {
        const pwd = await hashPassword(String(plainPassword));
        user.hash = pwd.hash;
        user.salt = pwd.salt;
        delete user.p;
        delete user.password;
        delete user.rawPassword;
      }
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(liveDb));
    return liveDb;
  }

  function ensureSecureSeed() {
    if (typeof window.seed !== 'function') return;

    const originalSeed = window.seed;
    window.seed = async function patchedSeed() {
      const base = originalSeed();
      const seededUsers = Array.isArray(base.users) ? base.users : [];

      for (const user of seededUsers) {
        if (!user.hash && user.p) {
          const hashed = await hashPassword(String(user.p));
          user.hash = hashed.hash;
          user.salt = hashed.salt;
          delete user.p;
        }
      }

      return base;
    };
  }

  function patchSave() {
    if (typeof window.save === 'function') {
      const originalSave = window.save;
      window.save = function patchedSave() {
        try {
          if (typeof localStorage !== 'undefined') {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(window.DB || {}));
          }
          return originalSave && originalSave();
        } catch (e) {
          console.error('Save failed', e);
          return false;
        }
      };
    }
  }

  function patchLogin() {
    if (typeof window.bindLogin !== 'function') return;

    const originalBindLogin = window.bindLogin;
    window.bindLogin = function patchedBindLogin() {
      originalBindLogin();

      const form = document.querySelector('#formLogin');
      if (!form || form.dataset.securePatched === 'true') return;
      form.dataset.securePatched = 'true';

      form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const fd = new FormData(form);
        const username = String(fd.get('username') || '').trim().toLowerCase();
        const password = String(fd.get('password') || '');

        const users = Array.isArray(window.DB && window.DB.users) ? window.DB.users : [];
        const target = users.find(u => String(u.u || u.username || '').trim().toLowerCase() === username);

        if (!target) {
          if (typeof window.toast === 'function') {
            window.toast('Username atau password salah', 'err');
          }
          return;
        }

        const storedHash = target.hash || target.passwordHash || '';
        const storedSalt = target.salt || '';

        const ok = await verifyPassword(password, storedHash, storedSalt);
        if (!ok) {
          if (typeof window.toast === 'function') {
            window.toast('Username atau password salah', 'err');
          }
          return;
        }

        writeSession(target);
        window.currentUser = target;
        if (typeof window.render === 'function') window.render();
      });
    };
  }

  function patchSeedValuesOnce() {
    try {
      const db = safeParseDb();
      if (!db) {
        if (typeof window.seed === 'function') {
          const base = window.seed();
          if (base && Array.isArray(base.users)) {
            window.DB = migrateDb(base);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(window.DB));
          }
        }
        return;
      }

      window.DB = migrateDb(db);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(window.DB));
    } catch (e) {
      console.error('Seed migration failed', e);
    }
  }

  function patchExportImport() {
    const exportButton = document.getElementById('btnExportData');
    if (exportButton && !exportButton.dataset.securePatched) {
      exportButton.dataset.securePatched = 'true';
      exportButton.addEventListener('click', () => {
        const payload = JSON.stringify(window.DB || {}, null, 2);
        const blob = new Blob([payload], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'assunniyyah-backup.json';
        a.click();
        URL.revokeObjectURL(a.href);
      });
    }

    const importButton = document.getElementById('btnImportData');
    if (importButton && !importButton.dataset.securePatched) {
      importButton.dataset.securePatched = 'true';
      importButton.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'application/json';
        input.onchange = (event) => {
          const file = event.target.files && event.target.files[0];
          if (!file) return;
          const reader = new FileReader();
          reader.onload = () => {
            try {
              const parsed = JSON.parse(String(reader.result));
              window.DB = migrateDb(parsed);
              localStorage.setItem(STORAGE_KEY, JSON.stringify(window.DB));
              if (typeof window.render === 'function') window.render();
              if (typeof window.toast === 'function') window.toast('Data berhasil dipulihkan', 'ok');
            } catch (e) {
              if (typeof window.toast === 'function') window.toast('File backup tidak valid', 'err');
            }
          };
          reader.readAsText(file);
        };
        input.click();
      });
    }
  }

  function patchQrParser() {
    if (typeof window.parseSiswa === 'function') {
      const original = window.parseSiswa;
      window.parseSiswa = function patchedParseSiswa(code) {
        const clean = String(code || '').trim();
        const normalized = clean.replace(/^ASN-S:/i, '').replace(/^ASN-S:ASN-S:/i, '').trim();
        if (!normalized) return null;
        const parsed = normalized.split(/\s+/).join('');
        return Array.isArray(window.DB && window.DB.siswa)
          ? window.DB.siswa.find(s => String(s.nis).trim() === String(parsed).trim()) || null
          : original(code);
      };
    }
  }

  function startSecurePatch() {
    patchSeedValuesOnce();
    patchSave();
    patchLogin();
    patchQrParser();
    patchExportImport();

    const session = readSession();
    if (session && typeof window.render === 'function') {
      const users = Array.isArray(window.DB && window.DB.users) ? window.DB.users : [];
      const match = users.find(u => String(u.u || u.username || '').toLowerCase() === String(session.userId || '').toLowerCase());
      if (match) {
        window.currentUser = match;
        window.currentView = window.currentView || 'dashboard';
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startSecurePatch, { once: true });
  } else {
    startSecurePatch();
  }
})();
