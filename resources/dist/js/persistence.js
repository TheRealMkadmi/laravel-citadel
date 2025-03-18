(function () {
  const STORAGE_KEY = "persistentFingerprint_visitor_id";
  const COOKIE_NAME = STORAGE_KEY;
  const COOKIE_DAYS = 365 * 20;

  function getCookie(name) {
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? match[2] : null;
  }
  function setCookie(name, value, days) {
    const exp = new Date();
    exp.setTime(exp.getTime() + days * 24 * 60 * 60 * 1000);
    const secureFlag = location.protocol === "https:" ? ";secure" : "";
    document.cookie = `${name}=${value};path=/;expires=${exp.toUTCString()}${secureFlag}`;
  }
  function deleteCookie(name) {
    document.cookie = `${name}=;path=/;expires=Thu, 01 Jan 1970 00:00:01 GMT;secure`;
  }

  function getLocalStorage(key) {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }
  function setLocalStorage(key, value) {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      return false;
    }
  }
  function removeLocalStorage(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (e) {
      return false;
    }
  }

  function getSessionStorage(key) {
    try {
      return sessionStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }
  function setSessionStorage(key, value) {
    try {
      sessionStorage.setItem(key, value);
      return true;
    } catch (e) {
      return false;
    }
  }
  function removeSessionStorage(key) {
    try {
      sessionStorage.removeItem(key);
      return true;
    } catch (e) {
      return false;
    }
  }

  function openIDB(dbName, storeName) {
    return new Promise((resolve, reject) => {
      try {
        const request = indexedDB.open(dbName, 1);
        const timeout = setTimeout(() => {
          reject(new Error("IndexedDB open timed out"));
        }, 3000);
        request.onupgradeneeded = function (event) {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(storeName)) {
            db.createObjectStore(storeName, { keyPath: "key" });
          }
        };
        request.onsuccess = function (event) {
          clearTimeout(timeout);
          resolve(event.target.result);
        };
        request.onerror = function (event) {
          clearTimeout(timeout);
          reject(event.target.error);
        };
      } catch (err) {
        reject(err);
      }
    });
  }

  function getFromIDB(db, storeName, key) {
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const request = store.get(key);
        const timeout = setTimeout(() => {
          resolve(null);
        }, 1000);
        request.onsuccess = () => {
          clearTimeout(timeout);
          resolve(request.result ? request.result.value : null);
        };
        request.onerror = () => {
          clearTimeout(timeout);
          reject(request.error);
        };
      } catch (err) {
        resolve(null);
      }
    });
  }

  function setToIDB(db, storeName, key, value) {
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(storeName, "readwrite");
        const store = tx.objectStore(storeName);
        const request = store.put({ key, value });
        const timeout = setTimeout(() => {
          resolve(false);
        }, 1000);
        request.onsuccess = () => {
          clearTimeout(timeout);
          resolve(true);
        };
        request.onerror = () => {
          clearTimeout(timeout);
          resolve(false);
        };
      } catch (err) {
        resolve(false);
      }
    });
  }

  function removeFromIDB(db, storeName, key) {
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(storeName, "readwrite");
        const store = tx.objectStore(storeName);
        const request = store.delete(key);
        const timeout = setTimeout(() => {
          resolve(false);
        }, 1000);
        request.onsuccess = () => {
          clearTimeout(timeout);
          resolve(true);
        };
        request.onerror = () => {
          clearTimeout(timeout);
          resolve(false);
        };
      } catch (err) {
        resolve(false);
      }
    });
  }

  class PersistentStorage {
    constructor() {
      this.cookieName = COOKIE_NAME;
      this.storageKey = STORAGE_KEY;
      this.cookieDays = COOKIE_DAYS;
      this.idbName = "PersistentStorageDB";
      this.idbStore = "PersistentStore";
      this.db = null;
      this.initialized = false;
      this.initializationPromise = null;
      this.initializationInProgress = false;
    }

    async _initialize() {
      if (this.initializationInProgress) {
        return this.initializationPromise;
      }
      if (this.initialized) {
        return Promise.resolve();
      }
      this.initializationInProgress = true;
      this.initializationPromise = (async () => {
        try {
          try {
            const idbPromise = openIDB(this.idbName, this.idbStore);
            this.db = await Promise.race([
              idbPromise,
              new Promise((_, reject) => 
                setTimeout(() => reject(new Error('IndexedDB timeout')), 2000)
              )
            ]);
          } catch (err) {
            this.db = null;
          }
        } catch (err) {
          console.error("Storage initialization error:", err);
        } finally {
          this.initialized = true;
          this.initializationInProgress = false;
        }
      })();
      return this.initializationPromise;
    }

    async set(key, value) {
      if (!key) throw new Error("Storage key is required");
      if (!this.initialized) {
        try {
          await Promise.race([
            this._initialize(),
            new Promise(resolve => setTimeout(resolve, 2000))
          ]);
        } catch (err) {
          this.initialized = true;
        }
      }
      const storageKey = `${this.storageKey}_${key}`;
      const cookieKey = `${this.cookieName}_${key}`;
      
      if (value === null) {
        // Delete the key from all storage mechanisms
        deleteCookie(cookieKey);
        removeLocalStorage(storageKey);
        removeSessionStorage(storageKey);
        const promises = [];
        if (this.db) {
          promises.push(
            Promise.race([
              removeFromIDB(this.db, this.idbStore, storageKey),
              new Promise(resolve => setTimeout(resolve, 1000))
            ])
          );
        }
        await Promise.race([
          Promise.allSettled(promises),
          new Promise(resolve => setTimeout(resolve, 2000))
        ]);
        return true;
      }

      const stringValue = typeof value === 'object' ?
          JSON.stringify(value) : String(value);
      setCookie(cookieKey, stringValue, this.cookieDays);
      setLocalStorage(storageKey, stringValue);
      setSessionStorage(storageKey, stringValue);
      const promises = [];
      if (this.db) {
        promises.push(
          Promise.race([
            setToIDB(this.db, this.idbStore, storageKey, stringValue),
            new Promise(resolve => setTimeout(resolve, 1000))
          ])
        );
      }
      await Promise.race([
        Promise.allSettled(promises),
        new Promise(resolve => setTimeout(resolve, 2000))
      ]);
      return true;
    }

    async get(key, defaultValue = null) {
      if (!key) throw new Error("Storage key is required");
      if (!this.initialized) {
        try {
          await Promise.race([
            this._initialize(),
            new Promise(resolve => setTimeout(resolve, 2000))
          ]);
        } catch (err) {
          this.initialized = true;
        }
      }
      const storageKey = `${this.storageKey}_${key}`;
      const cookieKey = `${this.cookieName}_${key}`;
      let value = getCookie(cookieKey);
      if (value) return this._parseValue(value);
      value = getLocalStorage(storageKey);
      if (value) return this._parseValue(value);
      value = getSessionStorage(storageKey);
      if (value) return this._parseValue(value);
      try {
        if (this.db) {
          value = await Promise.race([
            getFromIDB(this.db, this.idbStore, storageKey),
            new Promise(resolve => setTimeout(() => resolve(null), 1000))
          ]);
          if (value) return this._parseValue(value);
        }
      } catch (err) {
        console.warn("Error in async storage retrieval:", err);
      }
      return defaultValue;
    }

    async clear() {
      const promises = [];
      // Clear cookies with the COOKIE_NAME prefix
      const cookies = document.cookie.split(';');
      for (const cookie of cookies) {
        const [name] = cookie.trim().split('=');
        if (name.startsWith(this.cookieName)) {
          deleteCookie(name);
        }
      }

      // Clear localStorage with the STORAGE_KEY prefix
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key.startsWith(this.storageKey)) {
            removeLocalStorage(key);
          }
        }
      } catch (e) {
        console.warn("Error clearing localStorage:", e);
      }

      // Clear sessionStorage with the STORAGE_KEY prefix
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (key.startsWith(this.storageKey)) {
            removeSessionStorage(key);
          }
        }
      } catch (e) {
        console.warn("Error clearing sessionStorage:", e);
      }

      // Clear IndexedDB store
      if (this.db) {
        try {
          const tx = this.db.transaction(this.idbStore, "readwrite");
          const store = tx.objectStore(this.idbStore);
          store.clear();
        } catch (e) {
          console.warn("Error clearing IndexedDB:", e);
        }
      }

      return true;
    }

    _parseValue(value) {
      if (!value) return null;
      if ((value.startsWith('{') && value.endsWith('}')) ||
          (value.startsWith('[') && value.endsWith(']'))) {
        try {
          return JSON.parse(value);
        } catch (e) {
        }
      }
      return value;
    }
  }

  const persistence = new PersistentStorage();

  window.Persistence = {
    set: async (key, value) => persistence.set(key, value),
    get: async (key, defaultValue = null) => persistence.get(key, defaultValue),
    clear: async () => persistence.clear()
  };
})();
