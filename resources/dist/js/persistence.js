(async function () {
    const STORAGE_KEY = "persistentFingerprint";
    const COOKIE_NAME = STORAGE_KEY;
    const COOKIE_DAYS = 365 * 20; // 20 years

    // --- Cookie Helpers ---
    function getCookie(name) {
      const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
      return match ? match[2] : null;
    }
    function setCookie(name, value, days) {
      const exp = new Date();
      exp.setTime(exp.getTime() + days * 24 * 60 * 60 * 1000);
      document.cookie = `${name}=${value};path=/;expires=${exp.toUTCString()};secure`;
    }

    // --- localStorage & sessionStorage are synchronous ---
    function getLocalStorage(key) {
      return localStorage.getItem(key);
    }
    function setLocalStorage(key, value) {
      localStorage.setItem(key, value);
    }
    function getSessionStorage(key) {
      return sessionStorage.getItem(key);
    }
    function setSessionStorage(key, value) {
      sessionStorage.setItem(key, value);
    }

    // --- Global Storage (non-standard, deprecated in modern browsers) ---
    function getGlobalStorage(key) {
      try {
        if (window.globalStorage) {
          const store = window.globalStorage[location.hostname];
          return store ? store[key] && store[key].value : null;
        }
      } catch (e) {
        // Not available or error.
      }
      return null;
    }
    function setGlobalStorage(key, value) {
      try {
        if (window.globalStorage) {
          window.globalStorage[location.hostname][key] = value;
        }
      } catch (e) {
        // Fail silently.
      }
    }

    // --- Flash Local Shared Objects (Flash cookies) ---
    function getFlashCookie(key) {
      try {
        if (window.swfobject && window.swfobject.hasFlashPlayerVersion("9.0.0")) {
          const flashCookie = document.getElementById("flash_cookie_container");
          if (flashCookie && typeof flashCookie.getCookie === "function") {
            return flashCookie.getCookie(key);
          }
        }
      } catch (e) {
        // Not available or error.
      }
      return null;
    }

    function setFlashCookie(key, value) {
      try {
        if (window.swfobject && window.swfobject.hasFlashPlayerVersion("9.0.0")) {
          const flashCookie = document.getElementById("flash_cookie_container");
          if (flashCookie && typeof flashCookie.setCookie === "function") {
            flashCookie.setCookie(key, value);
          }
        }
      } catch (e) {
        // Fail silently.
      }
    }

    // --- IndexedDB Helpers ---
    function openIDB(dbName, storeName) {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, 1);
        request.onupgradeneeded = function (event) {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(storeName)) {
            db.createObjectStore(storeName, { keyPath: "key" });
          }
        };
        request.onsuccess = function (event) {
          resolve(event.target.result);
        };
        request.onerror = function (event) {
          reject(event.target.error);
        };
      });
    }
    function getFromIDB(db, storeName, key) {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const request = store.get(key);
        request.onsuccess = () => resolve(request.result ? request.result.value : null);
        request.onerror = () => reject(request.error);
      });
    }
    function setToIDB(db, storeName, key, value) {
      return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, "readwrite");
        const store = tx.objectStore(storeName);
        const request = store.put({ key, value });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    }

    // --- Web SQL Database Helpers ---
    function openWebSQL(dbName) {
      // Open a Web SQL database (deprecated, but still available in some browsers)
      try {
        return window.openDatabase(dbName, "1.0", "Fingerprint DB", 2 * 1024 * 1024);
      } catch (e) {
        console.warn("Web SQL not supported:", e);
        return null;
      }
    }
    function initWebSQL(db) {
      return new Promise((resolve, reject) => {
        if (!db) return resolve();
        db.transaction(tx => {
          tx.executeSql(
            "CREATE TABLE IF NOT EXISTS FingerprintStore (key unique, value)",
            [],
            () => resolve(),
            (_, error) => reject(error)
          );
        });
      });
    }
    function getFromWebSQL(db, key) {
      return new Promise((resolve, reject) => {
        if (!db) return resolve(null);
        db.transaction(tx => {
          tx.executeSql(
            "SELECT value FROM FingerprintStore WHERE key = ?",
            [key],
            (_, result) => {
              if (result.rows.length > 0) {
                resolve(result.rows.item(0).value);
              } else {
                resolve(null);
              }
            },
            (_, error) => reject(error)
          );
        });
      });
    }
    function setToWebSQL(db, key, value) {
      return new Promise((resolve, reject) => {
        if (!db) return resolve();
        db.transaction(tx => {
          tx.executeSql(
            "INSERT OR REPLACE INTO FingerprintStore (key, value) VALUES (?, ?)",
            [key, value],
            () => resolve(),
            (_, error) => reject(error)
          );
        });
      });
    }

    // --- Cache API Support ---
    async function setToCache(key, value) {
      try {
        if ('caches' in window) {
          const cache = await caches.open('fingerprint-storage');
          const response = new Response(value);
          await cache.put(`https://cache.store/${key}`, response);
          return true;
        }
      } catch (e) {
        console.warn("Cache API storage failed:", e);
      }
      return false;
    }

    async function getFromCache(key) {
      try {
        if ('caches' in window) {
          const cache = await caches.open('fingerprint-storage');
          const response = await cache.match(`https://cache.store/${key}`);
          if (response) {
            return await response.text();
          }
        }
      } catch (e) {
        console.warn("Cache API retrieval failed:", e);
      }
      return null;
    }

    // --- Service Worker State ---
    async function registerServiceWorkerStore() {
      try {
        if ('serviceWorker' in navigator) {
          // Check if we already have a service worker
          const registration = await navigator.serviceWorker.getRegistration();

          if (!registration) {
            // Create a minimal service worker script for storage
            const swBlob = new Blob([`
              const CACHE_NAME = 'fingerprint-data';
              const storageData = {};

              self.addEventListener('message', (event) => {
                if (event.data && event.data.type === 'STORE') {
                  storageData[event.data.key] = event.data.value;
                  event.ports[0].postMessage({ success: true });
                } else if (event.data && event.data.type === 'RETRIEVE') {
                  event.ports[0].postMessage({
                    value: storageData[event.data.key] || null
                  });
                }
              });

              // Keep the service worker alive
              self.addEventListener('fetch', (event) => {
                if (event.request.url.includes('fingerprint-keep-alive')) {
                  event.respondWith(new Response('alive'));
                }
              });
            `], { type: 'application/javascript' });

            // Register the service worker from the blob
            const swUrl = URL.createObjectURL(swBlob);
            await navigator.serviceWorker.register(swUrl, { scope: '/' });
            URL.revokeObjectURL(swUrl);
          }

          return true;
        }
      } catch (e) {
        console.warn("Service Worker registration failed:", e);
      }
      return false;
    }

    async function storeInServiceWorker(key, value) {
      try {
        if ('serviceWorker' in navigator) {
          // Make sure service worker is registered
          await registerServiceWorkerStore();

          // Connect to service worker
          const registration = await navigator.serviceWorker.ready;
          if (registration.active) {
            // Create a message channel
            const messageChannel = new MessageChannel();

            // Return a promise that resolves when the service worker responds
            return new Promise((resolve) => {
              messageChannel.port1.onmessage = (event) => {
                resolve(event.data.success);
                messageChannel.port1.close();
              };

              registration.active.postMessage({
                type: 'STORE',
                key: key,
                value: value
              }, [messageChannel.port2]);
            });
          }
        }
      } catch (e) {
        console.warn("Service Worker storage failed:", e);
      }
      return false;
    }

    async function retrieveFromServiceWorker(key) {
      try {
        if ('serviceWorker' in navigator) {
          const registration = await navigator.serviceWorker.ready;
          if (registration.active) {
            // Create a message channel
            const messageChannel = new MessageChannel();

            // Return a promise that resolves when the service worker responds
            return new Promise((resolve) => {
              messageChannel.port1.onmessage = (event) => {
                resolve(event.data.value);
                messageChannel.port1.close();
              };

              registration.active.postMessage({
                type: 'RETRIEVE',
                key: key
              }, [messageChannel.port2]);
            });
          }
        }
      } catch (e) {
        console.warn("Service Worker retrieval failed:", e);
      }
      return null;
    }

    // --- History State ---
    function storeInHistory(key, value) {
      try {
        if (window.history && window.history.replaceState) {
          // Get current state or create new one
          const currentState = window.history.state || {};

          // Store our data in _fp namespace to avoid conflicts
          currentState._fp = currentState._fp || {};
          currentState._fp[key] = value;

          // Replace state with our modified version
          window.history.replaceState(currentState, document.title, window.location.href);
          return true;
        }
      } catch (e) {
        console.warn("History API storage failed:", e);
      }
      return false;
    }

    function getFromHistory(key) {
      try {
        if (window.history && window.history.state &&
            window.history.state._fp && window.history.state._fp[key]) {
          return window.history.state._fp[key];
        }
      } catch (e) {
        console.warn("History API retrieval failed:", e);
      }
      return null;
    }

    // --- PersistentStorage class ---
    class PersistentStorage {
      constructor() {
        this.cookieName = COOKIE_NAME;
        this.storageKey = STORAGE_KEY;
        this.cookieDays = COOKIE_DAYS;
        this.idbName = "PersistentStorageDB";
        this.idbStore = "PersistentStore";
        this.websqlName = "PersistentStorageWebSQL";
        this.db = null;         // IndexedDB instance
        this.websqlDB = null;   // Web SQL Database instance
        this.swInitialized = false; // Service worker initialization flag

        // Initialize the storage backends
        this._initialize();
      }

      // Private method to initialize storage backends
      async _initialize() {
        // Open IndexedDB
        try {
          this.db = await openIDB(this.idbName, this.idbStore);
        } catch (err) {
          console.error("IndexedDB open failed:", err);
        }
        // Open Web SQL Database and initialize table
        this.websqlDB = openWebSQL(this.websqlName);
        if (this.websqlDB) {
          try {
            await initWebSQL(this.websqlDB);
          } catch (err) {
            console.error("WebSQL initialization failed:", err);
          }
        }

        // Initialize Service Worker storage
        try {
          this.swInitialized = await registerServiceWorkerStore();
        } catch (err) {
          console.error("Service Worker initialization failed:", err);
        }

        // Keep service worker alive
        if (this.swInitialized) {
          setInterval(() => {
            fetch('/fingerprint-keep-alive').catch(() => {});
          }, 50000);
        }
      }

      // Store a value across all available persistence mechanisms
      async set(key, value) {
        if (!key) throw new Error("Storage key is required");

        const storageKey = `${this.storageKey}_${key}`;

        // Ensure databases are initialized
        if (!this.db && !this.websqlDB) {
          await this._initialize();
        }

        // Stringify objects/arrays before storage
        const stringValue = typeof value === 'object' ?
            JSON.stringify(value) : String(value);

        // Store in all available mechanisms
        setCookie(`${this.cookieName}_${key}`, stringValue, this.cookieDays);
        setLocalStorage(storageKey, stringValue);
        setSessionStorage(storageKey, stringValue);
        setGlobalStorage(storageKey, stringValue);
        setFlashCookie(storageKey, stringValue);
        storeInHistory(storageKey, stringValue);

        // Async storage mechanisms
        await setToCache(storageKey, stringValue);
        await storeInServiceWorker(storageKey, stringValue);

        // Store in IndexedDB
        if (this.db) {
          try {
            await setToIDB(this.db, this.idbStore, storageKey, stringValue);
          } catch (err) {
            console.error("IndexedDB storage error:", err);
          }
        }

        // Store in WebSQL
        if (this.websqlDB) {
          try {
            await setToWebSQL(this.websqlDB, storageKey, stringValue);
          } catch (err) {
            console.error("WebSQL storage error:", err);
          }
        }

        return true;
      }

      // Retrieve a value from any available persistence mechanism
      async get(key, defaultValue = null) {
        if (!key) throw new Error("Storage key is required");

        const storageKey = `${this.storageKey}_${key}`;
        const cookieKey = `${this.cookieName}_${key}`;

        // Ensure databases are initialized
        if (!this.db && !this.websqlDB) {
          await this._initialize();
        }

        // Check all storage mechanisms in order of priority
        const value =
          getCookie(cookieKey) ||
          getLocalStorage(storageKey) ||
          getSessionStorage(storageKey) ||
          getGlobalStorage(storageKey) ||
          getFlashCookie(storageKey) ||
          getFromHistory(storageKey);

        if (value) return this._parseValue(value);

        // Try Cache API
        const cacheValue = await getFromCache(storageKey);
        if (cacheValue) return this._parseValue(cacheValue);

        // Try Service Worker
        const swValue = await retrieveFromServiceWorker(storageKey);
        if (swValue) return this._parseValue(swValue);

        // Try IndexedDB
        if (this.db) {
          try {
            const idbValue = await getFromIDB(this.db, this.idbStore, storageKey);
            if (idbValue) return this._parseValue(idbValue);
          } catch (err) {
            console.error("IndexedDB retrieval error:", err);
          }
        }

        // Try WebSQL
        if (this.websqlDB) {
          try {
            const sqlValue = await getFromWebSQL(this.websqlDB, storageKey);
            if (sqlValue) return this._parseValue(sqlValue);
          } catch (err) {
            console.error("WebSQL retrieval error:", err);
          }
        }

        return defaultValue;
      }

      // Synchronize the value across all storage mechanisms
      async sync(key) {
        if (!key) throw new Error("Storage key is required");

        // Get the current value
        const value = await this.get(key);
        if (value === null) return false;

        // Re-save it to sync across all stores
        await this.set(key, value);
        return true;
      }

      // Helper to parse stored values
      _parseValue(value) {
        if (!value) return null;

        // Try to parse as JSON if it looks like JSON
        if ((value.startsWith('{') && value.endsWith('}')) ||
            (value.startsWith('[') && value.endsWith(']'))) {
          try {
            return JSON.parse(value);
          } catch (e) {
            // If parsing fails, return as is
          }
        }
        return value;
      }
    }

    // Initialize and expose the API - single instance only
    const persistence = new PersistentStorage();

    // Public API - simplified with only necessary methods
    window.Persistence = {
      /**
       * Store a value persistently across browser storage mechanisms
       * @param {string} key - The storage key
       * @param {any} value - The value to store (will be serialized if object)
       * @return {Promise<boolean>} - True if storage was successful
       */
      set: async (key, value) => persistence.set(key, value),

      /**
       * Retrieve a stored value from any available storage mechanism
       * @param {string} key - The storage key to retrieve
       * @param {any} defaultValue - Value to return if key not found
       * @return {Promise<any>} - The stored value or defaultValue if not found
       */
      get: async (key, defaultValue = null) => persistence.get(key, defaultValue),

      /**
       * Synchronize a value across all storage mechanisms
       * @param {string} key - The key to synchronize
       * @return {Promise<boolean>} - True if successful, false if key not found
       */
      sync: async (key) => persistence.sync(key)
    };
  })();
