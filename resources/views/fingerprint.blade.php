<script defer>
  (function () {
    const FINGERPRINT_STORAGE_KEY = 'persistentFingerprint_visitor_id';
    const FINGERPRINT_HEADER = 'X-Fingerprint';
    const FINGERPRINT_COOKIE = 'persistentFingerprint_visitor_id';

    function loadScript(src, type = '') {
      return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        if (type) script.type = type;
        script.onload = resolve;
        script.onerror = reject;
        document.body.appendChild(script);
      });
    }

    async function doFingerprinting() {
      try {
        await loadScript("{{ asset('vendor/citadel/js/persistence.js') }}");
        let cachedId;
        try {
          cachedId = await window.Persistence.get(FINGERPRINT_STORAGE_KEY);
        } catch (error) {
          console.error('Error retrieving cached fingerprint:', error);
        }
        if (cachedId) {
          handleFingerprint(cachedId, true);
        } else {
          await loadFingerprintJS();
        }
      } catch (error) {
        console.error('Error loading persistence script:', error);
      }
    }

    async function loadFingerprintJS() {
      try {
        await loadScript("https://cdn.jsdelivr.net/npm/@thumbmarkjs/thumbmarkjs/dist/thumbmark.umd.js", "text/javascript");
        const visitorId = await ThumbmarkJS.getFingerprint();
        console.log('Generated fingerprint:', visitorId);
        if (window.Persistence && visitorId) {
          try {
            await window.Persistence.set(FINGERPRINT_STORAGE_KEY, visitorId);
          } catch (error) {
            console.error('Error storing fingerprint:', error);
          }
        }
        handleFingerprint(visitorId, false);
      } catch (error) {
        console.error('Error loading FingerprintJS:', error);
      }
    }

    function setCookie(name, value, days = 365) {
      const date = new Date();
      date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
      const expires = "; expires=" + date.toUTCString();
      document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax";
    }

    function setupFormSubmissionHandling(visitorId) {
      // Set cookie immediately
      setCookie(FINGERPRINT_COOKIE, visitorId);
      
      // Handle all form submissions
      document.addEventListener('submit', function(e) {
        const form = e.target;
        
        // For regular form submissions, ensure cookie is set
        setCookie(FINGERPRINT_COOKIE, visitorId);
        
        // For AJAX form submissions via fetch
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
          options = options || {};
          options.headers = options.headers || {};
          options.headers[FINGERPRINT_HEADER] = visitorId;
          return originalFetch(url, options);
        };
        
        // For AJAX form submissions via XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function() {
          const xhrInstance = this;
          const originalSend = this.send;
          
          this.send = function(body) {
            xhrInstance.setRequestHeader(FINGERPRINT_HEADER, visitorId);
            return originalSend.apply(this, arguments);
          };
          
          return originalXHROpen.apply(this, arguments);
        };
      });
    }

    function handleFingerprint(visitorId, fromCache) {
      window.citadelFingerprint = visitorId;
      
      // Setup form submission handling with the fingerprint
      setupFormSubmissionHandling(visitorId);
      
      window.dispatchEvent(new CustomEvent('fingerprintReady', {
        detail: {
          visitorId: visitorId,
          fromCache: fromCache
        }
      }));
    }

    function initFingerprinting() {
      if ('requestIdleCallback' in window) {
        requestIdleCallback(doFingerprinting, { timeout: 2000 });
      } else {
        setTimeout(doFingerprinting, 50);
      }
    }

    // Debug mode utility functions
    @if(config('app.debug'))
    async function cleanCitadelTrace() {
      console.log('Clearing Citadel fingerprint traces...');
      try {
      // Ensure persistence script is loaded
      if (!window.Persistence) {
        await loadScript("{{ asset('vendor/citadel/js/persistence.js') }}");
      }

      // Clear fingerprint from all storage mechanisms
      await window.Persistence.set(FINGERPRINT_STORAGE_KEY, null);

      // Clear window objects
      window.citadelFingerprint = null;
      window.fpJs = null;

      console.log('Citadel fingerprint traces cleared successfully');
      return true;
      } catch (error) {
      console.error('Error clearing Citadel fingerprint:', error);
      return false;
      }
    }

    async function refreshFingerprint() {
      console.log('Refreshing Citadel fingerprint...');
      try {
      // First clean all traces
      await cleanCitadelTrace();

      // Generate new fingerprint
      await loadFingerprintJS();

      console.log('Citadel fingerprint refreshed successfully');
      return true;
      } catch (error) {
      console.error('Error refreshing Citadel fingerprint:', error);
      return false;
      }
    }

    // Expose debug functions globally
    window.cleanCitadelTrace = cleanCitadelTrace;
    window.refreshFingerprint = refreshFingerprint;
  @endif

    if (document.readyState === 'complete') {
      initFingerprinting();
    } else {
      window.addEventListener('load', initFingerprinting);
    }
  })();
</script>