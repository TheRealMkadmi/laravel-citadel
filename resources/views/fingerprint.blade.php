<script defer>
  (function() {
    const FINGERPRINT_STORAGE_KEY = 'visitor_id';
    
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
      } catch(error) {
        console.error('Error loading persistence script:', error);
      }
    }

    async function loadFingerprintJS() {
      try {
        const fpModule = await import("{{ asset('vendor/citadel/js/fp.min.js') }}");
        window.FingerprintJS = fpModule.default;
        const fp = await window.FingerprintJS.load();
        const result = await fp.get();
        window.fpJs = result;
        console.log('FingerprintJS loaded:', result);
        const visitorId = result.visitorId;
        console.log('Generated fingerprint:', visitorId);
        if (window.Persistence && visitorId) {
          try {
            await window.Persistence.set(FINGERPRINT_STORAGE_KEY, visitorId);
          } catch (error) {
            console.error('Error storing fingerprint:', error);
          }
        }
        handleFingerprint(visitorId, false);
      } catch(error) {
        console.error('Error loading FingerprintJS:', error);
      }
    }

    function handleFingerprint(visitorId, fromCache) {
      window.citadelFingerprint = visitorId;
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
