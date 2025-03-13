<script defer>
  document.addEventListener('DOMContentLoaded', () => {
    // Use idle callback for all fingerprint operations
    window.requestIdleCallback(() => {
      // Helper function to dynamically load script
      const loadScript = (src) => {
        return new Promise((resolve, reject) => {
          const script = document.createElement('script');
          script.src = src;
          script.onload = () => resolve();
          script.onerror = () => reject(new Error(`Failed to load ${src}`));
          document.head.appendChild(script);
        });
      };
      // Wait for the Persistence API to become available
      const waitForPersistenceAPI = (timeout = 5000) => {
        return new Promise((resolve) => {
          if (window.Persistence?.set) return resolve(true);
          const timeoutId = setTimeout(() => resolve(false), timeout);
          const interval = setInterval(() => {
            if (window.Persistence?.set) {
              clearInterval(interval);
              clearTimeout(timeoutId);
              resolve(true);
            }
          }, 100);
        });
      };
      // Main fingerprint workflow
      async function initFingerprint() {
        // First, dynamically load the persistence library
        try {
          await loadScript("{{ asset('vendor/citadel/js/persistence.js') }}");
          const isApiAvailable = await waitForPersistenceAPI();
          if (!isApiAvailable) {
            console.warn('Persistence API not available after loading');
            return;
          }
          // Check for existing fingerprint
          let existingFingerprint = null;
          try {
            existingFingerprint = await window.Persistence.get('visitor_id');
            if (existingFingerprint) {
              console.log('Retrieved existing fingerprint');
              window.citadelFingerprint = existingFingerprint;
              window.dispatchEvent(new CustomEvent('fingerprintReady', {
                detail: { visitorId: existingFingerprint, fromCache: true }
              }));
            }
          } catch (error) {
            console.error('Error retrieving fingerprint:', error);
          }
          // Generate new fingerprint
          const worker = new Worker("{{ asset('vendor/citadel/js/fingerprint-worker.js') }}");
          worker.onmessage = async function(e) {
            const visitorId = e.data.visitorId;
            // Persist the fingerprint
            try {
              await window.Persistence.set('visitor_id', visitorId);
            } catch (error) {
              console.error('Failed to persist fingerprint:', error);
            }
            // Make globally available and dispatch event
            window.citadelFingerprint = visitorId;
            window.dispatchEvent(new CustomEvent('fingerprintReady', {
              detail: {
                visitorId,
                fromCache: false,
                changed: existingFingerprint && existingFingerprint !== visitorId
              }
            }));
            worker.terminate();
          };
        } catch (err) {
          console.error('Error in fingerprint initialization:', err);
        }
      }
      // Start the fingerprint workflow
      initFingerprint();
    }, { timeout: 10000 });
  });
</script>
