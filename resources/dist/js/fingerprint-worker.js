self.importScripts('../vendor/laravel-citadel/js/fp.min.js');

self.FingerprintJS.load()
  .then(fp => fp.get())
  .then(result => {
    self.postMessage({visitorId: result.visitorId});
  });
