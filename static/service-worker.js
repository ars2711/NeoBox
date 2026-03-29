self.addEventListener("install", (e) => {
	e.waitUntil(
		caches
			.open("neobox-cache")
			.then((cache) =>
				cache.addAll([
					"/",
					"/static/styles.css",
					"/static/script.js",
					"/static/logos/favicon.png",
					"/static/logos/favicon.ico",
					"/static/logos/logo-192.png",
					"/static/logos/logo-512.png",
					"/static/logos/logo.png",
					"/static/logos/apple-touch-icon.png",
				]),
			),
	);
});
self.addEventListener("fetch", (e) => {
	e.respondWith(
		caches.match(e.request).then((resp) => resp || fetch(e.request)),
	);
});
