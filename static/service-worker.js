self.addEventListener("install", (e) => {
	e.waitUntil(
		caches
			.open("neobox-cache")
			.then((cache) =>
				cache.addAll([
					"/",
					"/static/styles.css",
					"/static/themes.css",
					"/static/script.js",
					"/static/favicon.ico",
					"/static/icons/neobox-light.svg",
					"/static/icons/neobox-dark.svg",
					"/static/icons/icon-192x192.png",
					"/static/icons/icon-512x512.png",
					"/static/icons/neobox-192.svg",
					"/static/icons/neobox-512.svg"
				])
			)
	);
});
self.addEventListener("fetch", (e) => {
	e.respondWith(
		caches.match(e.request).then((resp) => resp || fetch(e.request))
	);
});
