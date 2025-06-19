self.addEventListener("install", (e) => {
	e.waitUntil(
		caches
			.open("neobox-cache")
			.then((cache) =>
				cache.addAll([
					"/",
					"/static/styles.css",
					"/static/script.js",
					"/static/favicon.ico",
				])
			)
	);
});
self.addEventListener("fetch", (e) => {
	e.respondWith(
		caches.match(e.request).then((resp) => resp || fetch(e.request))
	);
});
