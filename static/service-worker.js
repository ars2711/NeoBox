self.addEventListener("install", (e) => {
	e.waitUntil(
		caches.open("neobox-cache").then((cache) =>
			cache.addAll([
				"/",
				"/static/styles.css",
				// Add more static files here
			])
		)
	);
});
self.addEventListener("fetch", (e) => {
	e.respondWith(
		caches.match(e.request).then((resp) => resp || fetch(e.request))
	);
});
