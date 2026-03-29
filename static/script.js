document.addEventListener("DOMContentLoaded", function () {
	const allowedSchemes = new Set(["light", "dark", "auto"]);
	const currentAttr = document.documentElement.getAttribute("data-bs-theme");
	const initialScheme = allowedSchemes.has(currentAttr) ? currentAttr : "light";

	function resolveTheme(scheme) {
		if (scheme === "auto") {
			return window.matchMedia("(prefers-color-scheme: dark)").matches
				? "dark"
				: "light";
		}
		return scheme === "dark" || scheme === "light" ? scheme : "light";
	}

	function setColorScheme(scheme) {
		const resolved = resolveTheme(scheme);
		document.documentElement.setAttribute("data-bs-theme", resolved);
		localStorage.setItem("colorScheme", scheme); // Store original scheme (auto/light/dark)
	}

	const storedScheme = localStorage.getItem("colorScheme");
	setColorScheme(
		allowedSchemes.has(storedScheme) ? storedScheme : initialScheme,
	);
	localStorage.removeItem("uiTheme");

	const schemeOptions = document.querySelectorAll(".scheme-option");
	schemeOptions.forEach((option) => {
		option.addEventListener("click", function (e) {
			e.preventDefault();
			const selectedScheme = this.getAttribute("data-scheme");
			setColorScheme(selectedScheme);
		});
	});

	const validatorInput = document.querySelector(
		'form[action="https://validator.w3.org/check"] > input[name="fragment"]',
	);
	if (validatorInput) {
		const html =
			"<!DOCTYPE " +
			document.doctype.name +
			(document.doctype.publicId
				? ' PUBLIC "' + document.doctype.publicId + '"'
				: "") +
			(!document.doctype.publicId && document.doctype.systemId
				? " SYSTEM"
				: "") +
			(document.doctype.systemId
				? ' "' + document.doctype.systemId + '"'
				: "") +
			">\n" +
			document.documentElement.outerHTML;
		validatorInput.value = html;
	}
});

// Fade out on link click
document.addEventListener("DOMContentLoaded", function () {
	const mainContent = document.getElementById("main-content");
	document
		.querySelectorAll('a[href]:not([target="_blank"]):not([href^="#"])')
		.forEach(function (link) {
			link.addEventListener("click", function (e) {
				// Only fade if navigating within the site
				if (
					link.hostname === window.location.hostname &&
					!link.hasAttribute("data-no-fade")
				) {
					e.preventDefault();
					mainContent.classList.remove("fade-in");
					mainContent.classList.add("fade-out");
					setTimeout(function () {
						window.location = link.href;
					}, 300); // Match the CSS transition duration
				}
			});
		});
});

// Fade in on page load
window.addEventListener("pageshow", function () {
	const mainContent = document.getElementById("main-content");
	if (mainContent) {
		mainContent.classList.remove("fade-out");
		mainContent.classList.add("fade-in");
	}
});

document.addEventListener("DOMContentLoaded", function () {
	const searchInput = document.getElementById("toolSearch");
	if (!searchInput) return;

	const cards = Array.from(document.querySelectorAll(".tool-card"));

	// Ensure all cards are visible and not hidden on load
	cards.forEach((card) => {
		card.classList.remove("hide");
		card.style.display = "";
	});
	function filterTools() {
		const q = searchInput.value.trim().toLowerCase();
		const delay = 30;
		let visibleCount = 0;

		// First, add 'hide' class to all cards that should be hidden
		cards.forEach((card) => {
			const name = card.dataset.name ? card.dataset.name.toLowerCase() : "";
			const category = card.dataset.category
				? card.dataset.category.toLowerCase()
				: "";
			const shouldShow = !q || name.includes(q) || category.includes(q);

			if (!shouldShow && !card.classList.contains("hide")) {
				card.classList.add("hide");
			}
		});

		setTimeout(() => {
			cards.forEach((card, index) => {
				const name = card.dataset.name ? card.dataset.name.toLowerCase() : "";
				const category = card.dataset.category
					? card.dataset.category.toLowerCase()
					: "";
				const shouldShow = !q || name.includes(q) || category.includes(q);

				if (shouldShow) {
					visibleCount++;
					setTimeout(() => {
						if (card.classList.contains("hide")) {
							card.style.display = "";
							// Force reflow to restart transition
							void card.offsetWidth;
							card.classList.remove("hide");
						}
					}, index * delay);
				}
			});
		}, 100);
	}

	cards.forEach((card) => {
		card.addEventListener("transitionend", function (e) {
			if (e.propertyName === "opacity" && card.classList.contains("hide")) {
				card.style.display = "none";
			}
		});
	});

	searchInput.addEventListener("input", filterTools);
	searchInput.addEventListener("keyup", function (e) {
		if (e.key === "Enter") filterTools();
	});
});

// Service Worker registration
if ("serviceWorker" in navigator) {
	window.addEventListener("load", () => {
		navigator.serviceWorker
			.register("/static/service-worker.js")
			.then((reg) => console.log("Service worker registered.", reg))
			.catch((err) => console.error("SW registration failed:", err));
	});
}

// -- Scroll Reveal Animation with Intersection Observer --
document.addEventListener("DOMContentLoaded", function () {
	const reveals = document.querySelectorAll(".reveal");

	if (!reveals.length) return;

	const observer = new IntersectionObserver(
		(entries) => {
			entries.forEach((entry) => {
				if (entry.isIntersecting) {
					entry.target.classList.add("revealed");
					observer.unobserve(entry.target);
				}
			});
		},
		{ threshold: 0.05, rootMargin: "0px 0px -50px 0px" },
	);

	reveals.forEach((element) => {
		observer.observe(element);
	});

	// Fallback: reveal all elements after 2 seconds if not triggered by scroll
	setTimeout(() => {
		reveals.forEach((element) => {
			if (!element.classList.contains("revealed")) {
				element.classList.add("revealed");
			}
		});
	}, 2000);
});

// -- Auto-dismiss flash alerts ---------------------------------
(function () {
	document.querySelectorAll(".alert-dismissible").forEach((alert) => {
		setTimeout(() => {
			const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
			if (bsAlert) bsAlert.close();
		}, 5500);
	});
})();
