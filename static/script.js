document.addEventListener("DOMContentLoaded", function () {
	// Set up theme handling
	const themeIcon = document.getElementById("theme-icon");
	const themeToggle = document.getElementById("theme-toggle");

	function setTheme(theme) {
		document.documentElement.setAttribute("data-bs-theme", theme);
		localStorage.setItem("theme", theme);
		if (themeIcon) {
			themeIcon.className = theme === "dark" ? "bi bi-sun" : "bi bi-moon";
		}
	}

	// Initialize theme
	let currentTheme = localStorage.getItem("theme");
	if (!currentTheme) {
		currentTheme = "light"; // Default to light theme
		localStorage.setItem("theme", currentTheme);
	}
	setTheme(currentTheme);

	// Set up theme toggle
	if (themeToggle) {
		themeToggle.onclick = function () {
			const newTheme =
				document.documentElement.getAttribute("data-bs-theme") === "dark"
					? "light"
					: "dark";
			setTheme(newTheme);
		};
	}

	const validatorInput = document.querySelector(
		'form[action="https://validator.w3.org/check"] > input[name="fragment"]'
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
			.then((reg) => console.log("✅ Service worker registered!", reg))
			.catch((err) => console.error("❌ SW registration failed: ", err));
	});
}
