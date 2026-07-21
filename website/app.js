const navToggle = document.querySelector(".nav-toggle");
const nav = document.querySelector(".site-nav");

if (navToggle && nav) {
  navToggle.addEventListener("click", () => {
    const isOpen = navToggle.getAttribute("aria-expanded") === "true";
    navToggle.setAttribute("aria-expanded", String(!isOpen));
    nav.classList.toggle("open", !isOpen);
    document.body.classList.toggle("nav-open", !isOpen);
  });

  nav.addEventListener("click", (event) => {
    if (!event.target.closest("a")) return;
    navToggle.setAttribute("aria-expanded", "false");
    nav.classList.remove("open");
    document.body.classList.remove("nav-open");
  });
}

const gallery = document.querySelector("[data-gallery]");

if (gallery) {
  const tabs = [...gallery.querySelectorAll('[role="tab"]')];
  const image = gallery.querySelector("[data-gallery-image]");
  const caption = gallery.querySelector("[data-gallery-caption]");
  const description = gallery.querySelector("[data-gallery-description]");

  function selectTab(tab) {
    tabs.forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
    image.src = tab.dataset.image;
    image.alt = tab.dataset.alt;
    caption.textContent = tab.dataset.caption;
    description.textContent = tab.dataset.description;
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const direction = event.key === "ArrowRight" ? 1 : -1;
      const nextTab = tabs[(index + direction + tabs.length) % tabs.length];
      nextTab.focus();
      selectTab(nextTab);
    });
  });
}
