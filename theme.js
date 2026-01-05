(function () {
    // Immediate theme application to prevent flicker
    const theme = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    if (theme === 'dark') {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
})();

function toggleTheme() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    updateThemeIcons();
}

function updateThemeIcons() {
    const isDark = document.documentElement.classList.contains('dark');
    const sunIcons = document.querySelectorAll('.theme-sun-icon');
    const moonIcons = document.querySelectorAll('.theme-moon-icon');

    sunIcons.forEach(icon => {
        if (isDark) icon.classList.remove('hidden');
        else icon.classList.add('hidden');
    });

    moonIcons.forEach(icon => {
        if (isDark) icon.classList.add('hidden');
        else icon.classList.remove('hidden');
    });
}

// Update icons on load
document.addEventListener('DOMContentLoaded', updateThemeIcons);
