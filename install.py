import launch

if not launch.is_installed("watchdog"):
    launch.run_pip("install watchdog", "SD Encrypt Image requirements: watchdog")
