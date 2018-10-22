
Debian
====================
This directory contains files used to package hatchd/hatch-qt
for Debian-based Linux systems. If you compile hatchd/hatch-qt yourself, there are some useful files here.

## hatch: URI support ##


hatch-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install hatch-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your hatch-qt binary to `/usr/bin`
and the `../../share/pixmaps/hatch128.png` to `/usr/share/pixmaps`

hatch-qt.protocol (KDE)

