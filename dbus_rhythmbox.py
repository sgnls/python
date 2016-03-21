#! /usr/bin/env python
import dbus

session_bus = dbus.SessionBus()

proxy_obj = session_bus.get_object(
    'org.gnome.Rhythmbox', '/org/gnome/Rhythmbox/Player')

player = dbus.Interface(proxy_obj, 'org.gnome.Rhythmbox.Player')

print player.getPlayingUri()
