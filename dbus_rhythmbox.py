#! /usr/bin/env python
import dbus

session_bus = dbus.SessionBus()

rb_obj = session_bus.get_object(
    'org.gnome.Rhythmbox', '/org/gnome/Rhythmbox/Player')

player = dbus.Interface(rb_obj, 'org.gnome.Rhythmbox.Player')

print player.getPlayingUri()
