JSON attribute logging for FreeRADIUS
=====================================

This is an extra module for [FreeRADIUS](https://github.com/FreeRADIUS/freeradius-server) to add the possibility to send the full packets to a logging server. The packets are serialized as JSON structures and sent via UDP to a predefined target.

Options
-------

There are a few configurable options in this module

- `log_size`: The maximum size of a logging packet. Defaults to `65400`, which is possible using the default MTU on localhost on a Linux machine. You should prevent UDP fragmentation.
- `prefix`: The text written before the log message, to make it recognizable for the remove target. Defaults to "Radius: "
- `ip`: The IP address to send the logging to. Defaults to `127.0.0.1`
- `port`: The UDP port to send the logging to. Defaults to `1514`

Why should I want to use this?
------------------------------

The most likely answer here is: you won't. Normally the vanilla logging functions from FreeRADIUS (like `rlm_sql`) are more than enough.
