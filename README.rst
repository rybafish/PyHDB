RybaFish Fork of the PyHDB Driver
===================================
This is a fork of standard SAP PyHDB SAP HANA driver implementing list of key SAP HANA features missing in the original version.

Such features include:

* extended formats suppurt, such as longdate, etc
* commit/rollback support
* multiple resultsets support
* fetch for over 32k rows
* proper utf8 support
* other minor fixes

Unfortunately, SAP dicided to close the open-source version of the driver and those features were rejected to be merged in the standard one.
