# Overview

IDA scripts to help you:

- [`objc_stubs.py`](objc_stubs.py)
    - Fix all `objc_*` symbol types
- [`objc_hotkeys.py`](objc_hotkeys.py)
  - Add `Ctrl+4` HotKey to quickly navigate to selector's Xrefs.


# Before and After

Before running [`objc_stubs.py`](objc_stubs.py):

![](before.png)

After running [`objc_stubs.py`](objc_stubs.py):

![](after.png)

As you can see:

- The scripts fixed all selectors signatures:
  - For example: `int __cdecl __spoils<X0,X1,X2,X3,X4,X5,X6,X7> objc_msgSend_initWithCapacity_(id object, __unused SEL selector, id initWithCapacity)`
- In addition to fixing the `objc_retain/release` which now access high registers.
  - For example: `id __usercall __spoils<> objc_retain_x20_45@<X0>(id x20@<X20>)`

This makes it much easier to navigate through the code flow.

Have fun!
