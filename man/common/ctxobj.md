# Context Object Format

The type of a context object, whether it is a handle or file name, is
determined according to the following logic:

  * if the argument begins with the prefix "file:" it will be treated as a
    context file, e.g. file:0x0001
  * if the argument can be loaded as a number it will be treat as a handle,
    e.g. 0x81010013
  * otherwise the object is treated as a file
