# TPM2.0-tools Coding Standard

## Golden rule

* Code should hold as close to the C99 standard as possible with the exception
that GCC specific extensions are generally accepted.
* The code must compile without warnings (for the primary target compiler) if
the compiler is instructed to report all warnings.
* If some warning is unavoidable, the offensive line must be documented as to
why it can not be changed to remove the warning.
* It may also be possible to suppress specific warnings dependent on compiler
options [1]– this is acceptable but could also be dangerous if the suppression
has too large a scope.

## Commenting

There are four acceptable commenting styles: block, critical-line, next-line,
and line.

1. Block comments indicate many lines of code below are being covered by
the comment.  These are useful as file, function, algorithmic, or multi-line
equation level comments.
```
/*
 * This block comment could apply to some function and describe its inner
 * workings.  Notice these sentences have traditional capitalization and
 * punctuation... that's because it has to be read in a way completely
 * unlike the Post-It style content of next-line and line comments.
 */
```

2. Next-line comments apply only to the line of code immediately beneath them.
```
/* the next line is regular, but needs a comment */
```

3. Critical-line comments are equivalent to next-liners, but they are formatted
like block comments to indicate the line of code following (or the comment
itself) is more important than normal.
```
/*
 * This line or comment is important... at least more than usual
 */
```

4. Line comments apply to the line on which they appear, always to the right of
all code on the line. Line comments are preferred over next-liners because they
do not interrupt the vertical flow of code.
```
// This is also acceptable for a line comment.
```
```
// This is not an acceptable block comment.
// These read very imbalanced.
// Don't do this.
```

Note:

* Block comments, next-line comments and critical-line comments are formatted so
that the initial "/*" is left with the code/ scope to which it applies.

* The size of comment should be proportional to the size of the code that it
refers to. Consequently, properties of code that can fit within a single 24-line
screen should not be commented unless they are not obvious. By contrast, even
obvious global properties and invariants may need to be made explicit. This
doesn't have to be through comments, though. The assert() macro is an excellent
executable comment. [2]

* Use the next-line style if the line of code would exceed 80 characters when a
line comment is added. Next-line and line comments should be used sparingly
since they are rarely complete sentences, it is often better in the long run to
rewrite the line of code to be understandable alone or in the context of a
block comment.

* All source files and functions require leading block comments for consistency.

## Naming conventions

1. Variable names should clearly imply what their values mean. Do not rely on
the types of variables to do this.
2. Multiple word names are descriptive and most easily read if words are
separated with the underscore character, “_”.
3. DoNotUseCamelBackStyle because ItIsNotAs easy to read, especially when actual
whitespace IsAddedFor syntactical purposes.
4. It is common practice to keep variable and function names completely
lowercase.
5. Constants are usually lowercase as well, but some groups prefer the standard
of all-caps so they have the “eye feel” of older #define macros.
```
unsigned int table_index = find_index(jacket_table, “color”, COLOR_RED);
```
7. Single letter variable names should be avoided.  Exceptions are:
* i, j, k are loop counters or temporary array indexes
* m and n are row and column indexes for multidimensional arrays
* c and s are temporary/parameter characters or strings
* r, g, b, and a are red, green, blue, and alpha levels, but only when they are
used together x, y, and z are coordinate values.
8. Abbreviated words in variable names should be avoided.  Exceptions are:
* char = character
* col = column.  Typically there is also “row” so it's not confused with color
* cnt = count
* pos = position
* rem = remainder
6. Boolean variables should be named to reflect the true condition... even if the
variable is used to detect false conditions. Boolean variables should be
declared as type bool using <stdbool.h>.
```
int last_item = 0;
while(!last_item) {
     /* ... */
}
```
```
int char_found = is_alpha(c);
```
9. Function names should follow the naming conventions of variables and clearly
imply not only what the function does, but also the nature of what it returns
(if anything).
10. Functions that return boolean integers should be named to reflect the true
condition. Even if they are created to detect false conditions.
```
bool is_number_prime = is_prime(i);
if(is_number_prime) {
     /* ... */
}
```
11. Functions should never be hidden in conditional statements, with the
exception of loops where it makes the code simpler.
```
while(!labeled_correctly(sample[i])) {
     /* ... */
}
```
12. A function that is exported for use in multiple source files should be
prefixed with the source file (or object module) name it was defined in (not
declared. Infinite declarations are allowed, but only one definition).
* For example, the file list.c may contain the implementation of a dynamic list ADT
including an exported method for creating a list instance and an internal
(static) method for overflow checking.
* The first function might be named “list_create”, and the second,
“is_overflowed”.
13. A function used only within its definition source file should be declared
static (as should all variables global to only one file's scope), have no
prefix, and must not be declared in any header files.
14. A function used externally from its definition source file should be
declared extern in the source's associated header file.

## Files

1. Typically, every header file has the same base filename as an associated
source file.
2. Each header file is bound by conditional compilation commands using an
all caps and underscored variant of the complete filename.
3. Header files should never define functions or variables.
```
/*
 * File: basic_file.h
 * Header file block comment
 */
#ifndef BASIC_FILE_H
#define BASIC_FILE_H
/* standard #includes */
/* project #includes */
/* type/constant definitions */
/* extern variable declarations */
/* extern function declarations */
#endif /* BASIC_FILE_H */
```
```
/*
 * File: basic_file.c
 * Source file block comment...
 */
/* standard #includes */
/* project #includes */
#include “basic_file.h”
/* externalized variable definitions */
/* static variables (locally global) */
/* static function declarations */
/* externalized function definitions */
/* static function definitions */
```

4. Header files should only #include what is necessary to allow a file that
includes it to compile.
5. Associated source files will always #include the header of the same name, but
should #include files whose resources are used within the source even if they
are already included in that header. This provides a complete context for
readers of the source file; i.e. they don't have to search through headers to
determine  where a resource came from. For example, consider a header and source
that use FILE pointers declared in stdio.h.
* The header must #include <stdio.h> to ensure files that include it will be
able to compile.
* The corresponding source #includes the associated header and therefore receives
the benefit of stdio.h automatically.
* The source would be unnerving if the FILE type was used and stdio.h was not
#included.

## Variable Scope and types

1. Variables should be declared and scoped to the smallest scope of use. This
promotes descriptive variable names as well as dissuading variable re-use when
not proper. Also, it promotes a locality, where one can identify the variable
and it's corresponding usage in code.
```
/* This should be avoided */
void foo() {
	unsigned i;
	do_something();
	for(i=0; i < 100; i++) {
		do_more(i);
	}
}
```
```
/* Proper variable scope */
void foo() {

	do_something();
	unsigned i;
	for(i=0; i < 100; i++) {
		do_more(i);
	}
}
```

2. Variables should only be of a signed type if something should ever be
negative. A common, incorrect use, is to declare loop indices as int instead of
unsigned.

## Formatting

1. Always use space characters, 4 spaces per level of indentation.

2. Block statements encapsulated with braces should place the opening brace on
the same line after the end of the conditional statement or function parameter
list, and the closing brace at the same column position as the beginning of the
conditional statement or function return parameter, on the line immediately
after the end of the block.
```
if(some_int > 0) {
    statement1;
    statement2;
}

void some_function(arg1, arg2) {
    statement1;
    statement2;
}
```

3. Conditional statements (such as if, else, while, for, switch, etc) should
always be followed by such block statements, even if they contain only one line
statement. These formatting conditions are contrary to Kernighan and Ritchie's
“one true brace style”. [3]

4. Line Length should not exceed 80 characters and should be split on the
nearest whitespace or delimiter character.

### Formatters

Code formatters can found under misc/formatters

## Copyright Statements:
1. Copyright statements will not be included in header files, except under
certain conditions. i.e particular blocks of code originated from a different
source code base and have differing yet compatible licenses. In this case, that
code will be carefully documented.

2. Copyright statements will be permitted in the LICENSE file at the authors
discretion. They may choose to update, but it will not be required.

## License Inclusion:
All files that can contain an SPDX identifier shall contain an SPDX BSD-3 clause
identifier in a single line /* */ statement in the top of the file or closes to
top if not possible.

## References
1. Alan Bridger, Mick Brooks, and Jim Pisano, C Coding Standards, 2001,
http://www.alma.nrao.edu/development/computing/docs/joint/0009/2001-02-28.pdf
2. Jim Larson, Standards and Style for Coding in ANSI C, 1996,
http://www.jetcafe.org/jim/c-style.html
3. Brian Kernighan, Dennis Ritchie, The C Programing Language, 1988
