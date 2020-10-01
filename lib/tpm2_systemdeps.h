/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SYSTEM_H
#define SYSTEM_H

#if defined __FreeBSD__ || defined __DragonFly__
# include <sys/endian.h>
#else
# include <endian.h>
#endif

#endif
