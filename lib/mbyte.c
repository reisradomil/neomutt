/**
 * @file
 * Multi-byte String manipulation functions
 *
 * @authors
 * Copyright (C) 2017 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page mbyte Multi-byte String manipulation functions
 *
 * Some commonly-used multi-byte string manipulation routines.
 *
 * | Function                  | Description
 * | :------------------------ | :---------------------------------------------------------
 */

#include "config.h"
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include "string2.h"

/**
 * mutt_charlen - Count the bytes in a (multibyte) character
 * @param[in]  s     String to be examined
 * @param[out] width Number of screen columns the character would use
 * @retval n  Number of bytes in the first (multibyte) character of input consumes
 * @retval <0 Conversion error
 * @retval =0 End of input
 * @retval >0 Length (bytes)
 */
int mutt_charlen(const char *s, int *width)
{
  wchar_t wc;
  mbstate_t mbstate;
  size_t k, n;

  if (!s || !*s)
    return 0;

  n = mutt_strlen(s);
  memset(&mbstate, 0, sizeof(mbstate));
  k = mbrtowc(&wc, s, n, &mbstate);
  if (width)
    *width = wcwidth(wc);
  return (k == (size_t)(-1) || k == (size_t)(-2)) ? -1 : k;
}
