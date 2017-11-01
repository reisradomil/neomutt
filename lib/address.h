/**
 * @file
 * Representation of an email address
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

#ifndef _LIB_ADDRESS_H
#define _LIB_ADDRESS_H

#include <stdbool.h>
#include <stdio.h>

extern const char RFC822Specials[];
extern int RFC822Error;
extern const char *const RFC822Errors[];

#define rfc822_error(x) RFC822Errors[x]

/**
 * struct Address - An email address
 */
struct Address
{
  char *personal; /**< real name of address */
  char *mailbox;  /**< mailbox and host address */
  int group;      /**< group mailbox? */
  struct Address *next;
  bool is_intl : 1;
  bool intl_checked : 1;
};

/**
 * enum AddressError - possible values for RFC822Error
 */
enum AddressError
{
  ERR_MEMORY = 1,
  ERR_MISMATCH_PAREN,
  ERR_MISMATCH_QUOTE,
  ERR_BAD_ROUTE,
  ERR_BAD_ROUTE_ADDR,
  ERR_BAD_ADDR_SPEC
};

struct Address *rfc822_new_address(void);
struct Address *rfc822_cpy_adrlist(struct Address *addr, int prune);
struct Address *rfc822_cpy_adr(struct Address *addr);
struct Address *rfc822_append(struct Address **a, struct Address *b, int prune);
bool            rfc822_valid_msgid(const char *msgid);
void            rfc822_free_address(struct Address **p);
void            rfc822_qualify(struct Address *addr, const char *host);
struct Address *rfc822_parse_adrlist(struct Address *top, const char *s);
void            rfc822_cat(char *buf, size_t buflen, const char *value, const char *specials);
int             rfc822_remove_from_adrlist(struct Address **a, const char *mailbox);

#endif /* _LIB_ADDRESS_H */
