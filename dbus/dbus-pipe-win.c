/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-pipe-win.c windows related pipe implementation
 * 
 * Copyright (C) 2002, 2003, 2006  Red Hat, Inc.
 * Copyright (C) 2003 CodeFactory AB
 *
 * Licensed under the Academic Free License version 2.1
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>
#include "dbus-protocol.h"
#include "dbus-string.h"
#include "dbus-internals.h"
#include "dbus-pipe.h"

#include <io.h>
#include <errno.h>

/**
 * write data to a pipe.
 *
 * @param pipe the pipe instance
 * @param buffer the buffer to write data from
 * @param start the first byte in the buffer to write
 * @param len the number of bytes to try to write
 * @param error error return
 * @returns the number of bytes written or -1 on error
 */
int
_dbus_pipe_write (DBusPipe         *pipe,
                  const DBusString *buffer,
                  int               start,
                  int               len,
                  DBusError        *error)
{
  int written;
  const char *buffer_c = _dbus_string_get_const_data (buffer);

  written = _write (pipe->fd_or_handle, buffer_c + start, len);
  if (written < 0)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Writing to pipe: %s\n",
                      strerror (errno));
    }
  return written;
}

/**
 * close a pipe.
 *
 * @param pipe the pipe instance
 * @param error return location for an error
 * @returns #FALSE if error is set
 */
int
_dbus_pipe_close  (DBusPipe         *pipe,
                   DBusError        *error)
{
  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (_close (pipe->fd_or_handle) < 0)
    {
      dbus_set_error (error, _dbus_error_from_errno (errno),
                      "Could not close pipe %d: %s", pipe->fd_or_handle, strerror (errno));
      return -1;
    }
  else
    {
      _dbus_pipe_invalidate (pipe);
      return 0;
    }
}
