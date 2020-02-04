/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* cynagora.c  Cynagora runtime privilege checking
 *
 * Copyright (c) 2014 Samsung Electronics, Ltd.
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
#include "cynagora-check.h"
#include "check.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <dbus/dbus.h>
#include <dbus/dbus-watch.h>
#include <dbus/dbus-connection-internal.h>
#include <bus/connection.h>

#ifndef DBUS_ENABLE_CYNAGORA

BusCynagora *
bus_cynagora_new(BusCheck *check, DBusError *error)
{
  return NULL;
}

BusCynagora *
bus_cynagora_ref (BusCynagora *cynagora)
{
  return NULL;
}

void
bus_cynagora_unref (BusCynagora *cynagora)
{
}

BusResult
bus_cynagora_check_privilege (BusCynagora *cynagora,
                            DBusMessage *message,
                            DBusConnection *sender,
                            DBusConnection *addressed_recipient,
                            DBusConnection *proposed_recipient,
                            const char *privilege,
                            BusDeferredMessageStatus check_type,
                            BusDeferredMessage **deferred_message_param)
{
  return BUS_RESULT_FALSE;
}

#endif

#ifdef DBUS_ENABLE_CYNAGORA

#include <time.h>
#include <sys/epoll.h>

#include <cynagora.h>

#ifndef CYNAGORA_CACHE_SIZE
#define CYNAGORA_CACHE_SIZE 8000
#endif

typedef struct BusCynagora
{
  int refcount;

  BusContext   *context;
  BusCheck     *check;
  cynagora_t   *cynagora;
  DBusWatch    *cynagora_watch;
} BusCynagora;

static int async_callback(void *closure,
                          int op,
                          int fd,
                          uint32_t events);

BusCynagora *
bus_cynagora_new(BusCheck *check, DBusError *error)
{
  BusContext *context;
  BusCynagora *cynagora;
  int ret;

  cynagora = dbus_new(BusCynagora, 1);
  if (cynagora == NULL)
    {
      BUS_SET_OOM(error);
      return NULL;
    }

  context = bus_check_get_context(check);

  cynagora->refcount = 1;
  cynagora->check = check;
  cynagora->context = context;
  cynagora->cynagora_watch = NULL;

  ret = cynagora_create(&cynagora->cynagora, cynagora_Check, CYNAGORA_CACHE_SIZE, NULL);
  if (ret < 0)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED, "Failed to create Cynagora configuration");
    }
  else
    {
      ret = cynagora_async_setup(cynagora->cynagora, async_callback, cynagora);
      if (ret < 0)
        {
          dbus_set_error (error, DBUS_ERROR_FAILED, "Failed to initialize Cynagora client");
        }
        else
        {
          return cynagora;
        }
        cynagora_destroy(cynagora->cynagora);
    }

  dbus_free(cynagora);
  return NULL;
}

BusCynagora *
bus_cynagora_ref (BusCynagora *cynagora)
{
  _dbus_assert (cynagora->refcount > 0);
  cynagora->refcount += 1;

  return cynagora;
}

void
bus_cynagora_unref (BusCynagora *cynagora)
{
  _dbus_assert (cynagora->refcount > 0);

  cynagora->refcount -= 1;

  if (cynagora->refcount == 0)
    {
      cynagora_destroy(cynagora->cynagora);
      dbus_free(cynagora);
    }
}

static void
async_check_callback (void *closure, int status)
{
  BusDeferredMessage *deferred_message = closure;
  BusResult result;

  if (deferred_message == NULL)
    return;

  if (status == 1)
    result = BUS_RESULT_TRUE;
  else
    result = BUS_RESULT_FALSE;

  bus_deferred_message_response_received(deferred_message, result);
  bus_deferred_message_unref(deferred_message);
}

BusResult
bus_cynagora_check_privilege (BusCynagora *cynagora,
                            DBusMessage *message,
                            DBusConnection *sender,
                            DBusConnection *addressed_recipient,
                            DBusConnection *proposed_recipient,
                            const char *permission,
                            BusDeferredMessageStatus check_type,
                            BusDeferredMessage **deferred_message_param)
{
  int result;
  unsigned long uid;
  unsigned long pid;
  char *label;
  char user[32];
  char session[32];
  DBusConnection *connection = check_type == BUS_DEFERRED_MESSAGE_CHECK_RECEIVE ? proposed_recipient : sender;
  BusDeferredMessage *deferred_message;
  BusResult ret;
  cynagora_key_t key;

  _dbus_assert(connection != NULL);

  if (dbus_connection_get_unix_user(connection, &uid) == FALSE)
      return BUS_RESULT_FALSE;

  if (dbus_connection_get_unix_process_id(connection, &pid) == FALSE)
      return BUS_RESULT_FALSE;

  if (_dbus_connection_get_linux_security_label(connection, &label) == FALSE || label == NULL)
    {
      _dbus_warn("Failed to obtain security label for connection\n");
      return BUS_RESULT_FALSE;
    }

  snprintf(user, sizeof(user), "%lu", uid);
  snprintf(session, sizeof(session), "%lu", pid);

  key.client = label;
  key.session = session;
  key.user = user;
  key.permission = permission;

  result = cynagora_cache_check(cynagora->cynagora, &key);
  switch (result)
  {
  case 1:
    _dbus_verbose("Cynagora: got ALLOWED answer from cache (client=%s session_id=%s user=%s permission=%s)\n",
               label, session_id, user, permission);
    ret = BUS_RESULT_TRUE;
    break;

  case 0:
    _dbus_verbose("Cynagora: got DENIED answer from cache (client=%s session_id=%s user=%s permission=%s)\n",
               label, session_id, user, permission);
    ret = BUS_RESULT_FALSE;
    break;

  default:
     deferred_message = bus_deferred_message_new(message, sender, addressed_recipient,
         proposed_recipient, BUS_RESULT_LATER);
     if (deferred_message == NULL)
       {
         _dbus_verbose("Failed to allocate memory for deferred message\n");
         ret = BUS_RESULT_FALSE;
         goto out;
       }

    /* callback is supposed to unref deferred_message*/
    result = cynagora_async_check(cynagora->cynagora, &key, 1, 0, async_check_callback, deferred_message);
    if (result == 0)
      {
        _dbus_verbose("Created Cynagora request: client=%s session_id=%s user=%s permission=%s "
            "deferred_message=%p\n", label, session_id, user, permission, deferred_message);
        if (deferred_message_param != NULL)
          *deferred_message_param = deferred_message;
        ret = BUS_RESULT_LATER;
      }
    else
      {
        _dbus_verbose("Error on cynagora request create: %i\n", result);
        bus_deferred_message_unref(deferred_message);
        ret = BUS_RESULT_FALSE;
      }
    break;
  }
out:
  dbus_free(label);
  return ret;
}

static dbus_bool_t
watch_handler_callback(DBusWatch    *watch,
                       unsigned int  flags,
                       void         *data)
{
  BusCynagora *cynagora = (BusCynagora *)data;
  int result = cynagora_async_process(cynagora->cynagora);
  if (result < 0)
      _dbus_verbose("cynagora_async_process returned %d\n", result);

  return result != -ENOMEM ? TRUE : FALSE;
}

static int
async_callback(void *closure, int op, int fd, uint32_t events)
{
  BusCynagora *cynagora = (BusCynagora *)closure;
  DBusLoop *loop = bus_context_get_loop(cynagora->context);
  unsigned int flags;
  DBusWatch *watch;

  /* compute flags */
  flags = 0;
  if (events & EPOLLIN)
    flags |= DBUS_WATCH_READABLE;
  if (events & EPOLLOUT)
    flags |= DBUS_WATCH_WRITABLE;

  /* remove the watch if needed */
  watch = cynagora->cynagora_watch;
  if (watch != NULL)
    {
      cynagora->cynagora_watch = NULL;
      _dbus_loop_remove_watch(loop, watch);
      _dbus_watch_invalidate(watch);
      _dbus_watch_unref(watch);
    }

  /* create the watch if needed */
  watch = cynagora->cynagora_watch;
  if (op != EPOLL_CTL_DEL)
    {
      watch = _dbus_watch_new(fd, flags, TRUE, watch_handler_callback, cynagora, NULL);
      if (watch == NULL)
        return -ENOMEM;
      if (_dbus_loop_add_watch(loop, watch) != TRUE)
        {
          _dbus_watch_invalidate(watch);
          _dbus_watch_unref(watch);
          return -ENOMEM;
        }
      cynagora->cynagora_watch = watch;
    }
  return 0;
}

#endif /* DBUS_ENABLE_CYNAGORA */
