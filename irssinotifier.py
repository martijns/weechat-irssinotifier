# Author: Caspar Clemens Mierau <ccm@screenage.de>, Martijn Stolk <martijn.stolk@gmail.com>
# Homepage: https://github.com/leitmedium/weechat-irssinotifier
# Derived from: notifo
#   Author: ochameau <poirot.alex AT gmail DOT com>
#   Homepage: https://github.com/ochameau/weechat-notifo
# And from: notify
#   Author: lavaramano <lavaramano AT gmail DOT com>
#   Improved by: BaSh - <bash.lnx AT gmail DOT com>
#   Ported to Weechat 0.3.0 by: Sharn - <sharntehnub AT gmail DOT com)
# And from: notifo_notify
#   Author: SAEKI Yoshiyasu <laclef_yoshiyasu@yahoo.co.jp>
#   Homepage: http://bitbucket.org/laclefyoshi/weechat/
#
# This plugin brings IrssiNotifier to your Weechat. Setup and install
# IrssiNotifier first: https://irssinotifier.appspot.com
#
# Requires Weechat >= 0.3.7, openssl
# Released under GNU GPL v3
#
# 2013-07-27, Martijn Stolk <martijn.stolk@gmail.com>:
#     version 0.6: - openssl execution is asynchronous now as well, as it
#                    could take up some more time on slow machines
#                  - group messages that shortly follow each other as a
#                    single message. Useful for receiving multiline messages
#                    when using jabber, bitlbee or similar software. Time
#                    is configurable via the configuration setting
#                    'group_messages_time_ms' (default: 1000).
#                    Set to 0 to disable.
# 2013-01-18, ccm <ccm@screenage.de>:
#     version 0.5: - removed version check and legacy curl usage
# 2012-12-27, ccm <ccm@screenage.de>:
#     version 0.4: - use non-blocking hook_process_hashtable for url call
#                    for weechat >= 0.3.7
# 2012-12-22, ccm <ccm@screenage.de>:
#     version 0.3: - no longer notifies if the message comes from the user
#                    itself
#                  - removed curl dependency
#                  - cleaned up openssl call
#                  - no more crashes due to missing escaping
#                  - Kudos to Juergen "@tante" Geuter <tante@the-gay-bar.com>
#                    for the patches!
# 2012-10-27, ccm <ccm@screenage.de>:
#     version 0.2: - curl uses secure command call (decreases risk of command
#                    injection)
#                  - correct split of nick and channel name in a hilight
# 2012-10-26, ccm <ccm@screenage.de>:
#     version 0.1: - initial release - working proof of concept

import weechat, string, os, urllib, shlex, pickle, sys, tempfile

# Functions
def notify_show(data, bufferp, uber_empty, tagsn, isdisplayed,
        ishilight, prefix, message):

    #get local nick for buffer
    mynick = weechat.buffer_get_string(bufferp,"localvar_nick")

    # only notify if the message was not sent by myself
    if (weechat.buffer_get_string(bufferp, "localvar_type") == "private") and (prefix!=mynick):
            add_notification(prefix, prefix, message)

    elif ishilight == "1":
        buffer = (weechat.buffer_get_string(bufferp, "short_name") or
                weechat.buffer_get_string(bufferp, "name"))
        add_notification(buffer, prefix, message)

    return weechat.WEECHAT_RC_OK

def add_notification(chan, nick, message):
    global notifications, sendtimer

    # If the timer is already running, we'll restart it.
    if sendtimer:
        weechat.unhook(sendtimer)

    # Add the notification
    notifications.append({'chan': chan, 'nick': nick, 'message': message})

    # Start the timer after which we will send the messages
    group_messages_time_ms = int(weechat.config_get_plugin("group_messages_time_ms"))
    if group_messages_time_ms == 0:
        prepare_notifications_cb("", "")
    else:
        sendtimer = weechat.hook_timer(group_messages_time_ms, 0, 1, "prepare_notifications_cb", "")

def prepare_notifications_cb(data, remaining_calls):
    global notifications
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: Preparing notifications...")

    # Make sure we have an API token to begin with
    if not weechat.config_get_plugin("api_token"):
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: plugin option 'api_token' is not set, not sending notifications...")
        return weechat.WEECHAT_RC_OK

    # Assume that within the 'group message time' only one person caused a notification.
    message = ""
    for notification in notifications:
        chan = notification['chan']
        nick = notification['nick']
        if len(message) == 0:
            message = notification['message']
        else:
            message = message + "\n" + notification['message']

    # Log that we combined messages
    if is_debug() and len(notifications) > 1:
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: more than one notification within grouping time, combined %d notifications into chan: %s, nick: %s, message: %s" % (len(notifications), chan, nick, message))

    # Make a new object with all the values that we need encrypted
    notificationdata = {
        'tmpfile': "",
        'password': weechat.config_get_plugin("encryption_password"),
        'cryptdata': {
            'chan': {'value': chan, 'isencrypted': False},
            'nick': {'value': nick, 'isencrypted': False},
            'message': {'value': message, 'isencrypted': False}
        }
    }

    # Clear the notifications
    notifications = []

    # Start the async encrypting
    encrypt_notification_cb(pickle.dumps(notificationdata), "", 0, "", "")
    return weechat.WEECHAT_RC_OK

def encrypt_notification_cb(data, command, return_code, out, err):
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: encryption callback, out: %s, err: %s" % (out, err))

    # Deserialize the data
    data = pickle.loads(data)
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: current data: %s" % repr(data))

    # Bail out if something went wrong
    if return_code != 0:
        if is_debug():
            weechat.prnt(weechat.buffer_search_main(), "irssinotifier: openssl returned unexpected status code: %d" % return_code)
        return weechat.WEECHAT_RC_OK

    # Process the output if we have an output (first call doesn't have an output)
    if len(out) > 0:
        out = string.replace(out,"/","_")
        out = string.replace(out,"+","-")
        out = string.replace(out,"=","")
        for k, v in data['cryptdata'].iteritems():
            if v['isencrypted'] == False:
                if is_debug():
                    weechat.prnt(weechat.buffer_search_main(), "irssinotifier: encrypted '%s' from '%s' to '%s'" % (k, v['value'], out))
                v['value'] = out
                v['isencrypted'] = True
                break

    # Determine if anything is left unencrypted
    unencryptedValue = ""
    for k, v in data['cryptdata'].iteritems():
        if v['isencrypted'] == False:
            unencryptedValue = v['value']
            break

    # Something is left unencrypted, do another pass
    if len(unencryptedValue) > 0:

        # See if we have a tmpfile to work with yet, as we cannot send stdin to hook_process()
        if len(data['tmpfile']) == 0:
            f = tempfile.NamedTemporaryFile(delete=False)
            data['tmpfile'] = f.name
            if is_debug():
                weechat.prnt(weechat.buffer_search_main(), "irssinotifier: created temp file: %s" % data['tmpfile'])
        else:
            f = open(data['tmpfile'], 'w')
            if is_debug():
                weechat.prnt(weechat.buffer_search_main(), "irssinotifier: opened temp file: %s" % data['tmpfile'])

        # Write the unencrypted value to this file
        f.write(unencryptedValue + "\n")
        f.flush()

        # Encrypt it
        command="openssl enc -aes-128-cbc -salt -base64 -A -pass pass:%s -in %s" % (data['password'], f.name)
        if is_debug():
            weechat.prnt(weechat.buffer_search_main(), "irssinotifier: more encrypting to do, starting openssl process")
        weechat.hook_process(command, 30000, "encrypt_notification_cb", pickle.dumps(data))

    # There are no unencrypted values anymore
    else:

        if is_debug():
            weechat.prnt(weechat.buffer_search_main(), "irssinotifier: done encrypting, cleaning up and moving on")

        # Cleanup
        if len(data['tmpfile']) > 0 and os.path.exists(data['tmpfile']):
            if is_debug():
                weechat.prnt(weechat.buffer_search_main(), "irssinotifier: deleting temp file: %s" % data['tmpfile'])
            os.unlink(data['tmpfile'])

        # Send it
        send_notification(data)

    return weechat.WEECHAT_RC_OK

def send_notification(data):
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: sending notification")
    api_token = weechat.config_get_plugin("api_token")
    url = "https://irssinotifier.appspot.com/API/Message"
    nick = data['cryptdata']['nick']['value']
    chan = data['cryptdata']['chan']['value']
    message = data['cryptdata']['message']['value']
    postdata = urllib.urlencode({'apiToken':api_token,'nick':nick,'channel':chan,'message':message,'version':13})
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: postdata: %s" % postdata)
    hook1 = weechat.hook_process_hashtable("url:"+url, { "postfields":  postdata}, 30000, "send_notification_cb", "")

def send_notification_cb(data, command, return_code, out, err):
    if is_debug():
        weechat.prnt(weechat.buffer_search_main(), "irssinotifier: sent notification, return_code: %d" % return_code)
    return weechat.WEECHAT_RC_OK

def is_debug():
    return weechat.config_string_to_boolean(weechat.config_get_plugin("debug"))

# Plugin entry method
if __name__ == "__main__":
    weechat.register("irssinotifier", "Caspar Clemens Mierau <ccm@screenage.de>, Martijn Stolk <martijn.stolk@gmail.com>", "0.6", "GPL3", "irssinotifier: Send push notifications to Android's IrssiNotifier about your private message and highligts.", "", "")

    # Initialize some variables
    settings = {
        "api_token": "",
        "encryption_password": "",
        "debug": "off",
        "group_messages_time_ms": "1000"
    }
    notifications = []
    sendtimer = None

    # Set initial plugin values so they can be found in /set
    for option, default_value in settings.items():
        if not weechat.config_get_plugin(option):
            weechat.config_set_plugin(option, default_value)

    # Check mandatory settings
    if not weechat.config_get_plugin("api_token"):
        weechat.prnt(weechat.buffer_search_main(), weechat.prefix("error") + "irssinotifier: Please configure your API token: /set plugins.var.python.irssinotifier.api_token <token>")
    if not weechat.config_get_plugin("encryption_password"):
        weechat.prnt(weechat.buffer_search_main(), weechat.prefix("error") + "irssinotifier: Please configure your encryption password: /set plugins.var.python.irssinotifier.encryption_password <password>")

    # Hook privmsg/hilights
    weechat.hook_print("", "irc_privmsg", "", 1, "notify_show", "")

# vim: autoindent expandtab smarttab shiftwidth=4
