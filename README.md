# Irssi instructions

`make` (see below)

`cp build/lurch.so ~/.irssi/modules/liblurch_core.so`

`/load lurch`

`/lurch init` (in a query)

useful: add `$encryption_omemo` to your topic (in `~/.irssi/config`)

# lurch 0.6.7
/lʊʁç/. In German, an Axolotl is a type of Lurch, which simply means 'amphibian'. This plugin brings _Axolotl_, by now renamed to _double ratchet_, to _libpurple_ applications such as [Pidgin](https://www.pidgin.im/) by implementing the [XEP-0384: OMEMO Encryption](https://xmpp.org/extensions/xep-0384.html). For a higher-level overview, see [the official OMEMO homepage](https://conversations.im/omemo/).

(Plus I thought the word sounds funny.)

## News
I rewrote how MUCs are handled and they should work much better now. If not, feel free to open an issue, as usual.

The first Windows build of 0.6.6 was missing a compile-time flag, so if it does not work for you download it again, or get this version once available.

Version 0.2 of the _OMEMO XEP_ adopted the namespace actually implemented by all the clients, so there is no need for a 'compatible' version of the plugin any longer. This mostly concerns Windows users who used the `lurch_compat.dll`, so don't be confused if it's not there.

If you use a version <0.6.5, you should still definitely update for security reasons.

## Table of Contents
1. [Installation](#installation)
   1. [Linux](#linux)
   1. [Windows](#windows)
   1. [MacOS](#macos)
   1. [Additional plugins](#additional-plugins)
2. [Usage](#usage)
   1. [General](#general)
   1. [Group Chats](#group-chats)
3. [Bug Reports](#bug-reports)
4. [FAQ](#faq)
5. [Caveats](#caveats)

## Installation
### Linux
##### 1. Install the (submodules') dependencies
Below you can find the command to install the dependencies for popular distribution families. Make sure that you use at least version 2.7 of _mxml_, and 2.10.10 of _libpurple_.

__Debian, Ubuntu__
``` bash
sudo apt install git cmake libpurple-dev libmxml-dev libxml2-dev libsqlite3-dev libgcrypt20-dev
```
__ArchLinux, Parabola__
``` bash
sudo pacman -S base-devel git cmake pidgin libpurple mxml libxml2 sqlite libgcrypt
```
__Fedora__
``` bash
sudo dnf install git cmake libpurple-devel mxml-devel libxml2-devel libsqlite3x-devel libgcrypt-devel
```

##### 2A. EITHER: Build and install from source
``` bash
git clone https://github.com/gkdr/lurch/
cd lurch
git submodule update --init --recursive
make install-home
```
If you just pull a newer version (`git pull`), remember to also update the submodules as they might have changed!

The last command compiles the whole thing and copies the plugin into your local _libpurple_ plugin directory.

The next time you start Pidgin, or another libpurple client, you should be able to activate it in the "Plugins" window.

##### 2B. OR: Install from a community repo
* Arch - AUR: https://aur.archlinux.org/packages/libpurple-lurch-git/
* Fedora - COPR:  https://copr.fedorainfracloud.org/coprs/treba/pidgin-lurch/


### Windows
Thanks to [EionRobb](https://github.com/EionRobb), Windows users can use the dlls he compiled and provides here: https://eion.robbmob.com/lurch/

1. Download the plugin (_lurch.dll_) and put it in the `Program Files (x86)\Pidgin\plugins` directory.
2. Download _libgcrypt-20.dll_ and _libgpg-error-0.dll_ and put them in the `Program Files (x86)\Pidgin` directory.

These instructions can also be found at the provided link.

### MacOS
Homebrew should have all dependencies:

```
brew install cmake pidgin glib libxml2 libmxml sqlite libgcrypt
```
This should work on newer versions of MacOS, but if you run into problems check out [#8](https://github.com/gkdr/lurch/issues/8#issuecomment-285937828) for some hints. Complete instructions on how to get this running with Pidgin appreciated!

Alternatively, if you use Adium, you should definitely check out [shtrom](https://github.com/shtrom)'s [Lurch4Adium](https://github.com/shtrom/Lurch4Adium)!

### Additional plugins
The current version of _libpurple_'s _XMPP_ protocol plugin does not support many _XEPs_ by itself. For more features and compatibility with other clients such as _Conversations_ you can install the pulgins below.

#### carbons
If you have multiple devices and want messages sent and received by one device show up on all others, [XEP-0280: Message Carbons](https://xmpp.org/extensions/xep-0280.html) is what you are looking for.

You can find my plugin for it here: https://github.com/gkdr/carbons

#### pidgin-xmpp-receipts
In order to support the checkmarks for delivered messages, you could install this plugin implementing [XEP-0184: Message Delivery Receipts](https://xmpp.org/extensions/xep-0184.html):

 https://app.assembla.com/spaces/pidgin-xmpp-receipts/git/source

## Usage
### General
The first thing you can do to check if this plugin works is enter the `/lurch help` command in any conversation window. You will receive a list of the other commands you can use. I know this is a bit clunky, but using the command interface for interactions makes the plugin usable in clients that do not have a GUI.

After you have made sure it was installed correctly, you do not have to activate it specifically for each conversation partner you want to use it with, unlike with e.g. _OTR_. If it detects that the other side is using _OMEMO_ (by the existence of an _OMEMO_ devicelist), the conversation will be encrypted automatically. If you do not want this, you can blacklist the user by typing `/lurch blacklist add` in the conversation window.

This plugin will set the window title to notify the user if encryption is enabled or not. If it is, it will generally not send plaintext messages. If a plaintext message is received in a chat that is supposed to be encrypted, the user will be warned.

### Group Chats
Group chats (via [XEP-0045: Multi-User Chat](https://xmpp.org/extensions/xep-0045.html) aka MUCs) are __not__ part of the _OMEMO_ specification, but can work under specific circumstances as outlined on the [_Conversations_ README](https://github.com/siacs/Conversations/blob/master/README.md#omemo). These are:
* The MUC has to be non-anonymous so the real JID of each participant is visible. The channel owner has to set this property. In Pidgin you can get there by typing `/config`.
* Every participant has to be in every other participant's contact list! This is why this really only makes sense for member-only MUCs.

Once you have confirmed these conditions are met, every member has to activate _OMEMO_ him- or herself. Using this plugin it works by typing `/lurch enable`. Warning messages are displayed if it does not work for every user in the conference, hopefully helping to fix the issue.

It is __recommended__ you confirm the fingerprints look the same on each device, including among your own.To do this, you can e.g. display all fingerprints participating in a conversation using `/lurch show fp conv`.

## Bug Reports
If something does not work as expected, don't hesitate to open an issue.
You can also reach me on the Pidgin IRC channel (#pidgin on freenode) as `riba`, or send me an email.

It will usually be helpful (i.e. I will probably ask for it anyway) if you provide me with some information from the debug log, which you can find at _Help->Debug Window_ in Pidgin.

In case it is more serious and Pidgin crashes, I will have to ask you for a backtrace.
You can obtain it in the following way:
* Open Pidgin in gdb: `gdb pidgin`
* Run it: `run`
* Do whatever you were doing to make it crash
* When it does crash, type `bt` (or `backtrace`)
* Copy the whole thing

## FAQ
### Can it talk to other OMEMO clients?
__Yes__, it was (briefly) tested with:
* [Conversations](https://conversations.im/) (Android)
* [The gajim OMEMO plugin](https://dev.gajim.org/gajim/gajim-plugins/wikis/OmemoGajimPlugin) (Desktop OSs)
* [ChatSecure](https://chatsecure.org/) (iOS)

See https://omemo.top/ for additional clients.

### Does it work with Finch?
It should, but I only tried it briefly.

## Caveats
_OMEMO_ is not 'whatever Conversations can do', but a very specific _XEP_.

For instance, if you don't install the additional plugin mentioned above, this is probably not the right thing to use if you have multiple clients running at the same time, as there is no message carbons support in libpurple as of now.

At the moment, there is no [XEP-0313: Message Archive Management](https://xmpp.org/extensions/xep-0313.html) aka _MAM_ support in _libpurple_, so there are no 'offline messages'.

Finally, I can't stress this enough: This plugin is _highly experimental_, so you __should not trust your life on it__.
