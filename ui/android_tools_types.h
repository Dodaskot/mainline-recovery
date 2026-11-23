/* SPDX-License-Identifier: MIT */
#ifndef A22X_ANDROID_TOOLS_TYPES_H
#define A22X_ANDROID_TOOLS_TYPES_H
#define ANDROID_COMPAT_CHECKS 192u /* Full bounded 32-image analyzer reports, including optional checks. */
#define ANDROID_MODULES_MAX 96u
#define ANDROID_MODULE_CHANGES 192u
typedef struct {char id[96],status[24],reason[640];} AndroidCompatCheck;
typedef struct {char id[256],name[160],version[80],status[32],reason[384];unsigned int actions;bool disabled,remove_pending,pending_update;} AndroidModule;
typedef struct {char id[129],path[256],marker[16];bool before,after;} AndroidModuleChange;
#endif
