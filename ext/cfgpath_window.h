/**
 * @file  cfgpath.h
 * @brief Cross platform methods for obtaining paths to configuration files.
 *
 * Copyright (C) 2013 Adam Nielsen <malvineous@shikadi.net>
 *
 * This code is placed in the public domain.  You are free to use it for any
 * purpose.  If you add new platform support, please contribute a patch!
 *
 * Example use:
 *
 * char cfgdir[256];
 * get_user_config_file(cfgdir, sizeof(cfgdir), "myapp");
 * if (cfgdir[0] == 0) {
 *     printf("Unable to find home directory.\n");
 *     return 1;
 * }
 * printf("Saving configuration file to %s\n", cfgdir);
 *
 * A number of constants are also defined:
 *
 *  - MAX_PATH: Maximum length of a path, in characters.  Used to allocate a
 *      char array large enough to hold the returned path.
 *
 *  - PATH_SEPARATOR_CHAR: The separator between folders.  This will be either a
 *      forward slash or a backslash depending on the platform.  This is a
 *      character constant.
 *
 *  - PATH_SEPARATOR_STRING: The same as PATH_SEPARATOR_CHAR but as a C string,
 *      to make it easier to append to other string constants.
 */

#ifndef CFGPATH_H_WINDOW
#define CFGPATH_H_WINDOW

#ifdef _MSC_VER
#define inline __inline
#include <direct.h>
#define mkdir _mkdir
#endif

#if defined(WIN32)
#include <shlobj.h>
/* MAX_PATH is defined by the Windows API */
#define PATH_SEPARATOR_CHAR '\\'
#define PATH_SEPARATOR_STRING "\\"
#endif

/** Get an absolute path to a single configuration file, specific to this user.
 *
 * This function is useful for programs that need only a single configuration
 * file.  The file is unique to the user account currently logged in.
 *
 * Output is typically:
 *
 *   Windows: C:\Users\jcitizen\AppData\Roaming\appname.ini
 *   Linux: /home/jcitizen/.config/appname.conf
 *   Mac: /Users/jcitizen/Library/Application Support/appname.conf
 *
 * @param out
 *   Buffer to write the path.  On return will contain the path, or an empty
 *   string on error.
 *
 * @param maxlen
 *   Length of out.  Must be >= MAX_PATH.
 *
 * @param appname
 *   Short name of the application.  Avoid using spaces or version numbers, and
 *   use lowercase if possible.
 *
 * @post The file may or may not exist.
 * @post The folder holding the file is created if needed.
 */
static inline void get_user_config_file(char *out, unsigned int maxlen, const char *appname) {
    if (maxlen < MAX_PATH) {
        out[0] = 0;
        return;
    }
    if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, out))) {
        out[0] = 0;
        return;
    }
    /* We don't try to create the AppData folder as it always exists already */
    unsigned int appname_len = strlen(appname);
    if (strlen(out) + 1 + appname_len + strlen(".ini") + 1 > maxlen) {
        out[0] = 0;
        return;
    }
    strcat(out, "\\");
    strcat(out, appname);
    strcat(out, ".ini");
}

/** Get an absolute path to a configuration folder, specific to this user.
 *
 * This function is useful for programs that need to store multiple
 * configuration files.  The output is a folder (which may not exist and will
 * need to be created) suitable for storing a number of files.
 *
 * The returned path will always end in a platform-specific trailing slash, so
 * that a filename can simply be appended to the path.
 *
 * Output is typically:
 *
 *   Windows: C:\Users\jcitizen\AppData\Roaming\appname\
 *
 * @param out
 *   Buffer to write the path.  On return will contain the path, or an empty
 *   string on error.
 *
 * @param maxlen
 *   Length of out.  Must be >= MAX_PATH.
 *
 * @param appname
 *   Short name of the application.  Avoid using spaces or version numbers, and
 *   use lowercase if possible.
 *
 * @post The folder is created if needed.
 */
static inline void get_user_config_folder(char *out, unsigned int maxlen, const char *appname) {
    if (maxlen < MAX_PATH) {
        out[0] = 0;
        return;
    }
    if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, out))) {
        out[0] = 0;
        return;
    }
    /* We don't try to create the AppData folder as it always exists already */
    unsigned int appname_len = strlen(appname);
    if (strlen(out) + 1 + appname_len + 1 + 1 > maxlen) {
        out[0] = 0;
        return;
    }
    strcat(out, "\\");
    strcat(out, appname);
    /* Make the AppData\appname folder if it doesn't already exist */
    mkdir(out);
    strcat(out, "\\");
}

/** Get an absolute path to a data storage folder, specific to this user.
 *
 * This function is useful for programs that need to store larger amounts of
 * data specific to each user.  The output is a folder (which may not exist and
 * will need to be created) suitable for storing a number of data files.
 *
 * This path should be used for persistent, important data files the user would
 * want to keep.  Do not use this path for temporary files, cache files, or
 * other files that can be recreated if they are deleted.  Use
 * get_user_cache_folder() for those instead.
 *
 * The returned path will always end in a platform-specific trailing slash, so
 * that a filename can simply be appended to the path.
 *
 * Output is typically:
 *
 *   Windows: C:\Users\jcitizen\AppData\Roaming\appname-data\
 *
 * @param out
 *   Buffer to write the path.  On return will contain the path, or an empty
 *   string on error.
 *
 * @param maxlen
 *   Length of out.  Must be >= MAX_PATH.
 *
 * @param appname
 *   Short name of the application.  Avoid using spaces or version numbers, and
 *   use lowercase if possible.
 *
 * @post The folder is created if needed.
 */
static inline void get_user_data_folder(char *out, unsigned int maxlen, const char *appname)
{
    /* No distinction under Windows or OS X */
    get_user_config_folder(out, maxlen, appname);
}

/** Get an absolute path to a temporary storage folder, specific to this user.
 *
 * This function is useful for programs that temporarily need to store larger
 * amounts of data specific to each user.  The output is a folder (which may
 * not exist and will need to be created) suitable for storing a number of
 * temporary files.  The files may be lost or deleted when the program
 * terminates.
 *
 * This path should be used for temporary, unimportant data files that can
 * safely be deleted after the program terminates.  Do not use this path for
 * any important files the user would want to keep.  Use get_user_data_folder()
 * for those instead.
 *
 * The returned path will always end in a platform-specific trailing slash, so
 * that a filename can simply be appended to the path.
 *
 * Output is typically:
 *
 *   Windows: C:\Users\jcitizen\AppData\Local\appname\
 *
 * @param out
 *   Buffer to write the path.  On return will contain the path, or an empty
 *   string on error.
 *
 * @param maxlen
 *   Length of out.  Must be >= MAX_PATH.
 *
 * @param appname
 *   Short name of the application.  Avoid using spaces or version numbers, and
 *   use lowercase if possible.
 *
 * @post The folder is created if needed.
 */
static inline void get_user_cache_folder(char *out, unsigned int maxlen, const char *appname)
{
    if (maxlen < MAX_PATH) {
        out[0] = 0;
        return;
    }
    if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, out))) {
        out[0] = 0;
        return;
    }
    /* We don't try to create the AppData folder as it always exists already */
    unsigned int appname_len = strlen(appname);
    if (strlen(out) + 1 + appname_len + 1 + 1 > maxlen) {
        out[0] = 0;
        return;
    }
    strcat(out, "\\");
    strcat(out, appname);
    /* Make the AppData\appname folder if it doesn't already exist */
    mkdir(out);
    strcat(out, "\\");
}

#endif /* CFGPATH_H_WINDOW */