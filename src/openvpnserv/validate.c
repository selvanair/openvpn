/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "validate.h"

#include <lmaccess.h>
#include <shlwapi.h>
#include <lm.h>

static const WCHAR *white_list[] =
{
    L"auth-retry",
    L"config",
    L"log",
    L"log-append",
    L"management",
    L"management-forget-disconnect",
    L"management-hold",
    L"management-query-passwords",
    L"management-query-proxy",
    L"management-signal",
    L"management-up-down",
    L"mute",
    L"setenv",
    L"service",
    L"verb",

    NULL                                /* last value */
};

static BOOL IsUserInGroup(PSID sid, const WCHAR *group_name);

/*
 * Check workdir\fname is inside config_dir
 * The logic here is simple: we may reject some valid paths if ..\ is in any of the strings
 */
static BOOL
CheckConfigPath(const WCHAR *workdir, const WCHAR *fname, const settings_t *s)
{
    WCHAR tmp[MAX_PATH];
    const WCHAR *config_file = NULL;
    const WCHAR *config_dir = NULL;

    /* convert fname to full path */
    if (PathIsRelativeW(fname) )
    {
        snwprintf(tmp, _countof(tmp), L"%s\\%s", workdir, fname);
        tmp[_countof(tmp)-1] = L'\0';
        config_file = tmp;
    }
    else
    {
        config_file = fname;
    }

#ifdef UNICODE
    config_dir = s->config_dir;
#else
    if (MultiByteToWideChar(CP_UTF8, 0, s->config_dir, -1, widepath, MAX_PATH) == 0)
    {
        MsgToEventLog(M_SYSERR, TEXT("Failed to convert config_dir name to WideChar"));
        return FALSE;
    }
    config_dir = widepath;
#endif

    if (wcsncmp(config_dir, config_file, wcslen(config_dir)) == 0
        && wcsstr(config_file + wcslen(config_dir), L"..") == NULL)
    {
        return TRUE;
    }

    return FALSE;
}


/*
 * A simple linear search meant for a small wchar_t *array.
 * Returns index to the item if found, -1 otherwise.
 */
static int
OptionLookup(const WCHAR *name, const WCHAR *white_list[])
{
    int i;

    for (i = 0; white_list[i]; i++)
    {
        if (wcscmp(white_list[i], name) == 0)
        {
            return i;
        }
    }

    return -1;
}

/*
 * The Administrators group may be localized or renamed by admins.
 * Get the local name of the group using the SID.
 */
static BOOL
GetBuiltinAdminGroupName(WCHAR *name, DWORD nlen)
{
    BOOL b = FALSE;
    PSID admin_sid = NULL;
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    SID_NAME_USE snu;

    WCHAR domain[MAX_NAME];
    DWORD dlen = _countof(domain);

    admin_sid = malloc(sid_size);
    if (!admin_sid)
    {
        return FALSE;
    }

    b = CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid,  &sid_size);
    if (b)
    {
        b = LookupAccountSidW(NULL, admin_sid, name, &nlen, domain, &dlen, &snu);
    }

    free(admin_sid);

    return b;
}

/*
 * Check whether user is a member of Administrators group or
 * the group specified in s->ovpn_admin_group
 */
BOOL
IsAuthorizedUser(SID *sid, settings_t *s)
{
    const WCHAR *admin_group[2];
    WCHAR username[MAX_NAME];
    WCHAR domain[MAX_NAME];
    WCHAR sysadmin_group[MAX_NAME];
    DWORD len = MAX_NAME;
    BOOL ret = FALSE;
    SID_NAME_USE sid_type;

    /* Get username */
    if (!LookupAccountSidW(NULL, sid, username, &len, domain, &len, &sid_type))
    {
        MsgToEventLog(M_SYSERR, TEXT("LookupAccountSid"));
        /* not fatal as this is now used only for logging */
        username[0] = '\0';
        domain[0] = '\0';
    }

    if (GetBuiltinAdminGroupName(sysadmin_group, _countof(sysadmin_group)))
    {
        admin_group[0] = sysadmin_group;
    }
    else
    {
        MsgToEventLog(M_SYSERR, TEXT("Failed to get the name of Administrators group. Using the default."));
        /* use the default value */
        admin_group[0] = SYSTEM_ADMIN_GROUP;
    }

    admin_group[1] = s->ovpn_admin_group;

    for (int i = 0; i < 2; ++i)
    {
        ret = IsUserInGroup (sid, admin_group[i]);
        if (ret)
        {
            MsgToEventLog(M_INFO, TEXT("Authorizing user '%s@%s' by virtue of membership in group '%s'"),
                          username, domain, admin_group[i]);
            goto out;
        }
    }

out:
    return ret;
}

#include <sddl.h>
/**
 * Check a user with specified sid is in a local group named group_name
 *
 * Using sid instead of username avoids reference to domains so that
 * this could be completed without access to the Domain Controller.
 *
 * Returns true if the user is in the group, false otherwise.
 */
static BOOL
IsUserInGroup(PSID sid, const WCHAR *group_name)
{
    BOOL ret = FALSE;
    LOCALGROUP_MEMBERS_INFO_0 *groups;
    DWORD_PTR resume = 0;
    DWORD err, nread, nmax;
    int nloop = 0; /* a counter used to not get stuck in the do .. while() */

#if 1
    WCHAR *usersid = NULL;
    if (ConvertSidToStringSidW(sid, &usersid))
        MsgToEventLog(M_INFO, TEXT("Checking membership of user with sid '%s' in group '%s'"),
                      usersid, group_name);
    LocalFree(usersid);
#endif
    do
    {
        groups = NULL;
        err = NetLocalGroupGetMembers(NULL, group_name, 0, (LPBYTE *) &groups,
                                      MAX_PREFERRED_LENGTH, &nread, &nmax, &resume);
        if (err && err != ERROR_MORE_DATA)
        {
            break;
        }

        /* If a match is already found, ret = TRUE, the loop is skipped */
        for (int i = 0; i < nread && !ret; ++i)
        {
            ret = EqualSid(groups[i].lgrmi0_sid, sid);
#if 1
            WCHAR *strsid = NULL;
            ConvertSidToStringSidW(groups[i].lgrmi0_sid, &strsid);
            MsgToEventLog(M_INFO, TEXT("Group '%s' has a member with sid '%s'"), group_name, strsid);
            LocalFree(strsid);
#endif
        }

        NetApiBufferFree(groups);

    /* MSDN says the lookup should always iterate until err != ERROR_MORE_DATA */
    } while (err == ERROR_MORE_DATA && nloop++ < 100);

    if (err != NERR_Success && err != NERR_GroupNotFound)
    {
        SetLastError(err);
        MsgToEventLog(M_SYSERR, TEXT("In NetLocalGroupGetMembers for group '%s'"), group_name);
    }

    return ret;
}

/*
 * Check whether option argv[0] is white-listed. If argv[0] == "--config",
 * also check that argv[1], if present, passes CheckConfigPath().
 * The caller should set argc to the number of valid elements in argv[] array.
 */
BOOL
CheckOption(const WCHAR *workdir, int argc, WCHAR *argv[], const settings_t *s)
{
    /* Do not modify argv or *argv -- ideally it should be const WCHAR *const *, but alas...*/

    if (wcscmp(argv[0], L"--config") == 0
        && argc > 1
        && !CheckConfigPath(workdir, argv[1], s)
        )
    {
        return FALSE;
    }

    /* option name starts at 2 characters from argv[i] */
    if (OptionLookup(argv[0] + 2, white_list) == -1)   /* not found */
    {
        return FALSE;
    }

    return TRUE;
}
