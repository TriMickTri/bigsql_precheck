#!/bin/bash
################################################################################

#
# Licensed Materials - Property of IBM
#
# "Restricted Materials of IBM"
#
# (C) COPYRIGHT IBM Corp. 2016 All Rights Reserved.
#
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#
################################################################################
#
# NAME:     bigsql-precheck.sh
#
# FUNCTION: Check environment prior to Big SQL installation
#
# USAGE:    ./bigsql-precheck.sh [options]
#
# DETAILS:
#            Check for requirements and common cluster problems when installing
#
# Sample manual usage:
# bigsql-precheck.sh -M PRE_ADD_HOST -L /tmp/logdir -u bigsql -V
#
################################################################################

################################################################################
# 1 - Constants and variable declarations
################################################################################

# Save this away so we can log it later
CMD_LINE="$*"

# Get the full path and name to this script
RUN_SCRIPT=$(readlink -f $0)

FUNCNAME=""
SSH_CMD="ssh -o LogLevel=error -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
SSH_BATCH="ssh -o LogLevel=error -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
SCP_CMD="scp -o LogLevel=error -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_DIR=`dirname "$SCRIPT_DIR"`

BIGSQL_HOME="/usr/ibmpacks/current/bigsql/bigsql"
BIGSQL_DIST_HOME=`dirname "${BIGSQL_HOME}"`

. $SCRIPT_DIR/bigsql-util.sh

BIGSQL_VAR="/var/ibm/bigsql"

BIGSQL_PRECHECK_SUCCESS_FILE="/tmp/bigsqlPreChecker.Success"
BIGSQL_PRECHECK_FAILURE_FILE="/tmp/bigsqlPreChecker.Failure"
SUDO_SSH_USER=`whoami`

# Do not sudo when running as root
SUDO_CMD=$(get_sudo_cmd)

TMP_SCRIPT_DIR=/tmp
TMP_FILE=${TMP}/bigsql-precheck.tmp.$$
LOGGING_DIR=""

#---------------------------------------------------
# Synchronizing files
#---------------------------------------------------
BIGSQL_ADD_HOST_END_FILE=/tmp/BIGSQL_ADD_HOST_END

#---------------------------------------------------
# LOG LEVEL
#---------------------------------------------------
logLevel=0

# Default mode
MODE=PRE_ADD_HOST

#------------------------------------------------------------
# BIGSQL USERID DEFAULTS to 'bigsql'
#------------------------------------------------------------
BIGSQL_USER="bigsql"
BIGSQL_GROUP="hadoop"
THIS_HOST_NAME=`hostname --long`
HDFS_USER="hdfs"
HBASE_USER="hbase"
HIVE_USER="hive"
HAVE_BIGSQL_USER=0
HAVE_HOSTLIST_FILE=0
DISPLAY_REPORT=0
TARGET_NODE="${THIS_HOST_NAME}"
DEFAULT_MODE=0
RUNNING_ON_HEADNODE=0
STANDBY_CHECK=0

PLATFORM=`uname -p`
#------------------------------------------------------------
# Temporary files and log files
#------------------------------------------------------------
TIMESTAMP=$(get_timestamp)

# Error constants
BIGSQL_PRECHECK_ERR_CODE=1
BIGSQL_PRECHECK_WARN_CODE=101
BIGSQL_PRECHECK_SKIP_CODE=222

ALL_HOSTS=0
VERBOSE=0
PARALLEL=0
KINIT_FAIL=0

num_succ=0
num_err=0
num_warn=0
num_skip=0

###########################################################################
# Default host list
###########################################################################
SSH_HOSTLIST_FILE=/tmp/bigsqlSSHHostList
ALTERNATE_HOSTLIST_FILE=/etc/bigsql/bigsqlSSHHostList

###########################################################################
# If /tmp/bigsqlSSHHostList does not exist then use if exist from
# installed location.Alternate location would be there if install runs once
# but box rebooted /tmp/ might be removed
###########################################################################
if [[ -f $ALTERNATE_HOSTLIST_FILE ]] && [[ ! -f $SSH_HOSTLIST_FILE ]]
then
  SSH_HOSTLIST_FILE=$ALTERNATE_HOSTLIST_FILE
fi

RUN_CMD_AS()
{
  eval ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c \"$*\"
}

################################################################################
# Reporting function
################################################################################
report_check()
{
   local rc=$1
   local msg=""
   [ "$2" = "" ] || msg=" $2"
   local user_action_msg="$3"

   # Log to the report log
   if [ $rc -eq 0 ]; then

      if [[ ${VERBOSE} -ne 0 ]]; then
         printf "%-35s\E[32m\033[1m%15s\033[0m\n" "$msg" "[      OK ]"
         echo -e "OK${msg}\n" >> $REPORT_LOG
      else
         echo -e "OK${msg}\n" >> $REPORT_LOG
      fi

      # Increment success count
      ((num_succ++))

   # log errors with rc 1-99
   elif [[ $rc -gt 0 && $rc -lt 100 ]]; then

      if [ ${VERBOSE} -ne 0 ]; then
         printf "%-35s\E[31m\033[1m%15s\033[0m\n" "$msg" "[    FAIL ]"
         echo -e "FAIL${msg}\n" >> $REPORT_LOG
      else
         echo -e "FAIL${msg}\n" >> $REPORT_LOG
      fi

      # Log the suggested user action
      report_msg "${user_action_msg}"

      # Increment error count
      ((num_err++))

   # log warnings with rc 100-199
   elif [[ $rc -ge 100 && $rc -lt 200 ]]; then

      if [ ${VERBOSE} -ne 0 ]; then
         printf "%-35s\E[33m\033[1m%15s\033[0m\n" "$msg" "[ WARNING ]"
         echo -e "WARNING${msg}\n" >> $REPORT_LOG
      else
         echo -e "WARNING${msg}\n" >> $REPORT_LOG
      fi

      # Log the suggested user action
      report_msg "${user_action_msg}"

      # Increment warning count
      ((num_warn++))
   # log skip with rc = 222
   elif [[ $rc -eq ${BIGSQL_PRECHECK_SKIP_CODE} ]]; then

      if [ ${VERBOSE} -ne 0 ]; then
         printf "%-35s\E[32m\033[1m%15s\033[0m\n" "$msg" "[ SKIPPED ]"
         echo -e "SKIPPED${msg}\n" >> $REPORT_LOG
      else
         echo -e "SKIPPED${msg}\n" >> $REPORT_LOG
      fi

      # Increment warning count
      ((num_skip++))
   fi
}

report_msg()
{
   msg=$1

   echo "${msg}" | fold -s -w 75 >> $REPORT_LOG
   echo >> $REPORT_LOG
}

################################################################################
# Summary of the verification functions
################################################################################
#
# 01 - Check that /bin/ksh exist in all hosts
# 02 - Test db2set DB2RSHCMD is set / userprofile is not empty [post install ]
# 03 - Look at userprofile sanity check - more than x bytes
# 04 - If it is ldap make sure bigsql id & group that matches local or local
#      must not exist or same ie hadoop group of ldap if locally defined , that
#      must match ldap one if existed.
# 05 - Disk space
# 06 - Ensure that /etc/hosts/ has both long and short name of the host . ie.
#      blah.domain.com and blah for ip addr. make sure db2nodes.cfg included in
#      each not /etc/host and resolves ok
# 07 - Verify that the timediff between nodes is less than MAX_TIME_DIFF else create db wont work.
# 08 - bigsql userid is same or possible to have same in all boxes
# 09 - /tmp/bigsql is writable for bigsql
# 10 - Check that /etc/sudoers has requiretty commented out
# 11 - bigsql home is same on all boxes ie. path resolves to same string
# 12 - Make sure hdfs is available
# 13 - Check db data directory permissions by testing if they are writable by bigsql user
# 14 - Check if a sqllib already exists in bigsql user home
# 15 - Check if there are db2 entries in /etc/services
# 16 - Probable cause of db2ckgpfs error
# 17 - Validate passwordless ssh
# 18 - Validate client requirements
# 19 - Validate bigsql username length
# 20 - TSA resources check
# 21 - Check if the FCM port is in use
# 22 - Check if the DB2 comm port is in use
# 23 - Check that the hbase user has a valid login shell
# 24 - Check the hive primary group
# 25 - Check umask
# 26 - Check upper case in hostname
# 27 - Ensure bigsql home is not mounted with "nosuid" option
# 28 - Ensure that pam.i686 is installed
# 29 - Check HA package required on rhel 7
# 30 - Check Ping
# 31 - Add a warning for RHEL 6/7 based on repo
# 32 - Check that SELinux is in permisive mode
# 33 - Check that /tmp and /var has noexec and nosuid off
# 34 - Validate xml file syntax with xmllint: 
# 35 - Check that RemoveIPC=no is set on rhel 7
# 36 - Check sudo access
# 37 - Check passwordless from head to hive metastores
# 38 - Check permissions of /dev/shm
# 39 - Check that prelink is disabled
# 40 - Validate that the first head hostname is in the /etc/hosts file
# 41 - Check the ownership of bigsql user env files
# 42 - Check that the shell of the bigsql user is bash 
# 43 - Check that a non-root admin user has cron access
################################################################################

# 01 - /bin/ksh exist in all hosts
check_ksh()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check ksh"

   # Check that ksh is installed
   which ksh > /dev/null 2>&1
   rc=$?

   # Detailed error explanation in the report
   if [[ $rc -ne 0 ]]; then
      user_action_msg="The ksh shell is not installed or not found. Please install ksh."
   fi

   report_check $rc "KSH check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check ksh"

   logLevel=$((logLevel-1))

   return $rc
}

# 02 - db2set DB2RSHCMD is set
check_db2set_env()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check db2set"

   # As the bigsql user, su and run db2set. Check that
   log "${FUNCNAME}" "su - ${BIGSQL_USER} -c \"db2set -all | grep DB2RSHCMD\""
   rc=$?

   # Detailed error explanation in the report
   if [[ $rc -ne 0 ]]; then
      user_action_msg="Use db2set to set DB2RSHCMD to the desired secure shell executable."
   fi

   # Log to the report log
   report_check $rc "DB2 environment check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check db2set"

   logLevel=$((logLevel-1))

   return $rc
}

# 03 - userprofile is not empty [post install ]
check_userprofile()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   minimumsize=10

   log "${FUNCNAME}" "Enter - Check userprofile"

   # Check the size of userprofile
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then

      file="${BIGSQL_USER_HOME}/sqllib/userprofile"
      log "${FUNCNAME}" "Checking size of $file"

      if [ ! -f ${file} ]; then
         log "${FUNCNAME}" "File $file does not exist."
         user_action_msg="Check the install logs in ${SCRIPT_LOG_DIR} for errors. A new userprofile can be generated by running ${BIGSQL_HOME}/install/bigsql-setup.sh -M SLAVE_POST on the affected host."
         rc=1
      else

         actualsize=$(wc -c "$file" | cut -f 1 -d ' ')

         if [ $actualsize -ge $minimumsize ]; then
            log "${FUNCNAME}" "Userprofile size is OK."
            log "${FUNCNAME}" "Actual size is $actualsize bytes and over the minimum $minimumsize bytes"
            rc=0
         else
            log "${FUNCNAME}" "Userprofile size FAIL."
            log "${FUNCNAME}" "Actual size is $actualsize bytes and under the minimum $minimumsize bytes"
            user_action_msg="Check the install logs in ${SCRIPT_LOG_DIR} for errors. A new userprofile can be generated by running ${BIGSQL_HOME}/install/bigsql-setup.sh -M SLAVE_POST on the affected host."
            rc=1
         fi
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot validate userprofile."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Userprofile check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check userprofile"

   logLevel=$((logLevel-1))

   return $rc
}

# 04 - if it is ldap make sure bigsql id & group that matches local or local
# must not exist or same ie hadoop group of ldap if locally defined , that must
# match ldap one if existed.
checkBigsqlUserId()
{
   logLevel=$((logLevel+1))

   local rc=0
   local userDoesNotExistInLocal=0
   local groupDoesNotExistInLocal=0
   local host=`hostname --long`
   local user_action_msg=""

   local targetUser=$1
   local targetUserId=$2
   local targetGroup=$3
   local targetGroupId=$4

   log "$FUNCNAME"  "Validating bigsql user id"
   log "$FUNCNAME"  "Host          : $host"
   log "$FUNCNAME"  "TargetUser    : $targetUser"
   log "$FUNCNAME"  "TargeUserId   : $targetUserId"
   log "$FUNCNAME"  "TargetGroup   : $targetGroup"
   log "$FUNCNAME"  "TargetGroupId : $targetGroupId"

   # Scan username locally
   userExistLocally="`awk -v val=$targetUser -F ":" '$1==val{print $1}' /etc/passwd`"

   #--------------------------------------------------------------------------
   # LOCAL USERNAME AND ID VALIDATION
   #--------------------------------------------------------------------------
   if [ ! -z "$userExistLocally" ]
   then
      #
      # If user exists, check current id matches target id.
      #
      log "$FUNCNAME" "User ($userExistLocally) exists locally at $host"

      # Get uid for bigsql
      localUserId="`awk -v val=$targetUser -F ":" '$1==val{print $3}' /etc/passwd`"

      # Get user for uid
      localUserName="`awk -v val=$targetUserId -F ":" '$3==val{print $1}' /etc/passwd`"

      # Log
      log "$FUNCNAME" "localname for targetId[$targetUserId]=$localUserName"
      log "$FUNCNAME" "id for targetName[$targetUser]=$localUserId"

      if [ "$localUserId" -eq "$targetUserId" ]
      then
         # uid and uname both matches the target great ...
         log "$FUNCNAME" "$targetUserId is already owned by $targetUser at $host"
      else
         log "$FUNCNAME" "UID_ERR:($targetUser) has local id ($localUserId) different than ($targetUserId) at $host"
         user_action_msg="Change the user id to have the same value on all hosts. The ${targetUser} user has local id ($localUserId) different than ($targetUserId) at $host."
         rc=1
      fi
   else
      userDoesNotExistInLocal=1
      #
      # If user DOES NOT exist at local, then make sure target user id is NOT in use
      #
      log "$FUNCNAME" "->USR_OK:($targetUser) does not exist locally at $host"

      targetIdOwnedBy="`awk -v val=$targetUserId -F ":" '$3==val{print $1}' /etc/passwd`"
      if [ ! -z "$targetIdOwnedBy" ]
      then
         log "$FUNCNAME" "->UID_ERR: ($targetUserId) is owned by ($targetIdOwnedBy) in use at $host"
         user_action_msg="Change the user id to remove the conflict, or use a different user id for the Big SQL user. Target user id ($targetUserId) is in use by ($targetIdOwnedBy) on $host."
         rc=1
      else
         log "$FUNCNAME" "->UID_OK:($targetUserId) is not in use"
      fi
      # If user does not exist at local if there is ldap there is nothing
      # to worry beyond this point.
   fi

   groupExistLocally="`awk -v val=$targetGroup -F ":" '$1==val{print $1}' /etc/group`"
   if [ ! -z "$groupExistLocally" ]
   then
      #
      # If group exists, check current id matches target group id.
      #
      localGroupId="`awk -v val=$targetGroup -F ":" '$1==val{print $3}' /etc/group`"
      localGroup="`awk -v val=$targetGroupId -F ":" '$3==val{print $1}' /etc/group`"

      if [ "$localGroupId" -eq "$targetGroupId" ]
      then
         log "$FUNCNAME" "->GID_OK:($targetGroupId) matches group($targetGroup)"
      else
         log "$FUNCNAME" "GID_ERR at $host"
         log "$FUNCNAME" "localGroup for targetGroupId[$targetGroupId]=$localGroup"
         log "$FUNCNAME" "id for targetGroup[$targetGroup]=$localGroupId"
         user_action_msg="Ensure the Big SQL group id is the same on all hosts."
         rc=1
      fi
   else
      groupDoesNotExistInLocal=1
      #
      # If group DOES NOT exist at local, then make sure target group id is NOT in use
      #
      log "$FUNCNAME" "->GRP_OK: $targetGroup does not exists locally in /etc/group"

      targetIdOwnedBy="`awk -v val=$targetGroupId -F ":" '$3==val{print $1}' /etc/group`"
      if [ ! -z "$targetIdOwnedBy" ]
      then
         log "$FUNCNAME" "->GID_ERR: target group id ($targetGroupId) is in use by ($targetIdOwnedBy) at $host"
         rc=1
         user_action_msg="Change the group id to remove the conflict, or use a different user id for the Big SQL user. Target group id ($targetGroupId) is in use by ($targetIdOwnedBy) at $host."
      else
         log "$FUNCNAME" "->GID_OK: target group ($targetGroupId) is not in use"
      fi
      # If user does not exist at local if there is ldap there is nothing
      # to worry beyond this point.
   fi

   if [ $rc -eq 0 ]
   then
      # User may be ldap
      if [ "$userDoesNotExistInLocal" -eq 1 ]
      then
         log "$FUNCNAME" "User ($targetUserId) is not locally defined"
         lUid="`id -u $targetUser`"
         lGid="`id -g $targetUser`"
         lGrp="`id -gn $targetUser`"

         log "$FUNCNAME" "L->uid:$lUid, $targetUserId"
         log "$FUNCNAME" "L->gid:$lGid, $targetGroupId"
         log "$FUNCNAME" "L->grp:$lGrp, $targetGroup"
         if [ -z "$lUid" ]
         then
            log "$FUNCNAME" "User is not LDAP as well"
         else
            # username exists but not local
            if [ "$lUid" = "$targetUserId" ] && [ "$lGid" = "$targetGroupId" ] && [ "$lGrp" = "$targetGroup" ]
            then
               rc=0
            else
               # TO BE DETERMINED
               user_action_msg=""
               rc=1
            fi
         fi
      fi
   fi

   if [ $rc -eq 0 ]
   then
      log "$FUNCNAME" "Validated U:($targetUser, $targetUserId), G:($targetGroup, $targetGroupId ) successfully"
   else
      log "$FUNCNAME" "U:($targetUser, $targetUserId), G:($targetGroup, $targetGroupId ) validation failed, rc=$rc"
   fi

   # Log to the report log
   report_check $rc "Userid check" "${user_action_msg}"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 05 Check disk space
#
# Disk space for each component with 20% added and rounded up.
# du -sk /usr/ibmpacks/current/bigsql/*
# 339M - 347008  ->420000  /usr/ibmpacks/current/bigsql/bigsql
# 1.1G - 1067644 ->1280000 /usr/ibmpacks/current/bigsql/db2
# 39M  - 39848   ->48000   /home/<user>
# 581M - 594352  ->720000  /var/ibm/ (bigdb, ...)
# 5GB  - 5000000 ->5200000 /tmp (tmp space)
# 5GB  - 4500000 ->4800000 / (rpm tmp space)
#
################################################################################
check_disk_space()
{
   logLevel=$((logLevel+1))

   local rc=0
   local user_action_msg=""

   # Space calculated in 1K blocks.
   # Space requirement computed from existing build.
   # Add about %20 to the required space
   DU_BIGSQL_INSTALL=1280000
   DU_BIGSQL_DIST=420000
   BIGSQL_INSTALL_DIST_DIR=/usr

   DU_BIGSQL_SQLLIB=48000

   # Most users will be created under the /home directory. When the prechecker starts it
   # has no way of knowing that this will be the future home of the bigsql user. Check
   # it for space and return a good message if there is a problem.
   BIGSQL_USER_HOME_TO_TEST=""

   DU_BIGSQL_DB=720000
   BIGSQL_DB_DIR=/var

   # Validate that /tmp has about 5GB tmp space
   DU_TEMP_SPACE=5200000
   TEMP_DIR=/tmp
   
   # Disk usage for full install in bytes
   DU_INSTAL_DIST_TOT=$((${DU_BIGSQL_INSTALL} + ${DU_BIGSQL_DIST}))

   log "${FUNCNAME}" "Enter - check disk space processing"

   ##################################
   # Check space on /usr
   ##################################
   log "${FUNCNAME}" "Disk space needed by install: ${DU_INSTAL_DIST_TOT}"

   # Get the free space of the install dir
   if [[ -d ${BIGSQL_INSTALL_DIST_DIR} ]]; then
      cmd5="`df -P ${BIGSQL_INSTALL_DIST_DIR} | grep -vE '^Filesystem|^tmpfs|^cdrom' | awk '{ print $4 }'`"
      log "${FUNCNAME}" "df ${BIGSQL_INSTALL_DIST_DIR} : $cmd5"
      DF_INSTALL_DIST=$cmd5

      log "${FUNCNAME}" "Disk free on ${BIGSQL_INSTALL_DIST_DIR} = ${DF_INSTALL_DIST}"
   fi

   cmd6="$((${DF_INSTALL_DIST} - ${DU_INSTAL_DIST_TOT}))"
   log "${FUNCNAME}" "Disk available: $cmd6"
   DISK_AVAIL=$cmd6

   # Check that the disk available is not less than 0
   if [ ${DISK_AVAIL} -lt 0 ]; then
      log "${FUNCNAME}" "Not enough disk space to install on ${BIGSQL_INSTALL_DIST_DIR}."
      user_action_msg="At least ${DU_INSTAL_DIST_TOT}KB must be free on ${BIGSQL_INSTALL_DIST_DIR}."
      rc=1
   else
      log "${FUNCNAME}" "Disk has enough space for install on ${BIGSQL_INSTALL_DIST_DIR}."
   fi

   ############################################
   # Check the space on home where sqllib will go
   ############################################
   log "${FUNCNAME}" "Disk needed by sqllib: ${DU_BIGSQL_SQLLIB}"

   # Check space on bigsql user /home
   # If we have a bigsql user, user its home directory.
   # Otherwise we don't know where the home will bo so use the default.
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
       BIGSQL_USER_HOME_TO_TEST=$BIGSQL_USER_HOME
    else
       BIGSQL_USER_HOME_TO_TEST=/home
   fi

   log "${FUNCNAME}" "Using the user home \"${BIGSQL_USER_HOME_TO_TEST}\" test for space."

   if [[ -d ${BIGSQL_USER_HOME_TO_TEST} ]]; then
      cmd5="`df -P ${BIGSQL_USER_HOME_TO_TEST} | grep -vE '^Filesystem|^tmpfs|^cdrom' | awk '{ print $4 }'`"
      log "${FUNCNAME}" "df -P ${BIGSQL_USER_HOME_TO_TEST} : $cmd5"
      DF_SQLLIB=$cmd5

      log "${FUNCNAME}" "Disk free on ${BIGSQL_USER_HOME_TO_TEST} = ${DF_SQLLIB}"
   fi

   cmd6="$((${DF_SQLLIB} - ${DU_BIGSQL_SQLLIB}))"
   log "${FUNCNAME}" "Disk available: $cmd6"
   DISK_AVAIL=$cmd6

   # Check that the disk available is not less than 0
   if [ ${DISK_AVAIL} -lt 0 ]; then
      log "${FUNCNAME}" "Not enough disk space to install on ${BIGSQL_USER_HOME_TO_TEST}."
      user_action_msg="At least ${DU_BIGSQL_SQLLIB}KB must be free on ${BIGSQL_USER_HOME_TO_TEST}."
      rc=1
   else
      log "${FUNCNAME}" "Disk has enough space for install on ${BIGSQL_USER_HOME_TO_TEST}."
   fi

   ##################################
   # Check the size of the dbdir
   ##################################
   log "${FUNCNAME}" "Disk needed by dbdir: ${DU_BIGSQL_DB}"

   # Check space on /var
   if [[ -d ${BIGSQL_DB_DIR} ]]; then
      cmd5="`df -P ${BIGSQL_DB_DIR} | grep -vE '^Filesystem|^tmpfs|^cdrom' | awk '{ print $4 }'`"
      log "${FUNCNAME}" "df -P ${BIGSQL_DB_DIR} : $cmd5"
      DF_DB_DIR=$cmd5

      log "${FUNCNAME}" "Disk free on ${BIGSQL_DB_DIR} = ${DF_DB_DIR}"
   fi

   cmd6="$((${DF_DB_DIR} - ${DU_BIGSQL_DB}))"
   log "${FUNCNAME}" "Disk available: $cmd6"
   DISK_AVAIL=$cmd6

   # Check that the disk available is not less than 0
   if [ ${DISK_AVAIL} -lt 0 ]; then
      log "${FUNCNAME}" "Not enough disk space to install on ${BIGSQL_DB_DIR}."
      user_action_msg="At least ${DU_BIGSQL_DB}KB must be free on ${BIGSQL_DB_DIR}."
      rc=1
   else
      log "${FUNCNAME}" "Disk has enough space for install on ${BIGSQL_DB_DIR}."
   fi

   ##################################
   # Check the size of the /tmp
   ##################################
   log "${FUNCNAME}" "Space needed on ${TEMP_DIR}: ${DU_TEMP_SPACE}"

   # Check space on /tmp
   if [[ -d ${TEMP_DIR} ]]; then
      cmd5="`df -P ${TEMP_DIR} | grep -vE '^Filesystem|^cdrom' | awk '{ print $4 }'`"
      log "${FUNCNAME}" "df -P ${TEMP_DIR} : $cmd5"
      DF_TEMP_DIR=$cmd5

      log "${FUNCNAME}" "Disk free on ${TEMP_DIR} = ${DF_TEMP_DIR}"

      # Add a quick sanity to test if /tmp is mounted on tmpfs - this is not a problem
      # but log it here in case we see it.
      #if [[ $(df -P ${TEMP_DIR} | grep '^cdrom') -eq 0 ]]; then
      df -P ${TEMP_DIR} | grep '^tmpfs' 2>&1 > /dev/null
      if [ $rc -eq 0 ]; then
         log "${FUNCNAME}" "INFO: The dir ${TEMP_DIR} is mounted on tmpfs."
      fi
   fi

   cmd6="$((${DF_TEMP_DIR} - ${DU_TEMP_SPACE}))"
   log "${FUNCNAME}" "Disk available: $cmd6"
   DISK_AVAIL=$cmd6

   # Check that the disk available is not less than 0
   if [ ${DISK_AVAIL} -lt 0 ]; then
      log "${FUNCNAME}" "Not enough disk space to install on ${TEMP_DIR}."
      user_action_msg="At least ${DU_TEMP_SPACE}KB must be free on ${TEMP_DIR}."
      rc=1
   else
      log "${FUNCNAME}" "Disk has enough space for install on ${TEMP_DIR}."
   fi

   ##################################
   # End of space checks
   ##################################

   # Log to the report log
   report_check $rc "Disk space check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - check disk space with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 06 - /etc/hosts/ has both long and short name of the host . ie. blah.domain.com
#      and blah for ip addr. Make sure db2nodes.cfg included in each not /etc/host and resolves ok
check_etc_hosts()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check hosts file"

   hosts_file=/etc/hosts
   hostname_short=`hostname -s`
   hostname_long=`hostname -f`

   # Check that the hostname command returned different names
   log "${FUNCNAME}" "Check that the hostname command options returns properly."

   if [[ -z ${hostname_short} ||
         -z ${hostname_long} ]]; then
      log "${FUNCNAME}" "Long and short hostnames are not defined correctly."
      user_action_msg="Verify long and short hostnames are defined properly in ${hosts_file}. Short hostname: ${hostname_short}. Long hostname: ${hostname_long}."
      rc=1
   fi

   # Check that the hostname command returned different names
   if [[ $hostname_short = $hostname_long ]]; then
      log "${FUNCNAME}" "Long and short hostnames are the same: ${hostname_short}."
      user_action_msg="Long and short hostnames should not be the same: ${hostname_short}."
      rc=1
   fi

   if [[ ! `getent hosts ${hostname_short}` ]]; then
      log "${FUNCNAME}" "Hostname ${hostname_short} not found in ${hosts_file} using getent cmd."
      user_action_msg="Add host name ${hostname_short} to ${hosts_file}"
      rc=1
   fi

   if [[ ! `getent hosts ${hostname_long}` ]]; then
      log "${FUNCNAME}" "Hostname ${hostname_long} not found in ${hosts_file} using getent cmd."
      user_action_msg="Add host name ${hostname_long} to ${hosts_file}"
      rc=1
   fi
  
   # Log to the report log
   report_check $rc "Hosts file check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check hosts file with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 07 - timediff between nodes must be less than dbm cfg param else create db wont work.
#      The dbm cfg param MAX_TIME_DIFF is set to 60 min.
check_timediff()
{
   logLevel=$((logLevel+1))

   local rc=0
   local user_action_msg=""
   local_time=0
   remote_time=0

   max_time_diff=3600

   log "${FUNCNAME}" "Enter - Check local time"

   if [ ${HAVE_HOSTLIST_FILE} -eq 1 ]; then

      log "${FUNCNAME}" "Getting time from headnode: ${HEADNODE}."
      remote_time=$( RUN_CMD_AS ${SSH_CMD} ${HEADNODE} sh -c \"date +%s\")
      local_time=`date +%s`

      log "${FUNCNAME}" "Local time: $local_time. Remote time: $remote_time."

      server_time_diff=$((RUN_CMD_AS remote_time - local_time))

      if [ ${server_time_diff#-} -lt $max_time_diff ]; then
         log "${FUNCNAME}" "Time diff with server is OK."
         log "${FUNCNAME}" "Diff is $server_time_diff sec, less than $max_time_diff"
         rc=0
      else
         log "${FUNCNAME}" "Time diff with server FAIL."
         log "${FUNCNAME}" "Diff is $server_time_diff sec, greater than $max_time_diff"
         user_action_msg="Synchronize the server time on all hosts."
         rc=1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot check timediff."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Timediff check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check local time with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}


# 08 - bigsql userid and group id is same or possible to have same in all boxes
check_userid_same()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local_bigsql_uid=0
   headnode_bigsql_uid=0

   log "${FUNCNAME}" "Enter - Check Userid cluster consistency"

   if [[ ${HAVE_BIGSQL_USER} -eq 1 &&
         ${HAVE_HOSTLIST_FILE} -eq 1 ]]; then

      local_bigsql_uid="`awk -v val=${BIGSQL_USER} -F ":" '$1==val{print $3}' /etc/passwd`"
      headnode_bigsql_uid=$(RUN_CMD_AS ${SSH_CMD} ${HEADNODE} ${SUDO_CMD} sh -c \"echo `awk -v val=${BIGSQL_USER} -F ":" '$1==val{print $3}' /etc/passwd`\") > /dev/null 2>&1

      log "${FUNCNAME}" "Local id: $local_bigsql_uid, headnode id: $headnode_bigsql_uid"

      # Check UID
      if [[ ${local_bigsql_uid} -ne ${headnode_bigsql_uid} ]]; then
         log "${FUNCNAME}" "User id on $localhost(${local_bigsql_uid}) different than $HEADNODE(${headnode_bigsql_uid})"
         user_action_msg="The user id for ${BIGSQL_USER} on the local host (${local_bigsql_uid}) must match the user id on the head host (${headnode_bigsql_uid}). Either change the user id to match on all Big SQL hosts or remove the user id from all hosts."
         rc=1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot check user id."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Userid cluster consistency check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check Userid cluster consistency with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 09 - /tmp/bigsql is writable for a given user
# When script is called, this dir is created as part of create_logdir_logfile
# and should have all the right permissions
check_tmp_write()
{
   logLevel=$((logLevel+1))
   local rc=0
   local rc_1=0
   local rc_2=0
   local user_action_msg=""
   declare -a dir_in_err

   # If the bigsql user hasn't been created yet, we can't check it it has access to
   # tmp. Successfully exit, we'll check again later on.
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
      validate_tmp_dir="/tmp"
      validate_tmp_user_dir="/tmp/${BIGSQL_USER}/logs"

      log "${FUNCNAME}" "Enter - Check that some directories are writable by ${BIGSQL_USER}"
      
      rc_1=$(${SUDO_CMD} su - ${BIGSQL_USER} -c "test -w '${validate_tmp_dir}'" >> ${SCRIPT_LOG} 2>&1; echo $?)

      if [ ${rc_1} -ne 0 ]; then
         log "${FUNCNAME}" "Directory \"${validate_tmp_dir}\" is not valid for writing. rc: $rc_1"
         dir_in_err+=(${validate_tmp_dir})
         user_rc=1
      else
         log "${FUNCNAME}" "Directory \"${validate_tmp_dir}\" is valid for writing."
      fi

      if [ -d ${validate_tmp_user_dir} ]; then
         rc_2=$(${SUDO_CMD} su - ${BIGSQL_USER} -c "test -w '${validate_tmp_user_dir}'" >> ${SCRIPT_LOG} 2>&1; echo $?)

         if [ ${rc_2} -ne 0 ]; then
            log "${FUNCNAME}" "Directory \"${validate_tmp_user_dir}\" is not valid for writing. rc: $rc_2"
            dir_in_err+=(${validate_tmp_user_dir})
            user_rc=1
         else
            log "${FUNCNAME}" "Directory \"${validate_tmp_user_dir}\" is valid for writing."
         fi
      else
         log "${FUNCNAME}" "Directory \"${validate_tmp_user_dir}\" doesn't exist and connot be validated."
      fi

      if [[ ${user_rc} -ne 0 ]]; then
         dir_list_msg=$(printf ", %s" "${dir_in_err[@]}")
         dir_list_msg=${dir_list_msg:2}
         user_action_msg="The directories \"${dir_list_msg}\" are not writable by the bigsql user. Grant user ${BIGSQL_USER} write access to those directories."

         rc=${BIGSQL_PRECHECK_ERR_CODE}
      fi
   else
      log "${FUNCNAME}" "No bigsql user - access to tmp not validated."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "tmp and log dir permission check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check tmp writable with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 10 - /etc/sudoers Comment out requiretty with # or disable with !
check_sudoers()
{
   logLevel=$((logLevel+1))
   local user_action_msg=""
   local result=0
   found_tty_entry=0

   log "${FUNCNAME}" "Enter - Check sudoers"
   ${SUDO_CMD} -ll -U root >> ${SCRIPT_LOG} 2>&1 | grep "requiretty" | grep -vq "\!requiretty"
   result=$?

   # Log to the report log
   if [ $result -ne 1 ]; then
       found_tty_entry=1
       user_action_msg="Disable or remove requiretty for user root from sudoers."
   fi

   report_check $found_tty_entry "Sudoers check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check sudoers with rc=$found_tty_entry"

   logLevel=$((logLevel-1))

   return $found_tty_entry
}

# 11 - bigsql home is same on all boxes ie. path resolves to same string
check_user_home()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""
   local HEADNODE_HAS_BIGSQL_USER=0

   log "${FUNCNAME}" "Enter - Check user home"

   RUN_CMD_AS ${SSH_CMD} ${HEADNODE} "id ${BIGSQL_USER}" > /dev/null 2>&1

   if [[ $? -eq 0 ]]; then
      HEADNODE_HAS_BIGSQL_USER=1
   fi

   if [[ ${HEADNODE_HAS_BIGSQL_USER} -eq 1 &&
         ${HAVE_BIGSQL_USER} -eq 1 &&
         ${HAVE_HOSTLIST_FILE} -eq 1 ]]; then
      HEADNODE_BIGSQL_USER_HOME=$( RUN_CMD_AS ${SSH_CMD} ${HEADNODE} sh -c \"echo $(eval echo \\~${BIGSQL_USER})\")

      log "${FUNCNAME}" "Local user home: $BIGSQL_USER_HOME. Headnode user home: $HEADNODE_BIGSQL_USER_HOME."

      if [[ "$BIGSQL_USER_HOME" != "$HEADNODE_BIGSQL_USER_HOME" ]]; then
         user_action_msg="Local user home: $BIGSQL_USER_HOME. Headnode user home: $HEADNODE_BIGSQL_USER_HOME. The Big SQL user home path must be the same on all hosts."
         rc=1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot check user home."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "User home consistency check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check user home with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 12 - make sure hdfs is available
#      hdfs --config /etc/hadoop/conf dfsadmin -safemode get | grep OFF
check_hdfs_available()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check HDFS"

   # If kinit was run and failed, this test needs to be skipped
   if [ ${KINIT_FAIL} = 0 ];then
      # Run as hdfs user
      timeout 120 hdfs --config /etc/hadoop/conf dfsadmin -safemode get 2>&1 | grep OFF > /dev/null 2>&1
      cmd_rc=$?

      # Detailed error explanation in the report
      if [[ $cmd_rc -ne 0 ]]; then
         user_action_msg="Ensure the HDFS service is installed and operational."
      fi
   else
      log "${FUNCNAME}" "No kinit run, cannot check hdfs."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "HDFS check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check HDFS with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# Validate each that data directories are writable by bigsql user
# If we have a bigsql user, test write a file and delete it.
validate_data_dirs()
{
   logLevel=$((logLevel+1))
   local rc=0
   log "${FUNCNAME}" "Enter - Validate dir"

   data_dir_to_test=$1

   if [[ ${HAVE_BIGSQL_USER} ]]; then
      ${SUDO_CMD} su - ${BIGSQL_USER} sh -c "touch ${data_dir_to_test}/bigsql_t"
      touch_rc=$?

      if [[ ${touch_rc} -ne 0 ]]; then
         log "${FUNCNAME}" "Can't touch ${data_dir_to_test}/bigsql_t"
         rc=1
      fi
      rm -f ${data_dir_to_test}/bigsql_t

   else
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   log "${FUNCNAME}" "Exit - Validate dir rc=$rc"
   logLevel=$((logLevel-1))
   return $rc
}

# 13 - Check db data directory permissions by testing if they are writable by bigsql user
check_data_dir_perm()
{
   logLevel=$((logLevel+1))
   local rc=0
   local postRc=0
   local user_action_msg=""
   bad_dir_list=""

   log "${FUNCNAME}" "Enter - Check data dir permissions"

   # Go through the directories in BIGSQL_DATA_DIRS and check permissions
   pathArray=$(echo ${BIGSQL_DATA_DIRS} | tr "," "\n")

   for dirPath in $pathArray
   do
      log "$FUNCNAME" "Checking path $dirPath"
      
      # If the dir does not exist yet, that's OK, add-host may create it later on
      # so don't test it.
      if [[ -d "$dirPath" ]]; then
         validate_data_dirs "$dirPath"
         postRc=$?

         if [[ $postRc != 0 ]]; then
            bad_dir+=("${dirPath}")
            rc=1
         fi
      else
         log "${FUNCNAME}" "Skip - dir ${dirPath} does not exist yet."
      fi
   done

   bad_dir_list=$(printf ", %s" "${bad_dir[@]}")
   bad_dir_list=${bad_dir_list:2}
   user_action_msg="Ensure that the directories (${bad_dir_list}) are writable by the bigsql user ($BIGSQL_USER)"

   # Log to the report log
   report_check $rc "Data dir permission check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check data dir permissions with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 14 - Check if a sqllib already exists in bigsql user home
check_sqllib_exist()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check sqllib already exists"

   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then

      log "${FUNCNAME}" "Searching for $BIGSQL_USER_SQLLIB"

      if [[ -d ${BIGSQL_USER_SQLLIB} ]]; then
         user_action_msg="A sqllib directory was found in the user home. This could be due to an install retry otherwise it may need to be cleaned up"
         rc=${BIGSQL_PRECHECK_WARN_CODE}
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot check sqllib."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Sqllib existence check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check sqllib already exists with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 15 - Check if there are bigsql entries in /etc/services
check_bigsql_in_services()
{
   logLevel=$((logLevel+1))
   local rc=0
   local rc_grep=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check bigsql entries in /etc/services"

   grep -w "DB2_${BIGSQL_USER}\|DB2_${BIGSQL_USER}_END\|db2c_${BIGSQL_USER}" /etc/services >> ${REPORT_LOG} 2>&1
   rc_grep=$?
   if [ $rc_grep -eq 0 ]; then
      echo "" >> ${REPORT_LOG}
   fi

   # If we find entries here, only log a warning. The add-host and drop-host code will
   # clean the entries for our user.
   if [[ $rc_grep -eq 0 ]]; then
      user_action_msg="The entries shown above were found in the /etc/services file and need to be removed."
      rc=${BIGSQL_PRECHECK_WARN_CODE}
   fi

   # Log to the report log
   report_check $rc "Bigsql entries in /etc/services" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check bigsql entries in /etc/services with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 16 - Probable cause of db2ckgpfs error
#
# Placeholder
# So far, one issue causing db2ckpfs to fail was found: upper case hostnames.
#  - a specific test was added for that.
# If other solutions to db2ckgpfs are found, they will go here.
check_for_db2ckgpfs()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check db2ckgpfs potential errors."

   # Command to check

   if [[ $? -ne 0 ]]; then
      # TO BE DETERMINED
      user_action_msg=""
      rc=1
   fi

   # Log to the report log
   report_check $rc "Issues with gpfs utilities" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check db2ckgpfs potential errors rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 17 - Validate passwordless ssh
check_passwordless_ssh ()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local head_test_rc=0
   local namenode_test_rc=0
   local localhost_check=0

   declare -a ssh_head_err_str
   declare -a ssh_work_err_str

   START_SSH=1
   NUM_SSH_TRIES=3
   SLEEP_TIME=5

   log "${FUNCNAME}" "Enter - Check passwordless ssh setup"

   # Command to check
   if [[ ${HAVE_HOSTLIST_FILE} -eq 1 ]]; then

      # If we are on the headnode only, loop through all hosts and try a simple ssh command
      # In n*n, remove this check
      if [[ ${RUNNING_ON_HEADNODE} -eq 1 ]]; then

         for NODE in ${NODE_LIST[@]}; do

            # Retry a few time if needed.
            for (( count=$START_SSH; count<=$NUM_SSH_TRIES; count++ ))
            do
               # Reset the rc at the beginning of each iteration
               rc=0

               # If there's a retry, this entry will appear multiple times
               log "${FUNCNAME}" "Checking ssh connection from headnode (${HEADNODE}) to worker node ${NODE}"

               ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c "${SSH_BATCH} ${NODE} sh -c "exit 0"" > /dev/null 2>&1

               if [[ $? -ne 0 ]]; then
                  # Only add the host name to the error list once, on the last failure
                  if [[ $count -eq $NUM_SSH_TRIES ]]; then
                    ssh_head_err_str+=(${NODE})
                  else
                    # Wait a few seconds before trying again
                    sleep $SLEEP_TIME
                  fi
                  # Always set the error
                  rc=1
               else
                  break
               fi
            done

            # Track that at least one host failed
            if [[ $rc -ne 0 ]];then
                head_test_rc=1
            fi

         done

         # Test one way ssh to namenode.
         if [[ ! -z "${NAMENODE}" &&
               ${NAMENODE} != "localhost" ]]; then
            for (( count=$START_SSH; count<=$NUM_SSH_TRIES; count++ ))
            do
               # Reset the rc at the beginning of each iteration
               rc=0

               # If there's a retry, this entry will appear multiple times
               log "${FUNCNAME}" "Checking ssh connection from headnode (${HEADNODE}) to namenode ${NAMENODE}"

               ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c "${SSH_BATCH} ${NAMENODE} sh -c "exit 0"" > /dev/null 2>&1

               if [[ $? -ne 0 ]]; then
                  # Only add the host name to the error list once, on the last failure
                  if [[ $count -eq $NUM_SSH_TRIES ]]; then
                    ssh_head_err_str+=(${NAMENODE})
                  else
                    # Wait a few seconds before trying again
                    sleep $SLEEP_TIME
                  fi
                  # Always set the error
                  rc=1
               else
                  break
               fi
            done
         else
            log "${FUNCNAME}" "No namenode test requested. Unable to test ssh from headnode (${HEADNODE}) to namenode ${NAMENODE}."
         fi
         
         namenode_test_rc=$rc

         # Test ssh to localhost
         log "${FUNCNAME}" "Checking ssh connection to localhost on the headnode (${HEADNODE})"

         ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c "${SSH_BATCH} localhost sh -c "exit 0"" > /dev/null 2>&1

         localhost_check=$?

         if [[ $localhost_check -ne 0 ]]; then
            log "${FUNCNAME}" "Unable to ssh using localhost on the headnode (${HEADNODE})."
            ssh_head_err_str+=(localhost)
         else
            log "${FUNCNAME}" "SSH to localhost on the headnode (${HEADNODE}) successful."
         fi
      fi
   fi

   # If any of the tests failed, return a failure for the check
   if [[ $head_test_rc -ne 0 ||
         $namenode_test_rc -ne 0 ||
         $localhost_check -ne 0 ]]; then
      rc=${BIGSQL_PRECHECK_ERR_CODE}
   fi

   # Detailed error explanation in the report
   if [[ $rc -ne 0 ]]; then
      if [[ ${RUNNING_ON_HEADNODE} -eq 1 ]]; then
         # Create a formatted ssh host list
         ssh_head_host_list=$(printf ", %s" "${ssh_head_err_str[@]}")
         ssh_head_host_list=${ssh_head_host_list:1}
         user_action_msg="Passwordless ssh needs to be configured between the headnode and all hosts in the cluster. It's failing on the following hosts: ($ssh_head_host_list)"
      else
         user_action_msg="Passwordless ssh needs to be configured between this host and the headnode (${HEADNODE})."
      fi
   fi

   # Log to the report log
   report_check $rc "Passwordless ssh test" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check passwordless ssh setup with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 18 - Validate client requirements
# Clients to check:
#
# Currently check that the following clients are all installed on all hosts
# - hadoop
# - hdfs
# - hbase
# - hive
# - sqoop
# - hcat
#
# If a command times out, it'll return 124. Check for that and differentiate from
# command not found which is 127.
#
check_all_clients()
{
   logLevel=$((logLevel+1))

   local rc=0
   local rc_nf=0
   local rc_to=0
   local rc_oth=0
   local cmd_rc=0
   local user_action_msg_nf=""
   local user_action_msg_to=""

   # Client not found is an error
   declare -a client_not_found_err
   # Client timing out, maybe misconfigured, is a warning
   declare -a client_time_out_err
   # Client, any other error
   declare -a client_other_err

   CLIENT_TIMEOUT_CODE=124
   CLIENT_ERR_CODE=127

   log "${FUNCNAME}" "Enter - Check Big SQL client requirements"

   # hadoop client
   log "${FUNCNAME}" "Checking client: hadoop"
   timeout 60 hadoop version > /dev/null 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Hadoop client not found. Failed with $cmd_rc"
      client_not_found_err+=('hadoop')
      rc_nf=1
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Hadoop client timed out. Failed with $cmd_rc"
      client_time_out_err+=('hadoop')
      rc_to=1
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Hadoop client failed with unknown rc: $cmd_rc"
      client_other_err+=('hadoop')
      rc_oth=1
   fi

   # hdfs client
   log "${FUNCNAME}" "Checking client: hdfs"
   timeout 60 su - ${HDFS_USER} sh -c "hdfs -version" >> ${SCRIPT_LOG} 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Hdfs client note found. Failed with $cmd_rc"
      client_not_found_err+=('hdfs')
      rc_nf=1
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Hdfs client timed out. Failed with $cmd_rc"
      client_time_out_err+=('hdfs')
      rc_to=1
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Hdfs client failed with unknown rc: $cmd_rc"
      client_other_err+=('hdfs')
      rc_oth=1
   fi

   # hbase client
   log "${FUNCNAME}" "Checking client: hbase"
   timeout 60 su - ${HBASE_USER} sh -c "hbase -version" >> ${SCRIPT_LOG} 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Hbase client not found. Failed with $cmd_rc"
      client_not_found_err+=('hbase')
      rc_nf=1
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Hbase client timed out. Failed with $cmd_rc"
      client_time_out_err+=('hbase')
      rc_to=1
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Hbase client failed with unknown rc: $cmd_rc"
      client_other_err+=('hbase')
      rc_oth=1
   fi

   # hive client
   log "${FUNCNAME}" "Checking client: hive"
   timeout 60 su - ${HIVE_USER} sh -c "hive --version" >> ${SCRIPT_LOG} 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Hive client not found. Failed with $cmd_rc"
      client_not_found_err+=('hive')
      rc_nf=1
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Hive client timed out. Failed with $cmd_rc"
      client_time_out_err+=('hive')
      rc_to=1
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Hive client failed with unknown rc: $cmd_rc"
      client_other_err+=('hive')
      rc_oth=1
   fi

   # sqoop client
   log "${FUNCNAME}" "Checking client: sqoop"
   timeout 60 su - sqoop sh -c "sqoop version" >> ${SCRIPT_LOG} 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Sqoop client not found. Failed with $cmd_rc"
      client_not_found_err+=('sqoop')
      rc_nf=1
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Sqoop client timed out. Failed with $cmd_rc"
      client_time_out_err+=('sqoop')
      rc_to=1
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Sqoop client failed with unknown rc: $cmd_rc"
      client_other_err+=('sqoop')
      rc_oth=1
   fi

   # hcat
   # This command may fail if hcat user is not kinit. This type of failure
   # may be hard to detect and from tests, can take over 4 min to fail.
   # When running as part of the service check, log the err but be tolerant of errors.
   log "${FUNCNAME}" "Checking client: hcat"
   timeout 60 su - ${BIGSQL_USER} sh -c "hcat -h" >> ${SCRIPT_LOG} 2>&1
   cmd_rc=$?

   if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
      report_msg "Hcat client not found. Failed with $cmd_rc"
      if [ "${MODE}" = "POST_INSTALL" ]; then
         log "${FUNCNAME}" "Hcat client not found. Failed with $cmd_rc"
      else
         client_not_found_err+=('hcat')
         rc_nf=1
      fi
   elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
      report_msg "Hcat client timed out. Failed with $cmd_rc"
      if [ "${MODE}" = "POST_INSTALL" ]; then
         log "${FUNCNAME}" "Hcat client timed out. Failed with $cmd_rc"
      else
         client_time_out_err+=('hcat')
         rc_to=1
      fi
   elif [[ $cmd_rc -ne 0 ]]; then
      report_msg "Hcat client failed with unknown rc: $cmd_rc"
      if [ "${MODE}" = "POST_INSTALL" ]; then
         log "${FUNCNAME}" "Hcat client failed with rc: $cmd_rc"
         
         # Grep the script log in case we can tell the error was related
         # to Kerberos.
         grep "GSS initiate failed" ${SCRIPT_LOG}
         if [ $? -eq 0 ]; then
            log "${FUNCNAME}" "WARNING: Found \"GSS initiate fail\" in error message. The kinit command may be needed for the hcat user."
         fi
      else
         client_other_err+=('hcat')
         rc_oth=1
      fi
   fi

   # The following clients only need to be tested on the headnode
   # after add_node
   if [[ ${HAVE_HOSTLIST_FILE} -eq 1 &&
         ${RUNNING_ON_HEADNODE} -eq 1 &&
         ${MODE} != "PRE_ADD_HOST" ]]; then

      # slider
      log "${FUNCNAME}" "Checking client: slider"
      timeout 60 slider version >> ${SCRIPT_LOG} 2>&1

      cmd_rc=$?

      if [[ $cmd_rc -eq ${CLIENT_ERR_CODE} ]]; then
         report_msg "Slider client not found. Failed with $cmd_rc"
         client_not_found_err+=('slider')
         rc_nf=1
      elif [[ $cmd_rc -eq ${CLIENT_TIMEOUT_CODE} ]]; then
         report_msg "Slider client timed out. Failed with $cmd_rc"
         client_time_out_err+=('slider')
         rc_to=1
      elif [[ $cmd_rc -ne 0 ]]; then
         report_msg "Slider client failed with unknown rc: $cmd_rc"
         client_other_out_err+=('slider')
         rc_oth=1
      fi
   fi

   if [[ $rc_nf -ne 0 ]]; then
     # Create a formatted client list
      client_list_nf=$(printf ", %s" "${client_not_found_err[@]}")
      client_list_nf=${client_list_nf:2}

      user_action_msg_nf="The following client(s) are missing ($client_list_nf). \
Install all the required clients and restart the component."

      # Warning only:
      rc=${BIGSQL_PRECHECK_WARN_CODE}

   # Log to the report log
      report_check $rc "Client requirement check - missing" "${user_action_msg_nf}"
   fi
   
   if [[ $rc_to -ne 0 ]]; then
      # Create a formatted client list
      client_list_to=$(printf ", %s" "${client_time_out_err[@]}")
      client_list_to=${client_list_to:2}

      user_action_msg_to="The following client(s) are misconfigured ($client_list_to). \
Fix the required clients and restart the component. If the environment is kerberized, \
the client may require a principal and a kinit."

      # Warning only:
      rc=${BIGSQL_PRECHECK_WARN_CODE}
      
      # Log to the report log
      report_check $rc "Client requirement check - timeout" "${user_action_msg_to}"
   fi

   if [[ $rc_oth -ne 0 ]]; then
      # Create a formatted client list
      client_list_oth=$(printf ", %s" "${client_other_err[@]}")
      client_list_oth=${client_list_oth:2}

      user_action_msg_oth="The following client(s) are misconfigured ($client_list_oth) \
and an unknown error occured. Fix the required clients and restart the component."

      # Warning only:
      rc=${BIGSQL_PRECHECK_WARN_CODE}
      
      # Log to the report log
      report_check $rc "Client requirement check - unknown" "${user_action_msg_oth}"
   fi

   # Final message
   if [[ $rc -eq 0 ]]; then
      # Log to the report log
      report_check $rc "Client requirement check"
   fi

   log "${FUNCNAME}" "Exit - Check bigsql client requirements with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 19 - validate bigsql user id length
################################################################################
validate_bigsql_user()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check bigsql user name length"

   # Command to check
   user_name_length=${#BIGSQL_USER}

   if [[ $user_name_length -gt 8 ]]; then
      user_action_msg="The name \"${BIGSQL_USER}\" used for the Big SQL user is too long. It needs to be 8 characters or less."
      rc=1
   fi

   # Log to the report log
   report_check $rc "Big SQL user name length" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check bigsql user name length rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 20 - Check that there are not TSA resources leftover
################################################################################
check_TSA_resources()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check TSA resources"

   # Check if the command exists, which means TSA installed
   if [ -x "/usr/bin/lssam" ]; then
      # Command to check
      log "${FUNCNAME}" "Running lssam:"
      lssam >> ${SCRIPT_LOG} 2>&1
      cmd_rc=$?

      # An rc of 6 means "No resource groups defined or cluster is offline!"
      # This is what we want.
      if [ $cmd_rc -eq 6 ]; then
         log "${FUNCNAME}" "Success - lssam: No online domain found."
      elif [ $cmd_rc -eq 126 ]; then
         log "${FUNCNAME}" "No interpreter found. rc: $cmd_rc"
         log "${FUNCNAME}" "Verifying path /usr/sbin/rsct/perl5/bin/perl:"
         ls -al /usr/sbin/rsct/perl5/bin/perl >> ${SCRIPT_LOG} 2>&1
         user_action_msg="Error when running lssam utility. Check that the following link exists: /usr/sbin/rsct/perl5/bin/perl -> /usr/bin/perl"
         rc=1
      else
         log "${FUNCNAME}" "TSA resources found. rc: $cmd_rc"
         user_action_msg="TSA resources were found when running the lssam command. Remove leftover resources."
         rc=1
      fi

   else
      # Skip check
      log "${FUNCNAME}" "No lssam to run defined, cannot check TSA."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "TSA resources" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check TSA resources"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 21 - Check that the FCM port is not in use by other processes (default 28051)
################################################################################
check_FCM_port_usage()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check FCM port usage"

   # Check if the port was passed in and if it's already taken by another process
   if [ ! -z "${BIGSQL_PORT}" ]; then

      lsof -i:${BIGSQL_PORT} >> ${SCRIPT_LOG} 2>&1
      cmd_rc=$?

      # An rc of 0 means a resource was found
      if [ $cmd_rc == 0 ]; then
         user_action_msg="A process was found that uses port ${BIGSQL_PORT}. Use a different port for the bigsql service FCM port."
         rc=1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql ports defined, cannot validate FCM ports."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "BigSQL FCM service port" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check FCM port usage"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 22 - Check that the DB2 port is not in use by other processes (default 32051)
################################################################################
check_DB2_port_usage()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check DB2 port usage"

   # Check if the port was passed in and if it's already taken by another process
   if [ ! -z "${DB2_PORT}" ]; then

      lsof -i:${DB2_PORT} >> ${SCRIPT_LOG} 2>&1
      cmd_rc=$?

      # An rc of 0 means a resource was found
      if [ $cmd_rc == 0 ]; then
         user_action_msg="A process was found that uses port ${DB2_PORT}. Use a different port for the bigsql service port."
         rc=1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql ports defined, cannot validate DB2 ports."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "BigSQL service port" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check DB2 port usage"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 23 - Check that the hbase user has the proper shell setup in /etc/passwd
################################################################################
check_user_shell()
{
   logLevel=$((logLevel+1))
   local rc=0
   local cmd_rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check hbase user shell"

   # Check if the hbase user was passed in
   if [ ! -z "${HBASE_USER}" ]; then

      # Try to su to the user. If it doesn't have a login shell, this will fail
      su - "${HBASE_USER}" sh -c "exit 0"
      cmd_rc=$?

      if [ $cmd_rc -ne 0 ]; then
         shell_used=`getent passwd ${HBASE_USER} | cut -d: -f7`

         user_action_msg="The hbase user is not able to login to the shell $shell_used. Please set the shell to a valid login shell such as bash or ksh."
         rc=1
      fi

   else
      # Skip check
      log "${FUNCNAME}" "No hbase user defined, cannot validate hbase shell."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Hbase user shell" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check hbase user shell. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 24 - Check that the hive primary group id is consistent across the cluster
################################################################################
check_hive_gid_same()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local_hive_gid=0
   headnode_hive_gid=0

   log "${FUNCNAME}" "Enter - Check hive primary group id"

   local_hive_gid="`awk -v val=${HIVE_USER} -F ":" '$1==val{print $4}' /etc/passwd`"
   headnode_hive_gid=$( RUN_CMD_AS ${SSH_CMD} ${HEADNODE} "${SUDO_CMD} awk -v val=${HIVE_USER} -F: '\$1==val{print \$4}' /etc/passwd")

   log "${FUNCNAME}" "Local id: $local_hive_gid, headnode id: $headnode_hive_gid"

   # Check group id
   if [[ ${local_hive_gid} -ne ${headnode_hive_gid} ]]; then
      log "${FUNCNAME}" "Hive user primary group id on $localhost(${local_hive_gid}) different than $HEADNODE(${headnode_hive_gid})"
      user_action_msg="The primary group id for user ${HIVE_USER} on the local host (${local_hive_gid}) must match the group id on the head host (${headnode_hive_gid})."

      # This is a warning unless running in post-install mode
      if [ "${MODE}" = "POST_INSTALL" ]; then
         rc=${BIGSQL_PRECHECK_ERR_CODE}
      else
         rc=${BIGSQL_PRECHECK_WARN_CODE}
      fi
   fi

   # Log to the report log
   report_check $rc "Hive primary group id check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check Hive primary group id with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 25 - Check that the umask is 022 for both bigsql and root user
################################################################################
check_umask()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local REC_UMASK_VAL="0022"

   local bigsql_umask_val="";
   local user_rc=0;
   local root_rc=0;

   log "${FUNCNAME}" "Enter - Check umask setting"

   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
       bigsql_umask_val=`${SUDO_CMD} su - ${BIGSQL_USER} sh -c umask`
       log "${FUNCNAME}" "Bigsql user (${BIGSQL_USER}) umask is: ${bigsql_umask_val}."

       # Test bigsql umask
       if [[ "${bigsql_umask_val}" != ${REC_UMASK_VAL} ]]; then
           log "${FUNCNAME}" "Umask setting for ${BIGSQL_USER} is different than the documented value of ${REC_UMASK_VAL}."
           user_rc=1
       fi
   else
       log "${FUNCNAME}" "No bigsql user defined, cannot check umask."
   fi

   # Check the umask for root
   root_umask_val=`umask`
   log "${FUNCNAME}" "Root user umask is: ${root_umask_val}."

   # Test root umask
   if [[ "${root_umask_val}" != ${REC_UMASK_VAL} ]]; then
      log "${FUNCNAME}" "Umask setting for root is different than the documented value of ${REC_UMASK_VAL}."
      root_rc=1
   fi

   if [[ ${user_rc} -ne 0 ]] || [[ ${root_rc} -ne 0 ]]; then
      log "${FUNCNAME}" "The setting for umask is incorrect."
      user_action_msg="Set the umask according to the documented value of ${REC_UMASK_VAL} for the bigsql user and for root."

      rc=${BIGSQL_PRECHECK_WARN_CODE}
   fi

   # Log to the report log
   report_check $rc "User umask check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check umask setting with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 26 - Check that the hosname command does no return a hostname with uppercase
#      letters. This can cause a problem in ckgpfs when comparing the output
#      of the hostname command with the content of db2nodes.cfg.
################################################################################
check_upper_hostname()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local user_rc=0
   local test_rc=0

   log "${FUNCNAME}" "Enter - Check hostname for uppercase letters."

   declare -a str_cmd

   # Get the hostname in different ways as they could differ
   log "${FUNCNAME}" "Testing hostname command"
   hostname | grep -q '[[:upper:]]'
   test_rc=$?
   
   if [[ $test_rc -eq 0 ]]; then
       log "${FUNCNAME}" "This string has uppercase letters: \"`hostname`\""
       user_rc=$((user_rc+1))
       str_cmd+=('hostname')
   fi

   log "${FUNCNAME}" "Testing hostname --long command"
   hostname --long | grep -q '[[:upper:]]'
   test_rc=$?
   
   if [[ $test_rc -eq 0 ]]; then
       user_rc=$((user_rc+1))
       log "${FUNCNAME}" "This string has uppercase letters: \"`hostname --long`\""
       str_cmd+=('hostname --long')
   fi

   log "${FUNCNAME}" "Testing hostname --short command"
   hostname --short | grep -q '[[:upper:]]'
   test_rc=$?
   
   if [[ $test_rc -eq 0 ]]; then
       user_rc=$((user_rc+1))
       log "${FUNCNAME}" "This string has uppercase letters: \"`hostname --short`\""
       str_cmd+=('hostname --short')
   fi

   cmd_list=$(printf ", %s" "${str_cmd[@]}")
   cmd_list=${cmd_list:2}
   
   if [[ ${user_rc} -ne 0 ]]; then
      log "${FUNCNAME}" "The hostname string is non-standard. Commands that failed: $cmd_list"
      user_action_msg="The hostname contains uppercase characters. Please ensure that the value of hostame contains only lowercase. Commands in error: $cmd_list."

      rc=${BIGSQL_PRECHECK_ERR_CODE}
   fi
   
   # Log to the report log
   report_check $rc "Uppercase hostname check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check hostname for uppercase with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 27 - Ensure bigsql home is not mounted with "nosuid" option
################################################################################
check_mount_nosuid()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local test_rc=0
   local user_action_msg=""
   NOSUID_OPT="nosuid"

   log "${FUNCNAME}" "Enter - Check user home mount for ${NOSUID_OPT} setting."

   # Can only check nosuid on home if we have a bigsql user
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
      # Command to test the mount of the Big SQL user
      log "${FUNCNAME}" "Find mount point"

      # Break up the check so we have meaningful things to log
      bigsql_home_df_line=`df -P ${BIGSQL_USER_HOME} | grep -v Filesystem` > /dev/null 2>&1
      user_rc=$?

      # Ensure that we found an entry in the df command
      if [ ${user_rc} -ne 0 ]; then
         # If we found nothing in df, there is nothing else we can do. We'll flow out.
         log "${FUNCNAME}" "Looking in the df command for ${BIGSQL_USER_HOME} returned nothing. rc=${user_rc}"
         rc=${BIGSQL_PRECHECK_SKIP_CODE}
      else
         # Find the device where home is mounted
         bigsql_home_mount=`echo ${bigsql_home_df_line} | awk '{print $6}'` > /dev/null 2>&1
         user_rc=$?

         if [ ${user_rc} -ne 0 ]; then
            # If we found nothing in the mount command, there is nothing else we can do. We'll flow out.
            log "${FUNCNAME}" "Looking in the mount command for ${bigsql_home_df_line} turned nothing. rc=${user_rc}"
            rc=${BIGSQL_PRECHECK_SKIP_CODE}
         else
            # found the mount point for the bigsql home

            # Grep for the mountpoint in the output of the mount command and then check for nosuid
            # The mount point could be just "/" and in the output of the mount command it's
            # separated by spaces.
            bigsql_home_mount_line=`mount | grep " $bigsql_home_mount "` > /dev/null 2>&1

            echo ${bigsql_home_mount_line} | grep ${NOSUID_OPT} > /dev/null 2>&1
            user_rc=$?

            if [ ${user_rc} -eq 0 ]; then
               # Found the nosuid entry as an option to the mount point
               log "${FUNCNAME}" "The ${BIGSQL_USER} home (${BIGSQL_USER_HOME}) is mounted on \"$bigsql_home_mount\"."
               log "${FUNCNAME}" "That mount point is incorrectly mounted with the ${NOSUID_OPT} option."

               # Log extra data from the test
               log "${FUNCNAME}" "Df line:    ${bigsql_home_df_line}"
               log "${FUNCNAME}" "Mount line: ${bigsql_home_mount_line}"

               # Set the error manually
               test_rc=1
            fi
         fi
      fi
   fi

   if [[ ${test_rc} -ne 0 ]]; then
      log "${FUNCNAME}" "The bigsql home is on a mount point that is nosuid. user_rc=$user_rc"
      user_action_msg="The ${BIGSQL_USER} user home (${BIGSQL_USER_HOME}) is mounted on \"$bigsql_home_mount\" \
That mount point is incorrectly mounted with the \"${NOSUID_OPT}\" option. Big SQL cannot be installed \
on that mount point. Correct the mount by removing the \"${NOSUID_OPT}\" setting and then retry the installation."

      rc=${BIGSQL_PRECHECK_ERR_CODE}
   fi
   
   # Log to the report log
   report_check $rc "Check mount point for nosuid." "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check home mount for nosuid setting with rc=$rc."

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 28 - Ensure that pam.i686 is installed
#
# No need to check this anymore as it gets installed with db2luw.
# Comment out the call for now and remove after a few test itrations.
#
################################################################################
check_pam_prereq()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local user_rc=0;

   pam_pkg="pam.i686"

   log "${FUNCNAME}" "Enter - Check that ${pam_pkg} is installed"

   # Check that pam is installed
   log "${FUNCNAME}" "Looking in yum installed for ${pam_pkg}"

   yum list installed | grep ${pam_pkg} >> ${SCRIPT_LOG}
   user_rc=$?
   
   if [[ ${user_rc} -ne 0 ]]; then
      log "${FUNCNAME}" "The package \"${pam_pkg}\" is missing and needs to be installed."
      user_action_msg="The package \"${pam_pkg}\" is missing and needs to be installed."

      rc=${BIGSQL_PRECHECK_ERR_CODE}
   fi
   
   # Log to the report log
   report_check $rc "Check ${pam_pkg} installation." "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check that ${pam_pkg} is installed with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 29 - On RHEL 7, ensure that compat-libstdc is installed. Need for HA support.
################################################################################
check_rhel7_ha_prereqs()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local user_rc=0;

   log "${FUNCNAME}" "Enter - Check that rhel 7 optional packages is installed."

   # Need a version of compat-libstdc++-33-3.2.3-72.el7.x86_64 to be installed
   # If it's not there, enable it using:
   #   subscription-manager repos --enable rhel-7-server-optional-rpms

   rhel7_optional_pkg="compat-libstdc"

   user_action_msg="The package ${rhel7_optional_pkg} is missing and needs to be installed for HA support. The RHEL repo may need to be enabled with
\"subscription-manager repos --enable rhel-7-server-optional-rpms\"."

   if [ -f /etc/redhat-release ]; then

      # Do this check only on x86
      if [ ${PLATFORM} == "x86_64" ]; then

         cat /etc/redhat-release | grep "Server release 7" >> ${SCRIPT_LOG} 2>&1
         if [ $? -eq 0 ]; then
            log "${FUNCNAME}" "Enter - Check that ${rhel7_optional_pkg} is installed"

            log "${FUNCNAME}" "Get uname -a"
            uname -a | grep "x86_64" >> ${SCRIPT_LOG} 2>&1

            # Check that optional is installed
            log "${FUNCNAME}" "Looking in yum list for ${rhel7_optional_pkg}"

            yum list 2>&1 | egrep "${rhel7_optional_pkg}" >> ${SCRIPT_LOG}
            user_rc=$?

            if [[ ${user_rc} -ne 0 ]]; then
               log "${FUNCNAME}" "The package ${rhel7_optional_pkg} is missing and needs to be installed if HA will be used."
               rc=${BIGSQL_PRECHECK_WARN_CODE}
            else
               rc=0
            fi
         fi
      else
         rc=${BIGSQL_PRECHECK_SKIP_CODE}
      fi
   fi

   # Log to the report log
   report_check $rc "Check ${rhel7_optional_pkg} installation" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check that ${rhel7_optional_pkg} is installed with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

#####################################################
# 30 - Check Ping
#
# Only done from head node to workers
#####################################################
check_ping()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   declare -a ping_err_str

   log "${FUNCNAME}" "Enter - Check ping"

   if [[ ${RUNNING_ON_HEADNODE} -eq 1 ]]
   then
      log "${FUNCNAME}" "Enter - Check ping"
      for NODE in ${NODE_LIST[@]}; do

         # FDQN Check
         log "${FUNCNAME}" "Checking ping from headnode (${HEADNODE}) to worker node ${NODE}"
         timeout 30 dig ${NODE} >> ${SCRIPT_LOG} 2>&1
         ping -c 1 ${NODE} >> ${SCRIPT_LOG} 2>&1

         if [[ $? -ne 0 ]] 
         then
            ping_err_str+=(${NODE})
            rc=1
         fi 
      
         #
         # Hostname without domain check that is needed for HA + ssh setup also thinks this about HA and would 
         # fail while trying to make it good for HA .
         #
         SHORT_NODE=`echo ${NODE} | cut -d'.' -f1` 
         log "${FUNCNAME}" "Checking ping from headnode (${HEADNODE}) to short-hostname worker node ${SHORT_NODE}"
         ping -c 1 ${SHORT_NODE} >> ${SCRIPT_LOG} 2>&1
         if [[ $? -ne 0 ]] 
         then
            ping_err_str+=(${SHORT_NODE})
            rc=1
         fi 
      done

      if [[ $rc -ne 0 ]]
      then
         ping_err_msg_list=$(printf ", %s" "${ping_err_str[@]}")
         user_action_msg="Head node should be able to ping all worker nodes. A ping error was returned from the following workers: ($ping_err_msg_list)"
      fi

      #####################################################
      # Log to the report log
      #####################################################
      report_check $rc "Ping test" "${user_action_msg}"
      log "${FUNCNAME}" "Exit - Check ping test rc=$rc"
   else
      log "${FUNCNAME}" "Skip check ping on non-headnode."
   fi

   log "${FUNCNAME}" "Exit - Check ping"

   logLevel=$((logLevel-1))
   
   return $rc
}

################################################################################
# 31 - Add a warning for RHEL 6/7 based on repo
#
# Get the RHEL level and do a sanity check that the repos are pointing
# to the same level. This is to catch if a RHEL6 repo is installed on RHEL7
# and vice versa. The check is simple and in case of false positives, we
# will only WARN and note fail the install.
# 
# The warning will be helpful to detect that this was a problem.
#
################################################################################
check_rhel_repo_level()
{
   logLevel=$((logLevel+1))
   local rc=0
   local cmd_rc=0
   local user_action_msg=""

   dft_repo_path=/etc/yum.repos.d

   local user_rc=0;

   # If on RH
   if [ -f /etc/redhat-release ]; then
      log "${FUNCNAME}" "Enter - Check that RHEL level and repo match."

      # Check RHEL in repo
      log "${FUNCNAME}" "Looking in yum repo: ${dft_repo_path}"

      # If platform is RHEL 7, there should be no rhel6 in the repos
      log "${FUNCNAME}" "Look for \"Server release 7\" in /etc/redhat-release"
      cat /etc/redhat-release | grep "Server release 7" >> ${SCRIPT_LOG} 2>&1
      cmd_rc=$?
      if [ $cmd_rc -eq 0 ]; then
         log "${FUNCNAME}" "On RHEL 7 - Look for RHEL6 in ${dft_repo_path}"
         grep RHEL6 ${dft_repo_path}/* >> ${SCRIPT_LOG} 2>&1
         cmd_rc=$?
         # If we find something, there may be an incorrect repo.
         if [ $cmd_rc -eq 0 ]; then
            log "${FUNCNAME}" "Found a RHEL6 repo file on a RHEL7 system"
            ((user_rc++))
         fi
      fi

      # If platform is RHEL 6, there should be no rhel7 in the repos
      log "${FUNCNAME}" "Look for \"Server release 6\" in /etc/redhat-release"
      cat /etc/redhat-release | grep "Server release 6" >> ${SCRIPT_LOG} 2>&1
      cmd_rc=$?
      if [ $cmd_rc -eq 0 ]; then
         log "${FUNCNAME}" "On RHEL6 - Look for RHEL7 in ${dft_repo_path}"
         grep RHEL7 ${dft_repo_path}/* >> ${SCRIPT_LOG} 2>&1
         cmd_rc=$?
         # If we find something, there may be an incorrect repo.
         if [ $cmd_rc -eq 0 ]; then
            log "${FUNCNAME}" "Found a RHEL7 repo file on a RHEL6 system."
            ((user_rc++))
         fi
      fi
   
      if [[ ${user_rc} -ne 0 ]]; then
         user_action_msg="Found a RHEL repo file that does not match the RHEL level of this system. Verify the repo locations and ensure that the RHEL level (6 or 7) matches the system."

         rc=${BIGSQL_PRECHECK_WARN_CODE}
      fi

      # Log to the report log
      report_check $rc "Check RHEL level in repo files" "${user_action_msg}"

      log "${FUNCNAME}" "Exit - Check that RHEL level and repo match. rc=$rc" 

   # Not a RHEL system
   else
      log "${FUNCNAME}" "Skip repo validation on non-RHEL system."
   fi

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 32 - Check that SELinux is in permisive mode
#
# cat /etc/sysconfig/selinux
# 
# Use getenforce or sestatus.
#
# Can change mode temporarily with:
# setenforce 0 'to disable
# setenforce 1 'to enable
#
################################################################################
check_SE_permissive_mode()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local user_action_msg=""

   se_mode="unknown"

   # If on SELinux
   if [ -f /etc/sysconfig/selinux ]; then
      log "${FUNCNAME}" "Enter - Check that SELinux is running in permissive mode."
      
      log "${FUNCNAME}" "Running getenforce command:"
      se_mode=getenforce >> ${SCRIPT_LOG} 2>&1
      user_rc=$?
      log "${FUNCNAME}" "Command getenforce returned: ${se_mode} with rc: ${user_rc}"

      if [ ${user_rc} -ne 0 ]; then
         user_action_msg="SELinux detected but mode cannot be checked."
         rc=${BIGSQL_PRECHECK_WARN_CODE}
      else
         # Tool ran, test returned value
         if [ "${se_mode}" == "Enforcing" ]; then

            # Log extra info
            log "${FUNCNAME}" "Running sestatus to get more indo:"
            sestatus >> ${SCRIPT_LOG} 2>&1
         
            user_action_msg="SELinux is running in restrictive mode. Installation cannot be done in this mode. Enable permissive mode and retry the installation."

            rc=${BIGSQL_PRECHECK_ERR_CODE}
         fi
      fi

   # Not a SELinux supported system
   else
      log "${FUNCNAME}" "Not on SELinux, skip permissive mode check."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi
      
   # Log to the report log
   report_check $rc "Check SELinux running mode" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check that SELinux is running in permissive mode. rc=$rc" 

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 33 - Check that /tmp and /var has noexec and nosuid off
#
# Run a check like this:
# mount | grep `df -P /tmp | tail -1 | cut -d' ' -f 1` | egrep -i "nosuid|noexec" 
# 
################################################################################
check_fstab_noexec_nosuid()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local user_action_msg=""

   declare -a dir_in_err

   # Directories and options to check
   DIR_LIST_TO_TEST="/tmp,/var"
   DIR_OPTS="nosuid|noexec"

   log "${FUNCNAME}" "Enter - check directory mount options"

   OLD_IFS=${IFS}

   IFS=','

   for DIR_TO_TEST in ${DIR_LIST_TO_TEST}
   do
      log "${FUNCNAME}" "Checking dir: ${DIR_TO_TEST}"

      # Get the mount info for the directory
      dir_entry=$(mount | grep $(df -P ${DIR_TO_TEST} | tail -1 | cut -d' ' -f 1))
      rc_dir=$?

      log "${FUNCNAME}" "Returned entry: ${dir_entry} with rc: ${rc_dir}"

      if [[ ${rc_dir} -ne 0 ]]; then
         log_err "${FUNCNAME}" "Unexpected error running mount command"
         dir_in_err+=(${DIR_TO_TEST})
         user_rc=1
      else
      # Grep for mount option in the dir entry
         echo ${dir_entry} | grep -E ${DIR_OPTS} >> ${SCRIPT_LOG} 2>&1
      rc_grep=$?

      log "${FUNCNAME}" "Searched entry for ${DIR_OPTS} and got rc: ${rc_grep}"

      # Capture error
      # A 0 means grep found an invalid entry
         if [[ ${rc_grep} -eq 0 ]]; then
         log "${FUNCNAME}" "${dir_in_err} contains one of ${DIR_OPTS} which is invalid."
         dir_in_err+=(${DIR_TO_TEST})
         user_rc=1
      fi
      fi

   done

   IFS=${OLD_IFS}

   if [[ ${user_rc} -ne 0 ]]; then
      dir_list_msg=$(printf ", %s" "${dir_in_err[@]}")
      dir_list_msg=${dir_list_msg:2}
      
      user_action_msg="The directories \"${dir_list_msg}\" are mounted with one or more of the following options: \"${DIR_OPTS}\". Installation may not complete with these options and they should be removed."

      rc=${BIGSQL_PRECHECK_WARN_CODE}
   fi

   # Log to the report log
   report_check $rc "Check directory mount options" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - check directory mount options. rc=$rc" 

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 34 - Validate xml file syntax with xmllint: 
#      - /var/lib/ambari-server/resources/stacks/BigInsights/4.0/repos/repoinfo.xml
#      - /var/lib/ambari-server/resources/stacks/BigInsights/4.1/repos/repoinfo.xml
#      - /var/lib/ambari-server/resources/stacks/BigInsights/4.2/repos/repoinfo.xml
#
# This is a sanity test to validate xml files that are sometimes user edited.
# A syntax error in those files can be difficult to track. An xmllint run will
# ensure the files are valid.
#
################################################################################
validate_xml_syntax()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local cmd_rc=0
   local user_action_msg=""

   XML_BASE_PATH="/var/lib/ambari-server/resources/stacks/HDP"

   log "${FUNCNAME}" "Enter - Validate xml file syntax."
   
   XML_FILE_LIST=( $(find ${XML_BASE_PATH} -name repoinfo.xml 2>&1 ) ) 
   xml_rc=$?

   if [[ ${xml_rc} -eq 0 && ${#XML_FILE_LIST[@]} -ne 0 ]]; then
   
      for XML_FILE_TO_VAL in ${XML_FILE_LIST[@]}
      do
         log "${FUNCNAME}" "Validating file: ${XML_FILE_TO_VAL}"

         xmllint --noout ${XML_FILE_TO_VAL} >> ${SCRIPT_LOG} 2>&1
         rc_val=$?

         if [ ${rc_val} -ne 0 ]; then
            log_err "${FUNCNAME}" "XML file: ${XML_FILE_TO_VAL} failed validation."
            user_rc=1
         else
            log "${FUNCNAME}" "XML validation succeeded. rc: ${rc}"
         fi
      done

      if [[ ${user_rc} -ne 0 ]]; then
         user_action_msg="An xml file has invalid content. Review the log for the failing file and correct the XML."
         if [ "${MODE}" = "PRE_BACKUP" ]; then
            rc=${BIGSQL_PRECHECK_ERR_CODE}
         else
            rc=${BIGSQL_PRECHECK_WARN_CODE}
         fi
      fi
   else
      log "${FUNCNAME}" "Did not find any XML files to validate."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi
 
   # Log to the report log
   report_check $rc "Validate xml file syntax" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Validate xml file syntax. rc=$rc" 

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 35 - Ensure that on (rhel7) the non default option RemoveIPC=no is set in /etc/systemd/logind.conf
################################################################################
check_rhel7_ha_removeipc()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local user_rc=0;
   user_action_msg="RemoveIPC=no is not set in the /etc/systemd/logind.conf file, enabling BigSQL High Availability will fail without this setting."

   log "${FUNCNAME}" "Enter - Check RemoveIPC=no setting"

   if [ -f /etc/redhat-release ]; then
      cat /etc/redhat-release | grep "Server release 7" >> ${SCRIPT_LOG} 2>&1
      if [ $? -eq 0 ]; then
         log "${FUNCNAME}" "Enter - ${check_message}"
         if [ -f /etc/systemd/logind.conf ]; then
            cat /etc/systemd/logind.conf | grep '^RemoveIPC=no' >> ${SCRIPT_LOG} 2>&1
            user_rc=$?

            if [[ ${user_rc} -ne 0 ]]; then
               log "${FUNCNAME}" "${user_action_msg}"
               rc=${BIGSQL_PRECHECK_WARN_CODE}
            fi
         else
            rc=${BIGSQL_PRECHECK_WARN_CODE}
         fi

      else
         log "${FUNCNAME}" "Not on redhat release 7.x"
         rc=${BIGSQL_PRECHECK_SKIP_CODE}
      fi
   else
      log "${FUNCNAME}" "Not on a redhat system."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   report_check $rc "Check RemoveIPC=no setting" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check RemoveIPC=no setting. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 36 - Check that root can sudo properly
################################################################################
check_sudo()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   local user_rc=0;
   user_action_msg="Admin user (${SUDO_SSH_USER}) cannot sudo. Update the sudoers file to allow it. This may have caused other tests to fail."

   log "${FUNCNAME}" "Enter - Check sudo ability"

   sudo sh -c "id" >> ${SCRIPT_LOG} 2>&1
   user_rc=$?

   if [ ${user_rc} -ne 0 ]; then
      log_err "${FUNCNAME}" "There is a problem with sudo. rc=${user_rc}"
      rc=1
   else
      log "${FUNCNAME}" "Sudo test succeeded for ${SUDO_SSH_USER}. rc: ${user_rc}"
   fi

   report_check $rc "Check sudo ability" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check sudo. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc

}

################################################################################
# 37 - Check passwordless from head to hive metastores
################################################################################
check_passwordless_ssh_to_hive_metas()
{
   logLevel=$((logLevel+1))
   local rc=0
   local h1_rc=0
   local h2_rc=0
   local skipped=0
   local user_action_msg=""

   local user_rc=0;
   user_action_msg="Admin user (${SUDO_SSH_USER}) cannot ssh from the head node to the hive metastores. Enable ssh from head to all hive metastore hosts."

   log "${FUNCNAME}" "Enter - Check passwordless ssh from head to hive metastores."

   # Do the following tests only on first or second head node
   # We know this if RUNNING_ON_HEAD is set or STANDBY_CHECK is set
   if [[ ${RUNNING_ON_HEADNODE} -eq 1 || ${STANDBY_CHECK} -eq 1 ]]; then

      log "${FUNCNAME}" "Checking ssh connection on a headnode."

      # Check the first hive metastore if it's not the same as the headnode
      if [[ "${THIS_HOST_NAME}" != "${HIVE_METASTORE_HOST_1}" ]] && [[ "" != "${HIVE_METASTORE_HOST_1}" ]] ; then
         log "${FUNCNAME}" "Checking ssh connection from headnode (${THIS_HOST_NAME}) to hive metastore (${HIVE_METASTORE_HOST_1})."

         ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c "${SSH_BATCH} ${HIVE_METASTORE_HOST_1} sh -c "exit 0"" > /dev/null 2>&1
         h1_rc=$?
         if [[ $h1_rc -ne 0 ]]; then
            log_err "${FUNCNAME}" "SSH to hive metastore: ${HIVE_METASTORE_HOST_1} failed with rc: $h1_rc."
            rc=${BIGSQL_PRECHECK_ERR_CODE}
         fi
      else
         skipped=$((skipped+1))
      fi

      # Check the second hive metastore if it's not the same as the headnode
      if [[ "${THIS_HOST_NAME}" != "${HIVE_METASTORE_HOST_2}" ]] && [[ "" != "${HIVE_METASTORE_HOST_2}" ]] ; then
         log "${FUNCNAME}" "Checking ssh connection from headnode (${THIS_HOST_NAME}) to hive metastore 2 (${HIVE_METASTORE_HOST_2})."

         ${SUDO_CMD} su - ${SUDO_SSH_USER} sh -c "${SSH_BATCH} ${HIVE_METASTORE_HOST_2} sh -c "exit 0"" > /dev/null 2>&1
         h2_rc=$?
         if [[ $h2_rc -ne 0 ]]; then
            log_err "${FUNCNAME}" "SSH to hive metastore: ${HIVE_METASTORE_HOST_2} failed with rc: $h2_rc."
            rc=${BIGSQL_PRECHECK_ERR_CODE}
         fi
      else
         skipped=$((skipped+1))
      fi
   fi

   if [[ skipped -eq 2 ]];then
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   report_check $rc "Check ssh to hive metastore" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check passwordless ssh from head to hive metastores. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}       

# 38 - Check the permissions of /dev/shm.
# The permissions of this directory need to be set to 1777
check_devshm_perm()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""
   local user_rc=0

   dir_to_test="/dev/shm"
   perm_to_check=1777

   user_action_msg="The permissions for the directory ${dir_to_test} have to be ${perm_to_check}. Change the permissions with chmod and retry the install."

   log "${FUNCNAME}" "Enter - Check ${dir_to_test} permissions"

   cur_dir_perm=$(stat -c "%a" ${dir_to_test})
   user_rc=$?

   if [ ${user_rc} -ne 0 ]; then
      log_err "${FUNCNAME}" "There was a problem checking the permissions of ${dir_to_test}. rc=${user_rc}"
      rc=${BIGSQL_PRECHECK_ERR_CODE}
   else
      if [ ${cur_dir_perm} != ${perm_to_check} ]; then
         log "${FUNCNAME}" "The permissions of ${dir_to_test} are incorrectly set to ${cur_dir_perm}."
         rc=${BIGSQL_PRECHECK_ERR_CODE}
      else
         log "${FUNCNAME}" "The permissions of ${dir_to_test} are correctly set to ${cur_dir_perm}."
      fi
   fi

   report_check $rc "Check ${dir_to_test} permissions" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check ${dir_to_test} permissions. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 39 - Check that prelink is disabled
#
# cat /etc/sysconfig/prelink | grep "PRELINKING=no"
# 
# On RHEL6, by default prelinking is enabled, it is disabled by default on RHEL7.
# Check whether prelinking has been performed based on the existence of "PRELINKING=yes" 
# in /etc/sysconfig/prelink.
#
################################################################################
check_for_prelink()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check for prelinking"

   # If prelink installed
   if [ -f /etc/sysconfig/prelink ]; then
      log "${FUNCNAME}" "Found prelink file"

      cat /etc/sysconfig/prelink | grep "PRELINKING=no" >> ${SCRIPT_LOG} 2>&1
      user_rc=$?
      if [ ${user_rc} -ne 0 ]; then
         user_action_msg="Prelinking is enabled and it should be disabled. To disable, as root user, in /etc/sysconfig/prelink file, change PRELINKING=yes to PRELINKING=no. After saving changes, run prelink -ua"
         rc=${BIGSQL_PRECHECK_WARN_CODE}
      fi

   # prelink not installed
   else
      log "${FUNCNAME}" "Prelink not found, skip prelink check."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Check for prelinking" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check for prelinking. rc=$rc" 

   logLevel=$((logLevel-1))

   return $rc
}

# 40 - Validate the hostnames in the /etc/hosts files.
# TSA requires that both the first and second head node's hostnames
# are in the /etc/hosts file of both hosts.
# This test is only valid when run on the standby head node.
# Also handle if there is a public/private hostname
# This makes a potential total of 8 tests.
check_etc_host_for_entries()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""
   local user_rc=0
   local temp_rc=0

   user_action_msg=""
   ETC_HOSTS_FILE="/etc/hosts"

   log "${FUNCNAME}" "Enter - Check head node entries in /etc/hosts"

   BIGSQL_SECOND_HEAD=${CONFIGURED_HOSTNAME}
   PUBLIC_BIGSQL_SECOND_HEAD=`hostname -f`

   # Check that the hostname for the first head node is in /etc/hosts.
   # Note that in private network setups, we also need to check the public interface.
   if [[ ! -z ${BIGSQL_FIRST_HEAD} && ! -z ${BIGSQL_SECOND_HEAD} ]]; then
      # Get the public hostname of the first head
      PUBLIC_BIGSQL_FIRST_HEAD=$( RUN_CMD_AS ${SSH_CMD} ${BIGSQL_FIRST_HEAD} sh -c \"hostname -f\")
      temp_rc=$?

      # If we didn't get anything from the above call.
      if [ -z ${PUBLIC_BIGSQL_FIRST_HEAD} ]; then
         log "${FUNCNAME}" "Getting public hostname through ssh failed and returned rc: ${temp_rc}."
      else
         if [[ ${PUBLIC_BIGSQL_FIRST_HEAD} != ${BIGSQL_FIRST_HEAD} ]]; then
            log "${FUNCNAME}" "PUBLIC_BIGSQL_FIRST_HEAD=${PUBLIC_BIGSQL_FIRST_HEAD}"
         fi
      fi
      
      if [[ ${PUBLIC_BIGSQL_SECOND_HEAD} != ${BIGSQL_SECOND_HEAD} ]]; then
         log "${FUNCNAME}" "PUBLIC_BIGSQL_SECOND_HEAD=${PUBLIC_BIGSQL_SECOND_HEAD}"
      fi

      log ${FUNCNAME} "Looking for ${BIGSQL_FIRST_HEAD} and ${PUBLIC_BIGSQL_FIRST_HEAD} in ${ETC_HOSTS_FILE} on the second head ${BIGSQL_SECOND_HEAD}."

      # Check that the first head's regular hostname is in /etc/hosts
      if [[ $(cat ${ETC_HOSTS_FILE} | grep ${BIGSQL_FIRST_HEAD} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
         log ${FUNCNAME} "Found the first head node entry (${BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
      else
         log ${FUNCNAME} "Did not find the first head node entry (${BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
         user_rc=1
      fi

      # Check that the public version of the first head, if we have one, is in /etc/hosts
      if [[ ! -z ${PUBLIC_BIGSQL_FIRST_HEAD} && ${PUBLIC_BIGSQL_FIRST_HEAD} != ${BIGSQL_FIRST_HEAD} ]]; then 

         if [[ $(cat ${ETC_HOSTS_FILE} | grep ${PUBLIC_BIGSQL_FIRST_HEAD} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
            log ${FUNCNAME} "Found the first head node entry (${PUBLIC_BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
         else
            log ${FUNCNAME} "Did not find the first head node entry (${PUBLIC_BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
            user_rc=1
         fi
      else
         log ${FUNCNAME} "No public version of the first head node to validate."
      fi

      log ${FUNCNAME} "Looking for ${BIGSQL_SECOND_HEAD} and ${PUBLIC_BIGSQL_SECOND_HEAD} in ${ETC_HOSTS_FILE} on the second head ${BIGSQL_SECOND_HEAD}."

      # Check that the second head's regular hostname is in /etc/hosts
      if [[ $(cat ${ETC_HOSTS_FILE} | grep ${BIGSQL_SECOND_HEAD} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
         log ${FUNCNAME} "Found the second head node entry (${BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
      else
         log ${FUNCNAME} "Did not find the second head node entry (${BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
         user_rc=1
      fi

      # Check that the public version of the second head, if we have one, is in /etc/hosts
      if [[ ! -z ${PUBLIC_BIGSQL_SECOND_HEAD} && ${PUBLIC_BIGSQL_SECOND_HEAD} != ${BIGSQL_SECOND_HEAD} ]]; then 

         if [[ $(cat ${ETC_HOSTS_FILE} | grep ${PUBLIC_BIGSQL_SECOND_HEAD} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
            log ${FUNCNAME} "Found the second head node entry (${PUBLIC_BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
         else
            log ${FUNCNAME} "Did not find the second head node entry (${PUBLIC_BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_SECOND_HEAD}."
            user_rc=1
         fi
      else
         log ${FUNCNAME} "No public version of the second head node to validate."
      fi

      #
      # Now check the first head's /etc/hosts for the hostname of the second head
      #
      log ${FUNCNAME} "Looking for ${BIGSQL_FIRST_HEAD} and ${PUBLIC_BIGSQL_FIRST_HEAD} in ${ETC_HOSTS_FILE} on the first head ${BIGSQL_FIRST_HEAD}."

      # Check that the first head's regular hostname is in /etc/hosts on the first headnode
      if [[ $( RUN_CMD_AS ${SSH_CMD} ${BIGSQL_FIRST_HEAD} grep ${BIGSQL_FIRST_HEAD} ${ETC_HOSTS_FILE} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
         log ${FUNCNAME} "Found the first head node entry (${BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
      else
         log ${FUNCNAME} "Did not find the first head node entry (${BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
         user_rc=1
      fi

      # Check that the public version of the first head, if we have one, is in /etc/hosts
      if [[ ! -z ${PUBLIC_BIGSQL_FIRST_HEAD} && ${PUBLIC_BIGSQL_FIRST_HEAD} != ${BIGSQL_FIRST_HEAD} ]]; then 
         if [[ $( RUN_CMD_AS ${SSH_CMD} ${BIGSQL_FIRST_HEAD} grep ${PUBLIC_BIGSQL_FIRST_HEAD} ${ETC_HOSTS_FILE} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
            log ${FUNCNAME} "Found the first head node entry (${PUBLIC_BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
         else
            log ${FUNCNAME} "Did not find the first head node entry (${PUBLIC_BIGSQL_FIRST_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
            user_rc=1
         fi
      else
         log ${FUNCNAME} "No public version of the first head node to validate."
      fi

      log ${FUNCNAME} "Looking for ${BIGSQL_SECOND_HEAD} and ${PUBLIC_BIGSQL_SECOND_HEAD} in ${ETC_HOSTS_FILE} on the first head ${BIGSQL_FIRST_HEAD}."

     # Check that the second head's regular hostname is in /etc/hosts
      if [[ $( RUN_CMD_AS ${SSH_CMD} ${BIGSQL_FIRST_HEAD} grep ${BIGSQL_SECOND_HEAD} ${ETC_HOSTS_FILE} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
         log ${FUNCNAME} "Found the second head node entry (${BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
      else
         log ${FUNCNAME} "Did not find the second head node entry (${BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
         user_rc=1
      fi

      # Check that the public version of the second head, if we have one, is in /etc/hosts
      if [[ ! -z ${PUBLIC_BIGSQL_SECOND_HEAD} && ${PUBLIC_BIGSQL_SECOND_HEAD} != ${BIGSQL_SECOND_HEAD} ]]; then 
         if [[ $( RUN_CMD_AS ${SSH_CMD} ${BIGSQL_FIRST_HEAD} grep ${PUBLIC_BIGSQL_SECOND_HEAD} ${ETC_HOSTS_FILE} > /dev/null 2>&1 ; echo $?) -eq 0 ]]; then
            log ${FUNCNAME} "Found the second head node entry (${PUBLIC_BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
         else
            log ${FUNCNAME} "Did not find the second head node entry (${PUBLIC_BIGSQL_SECOND_HEAD}) in ${ETC_HOSTS_FILE} on ${BIGSQL_FIRST_HEAD}."
            user_rc=1
         fi
      else
         log ${FUNCNAME} "No public version of the second head node to validate."
      fi

      if [ ${user_rc} -ne 0 ]; then
         log_err "${FUNCNAME}" "There are missing entries in ${ETC_HOSTS_FILE}. rc=${user_rc}"
         rc=${BIGSQL_PRECHECK_WARN_CODE}
      else
         log "${FUNCNAME}" "The ${ETC_HOSTS_FILE} files are good for adding the second head node."
      fi
   else
      log "${FUNCNAME}" "Need first and second head node passed in. Cannot preform test."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   user_action_msg="Add the hostname entries for the first and second head node to the ${ETC_HOSTS_FILE} file on the first and second head nodes in order to add the second head node."

   report_check $rc "Check first head node entry in /etc/hosts" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check first head node entry in /etc/hosts. rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

# 41 - Check the ownership of bigsql user env files
# In some cases, removal of the bigsql user may leave files behind.
# If a new bigsql user is created with a diff uid, there 
# will be issues when running the .bash or .ksh files
# Check the following files and make sure they belong to the current
# bigsql user:
# - .bash_logout
# - .bash_profile
# - .bashrc
# - .kshrc
check_env_files()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_rc=0;
   local user_action_msg=""

   # Files to test
   declare -a env_file_arr=(".bash_logout" ".bash_profile" ".bashrc" ".kshrc")

   log "${FUNCNAME}" "Enter - Check ownership of bigsql env files"

   for env_file in "${env_file_arr[@]}"
   do
      log "${FUNCNAME}" "Validating file ${BIGSQL_USER_HOME}/${env_file}"

      if [ -f ${BIGSQL_USER_HOME}/${env_file} ]; then
         file_owner=`ls -al ${BIGSQL_USER_HOME}/${env_file} | awk '{print $3}'`

         log "${FUNCNAME}" "File ${BIGSQL_USER_HOME}/${env_file} is owned by ${file_owner}"

         if [ "${file_owner}" != "${BIGSQL_USER}" ]; then
            log_err "${FUNCNAME}" "File ${BIGSQL_USER_HOME}/${env_file} is not owned by ${BIGSQL_USER}."
            user_rc=1
         fi
      else
         log "${FUNCNAME}" "File ${BIGSQL_USER_HOME}/${env_file} does not exist. Validation OK."
      fi
   done

   if [ ${user_rc} -ne 0 ]; then
      user_action_msg="The env files in the ${BIGSQL_USER} home have incorrect ownership. Clean the home directory of the user and retry."
      rc=${BIGSQL_PRECHECK_ERR_CODE}
   fi

   # Log to the report log
   report_check $rc "Check owner of bigsql env files" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check ownership of bigsql env files. rc=$rc" 

   logLevel=$((logLevel-1))

   return $rc
}

# 42 - Check that the shell of the bigsql user is bash 
check_bigsql_shell()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check that the bigsql shell is bash"

   # Check only if the bigsql user exists
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then

      BIGSQL_SHELL=$(${SUDO_CMD} su - ${BIGSQL_USER} sh -c 'echo $SHELL')
      echo ${BIGSQL_SHELL} | grep bash > /dev/null 2>&1

      rc=$?

      if [ ${rc} -eq 0 ]; then
         log "${FUNCNAME}" "${BIGSQL_USER} shell is valid: ${BIGSQL_SHELL}."
      else
         log "${FUNCNAME}" "${BIGSQL_USER} shell is not valid: ${BIGSQL_SHELL}."

         user_action_msg="The shell for the Big SQL user ${BIGSQL_USER} is \"${BIGSQL_SHELL}\" which is not recommended. Please change the shell to bash."
         rc=${BIGSQL_PRECHECK_ERR_CODE}
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No bigsql user defined, cannot validate shell."
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Bigsql user shell check" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check that the bigsql shell is bash"

   logLevel=$((logLevel-1))

   return $rc
}

# 43 - Check that a non-root admin user has cron access
check_non_root_cron()
{
   logLevel=$((logLevel+1))
   local rc=0
   local user_action_msg=""

   log "${FUNCNAME}" "Enter - Check cron permission for non-root"

   # Check only if a non-root user is running Ambari
   if [[ ${HAVE_NON_ROOT_ADM_USER} -eq 1 ]]; then

      $(${SUDO_CMD} su - ${NON_ROOT_ADM_USER} sh -c "crontab -l > ${TMP_FILE} 2>&1")

      # See if there is a crontab; this is OK
      if grep -q "no crontab for" ${TMP_FILE}; then
         log "${FUNCNAME}" "There is no crontab and user ${NON_ROOT_ADM_USER} can use crontab."
      # Check is user not allowed to run cron
      elif grep -q "not allowed" ${TMP_FILE}; then
         log "${FUNCNAME}" "${NON_ROOT_ADM_USER} does not have permission to use crontab."

         user_action_msg="The non-root admin user \"${NON_ROOT_ADM_USER}\" is not allowed to use crontab. Use of crontab is needed to run Big SQL metrics. Change the cron configuration to allow cron usage for the user."
         rc=${BIGSQL_PRECHECK_ERR_CODE}
      # if not the above 2, there is already a cron job
      else
         log "${FUNCNAME}" "${NON_ROOT_ADM_USER} already has a cron job:"
         cat ${TMP_FILE} >> ${SCRIPT_LOG} 2>&1
      fi
   else
      # Skip check
      log "${FUNCNAME}" "No non-root admin user defined. Validation of cron not needed"
      rc=${BIGSQL_PRECHECK_SKIP_CODE}
   fi

   # Log to the report log
   report_check $rc "Cron permission for non-root" "${user_action_msg}"

   log "${FUNCNAME}" "Exit - Check cron permission for non-root"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# End Checking functions
################################################################################

# For diagnostics purposes, pre-emptively gather machine info:
# - dir listings
# - rpms
# - db2 version
get_machine_info()
{
   logLevel=$((logLevel+1))
   local rc=0

   log "${FUNCNAME}" "Enter - Get machine info"

   echo
   echo "Collecting machine information in ${MACHINE_INFO_DIR}"
   echo

   # Create a dir for the machine info
   mkdir -p ${MACHINE_INFO_DIR}
   chmod 777 ${MACHINE_INFO_DIR}

   # Gather files
   ls -al /var/ibm > ${MACHINE_INFO_DIR}/ls_var_ibm.out 2>&1
   ls -al /usr/ibmpacks > ${MACHINE_INFO_DIR}/ls_ibmpacks.out 2>&1
   ls -al ${BIGSQL_USER_HOME} > ${MACHINE_INFO_DIR}/ls_user_home.out 2>&1

   rpm -qa | egrep "bigsql|BI-Analyst|db2luw|ambari" > ${MACHINE_INFO_DIR}/rpm_list.out 2>&1

   ls -al /var/lib/ambari-agent/cache/stacks/BigInsights/4.?/services/BIGSQL/package/scripts > ${MACHINE_INFO_DIR}/ls_amb_ag_scr.out 2>&1

   # there could be other instances
   ${BIGSQL_DIST_HOME}/db2/instance/db2ilist > ${MACHINE_INFO_DIR}/instance_list.out 2>&1

   grep -i db2 /etc/services > ${MACHINE_INFO_DIR}/services_db2.out 2>&1

   ls -al /tmp/BIG* > ${MACHINE_INFO_DIR}/ls_BIG_tmp.out 2>&1

   # db2level
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
      ${SUDO_CMD} su - ${BIGSQL_USER} sh -c "db2level 2>&1 > ${MACHINE_INFO_DIR}/db2level.out" 2>&1
   fi

   if [ -d /etc/yum.repos.d ]
   then
     # Collect yum repo info
     cat /etc/yum.repos.d/*.repo > ${MACHINE_INFO_DIR}/yum_repo.out 2>&1
   fi

   # Collect all mount info - looking for bigsql home mounted with nosuid
   mount > ${MACHINE_INFO_DIR}/mount_info.out 2>&1

   # Collect the fstab file
   cp /etc/fstab ${MACHINE_INFO_DIR}/fstab.out

   # Get the bash version
   bash -version | grep version | head -n 1 > ${MACHINE_INFO_DIR}/mount_info.out 2>&1

   # Collect running env vars for root and bigsql
   set > ${MACHINE_INFO_DIR}/setenv_root.out 2>&1
   
   if [[ ${HAVE_BIGSQL_USER} -eq 1 ]]; then
      ${SUDO_CMD} su - ${BIGSQL_USER} sh -c "set > ${MACHINE_INFO_DIR}/setenv_bigsql.out" 2>&1
   fi

   log "${FUNCNAME}" "Exit - Get machine info with rc=$rc"

   logLevel=$((logLevel-1))

   return $rc
}

display_footer()
{
   log "${FUNCNAME}" "Test reported: $num_succ success(es), $num_err error(s), $num_warn warning(s) and $num_skip skipped."

   if [ $VERBOSE -eq 1 ]; then
      echo
      echo | tee -a ${REPORT_LOG}
      echo "Prechecker reported: $num_succ success(es), $num_err error(s) and $num_warn warning(s) and $num_skip skipped." | tee -a ${REPORT_LOG}
      echo >> ${REPORT_LOG}
   fi

   if [ $num_err -ne 0 ] || [ $num_warn -ne 0 ]; then
      echo
      echo "See REPORT_LOG for more information."
      echo "REPORT_LOG: $REPORT_LOG"

      # In the case of an error, echo the report_log so that it's displayed
      # in the Ambari console window.
      DISPLAY_REPORT=1
   fi
}

pre_add_host_checks()
{
   logLevel=$((logLevel+1))

   local rc=0
   SKIP_PRECHECKING=0

   log "${FUNCNAME}" "Entering pre add_host checks"

   # If the prechecker already ran clean on this host and the is the pre-add-host mode
   # there is no need to run it again. This can happen when the retry phase is
   # triggered from Ambari.
   if [[ -e ${BIGSQL_PRECHECK_SUCCESS_FILE} &&
          "${MODE}" == "PRE_ADD_HOST" ]]; then

      SKIP_PRECHECKING=1

      # echo "Skipping precheck since precheck success file was found."
      log "${FUNCNAME}" "Information - Precheck success file ( ${BIGSQL_PRECHECK_SUCCESS_FILE} ) was found. Skipping all checks."

      echo "Information - Precheck success file ( ${BIGSQL_PRECHECK_SUCCESS_FILE} ) was found. Skipping all checks."

      # Add an entry to the report log also
      echo >> $REPORT_LOG
      echo " Information - Precheck success file ( ${BIGSQL_PRECHECK_SUCCESS_FILE} ) was found." >> $REPORT_LOG
      echo " Skipping all checks." >> $REPORT_LOG
      echo >> $REPORT_LOG

   fi

   if [[ $SKIP_PRECHECKING -eq 0 ]]; then

      if  [ ! -z "$BIGSQL_UID_CHECK" ]
      then
         log "${FUNCNAME}" "Validating checkBigsqlUserId prevErr:($rc)"
         checkBigsqlUserId ${BIGSQL_UID_CHECK[@]}
         tmpRc=$?

         if [ "$tmpRc" -ne 0 ]
         then
            log "${FUNCNAME}" "Failure upon checkBigsqlUserId rc=$tmpRc"
            rc=1
         else
            log "${FUNCNAME}" "Validated BigsqlUser successfully"
         fi
      fi

      # Validate user for length
      validate_bigsql_user

      # log "${FUNCNAME}" "Validating ksh"
      check_ksh

      # log "${FUNCNAME}" "Validating disk space"
      check_disk_space

      # log "${FUNCNAME}" "Validating hosts file"
      check_etc_hosts

      # log "${FUNCNAME}" "Validating time diff"
      # Temporarily disabled (passwordless SSH)
      # check_timediff

      # log "${FUNCNAME}" "Validating userid consistency"
      # check_userid_same

      # log "${FUNCNAME}" "Validating Hive user group id consistency"
      # Temporarily disabled (passwordless SSH)
      # check_hive_gid_same

      # log "${FUNCNAME}" "Validating tmp permission"
      # Check that /tmp and /tmp/bigsql are writable by bigsql user
      check_tmp_write

      # log "${FUNCNAME}" "Validating sudoers"
      if [[ $EUID -ne 0 ]]; then
        check_sudoers
      fi

      # log "${FUNCNAME}" "Validating umask"
      check_umask

      # log "${FUNCNAME}" "Validating user home"
      # Temporarily disabled (passwordless SSH)
      # check_user_home

      # log "${FUNCNAME}" "Validating hdfs"
      check_hdfs_available

      # Validate data directories permissions
      check_data_dir_perm

      # There should not be bigsql entries in the /etc/services file
      check_bigsql_in_services

      # There should not be a sqllib in user home
      check_sqllib_exist

      # Check for potentail issues leading to db2ckgpfs errors
      # Placeholder
      # check_for_db2ckgpfs

      # Validate passwordless ssh
      check_passwordless_ssh

      # Validate that there are no TSA resources leftover
      check_TSA_resources

      # Check if ports specified are already in use by other processes
      check_FCM_port_usage
      check_DB2_port_usage

      # Check all required clients
      check_all_clients

      # Check user login shell setup
      check_user_shell

      # Check upper cases in hostname
      check_upper_hostname

      # Test that bigsql user home is not on a mount with nosuid
      check_mount_nosuid
      
      # Check that pam is installed
      #
      # No need to check this anymore as it gets installed with db2luw.
      # Comment out the call for now and remove after a few test itrations.
      #
      # check_pam_prereq

      # Check ping to worker nodes
      check_ping

      # Check that (rhel 7) optional is installed (required for HA)
      check_rhel7_ha_prereqs

      # Check that RHEL level match repo platform
      check_rhel_repo_level
      
      # Check the permissive mode on SELinux
      check_SE_permissive_mode

      # Check fstab options on some mount points
      check_fstab_noexec_nosuid

      # Validate the syntax of some XML files
      validate_xml_syntax

      # Validate RemoveIPC=no is set on rhel 7
      check_rhel7_ha_removeipc

      # Check that script runner can sudo (if not root)
      if [[ $EUID -ne 0 ]]; then
        check_sudo
      fi
      
      # Check passwordless from head to hive metastores
      check_passwordless_ssh_to_hive_metas

      # Check the permissions of /dev/shm
      check_devshm_perm

      # Check that prelink is disabled
      check_for_prelink

      # Do the following check only when validating a STANDBY host
      if [ ${STANDBY_CHECK} -eq 1 ]; then
         # Validate that the head hostnames are in the /etc/hosts file
         check_etc_host_for_entries
      fi

      # Check the ownership of bigsql user .bashrc* files
      check_env_files

      # Ensure bigsql user shell is bash
      check_bigsql_shell

      # Check non-root cron permission
      check_non_root_cron

      # get machine state info only when verbose mode is called.
      if [ ${VERBOSE} -eq 1 ]; then
         get_machine_info
      fi

   fi

   display_footer

   # Include the report data into the log file.
   log "${FUNCNAME}" "###################"
   log "${FUNCNAME}" "# Precheck Report"
   log "${FUNCNAME}" "###################"
   cat $REPORT_LOG >> ${SCRIPT_LOG}

   if [ $num_err -gt 0 ]; then
      rc=1
   fi

   log "${FUNCNAME}" "Exiting precheck main processing with $rc"

   logLevel=$((logLevel-1))

   return $rc

}

post_add_host_checks()
{
   logLevel=$((logLevel+1))
   local rc=0

   log "${FUNCNAME}" "Enter - precheck post_add_host processing"

   # log "${FUNCNAME}" "Validating db2set env"
   check_db2set_env

   display_footer

   # Include the report data into the log file.
   log "${FUNCNAME}" "###################"
   log "${FUNCNAME}" "# Precheck Report"
   log "${FUNCNAME}" "###################"
   cat $REPORT_LOG >> ${SCRIPT_LOG}

   if [ $num_err -gt 0 ]; then
      rc=1
   fi
   
   log "${FUNCNAME}" "Exiting precheck post_add_host processing with $rc"

   logLevel=$((logLevel-1))

   return $rc
}

post_install_checks()
{
   logLevel=$((logLevel+1))
   local rc=0

   log "${FUNCNAME}" "Enter - precheck post_install processing."

   # log "${FUNCNAME}" "Validating hdfs"
   check_hdfs_available

   # Check all required clients
   check_all_clients

   # Check Hive user primary group id consistency
   # Temporarily disabled (passwordless SSH)
   # check_hive_gid_same

   display_footer

   # Include the report data into the log file.
   log "${FUNCNAME}" "###################"
   log "${FUNCNAME}" "# Precheck Report"
   log "${FUNCNAME}" "###################"

   cat $REPORT_LOG >> ${SCRIPT_LOG}

   if [ $num_err -gt 0 ]; then
      DISPLAY_REPORT=1
      rc=1
   fi
   
   log "${FUNCNAME}" "Exiting precheck post_install processing with $rc"

   logLevel=$((logLevel-1))

   return $rc
}

post_configure_checks()
{
   logLevel=$((logLevel+1))

   local rc=0

   log "${FUNCNAME}" "Entering post configure checks"

   if [ ! -z "$BIGSQL_UID_CHECK" ]
   then
      log "${FUNCNAME}" "Validating checkBigsqlUserId prevErr:($rc)"
      checkBigsqlUserId ${BIGSQL_UID_CHECK[@]}
      tmpRc=$?

      if [ "$tmpRc" -ne 0 ]
      then
         log "${FUNCNAME}" "Failure upon checkBigsqlUserId rc=$tmpRc"
         rc=1
      else
         log "${FUNCNAME}" "Validated BigsqlUser successfully"
      fi
   fi

   # log "${FUNCNAME}" "Validating ksh"
   check_ksh

   # log "${FUNCNAME}" "Validating db2set env"
   check_db2set_env

   # log "${FUNCNAME}" "Validating userprofile"
   check_userprofile

   # log "${FUNCNAME}" "Validating disk space"
   check_disk_space

   # log "${FUNCNAME}" "Validating hosts file"
   check_etc_hosts

   # log "${FUNCNAME}" "Validating time diff"
   # Temporarily disabled (passwordless SSH)
   # check_timediff

   # log "${FUNCNAME}" "Validating userid consistency"
   # check_userid_same

   # log "${FUNCNAME}" "Validating Hive user group id consistency"
   # Temporarily disabled (passwordless SSH)
   # check_hive_gid_same

   # log "${FUNCNAME}" "Validating tmp permissi"
   # Check that /tmp and /tmp/bigsql are writable by bigsql user
   check_tmp_write

   # log "${FUNCNAME}" "Validating sudoers"
   if [[ $EUID -ne 0 ]]; then
     check_sudoers
   fi

   # log "${FUNCNAME}" "Validating user home"
   # Temporarily disabled (passwordless SSH)
   # check_user_home

   # log "${FUNCNAME}" "Validating hdfs"
   check_hdfs_available

   display_footer

   log "${FUNCNAME}" "Exiting post configure checks with $rc"

   if [ $num_err -gt 0 ]; then
      rc=1
   fi

   logLevel=$((logLevel-1))

   return $rc
}

# During this phase, we check the necessary prerequistes for Backup phase during Upgrade
backup_upgrade_checks()
{
   logLevel=$((logLevel+1))
   local rc=0

   log "${FUNCNAME}" "Enter - precheck Backup phase processing"

   #check for umask
   check_umask
   # log "${FUNCNAME}" "Validating hdfs"
   check_hdfs_available
   
   #adjust paths to point to HDP
   #get_machine_info

   check_rhel_repo_level

   # need to pass HDP paths
   validate_xml_syntax

   display_footer

   # Include the report data into the log file.
   log "${FUNCNAME}" "###################"
   log "${FUNCNAME}" "# Precheck Report"
   log "${FUNCNAME}" "###################"
   cat $REPORT_LOG >> ${SCRIPT_LOG}

   if [ $num_err -gt 0 ]; then
      rc=1
   fi
   
   log "${FUNCNAME}" "Exiting precheck post_add_host processing with $rc"

   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# General
################################################################################
usage()
{
cat 1>&2 <<-EOF
Usage: bigsql-precheck.sh [options]

   Options:
      -A                Run the prechecker on all hosts
      -b hbase user     Username for hbase
      -l host list file Non-default list of hosts to test
      -F                Force warnings to error.
      -H bigsqlhome     Provides the path to BIGSQL_DIST_HOME
      -i hive user      Username for hive
      -l hostlist       Path and filename listing bigsql hosts
      -L logdir         Specify the name of the log directory
      -M mode           Check phase: ( PRE_ADD_HOST )
      -P                Parallel mode for large cluster (if using Verbose, prints asynch)
      -R hdfs principal Principal name for hdfs user when using kerberos
      -s security type  Security feature user (ldap, kerberos, ldap_kerberos)
      -T hdfs keytab    Keytab for hdfs user when using kerberos
      -u bigsql user    Username for BigSQL
      -v vardir         Path to the "var" directory (the value of \$BIGSQL_DIST_VAR)
      -V                Verbose mode. Display individual test results to stdout.
      -x hdfs user      Username for hdfs
      -h                This help

      Example of a command to run before an install:

./bigsql-precheck.sh -M PRE_ADD_HOST -u bigsql -l /tmp/list_of_hosts.txt -z bigsql,2824,hadoop,515 -s os -x hdfs -b hbase -i hive -p 32051 -f 28051 -V -F

EOF
}

show_vars()
{
    cat <<-EOF

    +-------------------------------------------------+
    + CONSTANTS                                       +
    +-------------------------------------------------+

    BIGSQL_HOME              : ${BIGSQL_HOME}
    BIGSQL_VAR               : ${BIGSQL_VAR}
    MODE                     : ${MODE}
    DEFAULT_MODE             : ${DEFAULT_MODE}
    VERBOSE                  : ${VERBOSE}
    SCRIPT_LOG               : ${SCRIPT_LOG}
    TARGET_NODE              : ${TARGET_NODE}
    BIGSQL_FIRST_HEAD        : ${BIGSQL_FIRST_HEAD}
    BIGSQL_USER              : ${BIGSQL_USER}
    BIGSQL_UID_CHECK         : ${UIDARGS}
    HDFS_USER                : ${HDFS_USER}
    HBASE_USER               : ${HBASE_USER}
    HIVE_USER                : ${HIVE_USER}
    HIVE_METASTORE_HOST_1    : ${HIVE_METASTORE_HOST_1}
    HIVE_METASTORE_HOST_2    : ${HIVE_METASTORE_HOST_2}
    HDFS_PRINCIPAL           : ${HDFS_PRINCIPAL}
    HDFS_KEYTAB              : ${HDFS_KEYTAB}
    HEADNODE                 : ${HEADNODE}
    THIS_HOST_NAME           : ${THIS_HOST_NAME}
    SSH_HOSTLIST_FILE        : ${SSH_HOSTLIST_FILE}
    SUDO_SSH_USER            : ${SUDO_SSH_USER}
    BASE_LOG_DIR             : ${BASE_LOG_DIR}

EOF
}

OLD_IFS=$IFS

# If no options were passed in, we want to run in default mode. Track this
# so we can make some decisions later.
# In default mode, run verbosely.
if [ $# -eq 0 ]; then
   DEFAULT_MODE=1
   VERBOSE=1
fi

################################################################################
# Parse command line and get options
################################################################################
while getopts ":b:B:d:f:H:i:I:l:L:m:M:n:N:O:p:R:s:t:T:u:v:z:x:AFhPSVZ:" o; do
    case "${o}" in
        A) ALL_HOSTS=1
           ;;
        b) HBASE_USER="${OPTARG}"
           ;;
        B) BIGSQL_FIRST_HEAD="${OPTARG}"
           ;;
        d) BIGSQL_DATA_DIRS="${OPTARG}"
           ;;
        f) BIGSQL_PORT="${OPTARG}"
           ;;
        F) FORCE_ERR=1
           # Force warnings to errors
           BIGSQL_PRECHECK_WARN_CODE=${BIGSQL_PRECHECK_ERR_CODE}
           ;;
        l) NON_DEFAULT_HOST_LIST="${OPTARG}"
           ;;
        H) BIGSQL_HOME="${OPTARG}"
           ;;
        i) HIVE_USER="${OPTARG}"
           ;;
        I) HIVE_METASTORE_HOST_2="${OPTARG}"
           ;;
        L) SCRIPT_LOG_DIR="${OPTARG}"
           ;;
        m) HIVE_METASTORE_HOST_1="${OPTARG}"
           ;;
        M)  MODE="${OPTARG}"
            if [ "${MODE}" != "PRE_ADD_HOST" \
                 -a "${MODE}" != "POST_ADD_HOST" \
                 -a "${MODE}" != "POST_INSTALL" \
                 -a "${MODE}" != "PRE_BACKUP" \
                 -a "${MODE}" != "POST_SETUP" ]; then
               echo "Invalid execution mode: ${MODE}" 1>&2; exit 1
            fi
            ;;
        n) TARGET_NODE="${OPTARG}"
           ;;
        N) NAMENODE="${OPTARG}"
           ;;
        O) CONFIGURED_HOSTNAME="${OPTARG}"
           ;;
        p) DB2_PORT="${OPTARG}"
           ;;
        P) PARALLEL=1
           ;;
        R) HDFS_PRINCIPAL="${OPTARG}"
           ;;
        S) STANDBY_CHECK=1
           ;;
        s) SECURITY_TYPE="${OPTARG}"
           ;;
        t) TIMESTAMP="${OPTARG}"
           ;;
        T) HDFS_KEYTAB="${OPTARG}"
           ;;
        u) BIGSQL_USER="${OPTARG}"
           ;;
        v) BIGSQL_VAR="${OPTARG}"
           ;;
        V) VERBOSE=1
           ;;
        z) # Get comma separeated uid check args into array
           IFS=',' read -a BIGSQL_UID_CHECK <<< "${OPTARG}"
           ;;
        x) HDFS_USER="${OPTARG}"
           ;;
        h) echo "" 1>&2
           usage
           exit 0
           ;;
        Z) SUDO_SSH_USER="${OPTARG}"
           ;;
        *) echo "Unrecognized option: -${OPTARG}" 1>&2
           usage
           exit 1
           ;;
        :) if [[ "${OPTARG}" == "h" ]]; then
              usage
              exit 0
           else
              echo "Option: -${OPTARG} requires an argument." 1>&2
              usage
              exit 1
           fi
           ;;
    esac
done
shift $((OPTIND-1))

IFS=$OLD_IFS

# Track a non-root Ambari admin user
if [[ ${EUID} -ne 0 ]] && [[ ${SUDO_SSH_USER} != "root" ]]; then
   NON_ROOT_ADM_USER=${SUDO_SSH_USER}
   HAVE_NON_ROOT_ADM_USER=1
   log "${FUNCNAME}" "Non-root ambari admin user detected: ${NON_ROOT_ADM_USER}."
fi

###############################################################################
## 5 - CONFIGURE LOGGING AND CALCULATE VARIABLES
###############################################################################

# Add the check phase to the logfilename
PHASE=""
if [ "${MODE}" == "PRE_ADD_HOST" ]; then
  PHASE="1"
elif [ "${MODE}" == "POST_ADD_HOST" ]; then
  PHASE="2"
elif [ "${MODE}" == "POST_INSTALL" ]; then
  PHASE="3"
elif [ "${MODE}" == "POST_SETUP" ]; then
  PHASE="4"
elif [ "${MODE}" == "PRE_BACKUP" ]; then
  PHASE="backup_detailed"
fi

# Create log filename here and make use of mode
LOG_FILENAME=bigsql-precheck-${PHASE}-"${TIMESTAMP}".log

# Test using a report file
REPORT_FILENAME=bigsql-precheck-${PHASE}-"${TIMESTAMP}".report
MACHINE_INFO_FILENAME=bigsql-machine-info-"${TIMESTAMP}".txt

# Summary file when invoked on all hosts
SUMMARY_FILENAME=bigsql-precheck-${PHASE}-"${TIMESTAMP}".summary

if [[ -z ${SCRIPT_LOG_DIR+x} ]]; then
   LOGGING_DIR=${BASE_LOG_DIR}/${BIGSQL_USER}/logs
   SCRIPT_LOG=${LOGGING_DIR}/${LOG_FILENAME}
else
   LOGGING_DIR=${SCRIPT_LOG_DIR}
   SCRIPT_LOG=${SCRIPT_LOG_DIR}/${LOG_FILENAME}
fi

REPORT_LOG=${LOGGING_DIR}/${REPORT_FILENAME}
MACHINE_INFO_DIR=${LOGGING_DIR}/info-"${TIMESTAMP}"
MACHINE_INFO_LOG=${MACHINE_INFO_DIR}/${MACHINE_INFO_FILENAME}
SUMMARY_LOG=${LOGGING_DIR}/${SUMMARY_FILENAME}

id ${BIGSQL_USER} > /dev/null 2>&1
rc=$?

if [[ $rc -eq 0 ]]; then
   HAVE_BIGSQL_USER=1
   BIGSQL_GROUP=`id -gn ${BIGSQL_USER}`
   BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   BIGSQL_USER_SQLLIB=${BIGSQL_USER_HOME}/sqllib
fi

# Notify the user so they can tail the log if they are so inclined. A setup on a big
# cluster can take quite a while
echo "Log file for this script is: ${SCRIPT_LOG}"
echo

# Create the logging directory
create_logdir_logfile "${LOGGING_DIR}" "${SCRIPT_LOG}"
rc=$?

if [[ $rc != 0 ]]; then
   log_err "${FUNCNAME}" "Failed to create logging directory. rc: $rc"
   exit 1
fi

# This section header lets you identify which mode the script was being invoked from
echo "======================================================================" >> ${SCRIPT_LOG}
echo "bigsql-precheck executed from:" >> ${SCRIPT_LOG}
echo "${RUN_SCRIPT}" >> ${SCRIPT_LOG}
echo "bigsql-precheck executed with options:" >> ${SCRIPT_LOG}
echo "${CMD_LINE}" >> ${SCRIPT_LOG}

# Make a header for the report log
echo "======================================================================" >> ${REPORT_LOG}
echo "bigsql-precheck report" >> ${REPORT_LOG}
echo >> ${REPORT_LOG}

log "$FUNCNAME" "precheck started"

# If a non default host list file was passed in, use it instead.
if [[ ! -z ${NON_DEFAULT_HOST_LIST} ]]; then
  if [[ -f ${NON_DEFAULT_HOST_LIST} ]]; then
    SSH_HOSTLIST_FILE=${NON_DEFAULT_HOST_LIST}
  else
    log "${FUNCNAME}" "Error: File ${NON_DEFAULT_HOST_LIST} does not exist."
    echo "Error: File ${NON_DEFAULT_HOST_LIST} does not exist."
    echo "Please create a file with a list of hosts to run the prechecker on."
    echo "Example:"
    echo "host1.mydomain.com"
    echo "nost2.mydomain.com"
    echo
    exit 0
  fi
fi

# In the case where parallel and verbose are used, warn that output of the scripts
# will be asynchronously displayed until the summary at the end.
if [[ ${PARALLEL} -eq 1 ]] && [[ ${VERBOSE} -eq 1 ]]; then
   echo
   echo "Script is running in parallel mode with verbose output. Script"
   echo "results will be displayed asynchronously during runtime. A"
   echo "summary of the run will be displayed upon run completion."
   echo
fi

# Determine which node is the head node (this one)
if [ -f ${SSH_HOSTLIST_FILE} ]; then
   HAVE_HOSTLIST_FILE=1
   log "$FUNCNAME" "Using the following host list file: $SSH_HOSTLIST_FILE"

   # Build a list of hosts from the host default host list file.
   NODE_LIST=( $(<"${SSH_HOSTLIST_FILE}") )

   # Get the headnode
   HEADNODE=${NODE_LIST[0]}

   if [[ ${STANDBY_CHECK} -eq 1 ]]; then
      HEADNODE=${THIS_HOST_NAME}
   fi
   # Get all the hostnames defined for this host in case there is a private interface defined.
   THIS_HOST_LIST=`hostname -A`

   read -r -a THIS_HOST_LIST_ARRAY <<< "$THIS_HOST_LIST"

   for index in "${!THIS_HOST_LIST_ARRAY[@]}"
   do
      # Test if we are on the headnode
      if [[ ${THIS_HOST_LIST_ARRAY[index]} = ${HEADNODE} ]]; then
         RUNNING_ON_HEADNODE=1
      fi
   done
else
   log "$FUNCNAME" "INFO: The host list file $SSH_HOSTLIST_FILE was not found, unable to validate if this host is the headnode."
fi

# Log the script variables
show_vars >> ${SCRIPT_LOG}

# kinit users here, before doing any work
if [[ "${HDFS_KEYTAB}" != "" ]] && [[ "${HDFS_PRINCIPAL}" != "" ]]; then
   log "${FUNCNAME}" "${SUDO_CMD} su - ${HDFS_USER} sh -c \"kinit -k -t ${HDFS_KEYTAB} ${HDFS_PRINCIPAL}\""

   ${SUDO_CMD} su - ${HDFS_USER} sh -c "kinit -k -t ${HDFS_KEYTAB} ${HDFS_PRINCIPAL}" >> ${SCRIPT_LOG} 2>&1
   postRc=$?
   if [[ $postRc != 0 ]]; then
      log_err "${FUNCNAME}" "Command kinit failed with rc: $postRc"
      KINIT_FAIL=1
   fi
fi

precheck_pre_processing()
{
   logLevel=$((logLevel+1))
   log "${FUNCNAME}" "Entering precheck pre processing"

   local rc=0

   rm -f $BIGSQL_PRECHECK_FAILURE_FILE

   log "${FUNCNAME}" "Exiting precheck pre processing with rc=$rc"
   logLevel=$((logLevel-1))

   return $rc
}

getArgs()
{
   IFS=',' read -ra callArgs <<< "$1"
   return callArgs
}

precheck_main()
{
   logLevel=$((logLevel+1))
   log "${FUNCNAME}" "Entering precheck main processing"

   local rc=0
   local num_err=0
   local num_warn=0

   # Work to do in PRE_ADD_HOST mode
   if [ "${MODE}" = "PRE_ADD_HOST" ]; then

      log "${FUNCNAME}" "In PRE_ADD_HOST main, calling local system check."

      pre_add_host_checks
      rc=$?

   elif [ "${MODE}" = "POST_INSTALL" ]; then

     log "${FUNCNAME}" "In POST_INSTALL main, calling local system check."

      post_install_checks
      rc=$?
   
   elif [ "${MODE}" = "PRE_BACKUP" ]; then

     log "${FUNCNAME}" "In Backup Upgrade mode, calling local system check."

      backup_upgrade_checks
      rc=$?

   fi

   logLevel=$((logLevel-1))

   return $rc
}

precheck_post_processing()
{
   local rc=$1
   logLevel=$((logLevel+1))
   log "${FUNCNAME}" "Entering precheck post processing with rc=$rc"

   # Only create the status files if this was not a manual (verbose) call
   if [ $VERBOSE -eq 0 ]; then
      if [ "$1" -ne  0 ]
      then
         rc=1
         touch "$BIGSQL_PRECHECK_FAILURE_FILE"
      else
         touch "$BIGSQL_PRECHECK_SUCCESS_FILE"
      fi
   fi

   log "${FUNCNAME}" "Exiting precheck post processing, with rc=$rc"
   logLevel=$((logLevel-1))

   return $rc
}

################################################################################
# 7 - Main
################################################################################

index=0
declare -a host_state_list

if [ ${ALL_HOSTS} -eq 1 ]; then

  if [ -f ${SSH_HOSTLIST_FILE} ]; then

    echo "Running prechecker from ${THIS_HOST_NAME} on all hosts in ${SSH_HOSTLIST_FILE}:"
    cat ${SSH_HOSTLIST_FILE}

    # Use a new timestamp for the log files, so we don't overwrite the current one
    REMOTE_REPORT_LOG=${LOGGING_DIR}/bigsql-precheck-${PHASE}-"${TIMESTAMP}".report

    # Test running in parallel
    if [ ${PARALLEL} -eq 0 ]; then
      echo

      for HOST in `cat ${SSH_HOSTLIST_FILE}`
      do
        echo "Running prechecker on host $HOST"
        REMOTE_CMD_OPTIONS=`echo "${CMD_LINE} -t ${TIMESTAMP}" | sed 's/-A//g'`

        # Copy the script to the remote /tmp dir and run from there
        # Do this only for verbose runs
        if [ ${VERBOSE} -eq 1 ]; then
           ${SCP_CMD} ${SCRIPT_DIR}/bigsql-precheck.sh ${HOST}:${TMP_SCRIPT_DIR}
           rc=$?

           # if we couldn't copy, issue an error for the remote copies to be cleaned
           if [ ${rc} -ne 0 ]; then
              echo "Could not write ${TMP_SCRIPT_DIR}/bigsql-precheck.sh on ${HOST}. Delete it and retry."
              exit 1;
           fi

           ${SCP_CMD} ${SCRIPT_DIR}/bigsql-util.sh ${HOST}:${TMP_SCRIPT_DIR}
           rc=$?

           # if we couldn't copy, issue an error for the remote copies to be cleaned
           if [ ${rc} -ne 0 ]; then
              echo "Could not write ${TMP_SCRIPT_DIR}/bigsql-util.sh on ${HOST}. Delete it and retry."
              exit 1;
           fi

           SCRIPT_REMOTE_RUN_DIR=${TMP_SCRIPT_DIR}

        else
           SCRIPT_REMOTE_RUN_DIR=${SCRIPT_DIR}
        fi

        cmd="${SSH_CMD} $HOST ${SUDO_CMD} ${SCRIPT_REMOTE_RUN_DIR}/bigsql-precheck.sh ${REMOTE_CMD_OPTIONS}"
        log "${FUNCNAME}" "${cmd}"
        RUN_CMD_AS $cmd
        host_rc=$?

        # Gather hostname and state for summary
        if [[ $host_rc -ne 0 ]]; then
            host_state="Failed"
        else
            host_state="Success"
        fi

        host_state_list+=("$HOST: $host_state")
        
        # Now get the report file and append it to our summary file
        echo "======================================================================" >> ${REPORT_LOG}
        echo "Report log for host ${HOST}" >> ${SUMMARY_LOG}
        get_report_cmd="${SSH_CMD} ${HOST} ${SUDO_CMD} cat ${REMOTE_REPORT_LOG}"
        RUN_CMD_AS $get_report_cmd >> ${SUMMARY_LOG}
      done

      echo "Precheck on all hosts is complete."

      # Display host test summary
      echo "======================================================================" >> ${REPORT_LOG}
      echo "Summary of tests:" | tee -a ${SUMMARY_LOG}
      echo | tee -a ${SUMMARY_LOG}
      printf "%s\n" "${host_state_list[@]}" | tee -a ${SUMMARY_LOG}
      echo
      
      echo "Log file can be found on host ${THIS_HOST_NAME} at ${SCRIPT_LOG}"
      echo "Summary file can be found on host ${THIS_HOST_NAME} at ${SUMMARY_LOG}"
      echo
    # Run a parallel version of the prechecker
    else
      # To run in parallel
      #   - call the scripts on all hosts in parallel
      #   - then serially get the reports, waiting on child pids
      #     in the same order as the host file
      echo

      for HOST in `cat ${SSH_HOSTLIST_FILE}`
      do
        echo "Running prechecker on host $HOST"
        # Important:
        # When passing the cmd line options to the remote script
        # remove the -A (all hosts) and the -P (parallel) from the args
        REMOTE_CMD_OPTIONS=`echo "${CMD_LINE}" | sed 's/-A//g'`
        REMOTE_CMD_OPTIONS=`echo "${REMOTE_CMD_OPTIONS} -t ${TIMESTAMP}" | sed 's/-P//g'`
        
        # Copy the script to the remote /tmp dir and run from there
        # Do this only for verbose runs
        if [ ${VERBOSE} -eq 1 ]; then
           ${SCP_CMD} ${SCRIPT_DIR}/bigsql-precheck.sh ${HOST}:${TMP_SCRIPT_DIR}
           rc=$?

           # if we couldn't copy, issue an error for the remote copies to be cleaned
           if [ ${rc} -ne 0 ]; then
              echo "Could not write ${TMP_SCRIPT_DIR}/bigsql-precheck.sh on ${HOST}. Delete it and retry."
              exit 1;
           fi

           ${SCP_CMD} ${SCRIPT_DIR}/bigsql-util.sh ${HOST}:${TMP_SCRIPT_DIR}
           rc=$?

           # if we couldn't copy, issue an error for the remote copies to be cleaned
           if [ ${rc} -ne 0 ]; then
              echo "Could not write ${TMP_SCRIPT_DIR}/bigsql-util.sh on ${HOST}. Delete it and retry."
              exit 1;
           fi

           SCRIPT_REMOTE_RUN_DIR=${TMP_SCRIPT_DIR}

        else
           SCRIPT_REMOTE_RUN_DIR=${SCRIPT_DIR}
        fi

        cmd="${SSH_CMD} $HOST ${SUDO_CMD} ${SCRIPT_REMOTE_RUN_DIR}/bigsql-precheck.sh ${REMOTE_CMD_OPTIONS}"
        log "${FUNCNAME}" "${cmd}"
        RUN_CMD_AS $cmd &

        pidsToWait[$index]=$!
        msgIndex[$index]=$HOST
        log "${FUNCNAME}" "Spawned child ${pidsToWait[$index]}"
        index=$((index+1))
      done

      #
      # Waitpids
      #
      numLoop=${#pidsToWait[@]}
      log "${FUNCNAME}" "Total numPid:$numLoop"
      for ((index=0; index<$numLoop; index++))
      do
        log "${FUNCNAME}" "Waiting for $index, pid ${pidsToWait[$index]}"
        wait ${pidsToWait[$index]}
        pidRc=$?

        if [[ $pidRc -ne 0 ]]
        then
          log "${FUNCNAME}" "FAIL: on index:$index host:${msgIndex[$index]} with rc: $pidRc pid:${pidsToWait[$index]}"
          host_state="Failed"
          rc=1
        else
          log "${FUNCNAME}" "SUCCESS:on index:$index host:${msgIndex[$index]} pid:$pidsToWait[$index]"
          host_state="Success"
        fi

        # Now get the report file and append it to our summary file
        echo "Report log for host ${msgIndex[$index]}" >> ${SUMMARY_LOG}
        get_report_cmd="${SSH_CMD} ${msgIndex[$index]} ${SUDO_CMD} cat ${REMOTE_REPORT_LOG}"
        RUN_CMD_AS $get_report_cmd >> ${SUMMARY_LOG}

        host_state_list+=("${msgIndex[$index]}: $host_state")
      
      done # Done waiting for pids

      log "${FUNCNAME}" "Precheck on all hosts is complete."

      # Display host test summary
      echo "Summary of tests:" | tee -a ${SUMMARY_LOG}
      echo | tee -a ${SUMMARY_LOG}
      printf "%s\n" "${host_state_list[@]}" | tee -a ${SUMMARY_LOG}
      echo
      
      echo "Log file can be found at ${SCRIPT_LOG}"
      echo "Summary file can be found at ${SUMMARY_LOG}"
    fi

  else

    echo "${SSH_HOSTLIST_FILE} does not exist. Please create a file containing a list of hosts to test. The file is in the following format:"
    echo
    echo "host1.mydomain.com"
    echo "nost2.mydomain.com"
    echo
    exit 1

  fi

else

  precheck_pre_processing
  rc=$?
  if [ $rc -ne 0 ]; then
     exit $rc
  fi

  precheck_main
  rc=$?

  precheck_post_processing $rc
  rc=$?

fi

log "${FUNCNAME}" "Processing is complete with rc=$rc."

if [ ${DISPLAY_REPORT} -eq 1 ]; then
   cat ${REPORT_LOG} >&2
fi

echo
echo "Precheck on ${THIS_HOST_NAME} is complete with rc=$rc. More information can be found in the log file:"
echo "Log file: ${SCRIPT_LOG}"
echo

exit $rc
