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
# NAME:     bigsql-util.sh
#
# FUNCTION:
#
# USAGE:    ./bigsql-util.sh [options]
#
# DETAILS:
#            Utility script with common functions
#
#
################################################################################

################################################################################
# 1 - Constants and variable declarations
################################################################################

# Command macros
UTIL_SSH_CMD="ssh -o LogLevel=error -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
ROOT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

# Do not sudo when running as root
if [[ $EUID -eq 0 ]]; then
    SUDO_CMD=""
else
    SUDO_CMD="sudo"
fi

# Error codes
# Codes can only be positive ints.
BIGSQL_RC_NO_LOG_USER=100
BIGSQL_RC_NO_LOG_DIR=101

#---------------------------------------------------
# LOG LEVEL
#---------------------------------------------------
logLevel=0

#------------------------------------------------------------
# BIGSQL USERID DEFAULTS to 'bigsql'
#------------------------------------------------------------
THIS_HOST=$(hostname -f)

#------------------------------------------------------------
# Temporary files and log files
#------------------------------------------------------------
get_timestamp()
{
   local CURRENT_DATE_TIME=$(date +"%Y-%m-%d_%H.%M.%S.%4N")
   echo $CURRENT_DATE_TIME
}

################################################################################
# 2 - util functions
################################################################################
log_info()
{
   LINE="${BASH_LINENO[0]}"
   log "$1" "[INFO] - $2" $LINE
}

log_err()
{
   LINE="${BASH_LINENO[0]}"
   log "$1" "[ERROR] - $2" $LINE
}

log_warn()
{
   LINE="${BASH_LINENO[0]}"
   log "$1" "[WARNING] - $2" $LINE
}

log()
{
   local fun=$1
   local msg=$2
   LINE=$3

   if [ -z "$1" ]
   then
      fun="MAIN"
   else
      fun="$1"
   fi

   if [ -z "$LINE" ]
   then
      LINE="${BASH_LINENO[0]}"
   fi

   printf "%.23s @ Line(%-5.5d) @ Fun %32.32s: " $(date +%F.%T.%N) "${LINE}" "$fun" >> ${SCRIPT_LOG}

   local curLevel=$logLevel
   while [ $curLevel -gt 1 ]
   do
      echo -n "." >> ${SCRIPT_LOG}
      curLevel=$((curLevel-1))
   done

   echo "$msg" >> ${SCRIPT_LOG}
}

log_echo()
{
   local func=$1
   local msg="$2"
   local LINE="${BASH_LINENO[0]}"
   log "$func" "$msg" $LINE
   echo "${msg}"
}

attempt_log()
{
   local attemptLogRc=0
   FUNC=$1
   shift
   log "$FUNC" "Executing: $*"

   $1 >> ${SCRIPT_LOG} 2>&1
   attemptLogRc=$?

   return $attemptLogRc
}

# An attempt to get around problems with nested quotes in SUDO -> SSH commands
log_and_run()
{
   FUNC=$1
   CMD=$2
   log "$FUNC" "$CMD"
   eval "$CMD"
}

log_env()
{
   local SCRIPT_LOG=$1
   echo "======================================================================" >> ${SCRIPT_LOG}
   echo "                         START ENV LOGGING " >> ${SCRIPT_LOG}
   echo "======================================================================" >> ${SCRIPT_LOG}

   env >>  ${SCRIPT_LOG}

   echo "======================================================================" >> ${SCRIPT_LOG}
   echo "                         END ENV LOGGING " >> ${SCRIPT_LOG}
   echo "======================================================================" >> ${SCRIPT_LOG}
}

# Utility function to trim the trailing and leading spaces of a string value
trim_spaces()
{
    local ENTRIES="$@"
    result=$(echo "$ENTRIES" | sed -e 's/^ *//' -e 's/ *$//')
    echo $result
}

# Utility function to trim the leading char of a string value
trim_leading_char()
{
   local ENTRIES=$1
   local CHAR_TO_TRIM=$2
   result=${ENTRIES#"${CHAR_TO_TRIM}"}
   echo $result
}

# Utility function to trim the tailing char of a string value
trim_tailing_char()
{
   local ENTRIES=$1
   local CHAR_TO_TRIM=$2
   result=${ENTRIES%"${CHAR_TO_TRIM}"}
   echo $result
}

#Utility function - run cmd via passwordless ssh
sshexec()
{
   logLevel=$((logLevel+1))

   local NODE=$1
   shift

   log_info "${FUNCNAME}" "Executing '$*' on ${NODE}"

   sshresult=$(${UTIL_SSH_CMD} ${NODE} -q -o PasswordAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $@ 2>&1)
   sshexitcode=$?

   log_info "${FUNCNAME}" "Result: ${sshresult}. Exit code: ${sshexitcode}"

   logLevel=$((logLevel-1))
}

get_bigsql_nodes()
{
   local NODELIST=$1
   local node_list=`cat ${NODELIST} | cut -d " " -f 2`

   #remove duplications from the node_list
   local nodes=""
   for node in ${node_list}
   do
      node=$(trim_spaces "${node}")
      if [[ ! "${nodes}" =~ "${node}" ]]; then
         nodes="${nodes}""${node}",
      fi
   done

   nodes=$(trim_tailing_char "${nodes}" ",")
   echo ${nodes}
}

#Utility function - run cmd via passwordless ssh
#Check the nodelist locally on the same machine as the scripts
get_partitions()
{
   local node=$1
   local NODELIST=$2
   local partition_list=`cat ${NODELIST} | grep ${node} | cut -d " " -f 1`
   echo ${partition_list}
}

#Utility function - run cmd via passwordless ssh
#check the nodelist on the remote machine
#this is necessary as the drop partition will modify the db2nodes.cfg on the head node
get_partitions_remote()
{
   local node=$1
   local NODELIST=$2
   sshexec ${node} "cat ${NODELIST} | grep ${node} | cut -d \" \" -f 1"
   echo ${sshresult}
}

init_kerberos()
{
   local BIGSQL_USER=$1
   local NODELIST=$2
   local SECURITY_TYPE=$3
   local KERBEROS_KEYTAB=$4
   local KERBEROS_REALM=$5
   local KERBEROS_CACHE_FILE=$6

   local rc=1
   if [[ "${SECURITY_TYPE}" == "kerberos" || "${SECURITY_TYPE}" == "kerberos_ldap" ]]; then
      #init kerberos
      local BIGSQL_NODES=$(get_bigsql_nodes "${NODELIST}")
      for node in ${BIGSQL_NODES}
      do
         log_info "${FUNCNAME}" "init kerberos for ${node}"
         sshexec ${node} "id -u ${BIGSQL_USER}"
         KERBEROS_CACHE_FILE="/tmp/krb5cc_${sshresult}"
         sshexec ${node} "kinit -k -t ${KERBEROS_KEYTAB} ${BIGSQL_USER}/${node}@${KERBEROS_REALM} -c FILE:${KERBEROS_CACHE_FILE}"
         if [[ $sshexitcode != 1 ]]; then
            rc=$sshexitcode
            log_warn "${FUNCNAME}" "Node: ${node}. kinit finished with exit code $rc"
         fi
      done
   fi

   return $rc
}

###################################################################
# RUN_CMD_AS : Run commands as sudo_ssh_user id.
#
# Caller must set SUDO_SSH_USER and SCRIPT_LOG 
#
# SUDO_SSH_USER is the one that owns
# ambari pid.
# a -deafult would be id 'root'
# or
# b- id that owns ambari agent pid and can do sudo and ssh to
#    all cluster from head node(s)/ambari-server (1XN)and between 
#    head-nodes &  ambari-server (3x3)
##################################################################
RUN_CMD_AS()
{
  # Switch to local
  local scriptLog=${SCRIPT_LOG}
  local sudoCmd=${SUDO_CMD}
  local sudoSshUser=${SUDO_SSH_USER}

  # Set to defaults if not set.
  if [[ -z ${sudoSshUser} ]]
  then
     echo "SUDO_SSH_USER is not set, defaulting to root"
     sudoSshUser="root"
  fi

  # Do not sudo when we are root and perform ssh as root
  if [[ ${EUID} -eq 0 ]] && [[ ${SUDO_SSH_USER} == "root" ]]; then
      sudoCmd=""
  else
      sudoCmd="sudo"
  fi

  if [[ -z ${scriptLog} ]]
  then
     echo "SCRIPT_LOG is not set!, defaulting to /dev/null"
     scriptLog="/dev/null"
  fi

  # Log and run the cmd as sudo/ssh user
  cmd="${sudoCmd} su - ${sudoSshUser} sh -c \"$*\""
  echo "$sudoSshUser: Running cmd as: $cmd" >> ${scriptLog}
  eval ${sudoCmd} su - ${sudoSshUser} sh -c \"$*\"
}

bigsql_printMlnsForHost()
{
   local bigsqlHost=$1
   local nodesFile=$2
   local nodesForHost
   nodesForHost=`cat "$nodesFile" | grep $bigsqlHost | sed 's/ \+/\,/g'`
   echo "${nodesForHost}"
}


bigsql_getMlnCount()
{
   local nodesFile=$1
   local bigsqlHost=$2
   local portInUse
   local portIndex
   local port
   local currentPort

   portInUse=`cat "$nodesFile" | grep "${bigsqlHost}" | sed 's/ \+/\,/g' | cut -d',' -f3| sort -n`

   portIndex=0

   for port in ${portInUse}
   do
      currentPort=$port
      portIndex=$((portIndex+1))
   done

   currentPort=$((currentPort+1))

   return $portIndex
}

bigsql_getMlnsForHost()
{
   local bigsqlHost=$1
   local nodesFile=$2
   local portInUse
   local portIndex
   local port
   local currentPort

   portInUse=`cat "$nodesFile" | grep $bigsqlHost | sed 's/ \+/\,/g' | cut -d',' -f3| sort -n`

   portIndex=0

   for port in ${portInUse}
   do
      currentPort=$port
      portIndex=$((portIndex+1))
   done

   currentPort=$((currentPort+1))

   echo "$bigsqlHost(logicalWorkers: $currentPort)"
   bigsql_printMlnsForHost $1 $2

   return $portIndex
}

bigsql_getLogicalWorkerCount()
{
   local BIGSQL_USER=$1
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"

   logicalWorkerCount=`cat "$nodesFile" | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| wc -l`

   echo "Logical Big SQL Worker Count in the cluster: $logicalWorkerCount"
   return $logicalWorkerCount
}

bigsql_getLogicalWorkerCountOnHost()
{
   local BIGSQL_USER=$1
   local HOST=$2
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"

   logicalWorkerCount=`cat "$nodesFile" | grep ${HOST} | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| wc -l`

   echo "Logical Big SQL Worker Count for host $host: $logicalWorkerCount"
   return $logicalWorkerCount
}

bigsql_getPyhsicalWorkerCount()
{
   local BIGSQL_USER=$1
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"

   physicalWorkerCount=`cat "$nodesFile" | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| uniq | wc -l`

   echo "Logical Big SQL Worker Count in the cluster: $physicalWorkerCount"
   return $physicalWorkerCount
}

bigsql_listMlns()
{
   local BIGSQL_USER=$1
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"
   local maxPort=0
   local uniqHosts

   uniqHosts=`cat "$nodesFile" | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| uniq`

   echo "Logical Big SQL Worker Status"
   for host in $uniqHosts
   do
      bigsql_getMlnsForHost $host $nodesFile
      numMlnsInOneHost=$?
      if [[ $maxMln -lt $numMlnsInOneHost ]]
      then
         maxMln=$numMlnsInOneHost
      fi
   done
   echo "Max Logical Big SQL Worker Count in the cluster: $maxMln"
   return $maxMln
}

bigsql_getAverageMlnCount()
{
   local BIGSQL_USER=$1
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"
   local maxPort=0
   local uniqHosts

   uniqHosts=`cat "$nodesFile" | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| uniq`

   echo "Logical Big SQL Worker Status"
   for host in $uniqHosts
   do
      bigsql_getMlnsForHost $host $nodesFile
      numMlnsInOneHost=$?
      totalCount=$((numMlnsInOneHost+totalCount))
      hostCount=$((hostCount+1))
   done
   avgMlnCount=`echo $totalCount $hostCount | awk '{print int($1/$2+ 0.5)}'`

   if [[ $avgMlnCount -eq 0 ]]
   then
      avgMlnCount=1
   fi

   echo "Average Logical Big SQL Worker Count in the cluster: $avgMlnCount"
   return ${avgMlnCount}
}

bigsql_getMaxMlnCount()
{
   local BIGSQL_USER=${1}
   local host=${2}
   local BIGSQL_USER_HOME=$(eval echo ~${BIGSQL_USER})
   local BIGSQL_SQLLIB="$BIGSQL_USER_HOME/sqllib"
   local nodesFile="$BIGSQL_SQLLIB/db2nodes.cfg"
   local maxMln=0

   uniqHosts=`cat "$nodesFile" | grep "${host}" | grep -v ^0 | sed 's/ \+/\,/g' | cut -d',' -f2| sort -n| uniq`
   for host in $uniqHosts
   do
      bigsql_getMlnCount ${nodesFile} "${host}"
      numMlnsInOneHost=$?
      if [[ $maxMln -lt $numMlnsInOneHost ]]
      then
         maxMln=$numMlnsInOneHost
         maxHost=${host}
      fi
   done

   echo "Max Logical Big SQL Worker Count ${maxHost} : $maxMln"
   return $maxMln
}

#################################################
# Make logging error free with fallback mechanism
# Content of $SCRIPT_LOG is altered if it cant be
# created.
# The following one of three value used with
# fail-back mechanism  when a log
# file is attempted to be created:
# At the end of the executions
# SCRIPT_LOG is : 
#------------------------------------------------
#   i- ${SCRIPT_LOG}
#   ii- /tmp/`basename $SCRIPT_LOG` (if i failed)
# iii- stdout  (if ii failed)
#  iv- /dev/null  (if iii failed)
#################################################
createLogDirIfNotExist()
{
   local scriptLog=$1
   local scriptLogDir=`dirname $scriptLog`
   local sudo_cmd=""

   ##############################################
   # Check sudo access for user
   ##############################################
   if [[ $EUID -ne 0 ]]; then
      sudo -v > /dev/null 2>&1
      sudoCheckForUser=$?
      if [[ $sudoCheckForUser -eq 0 ]]
      then
         sudo_cmd="sudo" 
      fi
   fi

   #############################################
   # This log function my be used by root
   # sudo id or bigsql. For the case of no dir
   # but running id is bigsql then we must 
   # avoid the sudo, and attempt to create 
   # with non-sudo exec. Even that fails
   # fallback mechanism should avoid and error
   # as a result of this .
   #############################################
   ${sudo_cmd} mkdir -p ${scriptLogDir} > /dev/null 2>&1
   ${sudo_cmd} chmod 777 ${scriptLogDir} > /dev/null 2>&1
}

alterScriptLogWithFallback()
{

   SCRIPT_LOG=$1
   ################################################
   # if nothing specified then redirect to /dev/null
   ################################################
   if [[ -z ${SCRIPT_LOG} ]]
   then
      SCRIPT_LOG=/dev/null
      return 
   fi

   ################################################
   # Do not manipulate any directory that is not 
   # starting with /tmp
   # if user passes a weird dir its own responsiblity
   # making sure it is writable we can't assume
   # good intentions only.
   ################################################
   if [[ ${SCRIPT_LOG} == "/tmp"* ]]
   then
      ###############################################
      # If specified then check if dir exist
      ###############################################
      createLogDirIfNotExist ${SCRIPT_LOG}
   fi

  touch ${SCRIPT_LOG}
  logfileOK=$?
  if [[ ${logFileOK} -ne 0 ]]
  then
    ##############################################
    # if failed on target path, fall back to /tmp
    ##############################################
    LOG_FILE_NAME=`basename $SCRIPT_LOG`
    SCRIPT_LOG=/tmp/${LOG_FILE_NAME}
    touch ${SCRIPT_LOG}
    logfileOK=$?
    if [[ ${logFileOK} -ne 0 ]]
    then
       ###########################################
       # if failed on /tmp fall back to stdout
       ###########################################
       SCRIPT_LOG="/dev/stdout"
       touch ${SCRIPT_LOG}
       logfileOK=$?
       ###########################################
       # if failed on /dev/stdout then redirect
       # to /dev/null
       ###########################################
       if [[ ${logFileOK} -ne 0 ]]
       then
         SCRIPT_LOG="/dev/null"
       fi
    fi
  else
    chmod 666 ${SCRIPT_LOG} &> /dev/null
  fi
  #################################################
  # Explicitly return 0, to avoid misuse 
  # of rc of last exec-command to be a logging
  # caller does not set or returns  explicit rc
  # might end up at  higher levels of the 
  # call stack to intercept an error.
  # This below will gurantee not have any impact of
  # processing of the actual functionality that 
  # a-logs b-misuse this function by acting on its
  # return code whatever that might be.
  #################################################
  return 0
}

create_logdir_logfile()
{
   alterScriptLogWithFallback ${SCRIPT_LOG}
}

makeDirPathForUser()
{
   local path=$1
   local user=$2
   local group=$3

   echo "Path to create: $path"
   echo "Target User   : $user"
   echo "Target Group  : $group"

   mkdir -p $path
   mkdirResult=$?

   ###############################################
   # If mkdir failed or no-user given
   # then just return failure.
   ###############################################
   if [[ $mkdirResult -ne 0 ]] || [[ -z $user ]]
   then
      return $mkdirResult
   fi

   # Make target dir owned by user:group
   if [[ ! -z $user ]] 
   then
      chown $user $path
   fi

   # Test if dir is writable by the user
   if [[ ! -z $group ]] 
   then
      chgrp $group $path
   fi

   ${SUDO_CMD} su - $user  sh -c "exit 0"
   sudoResult=$?

   if [[ $sudoResult -eq 0 ]]
   then
      ############################################
      # Dir created or existed
      # A user is given
      # sudo to this user is possible
      # now check if dir is writable for 
      # the given user if so then
      # return success else
      # we will fix the permissions
      ############################################
      ${SUDO_CMD} su - $user sh -c "touch  $1/.write_test"
      writeResult=$?
      if [[ $writeResult -eq 0 ]]
      then
         ${SUDO_CMD} su - $user sh -c "unlink $1/.write_test"
         return $writeResult
      else
         ########################################
         # Fix The Permission of the path
         # for the user.
         ########################################
         IFS="/" read -ra PARTS <<< "$path"
         for token in "${PARTS[@]}"
         do
            if [[ ! -z $token ]]
            then
               scanpath="$scanpath/$token"
               chmod 755 $scanpath > /dev/null 2>&1
               echo "Changed Dir Perm of $scanpath with rc=$?"
            fi
         done
      fi
   fi
}

adjustBigSQLContainers()
{
   local changeCount=$1

   if [[ ${changeCount} -lt 0 ]]
   then
      sign="-"
   else
      sign="+"
   fi

   slider exists bigsql > /dev/null
   isBigSQLUnderSliderControl=$?
   if  [[ $isBigSQLUnderSliderControl -eq 0 ]]
   then
      echo "Big SQL is under Slider Control"
      slider flex bigsql --component BIGSQL_WORKER  $sign$changeCount
   else
      echo "Big SQL is not under Slider control. No adjustment will be made."
   fi
}

isSliderInControl()
{
   slider exists bigsql > /dev/null
   isBigSQLUnderSliderControl=$?
   if  [[ $isBigSQLUnderSliderControl -eq 0 ]]
   then
      return 0
   else
      return 1
   fi
}

restoreMemValue=""

evalAutoConfigureMemPct()
{
   logLevel=$[logLevel+1]
   local memPercent
   local instance_mem

   local target_mem=${1}

   log "${FUNCNAME}"  "Started"

   if [[ -z ${target_mem} ]]
   then
      instance_mem=`db2 get dbm cfg |  grep  'Global instance memory' | cut -d'=' -f2 |  awk '{print $1}'`
   else
      instance_mem=${target_mem}
   fi

   log "${FUNCNAME}"  "Instance Mem in 4kb: $instance_mem"
   local boxTotalMem=$(awk '/^MemTotal:/{print $2}' /proc/meminfo) 
   local boxTotalMemIn4K=$(($boxTotalMem/4))
   log "${FUNCNAME}"  "Box Total Mem in 4kb: $boxTotalMemIn4K"
   bigsql_listMlns ${BIGSQL_USER}
   maxMln=$?
   log_echo "${FUNCNAME}"  "Maximum number of logical nodes on a host in the instance: $maxMln"
   log_echo "${FUNCNAME}"  "Number of containers per worker: ${BIGSQL_NUM_CONTAINER}"

   isSliderInControl
   sliderInControl=$?
   if [[ $sliderInControl -eq 0 ]]
   then 
      echo "Slider is in control"
      if [[ ! -z  ${BIGSQL_NUM_CONTAINER} ]]
      then
         if [[ ${BIGSQL_NUM_CONTAINER} -lt ${maxMln} ]]
         then
            maxMln=${BIGSQL_NUM_CONTAINER}
            log_echo "${FUNCNAME}"  "Restricting max number of logical nodes to match number of containers: $maxMln"
         fi
      fi
   else
      echo "Slider is not in control"
   fi

   if [[ $instance_mem -lt 101 ]]
   then
      log "${FUNCNAME}"  "Big SQL Instance mem is set to: $instance_mem"
      memPercent=${instance_mem}
   else
      ################################################
      # We need to restore to this value if value is 
      # used and whenever autoconfigure is run.
      ################################################
      restoreMemValue=${instance_mem}
      log "${FUNCNAME}"  "Big SQL Instance mem is set to 4kb pages: $instance_mem"
      log "${FUNCNAME}"  "Box Total Mem in 4kb: $boxTotalMemIn4K"
      memPercent=$((100*$instance_mem*$maxMln/$boxTotalMemIn4K)) 
   fi

   if [[ $memPercent -eq 0 ]]
   then
      memPercent=1
      log "${FUNCNAME}"  "Setting evaluated memPercent from 0 to 1"
   fi

   log "${FUNCNAME}"  "Completed. memPercent: $memPercent"
   logLevel=$[logLevel-1]

   return $memPercent
}

stopBigSQL()
{
   log_echo "${FUNCNAME}" "Stopping Big SQL"
   isSliderInControl
   sliderInControl=$?
   if [[ $sliderInControl -eq 0 ]]
   then 
      log "${FUNCNAME}" "Slider is in control"
      slider stop bigsql  >> ${SCRIPT_LOG}
      result=$?
      log "${FUNCNAME}" "Stopped bigsql application with rc=$?"
      # STEP2 : HEAD STOP
      ###################################################
      # HEAD NODE is not controlled by slider 
      # We need to recyle with db2 interface
      ###################################################
      bigsql stop -n 0 >> ${SCRIPT_LOG}
      rc=$?
      log "${FUNCNAME}" "Stopped Big SQL Head with rc=$?"

   else
      log "${FUNCNAME}" "Db2 is in control"
      bigsql stop >> ${SCRIPT_LOG}
   fi
   log_echo "${FUNCNAME}" "Stopping Big SQL has Completed"
}

startBigSQL()
{
   log "${FUNCNAME}" "Starting Big SQL"
   isSliderInControl
   sliderInControl=$?
   if [[ $sliderInControl -eq 0 ]]
   then 
      log "${FUNCNAME}" "Slider is in control"
      bigsql start -n 0 >> ${SCRIPT_LOG}
      rc=$?
      log "${FUNCNAME}" "Started Big SQL HEADNODE with rc=$?"

      slider start bigsql >> ${SCRIPT_LOG}
      result=$?
      log "${FUNCNAME}" "Started bigsql application with rc=$?"
   else
      log "${FUNCNAME}" "Db2 is in control"
      log_echo "${FUNCNAME}" "Starting Big SQL"
      bigsql start >> ${SCRIPT_LOG}
   fi
   log "${FUNCNAME}" "Starting Big SQL is completed."
}

restartBigSQL()
{
   stopBigSQL
   startBigSQL 
}

restartBigSQLwithDb2()
{
   stopBigSQL
   log "${FUNCNAME}" "Starting Big SQL"
   bigsql start >> ${SCRIPT_LOG}
   log "${FUNCNAME}" "Starting Big SQL is completed."
}

get_bigsql_cpu_share()
{
   source /etc/profile.d/bigsqlenv.sh
   TOTAL_VCORES=`grep -c ^processor /proc/cpuinfo`
   TOTAL_CONTAINER_VCORES=$(( $BIGSQL_NUM_CONTAINER * $BIGSQL_CONTAINER_VCORE))
   TOTAL_CPU_SHARE=$(($TOTAL_CONTAINER_VCORES*100/$TOTAL_VCORES))

   echo "Number of Big SQL containers   : $BIGSQL_NUM_CONTAINER"
   echo "Big SQL container vCore request: $BIGSQL_CONTAINER_VCORE"
   echo "Total vCores on host           : $TOTAL_VCORES"
   echo "Big SQL overall vCore          : $TOTAL_CONTAINER_VCORES"
   echo "Big SQL CPU Share              : $TOTAL_CPU_SHARE"
   return ${TOTAL_CPU_SHARE}
}

autoConfigThenRestartBigSQL()
{
   local result
   local rc
   local sliderInControl
   local cont_mem4k=$1

   ####################################################
   # We now need to recycle the instance at first :
   ####################################################
   log_echo "${FUNCNAME}" "Restarting Big SQL service before autoconfigure."
   if [[ ! -z $cont_mem4k ]]
   then
    log_echo "${FUNCNAME}" "Container Mem4K : $cont_mem4k"
   fi

   restartBigSQLwithDb2
   ##########################################################
   # Evaluate Mem Percent for autoconfigure this evaluation 
   # handles both db2 or yarn/slider controlled env.
   # In yarn case instance memory is set to fix 4kb pages
   # below function distinguishes % or 4kb pages and 
   # re-evaluates the number
   #######$$$$$$$############################################
   evalAutoConfigureMemPct ${cont_mem4k}
   MEM_PERCENT=$?

   currentInstMem=`db2 get dbm cfg |  grep  'Global instance memory' | cut -d'=' -f2 |  awk '{print $1}'`
   if [[ ${currentInstMem} != ${MEM_PERCENT} ]]
   then 
      log_echo "${FUNCNAME}" "Updating instance memory"
      db2 update dbm cfg using instance_memory ${MEM_PERCENT}
      if [[ $? -ne 0 ]]
      then
         log_echo "${FUNCNAME}" "Failed to set instance memory to ${MEM_PERCENT}"
      else
         log_echo "${FUNCNAME}" "Instance memory set to ${MEM_PERCENT}"
      fi
   fi

   ##########################################################
   log_echo   "${FUNCNAME}" "Started Post Operations"
   log_echo   "${FUNCNAME}" "Running db2 autoconfigure" 
   MEM_CLAUSE="mem_percent ${MEM_PERCENT}"

   ##########################################################
   # Autconfigure will not run if all nodes are not up
   # best effort wise it will run. The reason is clear
   # there might be dead nodes as well...
   # bring all nodes up.
   ##########################################################
   for configAttempt  in 1 2 3
   do
      db2 connect to bigsql >> ${SCRIPT_LOG}
      result=$?

      if [[ $result -ne 0 ]]
      then
         db2 terminate >> ${SCRIPT_LOG}
         log_echo "${FUNCNAME}" "Connection failed with rc=$result"
         log_echo "${FUNCNAME}" "Updating temp mem value for connect to ${TEMP_MEM_PERCENT}"
         TEMP_MEM_PERCENT=$((( configAttempt + 1 ) * 25 ))
         db2 update dbm cfg using instance_memory ${TEMP_MEM_PERCENT}

         db2 connect to bigsql >> ${SCRIPT_LOG}
         result=$?
         if [[ $result -ne 0 ]]
         then
           log_echo "${FUNCNAME}" "Trying to reconnect after start"
           bigsql start
           db2 connect to bigsql >> ${SCRIPT_LOG}
         fi
      else
         log_echo "${FUNCNAME}" "Connection succeeded"
      fi

      db2 -s "autoconfigure using ${MEM_CLAUSE} workload_type complex is_populated no apply db and dbm" >> ${SCRIPT_LOG}
      result=$?

      if [[ $result -ne 0 ]]
      then
         rc=1
         log_echo "${FUNCNAME}" "Autoconfigure failed with error=$result, rc=$rc at attempt # $configAttempt"
         log_echo "${FUNCNAME}" "Recycling instance to retry autoconfig with mem_pct=${TEMP_MEM_PERCENT}"
         bigsql stop  >> ${SCRIPT_LOG}
         TEMP_MEM_PERCENT=$((( configAttempt + 1 ) * 25 ))
         db2 update dbm cfg using instance_memory ${TEMP_MEM_PERCENT}
         bigsql start >> ${SCRIPT_LOG}
         # Attempt to recover if db partitions are not good.
         db2_all "db2 add dbpartitionnum"  >> ${SCRIPT_LOG}
      else
         rc=0
         log_echo "${FUNCNAME}" "Autoconfigure is completed with success"
         break; 
      fi
      db2 terminate
   done
   log_echo "${FUNCNAME}" "Autoconfigure completed with rc=$result"

   if [[ ! -z ${BIGSQL_NUM_CONTAINER} ]]
   then
      get_bigsql_cpu_share
      BIGSQL_CPU_LIMIT=$?
      log_echo "${FUNCNAME}" "Setting cpu limit to ${BIGSQL_CPU_LIMIT}" 
      db2set "DB2_CPU_BINDING=MACHINE_SHARE=${BIGSQL_CPU_LIMIT}"
      result=$?
      if [[ $result -ne 0 ]]
      then
         rc=1
      fi
      log_echo "${FUNCNAME}" "db2set completed with rc=$result"
   fi

   ####################################################
   # We now need to recycle the instance..
   ####################################################
   isSliderInControl
   sliderInControl=$?
   if [[ $sliderInControl -eq 0 ]]
   then
     log_echo "${FUNCNAME}" "Slider is in control. Stopping Big SQL after autoconfigure"
     bigsql stop  >> ${SCRIPT_LOG}
   else
     log_echo "${FUNCNAME}" "Restarting Big SQL Globally after autoconfigure"
     restartBigSQLwithDb2
   fi

   log "${FUNCNAME}" "Restart completed with rc=$rc"
   return $rc
}

renew_kerberos_ticket()
{
   local cmd=0
   local rc=0

   kerberosLogFile=/tmp/bigsql-kinit.log

   . ${BIGSQL_HOME}/libexec/include-ctl.sh

   if [[ ! -z ${SCRIPT_LOG} ]]
   then
      kerberosLogFile=${SCRIPT_LOG}
   else
      if [[ ! -z ${OPERATION_LOG} ]] 
      then
         kerberosLogFile=${OPERATION_LOG}
      fi
   fi

   thisHost=`hostname --long`
   echo "Running on host: $thisHost" >  ${kerberosLogFile}


   echo "Checking Big SQL Service Config"  >> ${kerberosLogFile}
   client_conf="${BIGSQL_HOME}/conf/bigsql-conf.xml"
   if [ -f "${client_conf}" ]
   then
      echo "Checking Big SQL Kerberos in Service Config"  >> ${kerberosLogFile}
      kerberos_enabled=$(get_property "security.authentication.kerberos.enabled" "${client_conf}") # || return 1
      echo "Kerberos enabled: $kerberos_enabled"  >> ${kerberosLogFile}

      if (${kerberos_enabled} = "true") 
      then
         key_tab_file=$(get_property "security.authentication.kerberos.keytab_file" "${client_conf}") || return 1
         echo "Keytab file: $key_tab_file"  >> ${kerberosLogFile}

         kinit_location=$(get_property "security.authentication.kerberos.kinit_location" "${client_conf}") || return 1
         echo "Kinit location: $kinit_location"  >> ${kerberosLogFile}

         kerberos_principal=$(get_property "security.authentication.kerberos.principal" "${client_conf}") || return 1
         echo "Kerberos principal: $kerberos_principal"  >> ${kerberosLogFile}

         #prepare the kinit command for renewing ticket
         cmd="${kinit_location}/kinit -k -f -t ${key_tab_file} ${kerberos_principal}"
         echo "Renewing kerberos ticket: $cmd" >>  ${kerberosLogFile}
         ${cmd} >> ${kerberosLogFile} 2>&1
         result=$?
         if [[ $result -ne 0 ]]
         then
            echo "$cmd: Execution failed with rc=$result"   
            rc=1
         fi

         # Also kinit to populate the environment's default JDK - Open/Oracle JDK's cache
         cmd="kinit -k -t ${key_tab_file} ${kerberos_principal}"
         ${cmd} >> ${kerberosLogFile} 2>&1
         result=$?
         if [[ $result -ne 0 ]]
         then
            echo "$cmd: Execution failed with rc=$result"   
            rc=1
         fi
      fi
   fi

   return $rc
}


killOrphanDb2Proc()
{
 targetProc=$1
 killLog=/tmp/bigsql-kill.log
 echo "Killing orphan procs for $targetProc" >> ${killLog}
 host=`hostname --long`
 echo "Executed at $host " >> ${killLog}
 
 proclist=`ps -elf | grep ${targetProc} | sed 's/ \+/\,/g' | grep -v grep | cut -d',' -f4,5,15`
 for line in $proclist
 do
   pid=`echo $line| cut -d',' -f1`
   ppid=`echo $line| cut -d',' -f2`
   name=`echo $line| cut -d',' -f3`
    
   if [[ ${ppid} == 1 ]]
   then
      echo "Pid=$pid, PPid=$ppid, name=$name" >>  ${killLog}
      echo "Killing orphan $name pid=$pid" >>  ${killLog}
      kill -9 $pid  >>  ${killLog}
   fi
 done
}

killOrphanBigSQLProcs()
{
 killLog=/tmp/bigsql-kill.log
 echo "killOrphanBigSQLProcs" > ${killLog}

 killOrphanDb2Proc "db2fmp"
 killOrphanDb2Proc "db2sysc"
 killOrphanDb2Proc "db2ckpwd"
 killOrphanDb2Proc "db2acd"
}

switchToServiceMode()
{
    
    local result=0
    local rc=0
    DBNAME="bigsql"
    logLevel=$[logLevel+1]
  
    if [[ -z ${SCRIPT_LOG} ]]
    then
       SCRIPT_LOG=/tmp/bigsql_switchToServiceMode.log.$$
       rm -f  ${SCRIPT_LOG}
    fi

    log "$FUNCNAME"  "Start"

    for attempt in 1 2
    do
      ##################################################################
      # Reconnect to db
      ##################################################################
      db2 terminate
      db2 "connect to $DBNAME" >> ${SCRIPT_LOG}
      result=$?

      if [[ $result -ne 0 ]]
      then
         log "$FUNCNAME" "Connection attempt failed with $result, exiting"
         #####################################################
         # Attempt to bring up db2 at head node
         #####################################################
         log "$FUNCNAME" "Attempting to start head node"
         bigsql start -n 0 >> ${SCRIPT_LOG}
         log "$FUNCNAME" "Terminating clp session"
         db2 terminate  >> ${SCRIPT_LOG}
         log "$FUNCNAME" "Reconnect attempt"
         db2 connect to bigsql >> ${SCRIPT_LOG}
         result=$?
         if [[ $result -ne 0 ]]
         then 
            log "$FUNCNAME" "Reconnect attempt failed with result=$result"
            rc=1
         fi
      fi

      db2 "call syshadoop.big_sql_service_mode('on' )" >> ${SCRIPT_LOG}
      result=$?

      if [[ $result -ne 0 ]]
      then
         log "$FUNCNAME" "Failed to switch service mode with rc=[$result]"
         #####################################################
         # Service mode would fail if there is no worker up left
         #####################################################
         workerNode=`head -2 ~/sqllib/db2nodes.cfg | tail  -1 |cut -d' ' -f1`
         log "$FUNCNAME" "Starting first worker ${workerNode}"
         bigsql start -n ${workerNode}  >> ${SCRIPT_LOG}
         #####################################################
         # Service mode would fail if db is not activated
         #####################################################
         log "$FUNCNAME" "Terminating connection"
         db2 terminate >> ${SCRIPT_LOG}
         log "$FUNCNAME" "Activating database ${DBNAME}"
         db2 activate db ${DBNAME} >> ${SCRIPT_LOG}
         log "$FUNCNAME" "Reconnecting to database ${DBNAME}"
         db2 terminate >> ${SCRIPT_LOG}
         db2 connect to ${DBNAME}  >> ${SCRIPT_LOG}
         result=$?
         if [[ $result -ne 0 ]]
         then 
            log "$FUNCNAME" "Reconnect attempt failed with result=$result"
            rc=1
         fi
      else
         #####################################################
         log "$FUNCNAME" "Successfully switched to service mode with rc=[$result]"
         rc=0
         break
      fi
    
    done

    log "$FUNCNAME"  "Completed with rc=$rc"
    logLevel=$[logLevel-1]
    return $rc
}


no_user_data()
{
  local rc=0

  log $FUNCNAME "Check user data"
  db2 connect to bigsql >> $SCRIPT_LOG
  db2 "select substr(TABSCHEMA,1,15) , substr(TABNAME,1,15) , substr(TBSPACE,1,15)  from syscat.tables where TBSPACE = 'BIGSQLUTILITYSPACE'"
  #if any record is found return is 0.
  result=$?
  db2 terminate
  if [[ $result -eq 0 ]]
  then
     log ${FUNCNAME} "User Data Exists"
     # Abort caller
     rc=1
  else
     log ${FUNCNAME} "No user data or (can not be determined)"
     rc=0
  fi

  return $rc
}

