cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`
#log file setting
WHISTLE_CONF_PATH=$SPARROW_HOME/whistle/conf
LOG_CONF_ENGINE_RMI=-Dlogback.configurationFile="$WHISTLE_CONF_PATH/logback-engine-server.xml"
LOG_CONF_ENGINE_BOOT=-Dlogging.config="$WHISTLE_CONF_PATH/logback-engine-server.xml"
LOG_CONF_NEST_RMI=-Dlogback.configurationFile="$WHISTLE_CONF_PATH/logback-nest-server.xml"
LOG_CONF_NEST_BOOT=-Dlogging.config="$WHISTLE_CONF_PATH/logback-nest-server.xml"
LOG_CONF_COMMAND=-Dlogback.configurationFile="$WHISTLE_CONF_PATH/logback-command.xml"

ENGINE_RMI_SERVER_STARTUP=`cat sparrow.properties | grep engine.rmi.server.startup | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`
NEST_RMI_SERVER_STARTUP=`cat sparrow.properties | grep nest.rmi.server.startup | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`

ENGINE_RMI_REGISTRY_PORT=`cat sparrow.properties | grep engine.rmi.registry.port | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`
NEST_RMI_REGISTRY_PORT=`cat sparrow.properties | grep nest.rmi.registry.port | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`

PG_SQL_PATH=`cat sparrow.properties | grep nest.pgsql.path | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`
export LD_LIBRARY_PATH=$PG_SQL_PATH/../lib:$LD_LIBRARY_PATH

TARGET=$2
if [ "$TARGET" = "" ];then
   TARGET="all"
fi

START() {
  case "$TARGET" in
    tomcat|pgsql|migrate)
       START_TOMCAT_PGSQL
    ;;
    engine_rmi)
       START_ENGINE_RMI_SERVER
    ;;
    nest_rmi)
       START_NEST_RMI_SERVER
    ;;
    all)
       echo "[INFO ] Starting SPARROW..."
       START_TOMCAT_PGSQL
       START_NEST_RMI_SERVER
       START_ENGINE_RMI_SERVER
    ;;
    *)
       echo "Usage: ./sparrow-run.sh start {tomcat|pgsql|migrate|engine_rmi|nest_rmi}"
       exit 0
    ;;
  esac
}

START_TOMCAT_PGSQL() {
#change permission
  mkdir -p ${SPARROW_HOME}/logs/
  mkdir -p ${SPARROW_HOME}/data/temp
  "$SPARROW_HOME"/command.sh "$LOG_CONF_COMMAND" com.fasoo.sparrow.server.Bootstrap start "$TARGET"
}

START_ENGINE_RMI_SERVER() {
  if [ "$ENGINE_RMI_SERVER_STARTUP" = "true" ];then
    if [ $SPARROW_ENGINE_PID ];then
         echo -e "\033[31;1m[ERROR] Engine integrated server ${ENGINE_RMI_REGISTRY_PORT} port has already been used. Please restart or change port.\033[0m"
    else
         echo "[INFO ] Starting Remote Engine Server..."
         nohup "$SPARROW_HOME"/command.sh "$LOG_CONF_ENGINE_RMI" "$LOG_CONF_ENGINE_BOOT" -Djava.security.egd=file:/dev/./urandom com.fasoo.sparrow.engine.rmi.EngineServer > /dev/null 2>&1 &
    fi
  else
    if [ "$TARGET" = "engine_rmi" ];then
         echo "[INFO ] Please change the option(engine.rmi.server.startup) of the configuration file(sparrow.properties) to 'true' in order to run the program."
    fi
  fi
}

START_NEST_RMI_SERVER() {
  if [ "$NEST_RMI_SERVER_STARTUP" = "true" ];then
    if [ $SPARROW_NEST_PID ];then
         echo -e "\033[31;1m[ERROR] NEST integrated server ${NEST_RMI_REGISTRY_PORT} port has already been used. Please restart or change port.\033[0m"
    else
         echo "[INFO ] Starting Remote Analysis Control Server..."
         nohup "$SPARROW_HOME"/command.sh "$LOG_CONF_NEST_RMI" "$LOG_CONF_NEST_BOOT" -Djava.security.egd=file:/dev/./urandom com.fasoo.sparrow.nest.rmi.NestServer > /dev/null 2>&1 &
    fi
  else
    if [ "$TARGET" = "nest_rmi" ];then
       echo "[INFO ] Please change the option(nest.rmi.server.startup) of the configuration file(sparrow.properties) to 'true' in order to run the program."
    fi  
  fi
}

STOP() {
  case "$TARGET" in
    tomcat|pgsql)
       STOP_TOMCAT_PGSQL
    ;;
    engine_rmi)
       STOP_ENGINE_RMI_SERVER
    ;;
    nest_rmi)
       STOP_NEST_RMI_SERVER
    ;;
    all)
       echo "[INFO ] Stopping SPARROW..."
       STOP_ENGINE_RMI_SERVER
       STOP_NEST_RMI_SERVER
       STOP_TOMCAT_PGSQL
    ;;
    *)
       echo "Usage: ./sparrow-run.sh stop {tomcat|pgsql|engine_rmi|nest_rmi}"
       exit 0
    ;;
  esac
}

STOP_TOMCAT_PGSQL() {
  "$SPARROW_HOME"/command.sh "$LOG_CONF_COMMAND" com.fasoo.sparrow.server.Bootstrap stop "$TARGET"
  if [ $TARGET == "tomcat" ] || [ $TARGET == "all" ];then
     for tomcat_pid in `ps -ef | grep -v grep | grep tomcat | grep "$SPARROW_HOME/nest" | awk '{print $2}'`;do
         kill -9 $tomcat_pid
     done
  fi
}


STOP_ENGINE_RMI_SERVER() {
  if [ "$SPARROW_ENGINE_PID" = "" ];then
      if [ "$ENGINE_RMI_SERVER_STARTUP" = "true" ];then
          echo "[INFO ] Remote Engine Server has already been stopped."
      fi
  else
      for engine_rmi_pid in $SPARROW_ENGINE_PID;do
          if [ $engine_rmi_pid ];then
              echo "[INFO ] Stopping Remote Engine Server..."
              "$SPARROW_HOME"/killall.sh $engine_rmi_pid
          fi
      done
  fi
}

STOP_NEST_RMI_SERVER() {
  if [ "$SPARROW_NEST_PID" = "" ];then
      if [ "$NEST_RMI_SERVER_STARTUP" = "true" ];then
          echo "[INFO ] Remote Analysis Control Server has already been stopped."
      fi
  else
      for nest_rmi_pid in $SPARROW_NEST_PID;do
          if [ $nest_rmi_pid ];then
              echo "[INFO ] Stopping Remote Analysis Control Server..."
              "$SPARROW_HOME"/killall.sh $nest_rmi_pid
          fi
      done
  fi
}


RESTART() {
  case "$TARGET" in
    tomcat|pgsql)
       STOP_TOMCAT_PGSQL
       START_TOMCAT_PGSQL
    ;;
    engine_rmi)
       STOP_ENGINE_RMI_SERVER
       sleep 2
       SET_RMI_PID
       START_ENGINE_RMI_SERVER
    ;;
    nest_rmi)
       STOP_NEST_RMI_SERVER
       sleep 2
       SET_RMI_PID
       START_NEST_RMI_SERVER
    ;;
    all)
       echo "[INFO ] Restarting SPARROW..."
       STOP_ENGINE_RMI_SERVER
       STOP_NEST_RMI_SERVER
       STOP_TOMCAT_PGSQL
       SET_RMI_PID
       START_TOMCAT_PGSQL
       START_NEST_RMI_SERVER
       START_ENGINE_RMI_SERVER
   ;;
    *)
       echo "Usage: ./sparrow-run.sh restart {tomcat|pgsql|engine_rmi|nest_rmi}"
       exit 0
    ;;
  esac
}

SET_RMI_PID() {
  SPARROW_NEST_PID=`ps -ef | grep java | grep "$SPARROW_HOME/sparrow.properties" | grep NestServer | awk '{print $2}'`
  SPARROW_ENGINE_PID=`ps -ef | grep java | grep "$SPARROW_HOME/sparrow.properties" | grep EngineServer | awk '{print $2}'`
}

SET_RMI_PID
case "$1" in
  start)
    START
  ;;
  stop)
    STOP
  ;;
  restart)
    RESTART
  ;;
  *)
    echo "Usage: ./sparrow-run.sh {start|stop|restart}"
    exit 0
  ;;
esac


