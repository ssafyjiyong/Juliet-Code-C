#edited by kimkc 20100601 : init
cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`
WHISTLE_HOME=$SPARROW_HOME/whistle
WHISTLE_CONF_PATH=$WHISTLE_HOME/conf
SPARROW_CONF=$SPARROW_HOME/sparrow.properties

PG_SQL_LIB_PATH=$SPARROW_HOME/nest/pgsql/lib
if [ -f "${SPARROW_HOME}/sparrow.properties" ];then
  PG_SQL_LIB_PATH=`cat sparrow.properties | grep nest.pgsql.path | grep -v "#" | cut -d "=" -f 2 | sed 's/ //g' | sed 's/  //g'`/../lib
fi
export LD_LIBRARY_PATH=$PG_SQL_LIB_PATH:$LD_LIBRARY_PATH

LOG_CONF_COMMAND=-Dlogback.configurationFile="$SPARROW_HOME/whistle/conf/logback-command.xml"

CLASSPATH=$JAVA_HOME/lib/tools.jar
for f in "$WHISTLE_HOME"/lib/*.jar
do
 CLASSPATH="$CLASSPATH":"$f"
done

_JAVAPATH=
if [ -f "${SPARROW_HOME}/jre/bin/java" ];then
   _JAVAPATH=${SPARROW_HOME}/jre/bin/
fi

mkdir -p ${SPARROW_HOME}/logs/
mkdir -p ${SPARROW_HOME}/data/
mkdir -p ${SPARROW_HOME}/data/temp/

#run java
${_JAVAPATH}java -Xms256m -Xmx1024m -cp "$CLASSPATH:" -Dsparrow.home="$SPARROW_HOME" -Djava.security.policy="$POLICY" -Dsparrow.configuration="$SPARROW_CONF" "$LOG_CONF_COMMAND" com.fasoo.sparrow.server.Setup setup "$@"

