#edited by kimkc 20100601 : init

#set sparrow home
cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`

# set whistle home
WHISTLE_HOME=$SPARROW_HOME/whistle

#set classpath
CLASSPATH="$JAVA_HOME/lib/tools.jar:$WHISTLE_HOME/lib/*"

#set properties file
SPARROW_CONF=$SPARROW_HOME/sparrow.properties
POLICY=$WHISTLE_HOME/conf/policy

_JAVAPATH=
if [ -f "${SPARROW_HOME}/jre/bin/java" ];then
   _JAVAPATH=${SPARROW_HOME}/jre/bin/
fi

#run java
if [ -f "${SPARROW_HOME}/sparrow.properties" ];then
  ${_JAVAPATH}java -Dsparrow.home="$SPARROW_HOME" -Djava.security.policy="$POLICY" -Dsparrow.configuration="$SPARROW_CONF" -Dlogback.configurationFile="$WHISTLE_HOME/conf/logback-update.xml" -jar "$WHISTLE_HOME/update/update.jar" "$@"
  if [ -f "${SPARROW_HOME}/err_update" ];then
    echo ""
  else
    ${_JAVAPATH}java -Xmx1024m -cp "$CLASSPATH:" -Dsparrow.home="$SPARROW_HOME" -Djava.security.policy="$POLICY"  -Dsparrow.configuration="$SPARROW_CONF" "$@"
  fi
else
  echo Not exist [sparrow.properties]. Please setup first.
fi
