#edited by kimkc 20100415 : init
cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`
LOG_CONF=-Dlogback.configurationFile="$SPARROW_HOME/whistle/conf/logback-whistle.xml"

"$SPARROW_HOME"/command.sh "$LOG_CONF" com.fasoo.sparrow.whistle.command.MakeProjectCommand  "$@"
