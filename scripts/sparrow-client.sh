#edited by kimkc 20100415 : init

if [ not $BUILD_PATH ];then
    BUILD_PATH=`pwd`
fi

cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`
LOG_CONF_WHISTLE=-Dlogback.configurationFile="$SPARROW_HOME/whistle/conf/logback-whistle.xml"

if [ -f "$BUILD_PATH"/sparrow/.root ];then
   rm "$BUILD_PATH"/sparrow/.root
fi

"$SPARROW_HOME"/command.sh "$LOG_CONF_WHISTLE" com.fasoo.sparrow.whistle.command.WhistleCommand --build-path "$BUILD_PATH" "$@"
