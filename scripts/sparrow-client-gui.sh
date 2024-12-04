cd ${0%/*} 2>/dev/null
SPARROW_HOME=`dirname "$(echo $PWD/${0##*/})"`

OS=`uname`
export PORTABLE_EXECUTABLE_DIR=$SPARROW_HOME

if [ "$OS" = "Darwin" ];then
  cd ${SPARROW_HOME}/whistle/gui/mac
  GUIVER=`ls *.tar.gz | cut -d "-" -f 4`
  if [ -d "${SPARROW_HOME}/whistle/gui/mac/sparrow-client-gui.app" ];then
    EXISTVER=`cat ${SPARROW_HOME}/whistle/gui/mac/sparrow-client-gui.app/ver`
    if [ "${GUIVER}" != "${EXISTVER}" ];then
      rm -rf ${SPARROW_HOME}/whistle/gui/mac/sparrow-client-gui.app/
      tar xzvf *.tar.gz
      echo $GUIVER > ${SPARROW_HOME}/whistle/gui/mac/sparrow-client-gui.app/ver
    fi
  else
    tar xzvf *.tar.gz
    echo $GUIVER > ${SPARROW_HOME}/whistle/gui/mac/sparrow-client-gui.app/ver
  fi
  open $SPARROW_HOME/whistle/gui/mac/sparrow-client-gui.app
else
  $SPARROW_HOME/whistle/gui/linux/sparrow-client-gui --no-sandbox
fi

