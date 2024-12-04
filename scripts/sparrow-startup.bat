@echo off
SET LOG_CONF=%~dp0whistle\conf\log4j-command.properties
SET CLASSNAME=com.fasoo.sparrow.server.Bootstrap
echo [INFO ] Start SPARROW...
call ".\command.bat" start %*
